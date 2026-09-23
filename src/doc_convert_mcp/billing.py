"""Stripe billing: monthly subscriber plans that bypass per-call x402 charges.

Model: pay-as-you-go via x402 stays for non-subscribers; a Stripe monthly
subscription issues a subscriber key (``X-Subscriber-Key`` header) that the
x402 middleware accepts in place of a per-call payment.

Only the SHA-256 hash of a subscriber key is ever stored — the raw key is
shown to the user once (via ``GET /billing/key``) and never logged.

Everything is OFF by default; see ``stripe_effective_enabled`` (fail closed).
"""

from __future__ import annotations

import hashlib
import logging
import os
import secrets
import sqlite3
import threading
from datetime import datetime, timezone

import stripe

log = logging.getLogger("doc_convert_mcp.billing")

_SCHEMA = """
CREATE TABLE IF NOT EXISTS subscribers (
  key_hash    TEXT PRIMARY KEY,
  customer_id TEXT NOT NULL,
  email       TEXT,
  status      TEXT NOT NULL,
  created_at  TEXT NOT NULL,
  updated_at  TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_subscribers_customer ON subscribers(customer_id);
"""

_db_lock = threading.Lock()


def _env_flag(name: str, default: str = "false") -> bool:
    return os.environ.get(name, default).strip().lower() in ("1", "true", "yes", "on")


def stripe_effective_enabled() -> bool:
    """True only when Stripe is fully configured. Fail closed otherwise."""
    if not _env_flag("STRIPE_ENABLED"):
        return False
    missing = [
        name
        for name in ("STRIPE_SECRET_KEY", "STRIPE_WEBHOOK_SECRET", "STRIPE_PRICE_ID")
        if not os.environ.get(name, "").strip()
    ]
    if missing:
        log.error(
            "STRIPE_ENABLED=true but missing %s — Stripe DISABLED (fail closed).",
            ", ".join(missing),
        )
        return False
    return True


#: Default subscriber DB path: the Render persistent disk mount (see
#: render.yaml ``disk:``). Overridable with ``BILLING_DB_PATH`` — tests and
#: local dev point it at a temp dir instead.
DEFAULT_BILLING_DB_PATH = "/var/lib/doc-convert-mcp/billing.db"


def billing_db_path() -> str:
    return os.environ.get("BILLING_DB_PATH", DEFAULT_BILLING_DB_PATH).strip() or (
        DEFAULT_BILLING_DB_PATH
    )


def _connect() -> sqlite3.Connection:
    path = billing_db_path()
    parent = os.path.dirname(os.path.abspath(path))
    os.makedirs(parent, exist_ok=True)
    conn = sqlite3.connect(path)
    conn.executescript(_SCHEMA)
    return conn


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def hash_subscriber_key(raw_key: str) -> str:
    return hashlib.sha256(raw_key.encode("utf-8")).hexdigest()


def create_subscriber(customer_id: str, email: str | None, status: str = "active") -> str:
    """Issue a fresh subscriber key for a customer.

    Rotates any previous keys for that customer. Returns the RAW key — the
    caller shows it to the user once; only its hash is stored.
    """
    raw_key = secrets.token_hex(32)  # 32 random bytes, hex-encoded
    now = _now_iso()
    with _db_lock, _connect() as conn:
        conn.execute("DELETE FROM subscribers WHERE customer_id = ?", (customer_id,))
        conn.execute(
            "INSERT INTO subscribers (key_hash, customer_id, email, status, created_at, updated_at)"
            " VALUES (?, ?, ?, ?, ?, ?)",
            (hash_subscriber_key(raw_key), customer_id, email, status, now, now),
        )
    return raw_key


def deactivate_customer(customer_id: str | None) -> None:
    if not customer_id:
        return
    with _db_lock, _connect() as conn:
        conn.execute(
            "UPDATE subscribers SET status = 'canceled', updated_at = ? WHERE customer_id = ?",
            (_now_iso(), customer_id),
        )


def sync_customer_status(customer_id: str | None, status: str | None) -> None:
    if not customer_id or not status:
        return
    with _db_lock, _connect() as conn:
        conn.execute(
            "UPDATE subscribers SET status = ?, updated_at = ? WHERE customer_id = ?",
            (status, _now_iso(), customer_id),
        )


def subscriber_key_valid(raw_key: str | None) -> bool:
    """True if the key's hash maps to an active subscriber row."""
    if not raw_key or not stripe_effective_enabled():
        return False
    with _db_lock, _connect() as conn:
        row = conn.execute(
            "SELECT status FROM subscribers WHERE key_hash = ?",
            (hash_subscriber_key(raw_key.strip()),),
        ).fetchone()
    return row is not None and row[0] == "active"


def _stripe() -> stripe:
    stripe.api_key = os.environ["STRIPE_SECRET_KEY"].strip()
    return stripe


def create_checkout_session() -> str:
    """Create a Stripe Checkout Session for the monthly plan. Returns its URL."""
    session = _stripe().checkout.Session.create(
        mode="subscription",
        line_items=[{"price": os.environ["STRIPE_PRICE_ID"].strip(), "quantity": 1}],
        success_url=os.environ.get("STRIPE_SUCCESS_URL", "").strip(),
        cancel_url=os.environ.get("STRIPE_CANCEL_URL", "").strip(),
    )
    return session.url


def handle_stripe_webhook(payload: bytes, sig_header: str | None) -> dict:
    """Verify and apply a Stripe webhook event. Raises on bad signature."""
    try:
        event = _stripe().Webhook.construct_event(
            payload, sig_header or "", os.environ["STRIPE_WEBHOOK_SECRET"].strip()
        )
    except Exception as exc:  # signature or payload invalid
        log.warning("Stripe webhook signature verification failed: %s", type(exc).__name__)
        raise
    event_type = event.get("type")
    obj = event.get("data", {}).get("object", {}) if isinstance(event, dict) else {}
    if event_type == "checkout.session.completed":
        customer_id = obj.get("customer")
        details = obj.get("customer_details") or {}
        email = details.get("email") or obj.get("customer_email")
        if customer_id:
            create_subscriber(customer_id, email, status="active")
            log.info("Stripe subscriber activated (customer_id=%s)", customer_id)
        else:
            log.warning("checkout.session.completed without a customer id; ignored")
    elif event_type == "customer.subscription.deleted":
        deactivate_customer(obj.get("customer"))
        log.info("Stripe subscription deleted; subscriber deactivated")
    elif event_type == "customer.subscription.updated":
        sync_customer_status(obj.get("customer"), obj.get("status"))
        log.info("Stripe subscription updated; status synced")
    return {"received": True, "type": event_type}


def issue_key_for_session(session_id: str) -> str:
    """Return a fresh subscriber key for a paid checkout session.

    The session is re-fetched from Stripe and must be paid; the raw key is
    returned once and only its hash is stored.
    """
    session = _stripe().checkout.Session.retrieve(session_id)
    if session.get("payment_status") != "paid":
        raise LookupError(
            f"checkout session is not paid (status={session.get('payment_status')!r})"
        )
    customer_id = session.get("customer")
    if not customer_id:
        raise LookupError("checkout session has no customer")
    details = session.get("customer_details") or {}
    email = details.get("email")
    return create_subscriber(customer_id, email, status="active")

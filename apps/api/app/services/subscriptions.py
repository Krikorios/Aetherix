"""Subscription lifecycle for Aetherix customers.

This module manages **per-customer subscription instances** — distinct
from the catalog SKUs in :mod:`app.services.licensing`. Each customer
has at most one row in ``subscription_instances`` that tracks the
current status, trial window, billing period, and cancellation flag.
Every lifecycle transition writes an append-only row to
``subscription_events`` so auditors can reconstruct billing history.

Service functions never enforce RBAC themselves — the API layer
composes ``tenancy.has_permission`` with these calls.

The webhook entry point :func:`handle_webhook_event` is intentionally
provider-agnostic: it dispatches on ``event_kind`` rather than on
provider-specific payload shape. The HTTP layer is responsible for
validating the provider's signature (HMAC-SHA256 over the raw body
keyed with ``AETHERIX_WEBHOOK_SECRET``) before calling in.
"""

from __future__ import annotations

import hmac
import json
import uuid
from datetime import UTC, datetime, timedelta
from hashlib import sha256
from os import environ
from uuid import UUID

from app.db import connection
from app.schemas import (
    BillingCustomer,
    CancelSubscriptionRequest,
    StartTrialRequest,
    SubscribeRequest,
    SubscriptionEvent,
    SubscriptionInstance,
)


class SubscriptionError(Exception):
    """Domain error for subscription lifecycle operations (maps to 4xx)."""


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _now() -> datetime:
    return datetime.now(UTC)


def _row_to_instance(row: dict) -> SubscriptionInstance:
    return SubscriptionInstance(
        id=row["id"],
        customer_id=row["customer_id"],
        subscription_id=row["subscription_id"],
        subscription_sku=row["sku"],
        status=row["status"],
        trial_ends_at=row.get("trial_ends_at"),
        current_period_start=row.get("current_period_start"),
        current_period_end=row.get("current_period_end"),
        cancel_at_period_end=row["cancel_at_period_end"],
        canceled_at=row.get("canceled_at"),
        provider=row.get("provider"),
        provider_subscription_id=row.get("provider_subscription_id"),
        seats=row["seats"],
        created_at=row["created_at"],
        updated_at=row["updated_at"],
    )


def _row_to_event(row: dict) -> SubscriptionEvent:
    payload = row["payload"]
    if isinstance(payload, str):
        payload = json.loads(payload)
    return SubscriptionEvent(
        id=row["id"],
        subscription_instance_id=row["subscription_instance_id"],
        kind=row["kind"],
        payload=payload or {},
        source=row["source"],
        received_at=row["received_at"],
    )


def _row_to_billing_customer(row: dict) -> BillingCustomer:
    return BillingCustomer(
        customer_id=row["customer_id"],
        provider=row["provider"],
        external_id=row["external_id"],
        default_payment_method=row.get("default_payment_method"),
        status=row["status"],
        created_at=row["created_at"],
        updated_at=row["updated_at"],
    )


def _select_instance(cur, customer_id: UUID) -> dict | None:
    cur.execute(
        """
        select i.*, s.sku
        from subscription_instances i
        join subscriptions s on s.id = i.subscription_id
        where i.customer_id = %s
        """,
        (customer_id,),
    )
    return cur.fetchone()


def _resolve_sku(cur, sku: str) -> dict:
    cur.execute("select id, sku from subscriptions where sku = %s", (sku,))
    row = cur.fetchone()
    if row is None:
        raise SubscriptionError(f"unknown subscription sku {sku!r}")
    return row


def _record_event(
    cur,
    instance_id: UUID,
    kind: str,
    payload: dict | None = None,
    *,
    source: str = "internal",
) -> None:
    cur.execute(
        """
        insert into subscription_events (
            id, subscription_instance_id, kind, payload, source, received_at
        ) values (%s, %s, %s, %s::jsonb, %s, %s)
        """,
        (
            uuid.uuid4(),
            instance_id,
            kind,
            json.dumps(payload or {}),
            source,
            _now(),
        ),
    )


# ---------------------------------------------------------------------------
# Queries
# ---------------------------------------------------------------------------


def get_subscription_for(customer_id: UUID) -> SubscriptionInstance | None:
    with connection() as conn, conn.cursor() as cur:
        row = _select_instance(cur, customer_id)
    return _row_to_instance(row) if row else None


def list_events(
    customer_id: UUID, *, limit: int = 100
) -> list[SubscriptionEvent]:
    with connection() as conn, conn.cursor() as cur:
        row = _select_instance(cur, customer_id)
        if row is None:
            return []
        cur.execute(
            """
            select * from subscription_events
            where subscription_instance_id = %s
            order by received_at desc
            limit %s
            """,
            (row["id"], limit),
        )
        return [_row_to_event(r) for r in cur.fetchall()]


def get_billing_customer(customer_id: UUID) -> BillingCustomer | None:
    with connection() as conn, conn.cursor() as cur:
        cur.execute(
            "select * from billing_customers where customer_id = %s",
            (customer_id,),
        )
        row = cur.fetchone()
    return _row_to_billing_customer(row) if row else None


# ---------------------------------------------------------------------------
# Lifecycle transitions
# ---------------------------------------------------------------------------


def start_trial(
    customer_id: UUID, payload: StartTrialRequest
) -> SubscriptionInstance:
    """Open a trial subscription. Raises if the customer already has one."""

    now = _now()
    trial_end = now + timedelta(days=payload.trial_days)
    with connection() as conn, conn.cursor() as cur:
        if _select_instance(cur, customer_id) is not None:
            raise SubscriptionError(
                "customer already has a subscription instance"
            )
        sku_row = _resolve_sku(cur, payload.subscription_sku)
        instance_id = uuid.uuid4()
        cur.execute(
            """
            insert into subscription_instances (
                id, customer_id, subscription_id, status, trial_ends_at,
                current_period_start, current_period_end,
                cancel_at_period_end, seats, created_at, updated_at
            ) values (%s, %s, %s, 'trialing', %s, %s, %s, false, %s, %s, %s)
            """,
            (
                instance_id,
                customer_id,
                sku_row["id"],
                trial_end,
                now,
                trial_end,
                payload.seats,
                now,
                now,
            ),
        )
        _record_event(
            cur,
            instance_id,
            "trial_started",
            {
                "subscription_sku": payload.subscription_sku,
                "trial_days": payload.trial_days,
                "seats": payload.seats,
            },
        )
        row = _select_instance(cur, customer_id)
    return _row_to_instance(row)  # type: ignore[arg-type]


def subscribe(
    customer_id: UUID, payload: SubscribeRequest
) -> SubscriptionInstance:
    """Activate (or upgrade) a paid subscription. Creates the row if absent."""

    now = _now()
    period_end = now + timedelta(days=30)
    with connection() as conn, conn.cursor() as cur:
        existing = _select_instance(cur, customer_id)
        sku_row = _resolve_sku(cur, payload.subscription_sku)
        if existing is None:
            instance_id = uuid.uuid4()
            cur.execute(
                """
                insert into subscription_instances (
                    id, customer_id, subscription_id, status,
                    current_period_start, current_period_end,
                    cancel_at_period_end, provider,
                    provider_subscription_id, seats,
                    created_at, updated_at
                ) values (%s, %s, %s, 'active', %s, %s, false, %s, %s,
                          %s, %s, %s)
                """,
                (
                    instance_id,
                    customer_id,
                    sku_row["id"],
                    now,
                    period_end,
                    payload.provider,
                    payload.provider_subscription_id,
                    payload.seats,
                    now,
                    now,
                ),
            )
            _record_event(
                cur,
                instance_id,
                "subscribed",
                {
                    "subscription_sku": payload.subscription_sku,
                    "seats": payload.seats,
                    "provider": payload.provider,
                },
            )
        else:
            instance_id = existing["id"]
            cur.execute(
                """
                update subscription_instances
                set subscription_id = %s,
                    status = 'active',
                    cancel_at_period_end = false,
                    canceled_at = null,
                    provider = %s,
                    provider_subscription_id = %s,
                    seats = %s,
                    current_period_start = coalesce(current_period_start, %s),
                    current_period_end = coalesce(current_period_end, %s),
                    updated_at = %s
                where id = %s
                """,
                (
                    sku_row["id"],
                    payload.provider,
                    payload.provider_subscription_id,
                    payload.seats,
                    now,
                    period_end,
                    now,
                    instance_id,
                ),
            )
            _record_event(
                cur,
                instance_id,
                "subscribed",
                {
                    "subscription_sku": payload.subscription_sku,
                    "seats": payload.seats,
                    "provider": payload.provider,
                    "previous_status": existing["status"],
                },
            )
        row = _select_instance(cur, customer_id)
    return _row_to_instance(row)  # type: ignore[arg-type]


def cancel(
    customer_id: UUID, payload: CancelSubscriptionRequest
) -> SubscriptionInstance:
    """Cancel a subscription. ``at_period_end`` keeps service until period end."""

    now = _now()
    with connection() as conn, conn.cursor() as cur:
        existing = _select_instance(cur, customer_id)
        if existing is None:
            raise SubscriptionError("customer has no subscription to cancel")
        if existing["status"] == "canceled":
            raise SubscriptionError("subscription is already canceled")
        if payload.at_period_end:
            cur.execute(
                """
                update subscription_instances
                set cancel_at_period_end = true,
                    updated_at = %s
                where id = %s
                """,
                (now, existing["id"]),
            )
            kind = "cancel_scheduled"
        else:
            cur.execute(
                """
                update subscription_instances
                set status = 'canceled',
                    cancel_at_period_end = false,
                    canceled_at = %s,
                    updated_at = %s
                where id = %s
                """,
                (now, now, existing["id"]),
            )
            kind = "canceled"
        _record_event(
            cur,
            existing["id"],
            kind,
            {"reason": payload.reason, "at_period_end": payload.at_period_end},
        )
        row = _select_instance(cur, customer_id)
    return _row_to_instance(row)  # type: ignore[arg-type]


def resume(customer_id: UUID) -> SubscriptionInstance:
    """Reverse a pending cancel-at-period-end."""

    now = _now()
    with connection() as conn, conn.cursor() as cur:
        existing = _select_instance(cur, customer_id)
        if existing is None:
            raise SubscriptionError("customer has no subscription to resume")
        if existing["status"] == "canceled":
            raise SubscriptionError(
                "cannot resume a fully canceled subscription; resubscribe instead"
            )
        if not existing["cancel_at_period_end"]:
            raise SubscriptionError("subscription is not scheduled to cancel")
        cur.execute(
            """
            update subscription_instances
            set cancel_at_period_end = false,
                updated_at = %s
            where id = %s
            """,
            (now, existing["id"]),
        )
        _record_event(cur, existing["id"], "resumed", {})
        row = _select_instance(cur, customer_id)
    return _row_to_instance(row)  # type: ignore[arg-type]


def suspend(customer_id: UUID, *, reason: str | None = None) -> SubscriptionInstance:
    """Pause an active subscription (e.g. operator action)."""

    now = _now()
    with connection() as conn, conn.cursor() as cur:
        existing = _select_instance(cur, customer_id)
        if existing is None:
            raise SubscriptionError("customer has no subscription to suspend")
        cur.execute(
            """
            update subscription_instances
            set status = 'paused',
                updated_at = %s
            where id = %s
            """,
            (now, existing["id"]),
        )
        _record_event(cur, existing["id"], "suspended", {"reason": reason})
        row = _select_instance(cur, customer_id)
    return _row_to_instance(row)  # type: ignore[arg-type]


def mark_renewed(
    customer_id: UUID, *, period_days: int = 30, source: str = "internal"
) -> SubscriptionInstance:
    """Advance the current billing period after a successful payment."""

    now = _now()
    new_end = now + timedelta(days=period_days)
    with connection() as conn, conn.cursor() as cur:
        existing = _select_instance(cur, customer_id)
        if existing is None:
            raise SubscriptionError("customer has no subscription to renew")
        cur.execute(
            """
            update subscription_instances
            set status = case when cancel_at_period_end then 'canceled' else 'active' end,
                canceled_at = case when cancel_at_period_end then %s else null end,
                current_period_start = %s,
                current_period_end = %s,
                updated_at = %s
            where id = %s
            """,
            (now, now, new_end, now, existing["id"]),
        )
        _record_event(
            cur,
            existing["id"],
            "renewed",
            {"period_days": period_days},
            source=source,
        )
        row = _select_instance(cur, customer_id)
    return _row_to_instance(row)  # type: ignore[arg-type]


def record_payment_failure(
    customer_id: UUID, *, reason: str | None = None, source: str = "internal"
) -> SubscriptionInstance:
    """Mark a subscription past_due after a failed payment attempt."""

    now = _now()
    with connection() as conn, conn.cursor() as cur:
        existing = _select_instance(cur, customer_id)
        if existing is None:
            raise SubscriptionError("customer has no subscription")
        cur.execute(
            """
            update subscription_instances
            set status = 'past_due',
                updated_at = %s
            where id = %s
            """,
            (now, existing["id"]),
        )
        _record_event(
            cur,
            existing["id"],
            "payment_failed",
            {"reason": reason},
            source=source,
        )
        row = _select_instance(cur, customer_id)
    return _row_to_instance(row)  # type: ignore[arg-type]


# ---------------------------------------------------------------------------
# Billing customer link
# ---------------------------------------------------------------------------


def upsert_billing_customer(
    customer_id: UUID,
    provider: str,
    external_id: str,
    *,
    default_payment_method: str | None = None,
    status: str = "active",
) -> BillingCustomer:
    now = _now()
    with connection() as conn, conn.cursor() as cur:
        cur.execute(
            """
            insert into billing_customers (
                customer_id, provider, external_id, default_payment_method,
                status, created_at, updated_at
            ) values (%s, %s, %s, %s, %s, %s, %s)
            on conflict (customer_id) do update
                set provider = excluded.provider,
                    external_id = excluded.external_id,
                    default_payment_method = excluded.default_payment_method,
                    status = excluded.status,
                    updated_at = excluded.updated_at
            returning *
            """,
            (
                customer_id,
                provider,
                external_id,
                default_payment_method,
                status,
                now,
                now,
            ),
        )
        return _row_to_billing_customer(cur.fetchone())


# ---------------------------------------------------------------------------
# Webhook entry point
# ---------------------------------------------------------------------------


def verify_webhook_signature(body: bytes, signature: str | None) -> bool:
    """Constant-time HMAC-SHA256 verification of a webhook payload.

    Reads the shared secret from ``AETHERIX_WEBHOOK_SECRET``. Returns
    False when either the env var or the signature is missing — the
    caller MUST reject in that case.
    """

    secret = environ.get("AETHERIX_WEBHOOK_SECRET")
    if not secret or not signature:
        return False
    expected = hmac.new(secret.encode("utf-8"), body, sha256).hexdigest()
    return hmac.compare_digest(expected, signature.strip().lower())


def handle_webhook_event(
    provider: str, event_kind: str, payload: dict
) -> SubscriptionInstance | None:
    """Dispatch a verified webhook event to the appropriate transition.

    ``payload`` MUST include ``customer_id`` (Aetherix UUID); the HTTP
    layer is responsible for resolving the provider's customer id to
    the local UUID via ``billing_customers`` before calling here.
    """

    raw_cid = payload.get("customer_id")
    if raw_cid is None:
        raise SubscriptionError("webhook payload missing customer_id")
    try:
        customer_id = UUID(str(raw_cid))
    except ValueError as exc:
        raise SubscriptionError("webhook payload has invalid customer_id") from exc

    if event_kind in {"invoice.paid", "renewal.succeeded"}:
        return mark_renewed(
            customer_id,
            period_days=int(payload.get("period_days", 30)),
            source="webhook",
        )
    if event_kind in {"invoice.payment_failed", "payment.failed"}:
        return record_payment_failure(
            customer_id, reason=payload.get("reason"), source="webhook"
        )
    if event_kind in {"customer.subscription.deleted", "subscription.canceled"}:
        # Provider already terminated; record it without further changes.
        with connection() as conn, conn.cursor() as cur:
            existing = _select_instance(cur, customer_id)
            if existing is None:
                return None
            cur.execute(
                """
                update subscription_instances
                set status = 'canceled',
                    canceled_at = coalesce(canceled_at, %s),
                    cancel_at_period_end = false,
                    updated_at = %s
                where id = %s
                """,
                (_now(), _now(), existing["id"]),
            )
            _record_event(
                cur, existing["id"], "canceled", payload, source="webhook"
            )
            row = _select_instance(cur, customer_id)
        return _row_to_instance(row)  # type: ignore[arg-type]

    # Unknown event kind — record it on the customer's instance (if any)
    # so the auditor sees it, but do not change status.
    with connection() as conn, conn.cursor() as cur:
        existing = _select_instance(cur, customer_id)
        if existing is None:
            return None
        _record_event(
            cur,
            existing["id"],
            f"webhook:{event_kind}",
            payload,
            source="webhook",
        )
        row = _select_instance(cur, customer_id)
    return _row_to_instance(row)  # type: ignore[arg-type]

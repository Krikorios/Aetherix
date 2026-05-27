"""Subscription lifecycle: billing customers, subscription instances, events

Revision ID: 20260525_0004
Revises: 20260524_0003
Create Date: 2026-05-25 12:00:00

Adds three tables that move Aetherix from a static catalog (the
existing ``subscriptions`` table is now treated as an SKU catalog) to
a real per-customer subscription lifecycle:

- ``billing_customers``: one row per customer that has been linked to
  a payment provider (Stripe, manual invoicing, mock for tests). The
  ``(provider, external_id)`` tuple is unique so webhook payloads can
  resolve back to the owning customer without trusting the request body.
- ``subscription_instances``: one active row per customer that ties the
  customer to a catalog SKU and tracks ``status``, ``trial_ends_at``,
  the current billing period, and a ``cancel_at_period_end`` flag.
  ``status`` is constrained to the standard set
  (trialing / active / past_due / canceled / paused / incomplete).
- ``subscription_events``: append-only audit/event log for every
  lifecycle transition (trial-started, subscribed, canceled,
  payment_failed, renewal-succeeded, webhook-received, …). Source is
  marked ``internal`` or ``webhook`` so auditors can distinguish
  operator-driven changes from provider-driven changes.

All FKs cascade on customer delete. The single-row-per-customer
constraint lives on ``subscription_instances.customer_id`` as a
``UNIQUE`` index; renewals reuse the same row, cancellations leave it
in place with ``status='canceled'`` for evidence retention.

See docs/native-security-gap-review.md "P1 #5 — subscription lifecycle"
and docs/roadmap-2026.md.
"""

from __future__ import annotations

import sqlalchemy as sa  # noqa: F401  (kept for downstream migration tooling)
from alembic import op


revision = "20260525_0004"
down_revision = "20260524_0003"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute(
        """
        create table if not exists billing_customers (
            customer_id uuid primary key references customers(id) on delete cascade,
            provider text not null,
            external_id text not null,
            default_payment_method text,
            status text not null default 'active',
            created_at timestamptz not null,
            updated_at timestamptz not null,
            constraint ck_billing_customers_provider
                check (provider in ('stripe', 'manual', 'mock'))
        )
        """
    )
    op.execute(
        """
        create unique index if not exists billing_customers_provider_external_idx
        on billing_customers(provider, external_id)
        """
    )

    op.execute(
        """
        create table if not exists subscription_instances (
            id uuid primary key,
            customer_id uuid not null unique references customers(id) on delete cascade,
            subscription_id uuid not null references subscriptions(id),
            status text not null default 'trialing',
            trial_ends_at timestamptz,
            current_period_start timestamptz,
            current_period_end timestamptz,
            cancel_at_period_end boolean not null default false,
            canceled_at timestamptz,
            provider text,
            provider_subscription_id text,
            seats integer not null default 0,
            created_at timestamptz not null,
            updated_at timestamptz not null,
            constraint ck_subscription_status check (
                status in ('trialing', 'active', 'past_due', 'canceled',
                          'paused', 'incomplete')
            )
        )
        """
    )
    op.execute(
        """
        create index if not exists subscription_instances_status_idx
        on subscription_instances(status)
        """
    )

    op.execute(
        """
        create table if not exists subscription_events (
            id uuid primary key,
            subscription_instance_id uuid not null
                references subscription_instances(id) on delete cascade,
            kind text not null,
            payload jsonb not null default '{}'::jsonb,
            source text not null default 'internal',
            received_at timestamptz not null,
            constraint ck_subscription_events_source
                check (source in ('internal', 'webhook'))
        )
        """
    )
    op.execute(
        """
        create index if not exists subscription_events_instance_idx
        on subscription_events(subscription_instance_id, received_at desc)
        """
    )


def downgrade() -> None:
    op.execute("drop index if exists subscription_events_instance_idx")
    op.execute("drop table if exists subscription_events")
    op.execute("drop index if exists subscription_instances_status_idx")
    op.execute("drop table if exists subscription_instances")
    op.execute("drop index if exists billing_customers_provider_external_idx")
    op.execute("drop table if exists billing_customers")

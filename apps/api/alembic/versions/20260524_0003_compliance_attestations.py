"""Compliance Evidence Engine v0.5: attestations, reviews, vault references

Revision ID: 20260524_0003
Revises: 20260523_0002
Create Date: 2026-05-24 12:00:00

Adds three tables that take the Compliance Evidence Engine from v0
(signed JSON export) to v0.5 (auditor-deliverable PDF + attestations):

- `compliance_attestations`: signed sign-off rows from named operators
  (CEO/CTO/CISO/etc) tying a framework + reporting period to the
  current evidence bundle hash. `attested_role` and `attested_name`
  are snapshot columns so attestations remain auditor-valid after the
  signing account is hard-deleted.
- `compliance_reviews`: per-evidence-item review records so an operator
  can mark "I have inspected this item" before it appears in the
  auditor export. The reference is discriminated (`source_table` +
  `source_id`) against an allow-list of the five evidence-bearing
  tables; no cross-table FK because IDs are heterogeneous
  (`audit_log.seq` is bigserial, others are uuid).
- `compliance_vault_references`: pointers to large evidence artefacts
  held in an object store so Postgres does not bloat. The artefact
  hash and byte size are recorded for tamper-evidence.

All tables are tenant-scoped via `customer_id` (nullable to permit
platform-owner-level attestations) and append-only by convention;
deletions are not exposed via API. UUID primary keys are generated in
the service layer (uuid.uuid4()) to match the existing Aetherix
pattern; no server defaults and no pgcrypto dependency. The five
allowed `framework` slugs match the seed in 20260523_0002.

Downgrade warning: this migration is irreversible after attestations
exist — signed auditor data will be permanently lost. Do not run
`alembic downgrade` against a production database that has captured
operator sign-offs.

See docs/roadmap-2026.md P0-4 and docs/native-security-gap-review.md
"Native Development Priorities" #1.
"""

from __future__ import annotations

import sqlalchemy as sa  # noqa: F401  (kept for downstream migration tooling)
from alembic import op


# revision identifiers, used by Alembic.
revision = "20260524_0003"
down_revision = "20260523_0002"
branch_labels = None
depends_on = None


_FRAMEWORK_CHECK = (
    "framework in ("
    "'iso27001-2022', 'soc2-2017', 'nist-csf-2.0', 'gdpr', 'hipaa-security-rule'"
    ")"
)
_SOURCE_TABLE_CHECK = (
    "source_table in ("
    "'compliance_controls', 'policy_documents', 'evidence_events', "
    "'security_alerts', 'audit_log'"
    ")"
)


def upgrade() -> None:
    # ---- compliance_attestations -------------------------------------------------
    op.execute(
        f"""
        create table if not exists compliance_attestations (
            id uuid primary key,
            customer_id uuid references customers(id) on delete cascade,
            framework text not null,
            period_start date not null,
            period_end date not null,
            attested_by_account_id uuid references accounts(id) on delete set null,
            attested_role text not null,
            attested_name text not null,
            bundle_sha256 text not null,
            signature text not null,
            signature_algo text not null default 'hmac-sha256',
            statement text not null,
            created_at timestamptz not null,
            constraint ck_attestation_period check (period_end >= period_start),
            constraint ck_attestation_framework check ({_FRAMEWORK_CHECK}),
            constraint ck_attestation_bundle_sha256
                check (bundle_sha256 ~ '^[0-9a-f]{{64}}$')
        )
        """
    )
    op.execute(
        """
        create index if not exists ix_compliance_attestations_customer_framework
        on compliance_attestations(customer_id, framework, period_end)
        """
    )
    op.execute(
        """
        create index if not exists ix_compliance_attestations_attested_by
        on compliance_attestations(attested_by_account_id)
        """
    )

    # ---- compliance_reviews ------------------------------------------------------
    op.execute(
        f"""
        create table if not exists compliance_reviews (
            id uuid primary key,
            customer_id uuid references customers(id) on delete cascade,
            source_table text not null,
            source_id text not null,
            framework text not null,
            control_id text not null,
            reviewed_by_account_id uuid references accounts(id) on delete set null,
            reviewed_by_role text not null,
            reviewed_by_name text not null,
            decision text not null,
            note text,
            reviewed_at timestamptz not null,
            constraint ck_review_decision
                check (decision in ('accept', 'reject', 'needs_more')),
            constraint ck_review_framework check ({_FRAMEWORK_CHECK}),
            constraint ck_review_source_table check ({_SOURCE_TABLE_CHECK})
        )
        """
    )
    op.execute(
        """
        create index if not exists ix_compliance_reviews_lookup
        on compliance_reviews(source_table, source_id, framework, control_id)
        """
    )
    op.execute(
        """
        create index if not exists ix_compliance_reviews_customer
        on compliance_reviews(customer_id, framework, reviewed_at)
        """
    )

    # ---- compliance_vault_references --------------------------------------------
    op.execute(
        f"""
        create table if not exists compliance_vault_references (
            id uuid primary key,
            customer_id uuid references customers(id) on delete cascade,
            source_table text not null,
            source_id text not null,
            framework text not null,
            storage_kind text not null,
            storage_uri text not null,
            sha256 text not null,
            byte_size bigint not null,
            created_at timestamptz not null,
            constraint ck_vault_storage_kind
                check (storage_kind in ('filesystem', 's3', 'blob')),
            constraint ck_vault_framework check ({_FRAMEWORK_CHECK}),
            constraint ck_vault_source_table check ({_SOURCE_TABLE_CHECK}),
            constraint ck_vault_sha256 check (sha256 ~ '^[0-9a-f]{{64}}$'),
            constraint ck_vault_byte_size check (byte_size >= 0)
        )
        """
    )
    op.execute(
        """
        create index if not exists ix_compliance_vault_references_lookup
        on compliance_vault_references(source_table, source_id, framework)
        """
    )
    op.execute(
        """
        create index if not exists ix_compliance_vault_references_customer
        on compliance_vault_references(customer_id, framework, created_at)
        """
    )


def downgrade() -> None:
    # WARNING: irreversible after attestations exist; signed auditor data is lost.
    op.execute("drop index if exists ix_compliance_vault_references_customer")
    op.execute("drop index if exists ix_compliance_vault_references_lookup")
    op.execute("drop table if exists compliance_vault_references")

    op.execute("drop index if exists ix_compliance_reviews_customer")
    op.execute("drop index if exists ix_compliance_reviews_lookup")
    op.execute("drop table if exists compliance_reviews")

    op.execute("drop index if exists ix_compliance_attestations_attested_by")
    op.execute("drop index if exists ix_compliance_attestations_customer_framework")
    op.execute("drop table if exists compliance_attestations")

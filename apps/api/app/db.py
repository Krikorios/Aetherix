"""Postgres connection pool and schema bootstrap.

The control plane stores all state in Postgres. There is no SQLite fallback
and no in-memory mock data: every read goes through ``connection()``.

The schema is created idempotently on application startup via
``init_schema()``. Tests obtain a per-test database via the
``pytest-postgresql`` fixture which sets ``AETHERIX_DATABASE_URL`` and calls
:func:`reset_pool` so the pool re-opens against the test database.
"""

from __future__ import annotations

import atexit
import os
from contextlib import contextmanager
from typing import Iterator

import psycopg
from psycopg.rows import dict_row
from psycopg_pool import ConnectionPool


_DEFAULT_URL = "postgresql://aetherix:aetherix@127.0.0.1:55432/aetherix"
_pool: ConnectionPool | None = None


def database_url() -> str:
    return os.getenv("AETHERIX_DATABASE_URL", _DEFAULT_URL)


def _get_pool() -> ConnectionPool:
    global _pool
    if _pool is None:
        _pool = ConnectionPool(
            conninfo=database_url(),
            min_size=1,
            max_size=int(os.getenv("AETHERIX_DB_POOL_MAX", "10")),
            kwargs={"row_factory": dict_row, "autocommit": False},
            open=True,
        )
    return _pool


def reset_pool() -> None:
    """Close the existing pool. Next ``connection()`` re-opens against the
    current ``AETHERIX_DATABASE_URL``. Used by tests."""

    global _pool
    if _pool is not None:
        _pool.close()
        _pool = None


atexit.register(reset_pool)


@contextmanager
def connection() -> Iterator[psycopg.Connection]:
    """Yield a transactional connection. Commits on success, rolls back on
    exception. Mirrors the previous ``with _connect() as connection`` usage."""

    pool = _get_pool()
    with pool.connection() as conn:
        try:
            yield conn
            conn.commit()
        except Exception:
            conn.rollback()
            raise


_SCHEMA_STATEMENTS = (
    """
    create table if not exists partners (
        id uuid primary key,
        name text not null,
        slug text not null unique,
        deployment_mode text not null default 'cloud',
        created_at timestamptz not null
    )
    """,
    """
    create table if not exists customers (
        id uuid primary key,
        partner_id uuid not null references partners(id),
        customer_number text not null unique,
        company_type text not null default 'customer' check (company_type in ('partner', 'customer')),
        name text not null,
        industry text,
        country text,
        company_size text,
        status text not null default 'active',
        created_by text not null,
        created_at timestamptz not null
    )
    """,
    """
    create index if not exists customers_partner_id_idx on customers(partner_id)
    """,
    """
    alter table customers add column if not exists company_type text not null default 'customer'
    """,
    """
    update customers
    set company_type = 'customer'
    where company_type is null or company_type not in ('partner', 'customer')
    """,
    """
    alter table customers alter column company_type set default 'customer'
    """,
    """
    alter table customers alter column company_type set not null
    """,
    """
    do $$
    begin
        if not exists (
            select 1
            from pg_constraint
            where conname = 'customers_company_type_check'
              and conrelid = 'customers'::regclass
        ) then
            alter table customers
            add constraint customers_company_type_check
            check (company_type in ('partner', 'customer'));
        end if;
    end $$;
    """,
    """
    create table if not exists customer_groups (
        id uuid primary key,
        customer_id uuid not null references customers(id),
        name text not null,
        created_at timestamptz not null,
        unique(customer_id, name)
    )
    """,
    """
    create table if not exists policy_packages (
        id uuid primary key,
        partner_id uuid references partners(id),
        name text not null,
        description text,
        package_type text not null default 'custom',
        payload jsonb not null,
        version integer not null default 1,
        signature text not null,
        created_by text not null,
        created_at timestamptz not null
    )
    """,
    """
    create table if not exists policy_assignments (
        id uuid primary key,
        customer_id uuid not null references customers(id),
        group_id uuid references customer_groups(id),
        policy_package_id uuid not null references policy_packages(id),
        assigned_by text not null,
        assigned_at timestamptz not null
    )
    """,
    """
    create unique index if not exists policy_assignments_customer_group_idx
        on policy_assignments(customer_id, coalesce(group_id, '00000000-0000-0000-0000-000000000000'::uuid))
    """,
    """
    create table if not exists heartbeats (
        agent_id text primary key,
        payload jsonb not null,
        updated_at timestamptz not null
    )
    """,
    """
    create table if not exists alerts (
        id text primary key,
        payload jsonb not null,
        status text not null,
        created_at timestamptz not null
    )
    """,
    """
    create table if not exists acknowledged_alerts (
        id text primary key,
        acknowledged_at timestamptz not null
    )
    """,
    """
    create table if not exists enrollment_tokens (
        id bigserial primary key,
        token_hash text not null unique,
        note text,
        created_at timestamptz not null,
        expires_at timestamptz not null,
        consumed_at timestamptz
    )
    """,
    """
    alter table enrollment_tokens add column if not exists partner_id uuid references partners(id)
    """,
    """
    alter table enrollment_tokens add column if not exists customer_id uuid references customers(id)
    """,
    """
    alter table enrollment_tokens add column if not exists group_id uuid references customer_groups(id)
    """,
    """
    alter table enrollment_tokens add column if not exists policy_package_id uuid references policy_packages(id)
    """,
    """
    alter table enrollment_tokens add column if not exists purpose text not null default 'agent_enrollment'
    """,
    """
    alter table enrollment_tokens add column if not exists max_uses integer not null default 1
    """,
    """
    alter table enrollment_tokens add column if not exists use_count integer not null default 0
    """,
    """
    alter table enrollment_tokens add column if not exists created_by text not null default 'operator'
    """,
    """
    create table if not exists enrolled_agents (
        agent_id text primary key,
        hostname text not null,
        os text not null,
        secret text not null,
        enrolled_at timestamptz not null,
        last_nonce bigint not null default 0,
        revoked boolean not null default false
    )
    """,
    """
    alter table enrolled_agents add column if not exists partner_id uuid references partners(id)
    """,
    """
    alter table enrolled_agents add column if not exists customer_id uuid references customers(id)
    """,
    """
    alter table enrolled_agents add column if not exists group_id uuid references customer_groups(id)
    """,
    """
    alter table enrolled_agents add column if not exists policy_package_id uuid references policy_packages(id)
    """,
    """
    create index if not exists enrolled_agents_customer_id_idx on enrolled_agents(customer_id)
    """,
    """
    create table if not exists module_actions (
        id uuid primary key,
        endpoint_id text not null references enrolled_agents(agent_id),
        action text not null,
        payload jsonb,
        status text not null default 'queued',
        approval_required boolean not null default false,
        created_by text not null,
        created_at timestamptz not null,
        processed_by text,
        processed_at timestamptz,
        evidence_controls jsonb not null default '[]'::jsonb
    )
    """,
    # --- Remote EDR management additions (2026-05-27) ---------------------
    # `result` captures the ResponseEvidence payload returned by the agent
    # when it acks an action (or when a heartbeat carries a response_action
    # EdrEvent that references the action via matched_indicator).
    # `requested_by` records the operator account id that submitted the
    # request; `approved_by` records the second operator for dual-approval
    # flows (e.g. high/critical quarantine restores).
    """
    alter table module_actions add column if not exists result jsonb
    """,
    """
    alter table module_actions add column if not exists requested_by uuid
    """,
    """
    alter table module_actions add column if not exists approved_by uuid
    """,
    """
    alter table module_actions add column if not exists approved_at timestamptz
    """,
    """
    alter table module_actions add column if not exists customer_id uuid references customers(id)
    """,
    """
    create index if not exists module_actions_customer_idx on module_actions(customer_id)
    """,
    """
    create index if not exists module_actions_action_idx on module_actions(action)
    """,
    # Latest quarantine inventory snapshot per endpoint, refreshed when the
    # agent acks a `quarantine_list` request. Keeps the console fast without
    # rescanning security_alerts every render.
    """
    create table if not exists endpoint_quarantine_inventory (
        endpoint_id text primary key references enrolled_agents(agent_id) on delete cascade,
        customer_id uuid references customers(id) on delete cascade,
        items jsonb not null default '[]'::jsonb,
        source_action_id uuid,
        refreshed_at timestamptz not null
    )
    """,
    """
    alter table heartbeats add column if not exists partner_id uuid references partners(id)
    """,
    """
    alter table heartbeats add column if not exists customer_id uuid references customers(id)
    """,
    """
    alter table heartbeats add column if not exists group_id uuid references customer_groups(id)
    """,
    """
    alter table alerts add column if not exists partner_id uuid references partners(id)
    """,
    """
    alter table alerts add column if not exists customer_id uuid references customers(id)
    """,
    """
    create table if not exists installer_builds (
        id uuid primary key,
        partner_id uuid not null references partners(id),
        customer_id uuid not null references customers(id),
        group_id uuid references customer_groups(id),
        policy_package_id uuid not null references policy_packages(id),
        platform text not null,
        status text not null,
        artifact_url text,
        artifact_sha256 text,
        signing_status text not null,
        expires_at timestamptz,
        created_by text not null,
        created_at timestamptz not null
    )
    """,
    """
    create index if not exists installer_builds_customer_id_idx on installer_builds(customer_id)
    """,
    """
    create table if not exists quick_deploy_links (
        id uuid primary key,
        customer_id uuid not null references customers(id),
        group_id uuid references customer_groups(id),
        installer_build_id uuid references installer_builds(id),
        secret_hash text not null unique,
        platform text,
        max_downloads integer,
        download_count integer not null default 0,
        expires_at timestamptz not null,
        revoked_at timestamptz,
        created_by text not null,
        created_at timestamptz not null
    )
    """,
    """
    create table if not exists policy_documents (
        version integer primary key,
        payload jsonb not null,
        is_active boolean not null default false,
        created_at timestamptz not null
    )
    """,
    """
    create unique index if not exists policy_documents_one_active
        on policy_documents(is_active) where is_active
    """,
    """
    create table if not exists custom_detection_rules (
        id uuid primary key,
        partner_id uuid references partners(id),
        customer_id uuid references customers(id) on delete cascade,
        name text not null,
        description text not null,
        severity text not null check (severity in ('low', 'medium', 'high', 'critical')),
        status text not null default 'draft' check (status in ('draft', 'simulated', 'active')),
        query text not null,
        author text not null,
        mitre_attacks jsonb not null default '[]'::jsonb,
        last_modified timestamptz not null,
        last_simulation_run timestamptz,
        scanned_agents_count integer not null default 0
    )
    """,
    """
    create index if not exists custom_detection_rules_customer_idx
    on custom_detection_rules(customer_id, last_modified desc)
    """,
    """
    create index if not exists custom_detection_rules_partner_idx
    on custom_detection_rules(partner_id, last_modified desc)
    """,
    """
    create table if not exists policy_documents_v2 (
        id uuid primary key,
        name text not null,
        schema_version text not null default '2.0',
        status text not null default 'draft',
        partner_id uuid references partners(id),
        customer_id uuid references customers(id),
        group_id uuid references customer_groups(id),
        endpoint_id text,
        latest_version integer not null default 1,
        active_version integer,
        created_at timestamptz not null,
        created_by text not null,
        updated_at timestamptz not null,
        updated_by text not null,
        evidence_controls jsonb not null default '[]'::jsonb
    )
    """,
    """
    create index if not exists policy_documents_v2_partner_idx on policy_documents_v2(partner_id)
    """,
    """
    create index if not exists policy_documents_v2_customer_idx on policy_documents_v2(customer_id)
    """,
    """
    create table if not exists policy_versions (
        id uuid primary key,
        policy_id uuid not null references policy_documents_v2(id) on delete cascade,
        version integer not null,
        status text not null default 'draft',
        payload jsonb not null,
        payload_hash text not null,
        signed_by text not null,
        signature text not null,
        promoted_from_simulation_id uuid,
        created_at timestamptz not null,
        created_by text not null,
        evidence_controls jsonb not null default '[]'::jsonb,
        unique(policy_id, version)
    )
    """,
    """
    create index if not exists policy_versions_policy_idx on policy_versions(policy_id)
    """,
    """
    create unique index if not exists policy_versions_one_active_per_policy
        on policy_versions(policy_id, status)
        where status = 'active'
    """,
    """
    create table if not exists policy_assignments_v2 (
        id uuid primary key,
        policy_id uuid not null references policy_documents_v2(id) on delete cascade,
        policy_version_id uuid not null references policy_versions(id) on delete cascade,
        partner_id uuid references partners(id),
        customer_id uuid references customers(id),
        group_id uuid references customer_groups(id),
        endpoint_id text,
        assigned_by text not null,
        assigned_at timestamptz not null,
        evidence_controls jsonb not null default '[]'::jsonb
    )
    """,
    """
    create unique index if not exists policy_assignments_v2_scope_unique
    on policy_assignments_v2(
        coalesce(partner_id, '00000000-0000-0000-0000-000000000000'::uuid),
        coalesce(customer_id, '00000000-0000-0000-0000-000000000000'::uuid),
        coalesce(group_id, '00000000-0000-0000-0000-000000000000'::uuid),
        coalesce(endpoint_id, '')
    )
    """,
    """
    create index if not exists policy_assignments_v2_policy_idx on policy_assignments_v2(policy_id)
    """,
    """
    create table if not exists policy_simulations (
        id uuid primary key,
        policy_id uuid not null references policy_documents_v2(id) on delete cascade,
        policy_version_id uuid not null references policy_versions(id) on delete cascade,
        status text not null,
        summary jsonb not null,
        outcomes jsonb not null,
        approval_required boolean not null default false,
        approved boolean not null default false,
        approved_by text,
        approval_reason text,
        approved_at timestamptz,
        evidence_event_id uuid,
        created_at timestamptz not null,
        created_by text not null,
        evidence_controls jsonb not null default '[]'::jsonb
    )
    """,
    """
    alter table policy_simulations add column if not exists evidence_event_id uuid
    """,
    """
    create index if not exists policy_simulations_policy_idx on policy_simulations(policy_id, created_at desc)
    """,
    """
    create table if not exists policy_promotions (
        id uuid primary key,
        policy_id uuid not null references policy_documents_v2(id) on delete cascade,
        policy_version_id uuid not null references policy_versions(id) on delete cascade,
        simulation_id uuid not null references policy_simulations(id) on delete cascade,
        status text not null,
        operator_approved boolean not null default false,
        approval_reason text,
        approver text not null,
        approved_at timestamptz not null,
        evidence_event_id uuid,
        evidence_controls jsonb not null default '[]'::jsonb
    )
    """,
    """
    create index if not exists policy_promotions_policy_idx
    on policy_promotions(policy_id, approved_at desc)
    """,
    """
    create table if not exists evidence_events (
        id uuid primary key,
        action text not null,
        resource text not null,
        actor text not null,
        scope jsonb not null default '{}'::jsonb,
        payload jsonb not null default '{}'::jsonb,
        evidence_controls jsonb not null default '[]'::jsonb,
        created_at timestamptz not null
    )
    """,
    """
    create index if not exists evidence_events_action_idx
    on evidence_events(action, created_at desc)
    """,
    """
    create table if not exists policy_acks (
        id uuid primary key,
        endpoint_id text not null references enrolled_agents(agent_id),
        policy_version_hash text not null,
        agent_version text not null,
        acknowledged_at timestamptz not null
    )
    """,
    """
    create index if not exists policy_acks_endpoint_idx
    on policy_acks(endpoint_id, acknowledged_at desc)
    """,
    """
    create table if not exists audit_log (
        seq bigserial primary key,
        ts timestamptz not null,
        actor text not null,
        action text not null,
        resource text not null,
        before_hash text,
        after_hash text,
        request_id text,
        prev_chain_hash text not null,
        chain_hash text not null
    )
    """,
    """
    alter table audit_log add column if not exists evidence_controls jsonb not null default '[]'::jsonb
    """,
    """
    create table if not exists telemetry_events (
        id uuid primary key,
        customer_id uuid not null references customers(id),
        agent_id text not null references enrolled_agents(agent_id),
        event_type text not null,
        payload jsonb not null,
        timestamp timestamptz not null
    )
    """,
    """
    create table if not exists security_alerts (
        id uuid primary key,
        customer_id uuid not null references customers(id),
        agent_id text not null references enrolled_agents(agent_id),
        category text not null,
        severity text not null,
        confidence integer not null,
        recommended_action text not null,
        ai_summary text,
        payload jsonb not null,
        status text not null default 'new',
        created_at timestamptz not null
    )
    """,
    """
    create table if not exists incident_cases (
        id uuid primary key,
        customer_id uuid not null references customers(id),
        title text not null,
        description text,
        severity text not null,
        status text not null default 'open',
        recommended_response text,
        created_at timestamptz not null,
        updated_at timestamptz not null
    )
    """,
    """
    alter table alerts add column if not exists evidence_controls jsonb not null default '[]'::jsonb
    """,
    """
    alter table policy_documents add column if not exists evidence_controls jsonb not null default '[]'::jsonb
    """,
    """
    alter table security_alerts add column if not exists evidence_controls jsonb not null default '[]'::jsonb
    """,
    """
    alter table security_alerts add column if not exists severity_uplifted_from text
    """,
    # Persisted FIM events used for cross-module correlation (FIM ↔ EDR).
    # The compliance trail still flows through evidence_events; this table
    # exists so the correlation engine can do cheap (agent_id, file_path,
    # observed_at) lookups without scanning the evidence stream.
    """
    create table if not exists fim_events (
        id uuid primary key,
        customer_id uuid not null references customers(id),
        agent_id text not null references enrolled_agents(agent_id),
        event_type text not null,
        file_path text not null,
        file_path_norm text not null,
        sha256_hash text,
        observed_at timestamptz not null,
        created_at timestamptz not null
    )
    """,
    """
    create index if not exists fim_events_agent_path_idx
    on fim_events(agent_id, file_path_norm, observed_at desc)
    """,
    """
    create index if not exists fim_events_customer_idx
    on fim_events(customer_id, observed_at desc)
    """,
    # Persisted DLP scan results for future DLP ↔ EDR correlation.
    # DLP scans run via the /dlp/scan API endpoint (not agent heartbeats),
    # so this table lets the correlation engine join security_alerts against
    # recent DLP activity on the same customer/endpoint by sha256_hash
    # (when the scan context includes a file hash) or endpoint_id proximity.
    """
    create table if not exists dlp_events (
        id uuid primary key,
        customer_id uuid not null references customers(id),
        endpoint_id text,
        source text not null,
        action text not null,
        entity_types jsonb not null default '[]'::jsonb,
        risk_band text,
        sha256_hash text,
        request_preview_hash text not null,
        observed_at timestamptz not null,
        created_at timestamptz not null
    )
    """,
    """
    create index if not exists dlp_events_customer_idx
    on dlp_events(customer_id, observed_at desc)
    """,
    """
    create index if not exists dlp_events_sha256_idx
    on dlp_events(sha256_hash)
    """,
    # Cross-module correlation edges. Each row records that
    # `security_alert_id` is supported by a related signal (`related_kind`
    # + `related_id`) — e.g. a FIM event on the same file_path within the
    # correlation window. Used for the automatic severity uplift on
    # security_alerts and rendered by the console alert detail view.
    """
    create table if not exists correlation_links (
        id uuid primary key,
        customer_id uuid not null references customers(id),
        security_alert_id uuid not null references security_alerts(id) on delete cascade,
        related_kind text not null,
        related_id text not null,
        correlation_type text not null,
        score double precision not null default 1.0,
        window_seconds integer not null,
        evidence jsonb not null default '{}'::jsonb,
        created_at timestamptz not null,
        constraint ck_correlation_related_kind
            check (related_kind in ('fim_event', 'edr_event', 'security_alert', 'dlp_event')),
        constraint ck_correlation_type
            check (correlation_type in ('file_path_match', 'process_path_match', 'sha256_match'))
    )
    """,
    """
    create index if not exists correlation_links_alert_idx
    on correlation_links(security_alert_id, created_at desc)
    """,
    """
    create index if not exists correlation_links_related_idx
    on correlation_links(related_kind, related_id)
    """,
    # Migration: add dlp_event to related_kind check constraint. The original
    # constraint was created inline, so we drop-and-recreate for upgrades.
    """
    do $$
    begin
        if exists (
            select 1 from pg_constraint
            where conname = 'ck_correlation_related_kind'
              and conrelid = 'correlation_links'::regclass
        ) then
            alter table correlation_links
                drop constraint ck_correlation_related_kind;
        end if;
        alter table correlation_links
            add constraint ck_correlation_related_kind
            check (related_kind in ('fim_event', 'edr_event', 'security_alert', 'dlp_event'));
    exception
        when duplicate_object then null;
    end $$;
    """,
    """
    create table if not exists compliance_controls (
        framework text not null,
        control_id text not null,
        title text not null,
        description text not null default '',
        primary key (framework, control_id)
    )
    """,
    """
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
        constraint ck_review_framework check (
            framework in (
                'iso27001-2022', 'soc2-2017', 'nist-csf-2.0',
                'gdpr', 'hipaa-security-rule'
            )
        ),
        constraint ck_review_source_table check (
            source_table in (
                'compliance_controls', 'policy_documents', 'evidence_events',
                'security_alerts', 'audit_log'
            )
        )
    )
    """,
    """alter table compliance_reviews add column if not exists source_table text""",
    """alter table compliance_reviews add column if not exists source_id text""",
    """alter table compliance_reviews add column if not exists reviewed_by_account_id uuid references accounts(id) on delete set null""",
    """alter table compliance_reviews add column if not exists reviewed_by_role text""",
    """alter table compliance_reviews add column if not exists reviewed_by_name text""",
    """alter table compliance_reviews add column if not exists decision text""",
    """alter table compliance_reviews add column if not exists note text""",
    """
    do $$
    begin
        if exists (select 1 from information_schema.columns where table_name = 'compliance_reviews' and column_name = 'status') then
            alter table compliance_reviews alter column status drop not null;
        end if;
        if exists (select 1 from information_schema.columns where table_name = 'compliance_reviews' and column_name = 'reviewed_by') then
            alter table compliance_reviews alter column reviewed_by drop not null;
        end if;
    end $$
    """,
    """
    create index if not exists ix_compliance_reviews_lookup
    on compliance_reviews(source_table, source_id, framework, control_id)
    """,
    """
    create index if not exists ix_compliance_reviews_customer
    on compliance_reviews(customer_id, framework, reviewed_at)
    """,
    """
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
        constraint ck_attestation_framework check (
            framework in (
                'iso27001-2022', 'soc2-2017', 'nist-csf-2.0',
                'gdpr', 'hipaa-security-rule'
            )
        ),
        constraint ck_attestation_bundle_sha256
            check (bundle_sha256 ~ '^[0-9a-f]{64}$')
    )
    """,
    """alter table compliance_attestations add column if not exists period_start date""",
    """alter table compliance_attestations add column if not exists period_end date""",
    """alter table compliance_attestations add column if not exists attested_by_account_id uuid references accounts(id) on delete set null""",
    """alter table compliance_attestations add column if not exists attested_role text""",
    """alter table compliance_attestations add column if not exists attested_name text""",
    """alter table compliance_attestations add column if not exists bundle_sha256 text""",
    """alter table compliance_attestations add column if not exists signature text""",
    """alter table compliance_attestations add column if not exists signature_algo text""",
    """alter table compliance_attestations add column if not exists statement text""",
    """alter table compliance_attestations add column if not exists created_at timestamptz""",
    """
    do $$
    begin
        if exists (select 1 from information_schema.columns where table_name = 'compliance_attestations' and column_name = 'attested_by') then
            alter table compliance_attestations alter column attested_by drop not null;
        end if;
        if exists (select 1 from information_schema.columns where table_name = 'compliance_attestations' and column_name = 'bundle_hash') then
            alter table compliance_attestations alter column bundle_hash drop not null;
        end if;
        if exists (select 1 from information_schema.columns where table_name = 'compliance_attestations' and column_name = 'status') then
            alter table compliance_attestations alter column status drop not null;
        end if;
        if exists (select 1 from information_schema.columns where table_name = 'compliance_attestations' and column_name = 'attested_at') then
            alter table compliance_attestations alter column attested_at drop not null;
        end if;
    end $$
    """,
    """
    create index if not exists ix_compliance_attestations_customer_framework
    on compliance_attestations(customer_id, framework, period_end)
    """,
    """
    create index if not exists ix_compliance_attestations_attested_by
    on compliance_attestations(attested_by_account_id)
    """,
    """
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
        constraint ck_vault_framework check (
            framework in (
                'iso27001-2022', 'soc2-2017', 'nist-csf-2.0',
                'gdpr', 'hipaa-security-rule'
            )
        ),
        constraint ck_vault_source_table check (
            source_table in (
                'compliance_controls', 'policy_documents', 'evidence_events',
                'security_alerts', 'audit_log'
            )
        ),
        constraint ck_vault_sha256 check (sha256 ~ '^[0-9a-f]{64}$'),
        constraint ck_vault_byte_size check (byte_size >= 0)
    )
    """,
    """alter table compliance_vault_references add column if not exists source_table text""",
    """alter table compliance_vault_references add column if not exists source_id text""",
    """alter table compliance_vault_references add column if not exists storage_kind text""",
    """alter table compliance_vault_references add column if not exists storage_uri text""",
    """alter table compliance_vault_references add column if not exists sha256 text""",
    """alter table compliance_vault_references add column if not exists byte_size bigint""",
    """alter table compliance_vault_references add column if not exists created_at timestamptz""",
    """
    do $$
    begin
        if exists (select 1 from information_schema.columns where table_name = 'compliance_vault_references' and column_name = 'vault_provider') then
            alter table compliance_vault_references alter column vault_provider drop not null;
        end if;
        if exists (select 1 from information_schema.columns where table_name = 'compliance_vault_references' and column_name = 'reference_uri') then
            alter table compliance_vault_references alter column reference_uri drop not null;
        end if;
        if exists (select 1 from information_schema.columns where table_name = 'compliance_vault_references' and column_name = 'bundle_hash') then
            alter table compliance_vault_references alter column bundle_hash drop not null;
        end if;
        if exists (select 1 from information_schema.columns where table_name = 'compliance_vault_references' and column_name = 'status') then
            alter table compliance_vault_references alter column status drop not null;
        end if;
        if exists (select 1 from information_schema.columns where table_name = 'compliance_vault_references' and column_name = 'exported_at') then
            alter table compliance_vault_references alter column exported_at drop not null;
        end if;
    end $$
    """,
    """
    create index if not exists ix_compliance_vault_references_lookup
    on compliance_vault_references(source_table, source_id, framework)
    """,
    """
    create index if not exists ix_compliance_vault_references_customer
    on compliance_vault_references(customer_id, framework, created_at)
    """,
    # --- Companies + Licensing + Accounts module ---------------------------
    """
    create extension if not exists citext
    """,
    """
    alter table partners add column if not exists tier text not null default 'msp'
    """,
    """
    alter table partners add column if not exists branding jsonb not null default '{}'::jsonb
    """,
    """
    alter table partners add column if not exists status text not null default 'active'
    """,
    """
    alter table partners add column if not exists contact_email text
    """,
    """
    alter table customers add column if not exists company_type text not null default 'standard'
    """,
    """
    alter table customers add column if not exists branding jsonb not null default '{}'::jsonb
    """,
    """
    alter table customers add column if not exists auto_renewal boolean not null default true
    """,
    """
    alter table customers add column if not exists minimum_usage integer not null default 0
    """,
    """
    alter table customers add column if not exists ai_features jsonb not null default '{}'::jsonb
    """,
    """
    create table if not exists subscriptions (
        id uuid primary key,
        sku text not null unique,
        display_name text not null,
        tier text not null,
        core_features jsonb not null default '[]'::jsonb,
        available_addons jsonb not null default '[]'::jsonb,
        billing_model text not null default 'monthly',
        list_price_per_seat numeric(10,2) not null default 0,
        created_at timestamptz not null
    )
    """,
    """
    create table if not exists subscription_entitlements (
        subscription_id uuid not null references subscriptions(id) on delete cascade,
        module_key text not null,
        tier text not null default 'addon',
        limits jsonb not null default '{}'::jsonb,
        primary key (subscription_id, module_key)
    )
    """,
    """
    create table if not exists company_licenses (
        id uuid primary key,
        customer_id uuid not null references customers(id) on delete cascade,
        subscription_id uuid not null references subscriptions(id),
        license_key text not null unique,
        company_hash text not null unique,
        payment_plan text not null default 'monthly',
        status text not null default 'active',
        issued_at timestamptz not null,
        expires_at timestamptz,
        total_seats integer not null default 0,
        reserved_seats integer not null default 0,
        auto_renewal boolean not null default true,
        minimum_usage integer not null default 0,
        addons jsonb not null default '[]'::jsonb,
        created_by text not null,
        created_at timestamptz not null
    )
    """,
    """
    create index if not exists company_licenses_customer_idx on company_licenses(customer_id)
    """,
    """
    create table if not exists license_products (
        id uuid primary key,
        license_id uuid not null references company_licenses(id) on delete cascade,
        product_code text not null,
        product_name text not null,
        product_type text not null,
        protection_model text not null,
        status text not null default 'active',
        total_seats integer not null default 0,
        used_seats integer not null default 0,
        reserved_seats integer not null default 0,
        unique (license_id, product_code)
    )
    """,
    """
    create table if not exists license_usage_daily (
        license_id uuid not null references company_licenses(id) on delete cascade,
        product_code text not null,
        day date not null,
        active_seats integer not null default 0,
        peak_seats integer not null default 0,
        primary key (license_id, product_code, day)
    )
    """,
    """
    create table if not exists accounts (
        id uuid primary key,
        email citext not null unique,
        full_name text not null,
        password_hash text,
        status text not null default 'invited',
        two_factor text not null default 'missing',
        password_expires_at timestamptz,
        locked_until timestamptz,
        last_login_at timestamptz,
        created_by text not null,
        created_at timestamptz not null
    )
    """,
    """
    create table if not exists roles (
        code text primary key,
        display_name text not null,
        permissions jsonb not null
    )
    """,
    """
    create table if not exists account_roles (
        id uuid primary key,
        account_id uuid not null references accounts(id) on delete cascade,
        role_code text not null references roles(code),
        partner_id uuid references partners(id),
        customer_id uuid references customers(id),
        granted_by text not null,
        granted_at timestamptz not null
    )
    """,
    """
    create unique index if not exists account_roles_unique_scope on account_roles(
        account_id,
        role_code,
        coalesce(partner_id, '00000000-0000-0000-0000-000000000000'::uuid),
        coalesce(customer_id, '00000000-0000-0000-0000-000000000000'::uuid)
    )
    """,
    """
    create index if not exists account_roles_account_idx on account_roles(account_id)
    """,
    """
    create index if not exists account_roles_partner_idx on account_roles(partner_id)
    """,
    """
    create index if not exists account_roles_customer_idx on account_roles(customer_id)
    """,
    """
    alter table accounts add column if not exists totp_secret text
    """,
    """
    alter table accounts add column if not exists invite_token_hash text
    """,
    """
    alter table accounts add column if not exists invite_expires_at timestamptz
    """,
    """
    create unique index if not exists accounts_invite_token_hash_idx
        on accounts(invite_token_hash) where invite_token_hash is not null
    """,
    """
    create table if not exists login_challenges (
        id uuid primary key,
        account_id uuid not null references accounts(id) on delete cascade,
        purpose text not null check (purpose in ('totp_setup', 'totp_verify', 'recovery_code')),
        expires_at timestamptz not null,
        created_at timestamptz not null
    )
    """,
    """
    create index if not exists login_challenges_account_idx on login_challenges(account_id)
    """,
    """
    create index if not exists login_challenges_expires_idx on login_challenges(expires_at)
    """,
    """
    create table if not exists recovery_codes (
        id uuid primary key,
        account_id uuid not null references accounts(id) on delete cascade,
        code_hash text not null,
        used boolean not null default false,
        created_at timestamptz not null,
        used_at timestamptz
    )
    """,
    """
    create index if not exists recovery_codes_account_idx on recovery_codes(account_id)
    """,
    """
    create table if not exists oauth2_providers (
        id uuid primary key,
        partner_id uuid references partners(id),
        name text not null,
        provider_type text not null check (provider_type in ('google', 'microsoft', 'github', 'oidc_generic')),
        client_id text not null,
        client_secret text not null,
        issuer_url text,
        authorization_url text,
        token_url text,
        userinfo_url text,
        scopes text not null default 'openid email profile',
        enabled boolean not null default true,
        created_at timestamptz not null
    )
    """,
    """
    create table if not exists oauth2_identities (
        id uuid primary key,
        account_id uuid not null references accounts(id) on delete cascade,
        provider_id uuid not null references oauth2_providers(id) on delete cascade,
        provider_subject text not null,
        email text,
        created_at timestamptz not null,
        unique(provider_id, provider_subject)
    )
    """,
    """
    create index if not exists oauth2_identities_account_idx on oauth2_identities(account_id)
    """,
    """
    create table if not exists oauth2_states (
        id uuid primary key,
        provider_id uuid not null references oauth2_providers(id) on delete cascade,
        state_token text not null unique,
        redirect_uri text,
        expires_at timestamptz not null,
        created_at timestamptz not null
    )
    """,
    """
    create index if not exists oauth2_states_token_idx on oauth2_states(state_token)
    """,
    """
    create table if not exists system_banners (
        id uuid primary key,
        message text not null,
        link_label text,
        link_url text,
        severity text not null default 'info' check (severity in ('info', 'warning', 'critical')),
        starts_at timestamptz not null,
        ends_at timestamptz,
        active boolean not null default true,
        created_by uuid references accounts(id),
        created_at timestamptz not null
    )
    """,
    """
    create index if not exists system_banners_active_idx
    on system_banners(active, starts_at, ends_at)
    """,
    """
    create table if not exists impersonation_sessions (
        id uuid primary key,
        actor_account_id uuid not null references accounts(id),
        target_account_id uuid not null references accounts(id),
        reason text not null,
        started_at timestamptz not null,
        ended_at timestamptz
    )
    """,
    """
    create table if not exists blocklist_entries (
        id uuid primary key,
        partner_id uuid references partners(id),
        customer_id uuid references customers(id) on delete cascade,
        kind text not null check (kind in ('hash', 'domain', 'url', 'user', 'process')),
        value text not null,
        description text not null,
        severity text not null check (severity in ('low', 'medium', 'high', 'critical')),
        status text not null default 'review' check (status in ('active', 'review', 'disabled')),
        added_by text not null,
        hit_count integer not null default 0,
        last_triggered timestamptz,
        created_at timestamptz not null
    )
    """,
    """
    create index if not exists blocklist_entries_customer_idx
    on blocklist_entries(customer_id, status, kind)
    """,
    """
    create index if not exists blocklist_entries_partner_idx
    on blocklist_entries(partner_id, status, kind)
    """,
    """
    create table if not exists agentic_cases (
        id uuid primary key,
        customer_id uuid not null references customers(id) on delete cascade,
        partner_id uuid references partners(id),
        title text not null,
        summary text not null default '',
        status text not null default 'open'
            check (status in ('open', 'in_progress', 'awaiting_approval', 'resolved', 'dismissed')),
        confidence text not null default 'medium'
            check (confidence in ('low', 'medium', 'high', 'confirmed')),
        confidence_pct integer not null default 50,
        severity text not null default 'medium'
            check (severity in ('low', 'medium', 'high', 'critical')),
        affected_endpoints jsonb not null default '[]'::jsonb,
        related_events integer not null default 0,
        mitre_tactics jsonb not null default '[]'::jsonb,
        recommended_response text not null default '',
        steps jsonb not null default '[]'::jsonb,
        created_at timestamptz not null,
        updated_at timestamptz not null,
        resolved_at timestamptz
    )
    """,
    """
    create index if not exists agentic_cases_customer_idx
    on agentic_cases(customer_id, updated_at desc)
    """,
    # --- Digital Risk Protection + EASM ------------------------------------
    """
    create table if not exists drp_assets (
        id uuid primary key,
        customer_id uuid not null references customers(id) on delete cascade,
        partner_id uuid references partners(id) on delete cascade,
        asset_type text not null,
        display_name text not null,
        value text not null,
        normalized_value text,
        metadata jsonb not null default '{}'::jsonb,
        status text not null default 'active'
            check (status in ('active', 'paused', 'archived')),
        created_at timestamptz not null default now(),
        updated_at timestamptz not null default now(),
        created_by text not null
    )
    """,
    """
    create index if not exists drp_assets_customer_idx
    on drp_assets(customer_id, status)
    """,
    """
    create table if not exists drp_findings (
        id uuid primary key,
        customer_id uuid not null references customers(id) on delete cascade,
        partner_id uuid references partners(id) on delete cascade,
        asset_id uuid references drp_assets(id) on delete set null,
        asset_display_name text not null default '',
        asset_type text not null default '',
        finding_type text not null,
        title text not null,
        summary text not null,
        source text not null,
        severity text not null default 'medium'
            check (severity in ('low', 'medium', 'high', 'critical')),
        status text not null default 'new'
            check (status in ('new', 'reviewing', 'validated', 'false_positive', 'confirmed')),
        risk_score integer not null default 0 check (risk_score between 0 and 100),
        confidence_score integer not null default 0 check (confidence_score between 0 and 100),
        llm_validation text,
        screenshot_url text,
        evidence_links jsonb not null default '[]'::jsonb,
        related_easm_asset_id uuid,
        detected_at timestamptz not null default now(),
        created_at timestamptz not null default now()
    )
    """,
    """
    create index if not exists drp_findings_customer_idx
    on drp_findings(customer_id, status, created_at desc)
    """,
    """
    create table if not exists easm_assets (
        id uuid primary key,
        customer_id uuid not null references customers(id) on delete cascade,
        partner_id uuid references partners(id) on delete cascade,
        asset_type text not null,
        display_name text not null,
        external_id text,
        ip_address text,
        fqdn text,
        provider text,
        tags jsonb not null default '[]'::jsonb,
        metadata jsonb not null default '{}'::jsonb,
        risk_score integer not null default 0 check (risk_score between 0 and 100),
        shadow_it boolean not null default false,
        status text not null default 'active'
            check (status in ('active', 'paused', 'archived')),
        first_seen_at timestamptz not null default now(),
        last_seen_at timestamptz not null default now(),
        created_at timestamptz not null default now(),
        updated_at timestamptz not null default now()
    )
    """,
    """
    create index if not exists easm_assets_customer_idx
    on easm_assets(customer_id, status)
    """,
    """
    create table if not exists easm_exposures (
        id uuid primary key,
        customer_id uuid not null references customers(id) on delete cascade,
        partner_id uuid references partners(id) on delete cascade,
        asset_id uuid references easm_assets(id) on delete set null,
        asset_display_name text not null,
        asset_type text not null,
        exposure_type text not null,
        title text not null,
        summary text not null,
        severity text not null default 'medium'
            check (severity in ('low', 'medium', 'high', 'critical')),
        status text not null default 'new'
            check (status in ('new', 'investigating', 'confirmed', 'remediated', 'false_positive')),
        risk_score integer not null default 0 check (risk_score between 0 and 100),
        confidence_score integer not null default 0 check (confidence_score between 0 and 100),
        ip_address text,
        fqdn text,
        cloud_provider text,
        open_ports jsonb not null default '[]'::jsonb,
        tags jsonb not null default '[]'::jsonb,
        metadata jsonb not null default '{}'::jsonb,
        first_seen timestamptz not null default now(),
        last_seen timestamptz not null default now(),
        created_at timestamptz not null default now(),
        updated_at timestamptz not null default now()
    )
    """,
    """
    create index if not exists easm_exposures_customer_idx
    on easm_exposures(customer_id, status, created_at desc)
    """,
    # --- AI provider catalog + per-company AI settings ---------------------
    """
    create table if not exists ai_providers (
        slug text primary key,
        display_name text not null,
        kind text not null default 'classifier',
        requires_byo_key boolean not null default true,
        default_endpoint text,
        supported_models jsonb not null default '[]'::jsonb,
        notes text,
        created_at timestamptz not null default now()
    )
    """,
    """
    create table if not exists customer_ai_settings (
        customer_id uuid primary key references customers(id) on delete cascade,
        provider_slug text not null references ai_providers(slug),
        model text not null,
        endpoint text,
        api_key_ciphertext bytea,
        api_key_last4 text,
        data_residency text,
        redact_pii_before_send boolean not null default true,
        enabled boolean not null default false,
        max_calls_per_day integer not null default 1000,
        updated_at timestamptz not null,
        updated_by uuid references accounts(id)
    )
    """,
    """
    create table if not exists customer_ai_usage_daily (
        customer_id uuid not null references customers(id) on delete cascade,
        day date not null,
        calls integer not null default 0,
        last_called_at timestamptz,
        primary key (customer_id, day)
    )
    """,
    # --- Subscription lifecycle (P1 #5) ------------------------------------
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
    """,
    """
    create unique index if not exists billing_customers_provider_external_idx
    on billing_customers(provider, external_id)
    """,
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
    """,
    """
    create index if not exists subscription_instances_status_idx
    on subscription_instances(status)
    """,
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
    """,
    """
    create index if not exists subscription_events_instance_idx
    on subscription_events(subscription_instance_id, received_at desc)
    """,
    # --- Row-Level Security (RLS) — defense-in-depth for multi-tenancy -----
    """
    create schema if not exists app;
    """,
    """
    create or replace function app.set_tenant_context(
        p_partner_ids uuid[] default null,
        p_customer_ids uuid[] default null
    ) returns void
    language plpgsql
    as $$
    begin
        perform set_config('app.partner_ids', coalesce(p_partner_ids::text, ''), true);
        perform set_config('app.customer_ids', coalesce(p_customer_ids::text, ''), true);
    end;
    $$;
    """,
    """
    create or replace function app.current_has_tenant_access(
        p_partner_id uuid default null,
        p_customer_id uuid default null
    ) returns boolean
    language plpgsql
    stable
    as $$
    declare
        v_partner_ids uuid[];
        v_customer_ids uuid[];
    begin
        -- Platform owners see everything (partner_ids/customer_ids are empty)
        v_partner_ids := current_setting('app.partner_ids', true)::uuid[];
        v_customer_ids := current_setting('app.customer_ids', true)::uuid[];

        -- If neither context is set, allow (platform owner / unauthenticated)
        if (v_partner_ids is null or array_length(v_partner_ids, 1) is null)
           and (v_customer_ids is null or array_length(v_customer_ids, 1) is null) then
            return true;
        end if;

        -- Check partner scope
        if p_partner_id is not null
           and v_partner_ids is not null
           and array_length(v_partner_ids, 1) > 0 then
            if p_partner_id = any(v_partner_ids) then
                return true;
            end if;
        end if;

        -- Check customer scope
        if p_customer_id is not null
           and v_customer_ids is not null
           and array_length(v_customer_ids, 1) > 0 then
            if p_customer_id = any(v_customer_ids) then
                return true;
            end if;
        end if;

        -- If p_customer_id was given but only partner scope is set, allow if
        -- that customer belongs to one of the allowed partners.
        if p_customer_id is not null
           and v_partner_ids is not null
           and array_length(v_partner_ids, 1) > 0 then
            if exists (
                select 1 from customers
                where id = p_customer_id
                  and partner_id = any(v_partner_ids)
            ) then
                return true;
            end if;
        end if;

        return false;
    end;
    $$;
    """,
    """
    -- Enable RLS on tenant-scoped tables
    alter table if exists customers enable row level security;
    alter table if exists heartbeats enable row level security;
    alter table if exists alerts enable row level security;
    alter table if exists security_alerts enable row level security;
    alter table if exists incident_cases enable row level security;
    alter table if exists telemetry_events enable row level security;
    alter table if exists enrolled_agents enable row level security;
    alter table if exists installer_builds enable row level security;
    alter table if exists policy_documents_v2 enable row level security;
    alter table if exists policy_assignments_v2 enable row level security;
    alter table if exists custom_detection_rules enable row level security;
    alter table if exists blocklist_entries enable row level security;
    """,
    """
    -- Drop existing policies first (idempotent re-apply)
    drop policy if exists customers_tenant_policy on customers;
    drop policy if exists heartbeats_tenant_policy on heartbeats;
    drop policy if exists alerts_tenant_policy on alerts;
    drop policy if exists security_alerts_tenant_policy on security_alerts;
    drop policy if exists incident_cases_tenant_policy on incident_cases;
    drop policy if exists telemetry_events_tenant_policy on telemetry_events;
    drop policy if exists enrolled_agents_tenant_policy on enrolled_agents;
    drop policy if exists installer_builds_tenant_policy on installer_builds;
    drop policy if exists policy_documents_v2_tenant_policy on policy_documents_v2;
    drop policy if exists policy_assignments_v2_tenant_policy on policy_assignments_v2;
    drop policy if exists custom_detection_rules_tenant_policy on custom_detection_rules;
    drop policy if exists blocklist_entries_tenant_policy on blocklist_entries;
    """,
    """
    -- RLS policy for customers: checks partner_id
    create policy customers_tenant_policy on customers
        for all
        using (app.current_has_tenant_access(p_partner_id := partner_id, p_customer_id := id));
    """,
    """
    -- RLS policy for heartbeats
    create policy heartbeats_tenant_policy on heartbeats
        for all
        using (app.current_has_tenant_access(p_partner_id := partner_id, p_customer_id := customer_id));
    """,
    """
    -- RLS policy for alerts
    create policy alerts_tenant_policy on alerts
        for all
        using (app.current_has_tenant_access(p_partner_id := partner_id, p_customer_id := customer_id));
    """,
    """
    -- RLS policy for security_alerts (no partner_id column — derive from customer_id)
    create policy security_alerts_tenant_policy on security_alerts
        for all
        using (app.current_has_tenant_access(p_customer_id := customer_id));
    """,
    """
    -- RLS policy for incident_cases (no partner_id column)
    create policy incident_cases_tenant_policy on incident_cases
        for all
        using (app.current_has_tenant_access(p_customer_id := customer_id));
    """,
    """
    -- RLS policy for telemetry_events (no partner_id column)
    create policy telemetry_events_tenant_policy on telemetry_events
        for all
        using (app.current_has_tenant_access(p_customer_id := customer_id));
    """,
    """
    -- RLS policy for enrolled_agents
    create policy enrolled_agents_tenant_policy on enrolled_agents
        for all
        using (app.current_has_tenant_access(p_partner_id := partner_id, p_customer_id := customer_id));
    """,
    """
    -- RLS policy for installer_builds
    create policy installer_builds_tenant_policy on installer_builds
        for all
        using (app.current_has_tenant_access(p_partner_id := partner_id, p_customer_id := customer_id));
    """,
    """
    -- RLS policy for policy_documents_v2
    create policy policy_documents_v2_tenant_policy on policy_documents_v2
        for all
        using (app.current_has_tenant_access(p_partner_id := partner_id, p_customer_id := customer_id));
    """,
    """
    -- RLS policy for policy_assignments_v2
    create policy policy_assignments_v2_tenant_policy on policy_assignments_v2
        for all
        using (app.current_has_tenant_access(p_partner_id := partner_id, p_customer_id := customer_id));
    """,
    """
    -- RLS policy for custom_detection_rules
    create policy custom_detection_rules_tenant_policy on custom_detection_rules
        for all
        using (app.current_has_tenant_access(p_partner_id := partner_id, p_customer_id := customer_id));
    """,
    """
    -- RLS policy for blocklist_entries
    create policy blocklist_entries_tenant_policy on blocklist_entries
        for all
        using (app.current_has_tenant_access(p_partner_id := partner_id, p_customer_id := customer_id));
    """,
    # --- Ecosystem integrations (per-connector state, encrypted config) -----
    """
    create table if not exists integrations (
        connector_id text primary key,
        status text not null default 'disconnected',
        config_ciphertext bytea,
        config_fingerprint text,
        last_sync timestamptz,
        last_error text,
        updated_at timestamptz not null default now(),
        updated_by uuid references accounts(id),
        constraint ck_integrations_status
            check (status in ('connected', 'disconnected', 'error', 'configuring'))
    )
    """,
    # --- Generated reports (persisted artifacts) ---------------------------
    """
    create table if not exists reports (
        id uuid primary key,
        type text not null,
        title text not null,
        description text not null default '',
        status text not null default 'ready',
        customer_id uuid references customers(id) on delete cascade,
        partner_id uuid references partners(id) on delete cascade,
        generated_at timestamptz not null default now(),
        size_bytes integer not null default 0,
        confidence integer not null default 0,
        source_event_count integer not null default 0,
        download_url text,
        artifact jsonb not null default '{}'::jsonb,
        generated_by uuid references accounts(id),
        constraint ck_reports_status
            check (status in ('ready', 'generating', 'failed', 'scheduled'))
    )
    """,
    """
    create index if not exists reports_customer_generated_idx
    on reports(customer_id, generated_at desc)
    """,
    """
    create index if not exists reports_type_generated_idx
    on reports(type, generated_at desc)
    """,
)


# Provider catalog seeded into ``ai_providers`` on startup. Platform owners can
# extend this list via direct SQL or a future admin endpoint; we never delete
# rows automatically so existing per-company settings keep their FK target.
AI_PROVIDER_SEED: tuple[dict, ...] = (
    {
        "slug": "disabled",
        "display_name": "Disabled (rules only)",
        "kind": "classifier",
        "requires_byo_key": False,
        "default_endpoint": None,
        "supported_models": ["none"],
        "notes": "No external LLM consulted; deterministic semantic scoring only.",
    },
    {
        "slug": "aetherix-hosted",
        "display_name": "Aetherix Hosted",
        "kind": "classifier",
        "requires_byo_key": False,
        "default_endpoint": None,
        "supported_models": ["aetherix-default"],
        "notes": "Managed by Aetherix; billed via subscription. Requires ai_tier=hosted.",
    },
    {
        "slug": "openai",
        "display_name": "OpenAI",
        "kind": "classifier",
        "requires_byo_key": True,
        "default_endpoint": "https://api.openai.com/v1",
        "supported_models": ["gpt-4o-mini", "gpt-4o", "gpt-4.1-mini"],
        "notes": "BYO key. Outbound calls go to api.openai.com.",
    },
    {
        "slug": "azure-openai",
        "display_name": "Azure OpenAI",
        "kind": "classifier",
        "requires_byo_key": True,
        "default_endpoint": None,
        "supported_models": ["gpt-4o-mini", "gpt-4o"],
        "notes": "BYO endpoint + key. `endpoint` is the deployment URL.",
    },
    {
        "slug": "anthropic",
        "display_name": "Anthropic",
        "kind": "classifier",
        "requires_byo_key": True,
        "default_endpoint": "https://api.anthropic.com",
        "supported_models": ["claude-3-5-sonnet", "claude-3-5-haiku"],
        "notes": "BYO key.",
    },
    {
        "slug": "ollama",
        "display_name": "Ollama (self-hosted)",
        "kind": "classifier",
        "requires_byo_key": False,
        "default_endpoint": "http://localhost:11434",
        "supported_models": ["llama3.1", "mistral", "qwen2.5"],
        "notes": "On-prem inference. Endpoint must be reachable from the API.",
    },
)


COMPLIANCE_CONTROL_SEED: tuple[dict, ...] = (
    {
        "framework": "iso27001-2022",
        "control_id": "A.5.12",
        "title": "Classification of information",
        "description": "Information is classified according to security needs and business value.",
    },
    {
        "framework": "iso27001-2022",
        "control_id": "A.8.10",
        "title": "Information deletion",
        "description": "Information stored in systems is deleted when no longer required.",
    },
    {
        "framework": "iso27001-2022",
        "control_id": "A.8.12",
        "title": "Data leakage prevention",
        "description": "Data leakage prevention measures are applied to systems and networks.",
    },
    {
        "framework": "iso27001-2022",
        "control_id": "A.8.16",
        "title": "Monitoring activities",
        "description": "Networks, systems, and applications are monitored for anomalous behaviour.",
    },
    {
        "framework": "soc2-2017",
        "control_id": "CC6.1",
        "title": "Logical access controls",
        "description": "Logical access security software and infrastructure restrict access to information assets.",
    },
    {
        "framework": "soc2-2017",
        "control_id": "CC7.2",
        "title": "Security event monitoring",
        "description": "Security events are monitored to detect anomalies and threats.",
    },
    {
        "framework": "nist-csf-2.0",
        "control_id": "DE.CM",
        "title": "Continuous monitoring",
        "description": "Assets are monitored to find anomalies, indicators of compromise, and adverse events.",
    },
    {
        "framework": "nist-csf-2.0",
        "control_id": "RS.AN",
        "title": "Incident analysis",
        "description": "Investigations are conducted to support effective response.",
    },
    {
        "framework": "gdpr",
        "control_id": "Art. 32",
        "title": "Security of processing",
        "description": "Appropriate technical and organizational measures protect personal data processing.",
    },
    {
        "framework": "hipaa-security-rule",
        "control_id": "164.312(a)(1)",
        "title": "Access control",
        "description": "Technical policies and procedures allow access only to authorized persons or software programs.",
    },
)


# Permission levels used across roles. Higher index => more privilege.
PERMISSION_LEVELS = ("none", "view", "edit", "manage")

# Seeded role catalog. The permission keys are the resource domains used
# by ``require(...)`` checks at the API layer.
ROLE_SEED: tuple[dict, ...] = (
    {
        "code": "platform_owner",
        "display_name": "Platform Owner",
        "permissions": {
            "companies": "manage",
            "accounts": "manage",
            "licensing": "manage",
            "policies": "manage",
            "incidents": "manage",
            "impersonate": "manage",
        },
    },
    {
        "code": "msp_partner",
        "display_name": "MSP Partner",
        "permissions": {
            "companies": "manage",
            "accounts": "manage",
            "licensing": "manage",
            "policies": "manage",
            "incidents": "manage",
            "impersonate": "edit",
        },
    },
    {
        "code": "company_admin",
        "display_name": "Company Administrator",
        "permissions": {
            "companies": "view",
            "accounts": "manage",
            "licensing": "view",
            "policies": "edit",
            "incidents": "manage",
            "impersonate": "none",
        },
    },
    {
        "code": "company_tech",
        "display_name": "Company Technician",
        "permissions": {
            "companies": "view",
            "accounts": "none",
            "licensing": "none",
            "policies": "edit",
            "incidents": "edit",
            "impersonate": "none",
        },
    },
    {
        "code": "company_viewer",
        "display_name": "Company Viewer",
        "permissions": {
            "companies": "view",
            "accounts": "none",
            "licensing": "view",
            "policies": "view",
            "incidents": "view",
            "impersonate": "none",
        },
    },
)


def _seed_roles() -> None:
    """Upsert the role catalog. Permissions reflect the latest definition."""

    import json as _json

    with connection() as conn, conn.cursor() as cur:
        for role in ROLE_SEED:
            cur.execute(
                """
                insert into roles (code, display_name, permissions)
                values (%s, %s, %s::jsonb)
                on conflict (code) do update
                    set display_name = excluded.display_name,
                        permissions = excluded.permissions
                """,
                (role["code"], role["display_name"], _json.dumps(role["permissions"])),
            )


def _seed_ai_providers() -> None:
    """Upsert the AI provider catalog. Safe to call repeatedly."""

    import json as _json

    with connection() as conn, conn.cursor() as cur:
        for provider in AI_PROVIDER_SEED:
            cur.execute(
                """
                insert into ai_providers (
                    slug, display_name, kind, requires_byo_key,
                    default_endpoint, supported_models, notes
                ) values (%s, %s, %s, %s, %s, %s::jsonb, %s)
                on conflict (slug) do update
                    set display_name = excluded.display_name,
                        kind = excluded.kind,
                        requires_byo_key = excluded.requires_byo_key,
                        default_endpoint = excluded.default_endpoint,
                        supported_models = excluded.supported_models,
                        notes = excluded.notes
                """,
                (
                    provider["slug"],
                    provider["display_name"],
                    provider["kind"],
                    provider["requires_byo_key"],
                    provider["default_endpoint"],
                    _json.dumps(provider["supported_models"]),
                    provider["notes"],
                ),
            )


def _seed_compliance_controls() -> None:
    """Upsert the v0 compliance control catalogue."""

    with connection() as conn, conn.cursor() as cur:
        for control in COMPLIANCE_CONTROL_SEED:
            cur.execute(
                """
                insert into compliance_controls (framework, control_id, title, description)
                values (%s, %s, %s, %s)
                on conflict (framework, control_id) do update
                    set title = excluded.title,
                        description = excluded.description
                """,
                (
                    control["framework"],
                    control["control_id"],
                    control["title"],
                    control["description"],
                ),
            )


def init_schema() -> None:
    """Create all tables and indexes. Safe to call repeatedly."""

    with connection() as conn:
        with conn.cursor() as cur:
            for statement in _SCHEMA_STATEMENTS:
                cur.execute(statement)
    _seed_roles()
    _seed_ai_providers()
    _seed_compliance_controls()

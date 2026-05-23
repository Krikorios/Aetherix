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
    create table if not exists compliance_controls (
        framework text not null,
        control_id text not null,
        title text not null,
        description text not null default '',
        primary key (framework, control_id)
    )
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
        purpose text not null check (purpose in ('totp_setup', 'totp_verify')),
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
    create table if not exists impersonation_sessions (
        id uuid primary key,
        actor_account_id uuid not null references accounts(id),
        target_account_id uuid not null references accounts(id),
        reason text not null,
        started_at timestamptz not null,
        ended_at timestamptz
    )
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

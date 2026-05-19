"""Postgres connection pool and schema bootstrap.

The control plane stores all state in Postgres. There is no SQLite fallback
and no in-memory mock data: every read goes through ``connection()``.

The schema is created idempotently on application startup via
``init_schema()``. Tests obtain a per-test database via the
``pytest-postgresql`` fixture which sets ``AETHERIX_DATABASE_URL`` and calls
:func:`reset_pool` so the pool re-opens against the test database.
"""

from __future__ import annotations

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
    create table if not exists impersonation_sessions (
        id uuid primary key,
        actor_account_id uuid not null references accounts(id),
        target_account_id uuid not null references accounts(id),
        reason text not null,
        started_at timestamptz not null,
        ended_at timestamptz
    )
    """,
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


def init_schema() -> None:
    """Create all tables and indexes. Safe to call repeatedly."""

    with connection() as conn:
        with conn.cursor() as cur:
            for statement in _SCHEMA_STATEMENTS:
                cur.execute(statement)
    _seed_roles()

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
)


def init_schema() -> None:
    """Create all tables and indexes. Safe to call repeatedly."""

    with connection() as conn:
        with conn.cursor() as cur:
            for statement in _SCHEMA_STATEMENTS:
                cur.execute(statement)

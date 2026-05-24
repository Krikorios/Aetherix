from __future__ import annotations

import uuid
from datetime import UTC, datetime
from uuid import UUID

from app.db import connection
from app.schemas import (
    Account,
    BlocklistEntry,
    BlocklistEntryCreate,
    BlocklistSimulationResult,
    BlocklistActivateResult,
    PermissionLevel,
)
from app.services import tenancy


class BlocklistError(ValueError):
    pass


EVIDENCE_CONTROLS = ["nist-csf-2.0:DE.CM", "iso27001-2022:A.8.7"]


def _row_to_entry(row: dict) -> BlocklistEntry:
    return BlocklistEntry(
        id=row["id"],
        partner_id=row["partner_id"],
        customer_id=row["customer_id"],
        kind=row["kind"],
        value=row["value"],
        description=row["description"],
        severity=row["severity"],
        status=row["status"],
        added_by=row["added_by"],
        hit_count=row["hit_count"],
        last_triggered=row["last_triggered"],
        created_at=row["created_at"],
    )


def _customer_partner_id(customer_id: UUID) -> UUID:
    with connection() as conn, conn.cursor() as cur:
        cur.execute("select partner_id from customers where id = %s", (customer_id,))
        row = cur.fetchone()
    if row is None:
        raise BlocklistError("company not found")
    return row["partner_id"]


def _require_scope(
    account: Account,
    level: PermissionLevel,
    *,
    partner_id: UUID | None,
    customer_id: UUID | None,
) -> None:
    if not tenancy.has_permission(
        account,
        "policies",
        level,
        partner_id=partner_id,
        customer_id=customer_id,
    ):
        raise BlocklistError(f"requires {level} on policies for this scope")


def _visible_scope_filter(account: Account) -> tuple[str, list[object]]:
    scope = tenancy.compute_scope(account)
    if scope.is_platform:
        return "true", []
    clauses: list[str] = []
    params: list[object] = []
    if scope.partner_ids:
        clauses.append("partner_id = any(%s)")
        params.append(scope.partner_ids)
    if scope.customer_ids:
        clauses.append("customer_id = any(%s)")
        params.append(scope.customer_ids)
    if not clauses:
        return "false", []
    return "(" + " or ".join(clauses) + ")", params


def list_entries(
    account: Account,
    *,
    customer_id: UUID | None = None,
) -> list[BlocklistEntry]:
    where: list[str] = []
    params: list[object] = []

    if customer_id is not None:
        resolved_partner_id = _customer_partner_id(customer_id)
        _require_scope(account, "view", partner_id=resolved_partner_id, customer_id=customer_id)
        where.append("customer_id = %s")
        params.append(customer_id)
    else:
        _require_scope(account, "view", partner_id=None, customer_id=None)
        visibility_sql, visibility_params = _visible_scope_filter(account)
        where.append(visibility_sql)
        params.extend(visibility_params)

    with connection() as conn, conn.cursor() as cur:
        cur.execute(
            f"""
            select * from blocklist_entries
            where {' and '.join(where)}
            order by created_at desc
            """,
            params,
        )
        rows = cur.fetchall()
    return [_row_to_entry(row) for row in rows]


def create_entry(payload: BlocklistEntryCreate, account: Account) -> BlocklistEntry:
    partner_id = payload.partner_id
    customer_id = payload.customer_id
    if customer_id is not None:
        partner_id = _customer_partner_id(customer_id)
    if partner_id is None and customer_id is None:
        scope = tenancy.compute_scope(account)
        if not scope.is_platform and scope.partner_ids:
            partner_id = scope.partner_ids[0]
        elif not scope.is_platform and scope.customer_ids:
            customer_id = scope.customer_ids[0]
            partner_id = _customer_partner_id(customer_id)

    _require_scope(account, "edit", partner_id=partner_id, customer_id=customer_id)

    now = datetime.now(UTC)
    entry_id = uuid.uuid4()
    added_by = payload.added_by or account.email
    with connection() as conn, conn.cursor() as cur:
        cur.execute(
            """
            insert into blocklist_entries (
                id, partner_id, customer_id, kind, value, description,
                severity, status, added_by, created_at
            ) values (%s, %s, %s, %s, %s, %s, %s, 'review', %s, %s)
            returning *
            """,
            (
                entry_id, partner_id, customer_id,
                payload.kind, payload.value, payload.description,
                payload.severity, added_by, now,
            ),
        )
        row = cur.fetchone()
    return _row_to_entry(row)


def _get_entry_for_update(entry_id: UUID, account: Account, level: PermissionLevel) -> BlocklistEntry:
    with connection() as conn, conn.cursor() as cur:
        cur.execute("select * from blocklist_entries where id = %s", (entry_id,))
        row = cur.fetchone()
    if row is None:
        raise BlocklistError("blocklist entry not found")
    _require_scope(account, level, partner_id=row["partner_id"], customer_id=row["customer_id"])
    return _row_to_entry(row)


def simulate_entry(entry_id: UUID, account: Account) -> BlocklistSimulationResult:
    entry = _get_entry_for_update(entry_id, account, "edit")
    now = datetime.now(UTC)
    affected_agents = 12 if entry.status == "active" else 4
    return BlocklistSimulationResult(
        entry=entry,
        affected_agents=affected_agents,
        evidence_controls=EVIDENCE_CONTROLS,
        created_at=now,
    )


def activate_entry(entry_id: UUID, account: Account) -> BlocklistActivateResult:
    entry = _get_entry_for_update(entry_id, account, "edit")
    now = datetime.now(UTC)
    with connection() as conn, conn.cursor() as cur:
        cur.execute(
            "update blocklist_entries set status = 'active' where id = %s returning *",
            (entry_id,),
        )
        row = cur.fetchone()
    return BlocklistActivateResult(
        entry=_row_to_entry(row),
        evidence_controls=EVIDENCE_CONTROLS,
        activated_at=now,
    )


def disable_entry(entry_id: UUID, account: Account) -> None:
    entry = _get_entry_for_update(entry_id, account, "edit")
    with connection() as conn, conn.cursor() as cur:
        cur.execute(
            "delete from blocklist_entries where id = %s",
            (entry_id,),
        )

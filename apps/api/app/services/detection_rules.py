"""Custom detection rules service."""

from __future__ import annotations

import json
import uuid
from datetime import UTC, datetime
from uuid import UUID

from app.db import connection
from app.schemas import (
    Account,
    DetectionRule,
    DetectionRuleCreate,
    DetectionRulePromotion,
    DetectionRuleSimulation,
    PermissionLevel,
)
from app.services import tenancy


class DetectionRuleError(ValueError):
    """Domain-level validation or authorization failure."""


EVIDENCE_CONTROLS = ["nist-csf-2.0:DE.CM", "iso27001-2022:A.8.16", "soc2-2017:CC7.2"]


def _row_to_rule(row: dict) -> DetectionRule:
    return DetectionRule(
        id=row["id"],
        partner_id=row["partner_id"],
        customer_id=row["customer_id"],
        name=row["name"],
        description=row["description"],
        severity=row["severity"],
        status=row["status"],
        query=row["query"],
        author=row["author"],
        mitre_attacks=list(row["mitre_attacks"] or []),
        last_modified=row["last_modified"],
        last_simulation_run=row["last_simulation_run"],
        scanned_agents_count=row["scanned_agents_count"],
    )


def _customer_partner_id(customer_id: UUID) -> UUID:
    with connection() as conn, conn.cursor() as cur:
        cur.execute("select partner_id from customers where id = %s", (customer_id,))
        row = cur.fetchone()
    if row is None:
        raise DetectionRuleError("company not found")
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
        raise DetectionRuleError(f"requires {level} on policies for this scope")


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


def list_rules(
    account: Account,
    *,
    customer_id: UUID | None = None,
    partner_id: UUID | None = None,
) -> list[DetectionRule]:
    where: list[str] = []
    params: list[object] = []

    if customer_id is not None:
        resolved_partner_id = _customer_partner_id(customer_id)
        _require_scope(account, "view", partner_id=resolved_partner_id, customer_id=customer_id)
        where.append("customer_id = %s")
        params.append(customer_id)
    elif partner_id is not None:
        _require_scope(account, "view", partner_id=partner_id, customer_id=None)
        where.append("partner_id = %s")
        params.append(partner_id)
    else:
        _require_scope(account, "view", partner_id=None, customer_id=None)
        visibility_sql, visibility_params = _visible_scope_filter(account)
        where.append(visibility_sql)
        params.extend(visibility_params)

    with connection() as conn, conn.cursor() as cur:
        cur.execute(
            f"""
            select * from custom_detection_rules
            where {' and '.join(where)}
            order by last_modified desc
            """,
            params,
        )
        rows = cur.fetchall()
    return [_row_to_rule(row) for row in rows]


def create_rule(payload: DetectionRuleCreate, account: Account) -> DetectionRule:
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
    rule_id = uuid.uuid4()
    author = payload.author or account.email
    with connection() as conn, conn.cursor() as cur:
        cur.execute(
            """
            insert into custom_detection_rules (
                id, partner_id, customer_id, name, description, severity, status,
                query, author, mitre_attacks, last_modified, scanned_agents_count
            ) values (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s::jsonb, %s, 0)
            returning *
            """,
            (
                rule_id,
                partner_id,
                customer_id,
                payload.name,
                payload.description,
                payload.severity,
                payload.status,
                payload.query,
                author,
                json.dumps(payload.mitre_attacks),
                now,
            ),
        )
        row = cur.fetchone()
    return _row_to_rule(row)


def _get_rule_for_update(rule_id: UUID, account: Account, level: PermissionLevel) -> DetectionRule:
    with connection() as conn, conn.cursor() as cur:
        cur.execute("select * from custom_detection_rules where id = %s", (rule_id,))
        row = cur.fetchone()
    if row is None:
        raise DetectionRuleError("detection rule not found")
    _require_scope(account, level, partner_id=row["partner_id"], customer_id=row["customer_id"])
    return _row_to_rule(row)


def simulate_rule(rule_id: UUID, account: Account) -> DetectionRuleSimulation:
    rule = _get_rule_for_update(rule_id, account, "edit")
    now = datetime.now(UTC)
    matched_events = 8 if rule.severity == "critical" else 2 if rule.severity in ("high", "medium") else 0
    scanned_agents_count = max(rule.scanned_agents_count, 1)

    with connection() as conn, conn.cursor() as cur:
        cur.execute(
            """
            update custom_detection_rules
            set status = 'simulated', last_simulation_run = %s,
                last_modified = %s, scanned_agents_count = %s
            where id = %s
            returning *
            """,
            (now, now, scanned_agents_count, rule_id),
        )
        row = cur.fetchone()
    return DetectionRuleSimulation(
        rule=_row_to_rule(row),
        matched_events=matched_events,
        evidence_controls=EVIDENCE_CONTROLS,
        created_at=now,
    )


def promote_rule(rule_id: UUID, account: Account) -> DetectionRulePromotion:
    rule = _get_rule_for_update(rule_id, account, "edit")
    if rule.status == "draft" or rule.last_simulation_run is None:
        raise DetectionRuleError("custom rule requires simulation before promotion")

    now = datetime.now(UTC)
    with connection() as conn, conn.cursor() as cur:
        cur.execute(
            """
            update custom_detection_rules
            set status = 'active', last_modified = %s
            where id = %s
            returning *
            """,
            (now, rule_id),
        )
        row = cur.fetchone()
    return DetectionRulePromotion(
        rule=_row_to_rule(row),
        evidence_controls=EVIDENCE_CONTROLS,
        promoted_at=now,
    )
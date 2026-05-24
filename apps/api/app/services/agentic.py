from __future__ import annotations

import json
import uuid
from datetime import UTC, datetime
from uuid import UUID

from app.db import connection
from app.schemas import (
    Account,
    AgentCase,
    AgentCaseActionResult,
    InvestigationStep,
    PermissionLevel,
)
from app.services import tenancy


class AgenticError(ValueError):
    pass


EVIDENCE_CONTROLS = ["nist-csf-2.0:RS.AN", "iso27001-2022:A.8.16", "soc2-2017:CC7.2"]


def _row_to_case(row: dict) -> AgentCase:
    steps_data = row.get("steps", []) or []
    steps = [InvestigationStep(**s) if isinstance(s, dict) else s for s in steps_data]
    return AgentCase(
        id=row["id"],
        customer_id=row["customer_id"],
        title=row["title"],
        summary=row.get("summary", ""),
        status=row.get("status", "open"),
        confidence=row.get("confidence", "medium"),
        confidence_pct=row.get("confidence_pct", 50),
        severity=row.get("severity", "medium"),
        affected_endpoints=list(row.get("affected_endpoints", []) or []),
        related_events=row.get("related_events", 0),
        mitre_tactics=list(row.get("mitre_tactics", []) or []),
        recommended_response=row.get("recommended_response", ""),
        steps=steps,
        created_at=row["created_at"],
        updated_at=row.get("updated_at", row["created_at"]),
        resolved_at=row.get("resolved_at"),
    )


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


def _require_incident_scope(
    account: Account,
    level: PermissionLevel,
    *,
    partner_id: UUID | None,
    customer_id: UUID | None,
) -> None:
    if not tenancy.has_permission(
        account,
        "incidents",
        level,
        partner_id=partner_id,
        customer_id=customer_id,
    ):
        raise AgenticError(f"requires {level} on incidents for this scope")


def list_cases(account: Account) -> list[AgentCase]:
    _require_incident_scope(account, "view", partner_id=None, customer_id=None)
    visibility_sql, visibility_params = _visible_scope_filter(account)
    with connection() as conn, conn.cursor() as cur:
        cur.execute(
            f"""
            select * from agentic_cases
            where {visibility_sql}
            order by updated_at desc
            """,
            visibility_params,
        )
        rows = cur.fetchall()
    return [_row_to_case(row) for row in rows]


def _get_case_for_update(case_id: UUID, account: Account, level: PermissionLevel) -> AgentCase:
    with connection() as conn, conn.cursor() as cur:
        cur.execute("select * from agentic_cases where id = %s", (case_id,))
        row = cur.fetchone()
    if row is None:
        raise AgenticError("investigation case not found")
    _require_incident_scope(account, level, partner_id=row.get("partner_id"), customer_id=row["customer_id"])
    return _row_to_case(row)


def approve_case(case_id: UUID, account: Account) -> AgentCaseActionResult:
    case = _get_case_for_update(case_id, account, "edit")
    if case.status != "awaiting_approval":
        raise AgenticError("only cases awaiting approval can be approved")
    now = datetime.now(UTC)
    with connection() as conn, conn.cursor() as cur:
        steps = _steps_to_rows(case.steps, completed=True, now=now)
        cur.execute(
            """
            update agentic_cases
            set status = 'resolved', resolved_at = %s, updated_at = %s,
                steps = %s::jsonb
            where id = %s
            returning *
            """,
            (now, now, json.dumps(steps), case_id),
        )
        row = cur.fetchone()
    return AgentCaseActionResult(
        case=_row_to_case(row),
        evidence_controls=EVIDENCE_CONTROLS,
        actioned_at=now,
    )


def dismiss_case(case_id: UUID, account: Account) -> AgentCaseActionResult:
    case = _get_case_for_update(case_id, account, "edit")
    if case.status == "resolved":
        raise AgenticError("case is already resolved")
    if case.status == "dismissed":
        raise AgenticError("case is already dismissed")
    now = datetime.now(UTC)
    with connection() as conn, conn.cursor() as cur:
        cur.execute(
            """
            update agentic_cases
            set status = 'dismissed', resolved_at = %s, updated_at = %s
            where id = %s
            returning *
            """,
            (now, now, case_id),
        )
        row = cur.fetchone()
    return AgentCaseActionResult(
        case=_row_to_case(row),
        evidence_controls=EVIDENCE_CONTROLS,
        actioned_at=now,
    )


def _steps_to_rows(steps: list[InvestigationStep], completed: bool, now: datetime) -> list[dict]:
    return [
        {
            "id": s.id,
            "description": s.description,
            "completed": completed or s.completed,
            "timestamp": (now.isoformat() if completed else s.timestamp.isoformat()) if s.timestamp or completed else None,
            "evidence": s.evidence,
        }
        for s in steps
    ]

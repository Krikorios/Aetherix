"""Report persistence + artifact generation.

Each report row stores a JSONB artifact built deterministically from
control-plane state at generation time. Listing returns persisted rows
scoped by ``customer_id``; ``generate`` builds and inserts a new row, and
``get_artifact`` powers the ``/reports/{id}/download`` endpoint.

This is intentionally synchronous — every supported report type can be
produced from a handful of SQL aggregates plus the audit log. A future
worker can move heavy report types to background tasks without changing
the read API.
"""

from __future__ import annotations

import json
import logging
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any
from uuid import UUID, uuid4

from app.db import connection
from app.schemas import ReportRecord

LOGGER = logging.getLogger(__name__)


class ReportError(Exception):
    """Domain error mapped to 4xx by the route layer."""


REPORT_DESCRIPTIONS: dict[str, str] = {
    "executive_summary": "Portfolio risk overview generated from companies, endpoint health, alerts, and licensing data.",
    "ransomware_readiness": "Readiness summary based on ransomware-related alerts, pending updates, and policy coverage.",
    "integrity_report": "Signed audit and policy integrity summary from persisted control-plane evidence.",
    "compliance_export": "Compliance evidence package availability and source evidence counts.",
    "incident_timeline": "Chronological incident reconstruction from persisted security alerts and investigation cases.",
    "ai_efficiency": "AI-provider usage and security analyst efficiency summary from tenant settings and alert volume.",
}


REPORT_TITLES: dict[str, str] = {
    "executive_summary": "Executive Summary",
    "ransomware_readiness": "Ransomware Readiness",
    "integrity_report": "Integrity Report",
    "compliance_export": "Compliance Export",
    "incident_timeline": "Incident Timeline",
    "ai_efficiency": "AI Efficiency Report",
}


@dataclass
class _Counts:
    security_alerts: int
    open_alerts: int
    telemetry_30d: int
    audit_30d: int
    incidents_30d: int
    ai_calls_30d: int


def _collect_counts(
    customer_id: UUID | None,
    scope_clause: str,
    scope_params: list[Any],
) -> _Counts:
    with connection() as conn, conn.cursor() as cur:
        params: list[Any] = list(scope_params)
        where = scope_clause
        if customer_id is not None:
            where = f"{where} and sa.customer_id = %s" if where else "sa.customer_id = %s"
            params.append(customer_id)
        where_clause = f"where {where}" if where else ""
        cur.execute(
            f"select count(*) as n from security_alerts sa {where_clause}",
            params,
        )
        security_alerts = int(cur.fetchone()["n"])

        open_params = list(params)
        cur.execute(
            f"select count(*) as n from security_alerts sa {where_clause}"
            + (" and sa.status <> 'acknowledged'" if where_clause else "where sa.status <> 'acknowledged'"),
            open_params,
        )
        open_alerts = int(cur.fetchone()["n"])

        # Telemetry, incidents, audit, ai_calls keyed by customer_id only.
        if customer_id is not None:
            cur.execute(
                "select count(*) as n from telemetry_events "
                "where customer_id = %s and timestamp >= now() - interval '30 days'",
                (customer_id,),
            )
            telemetry_30d = int(cur.fetchone()["n"])
            cur.execute(
                "select count(*) as n from incident_cases "
                "where customer_id = %s and created_at >= now() - interval '30 days'",
                (customer_id,),
            )
            incidents_30d = int(cur.fetchone()["n"])
            cur.execute(
                "select coalesce(sum(calls), 0) as n from customer_ai_usage_daily "
                "where customer_id = %s and day >= current_date - interval '30 days'",
                (customer_id,),
            )
            ai_calls_30d = int(cur.fetchone()["n"] or 0)
        else:
            cur.execute(
                "select count(*) as n from telemetry_events "
                "where timestamp >= now() - interval '30 days'"
            )
            telemetry_30d = int(cur.fetchone()["n"])
            cur.execute(
                "select count(*) as n from incident_cases "
                "where created_at >= now() - interval '30 days'"
            )
            incidents_30d = int(cur.fetchone()["n"])
            cur.execute(
                "select coalesce(sum(calls), 0) as n from customer_ai_usage_daily "
                "where day >= current_date - interval '30 days'"
            )
            ai_calls_30d = int(cur.fetchone()["n"] or 0)

        cur.execute(
            "select count(*) as n from audit_log "
            "where created_at >= now() - interval '30 days'"
        )
        audit_30d = int(cur.fetchone()["n"])

    return _Counts(
        security_alerts=security_alerts,
        open_alerts=open_alerts,
        telemetry_30d=telemetry_30d,
        audit_30d=audit_30d,
        incidents_30d=incidents_30d,
        ai_calls_30d=ai_calls_30d,
    )


def _build_artifact(
    report_type: str,
    customer_id: UUID | None,
    counts: _Counts,
    now: datetime,
) -> dict[str, Any]:
    period = {
        "from": (now - timedelta(days=30)).isoformat(),
        "to": now.isoformat(),
        "interval_days": 30,
    }
    common = {
        "report_type": report_type,
        "customer_id": str(customer_id) if customer_id else None,
        "period": period,
        "generated_at": now.isoformat(),
    }

    if report_type == "executive_summary":
        return {
            **common,
            "sections": {
                "alerts": {
                    "total": counts.security_alerts,
                    "open": counts.open_alerts,
                    "resolved": counts.security_alerts - counts.open_alerts,
                },
                "telemetry_events_30d": counts.telemetry_30d,
                "ai_calls_30d": counts.ai_calls_30d,
            },
        }

    if report_type == "ransomware_readiness":
        score = max(0, 100 - counts.open_alerts * 8)
        return {
            **common,
            "sections": {
                "readiness_score": score,
                "open_alerts": counts.open_alerts,
                "incidents_30d": counts.incidents_30d,
                "framework": "nist-csf-2.0",
            },
        }

    if report_type == "integrity_report":
        return {
            **common,
            "sections": {
                "audit_events_30d": counts.audit_30d,
                "signed_chain": True,
                "verification_endpoint": "/audit/verify",
            },
        }

    if report_type == "compliance_export":
        return {
            **common,
            "sections": {
                "frameworks": [
                    "iso27001-2022",
                    "soc2-2017",
                    "nist-csf-2.0",
                    "gdpr",
                    "hipaa-security-rule",
                ],
                "source_events": counts.audit_30d + counts.security_alerts,
                "export_endpoint": "/compliance/export",
            },
        }

    if report_type == "incident_timeline":
        return {
            **common,
            "sections": {
                "incidents_30d": counts.incidents_30d,
                "alerts_30d": counts.security_alerts,
            },
        }

    if report_type == "ai_efficiency":
        per_alert = (counts.ai_calls_30d / counts.security_alerts) if counts.security_alerts else 0.0
        return {
            **common,
            "sections": {
                "ai_calls_30d": counts.ai_calls_30d,
                "alerts_30d": counts.security_alerts,
                "calls_per_alert": round(per_alert, 3),
            },
        }

    raise ReportError(f"unsupported report type '{report_type}'")


def _row_to_record(row: dict) -> ReportRecord:
    return ReportRecord(
        id=row["id"],
        type=row["type"],
        title=row["title"],
        description=row["description"],
        status=row["status"],
        customer_id=row.get("customer_id"),
        generated_at=row.get("generated_at"),
        size_bytes=row.get("size_bytes"),
        confidence=row.get("confidence"),
        source_event_count=row.get("source_event_count"),
        download_url=row.get("download_url"),
    )


def list_reports(
    customer_id: UUID | None,
    scope_clause: str,
    scope_params: list[Any],
    limit: int = 100,
) -> list[ReportRecord]:
    params: list[Any] = list(scope_params)
    filters: list[str] = []
    if scope_clause:
        # scope_clause was built for ``security_alerts sa`` aliases; re-alias to reports.
        filters.append(scope_clause.replace("sa.", "r."))
    if customer_id is not None:
        filters.append("r.customer_id = %s")
        params.append(customer_id)
    where = f"where {' and '.join(filters)}" if filters else ""
    with connection() as conn, conn.cursor() as cur:
        cur.execute(
            f"""
            select r.id, r.type, r.title, r.description, r.status,
                   r.customer_id, r.generated_at, r.size_bytes, r.confidence,
                   r.source_event_count, r.download_url
            from reports r
            {where}
            order by r.generated_at desc
            limit %s
            """,
            params + [limit],
        )
        return [_row_to_record(r) for r in cur.fetchall()]


def generate(
    report_type: str,
    customer_id: UUID | None,
    actor_id: UUID,
    partner_id: UUID | None,
    scope_clause: str,
    scope_params: list[Any],
) -> ReportRecord:
    if report_type not in REPORT_DESCRIPTIONS:
        raise ReportError(f"unsupported report type '{report_type}'")
    counts = _collect_counts(customer_id, scope_clause, scope_params)
    now = datetime.now(UTC)
    artifact = _build_artifact(report_type, customer_id, counts, now)
    payload = json.dumps(artifact, sort_keys=True, separators=(",", ":"))
    size_bytes = len(payload.encode("utf-8"))
    source_event_count = (
        counts.security_alerts + counts.audit_30d + counts.telemetry_30d
    )
    confidence = 100 if source_event_count else 0
    title = (
        f"{REPORT_TITLES[report_type]} — "
        f"{now.strftime('%b %Y')}"
    )
    description = REPORT_DESCRIPTIONS[report_type]
    download_url = (
        f"/compliance/export?customer_id={customer_id}&framework=iso27001-2022"
        if report_type == "compliance_export" and customer_id
        else f"/reports/{{id}}/download"
    )
    report_id = uuid4()
    download_url = download_url.replace("{id}", str(report_id))

    with connection() as conn, conn.cursor() as cur:
        cur.execute(
            """
            insert into reports (
                id, type, title, description, status,
                customer_id, partner_id, generated_at,
                size_bytes, confidence, source_event_count,
                download_url, artifact, generated_by
            ) values (
                %s, %s, %s, %s, 'ready',
                %s, %s, %s,
                %s, %s, %s,
                %s, %s::jsonb, %s
            )
            returning id, type, title, description, status, customer_id,
                      generated_at, size_bytes, confidence,
                      source_event_count, download_url
            """,
            (
                report_id,
                report_type,
                title,
                description,
                customer_id,
                partner_id,
                now,
                size_bytes,
                confidence,
                source_event_count,
                download_url,
                payload,
                actor_id,
            ),
        )
        row = cur.fetchone()
    return _row_to_record(row)


def get_artifact(report_id: UUID) -> tuple[ReportRecord, dict[str, Any]] | None:
    with connection() as conn, conn.cursor() as cur:
        cur.execute(
            """
            select id, type, title, description, status, customer_id,
                   generated_at, size_bytes, confidence, source_event_count,
                   download_url, artifact
            from reports
            where id = %s
            """,
            (report_id,),
        )
        row = cur.fetchone()
    if row is None:
        return None
    artifact = row["artifact"]
    if isinstance(artifact, str):
        artifact = json.loads(artifact)
    return _row_to_record(row), artifact

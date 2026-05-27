"""Compliance Evidence Engine v0.

The engine maps platform events to compliance controls at write time and
exports tenant-scoped evidence bundles for auditor review.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import uuid
from datetime import UTC, date, datetime
from typing import Any
from uuid import UUID

from app.db import connection


SUPPORTED_FRAMEWORKS = {
    "iso27001-2022",
    "soc2-2017",
    "nist-csf-2.0",
    "gdpr",
    "hipaa-security-rule",
}

CONTROL_MAPPINGS: dict[str, list[str]] = {
    "dlp.scan": [
        "iso27001-2022:A.5.12",
        "iso27001-2022:A.8.12",
        "soc2-2017:CC6.1",
        "gdpr:Art. 32",
        "hipaa-security-rule:164.312(a)(1)",
    ],
    "alert.ack": ["iso27001-2022:A.8.16", "soc2-2017:CC7.2", "nist-csf-2.0:RS.AN"],
    "agent.heartbeat": ["iso27001-2022:A.8.16", "soc2-2017:CC7.2", "nist-csf-2.0:DE.CM"],
    "agent.fim_event": ["iso27001-2022:A.8.12", "soc2-2017:CC7.1", "nist-csf-2.0:PR.PS"],
    "agent.edr_event": ["iso27001-2022:A.8.16", "soc2-2017:CC7.2", "nist-csf-2.0:DE.CM"],
    # `agent.response_action` covers operator-driven or policy-driven
    # responses (quarantine, restore, list, kill, isolate) — i.e. incident
    # response + recovery + integrity-of-response controls. Kept distinct
    # from `agent.edr_event` so auditor exports show the recovery trail
    # alongside detection telemetry.
    "agent.response_action": [
        "iso27001-2022:A.5.26",
        "iso27001-2022:A.5.30",
        "iso27001-2022:A.8.13",
        "iso27001-2022:A.8.16",
        "soc2-2017:CC7.2",
        "soc2-2017:CC7.4",
        "soc2-2017:CC7.5",
        "nist-csf-2.0:RS.MI",
        "nist-csf-2.0:RS.AN",
        "nist-csf-2.0:RC.RP",
    ],
    "agent.cis_check": ["iso27001-2022:A.8.8", "soc2-2017:CC7.1", "nist-csf-2.0:PR.PS"],
    # Operator-driven quarantine management — distinct from
    # `agent.response_action` (which is the agent's executed outcome) so
    # auditor exports can show *request*, *approve*, *deny*, and
    # *execute* as separate evidence steps for one remote response.
    "endpoint.quarantine.list_requested": [
        "iso27001-2022:A.5.26",
        "iso27001-2022:A.8.16",
        "soc2-2017:CC7.2",
        "nist-csf-2.0:DE.CM",
        "nist-csf-2.0:RS.AN",
    ],
    "endpoint.quarantine.restore_requested": [
        "iso27001-2022:A.5.26",
        "iso27001-2022:A.5.30",
        "iso27001-2022:A.8.13",
        "soc2-2017:CC7.4",
        "soc2-2017:CC7.5",
        "nist-csf-2.0:RS.MI",
        "nist-csf-2.0:RC.RP",
    ],
    "endpoint.quarantine.restore_approved": [
        "iso27001-2022:A.5.16",
        "iso27001-2022:A.5.18",
        "iso27001-2022:A.5.30",
        "iso27001-2022:A.8.13",
        "soc2-2017:CC6.3",
        "soc2-2017:CC7.4",
        "nist-csf-2.0:RS.MI",
        "nist-csf-2.0:RC.RP",
    ],
    "endpoint.quarantine.restore_denied": [
        "iso27001-2022:A.5.16",
        "iso27001-2022:A.5.26",
        "soc2-2017:CC7.4",
        "nist-csf-2.0:RS.AN",
    ],
    "policy.promote": ["iso27001-2022:A.5.12", "iso27001-2022:A.8.12", "soc2-2017:CC6.1", "gdpr:Art. 32"],
    "policy.simulate": ["iso27001-2022:A.8.12", "soc2-2017:CC6.1"],
    "policy_v2.create": ["iso27001-2022:A.5.12", "soc2-2017:CC6.1"],
    "policy_v2.simulate": ["iso27001-2022:A.8.12", "soc2-2017:CC6.1"],
    "policy_v2.promote": ["iso27001-2022:A.5.12", "iso27001-2022:A.8.12", "soc2-2017:CC6.1", "gdpr:Art. 32"],
    "policy_v2.assign": ["iso27001-2022:A.5.12", "soc2-2017:CC6.1"],
    "policy_v2.effective": ["iso27001-2022:A.8.16", "soc2-2017:CC7.2", "nist-csf-2.0:DE.CM"],
    "policy_v2.agent_fetch": ["iso27001-2022:A.8.16", "soc2-2017:CC7.2", "nist-csf-2.0:DE.CM"],
    "security.alert": ["iso27001-2022:A.8.16", "soc2-2017:CC7.2", "nist-csf-2.0:DE.CM"],
    # Cross-module correlation: when a FIM event and an EDR detection
    # touch the same file path on the same agent inside the correlation
    # window, the engine uplifts the security_alert severity and writes
    # a `correlation.severity_uplift` evidence event. Auditors get a
    # concrete event-aggregation/analysis artefact (DE.AE-3, RS.AN) and
    # a system-monitoring/integrity trail (A.5.25, A.8.16, CC7.2/CC7.3).
    "correlation.severity_uplift": [
        "iso27001-2022:A.5.25",
        "iso27001-2022:A.8.16",
        "soc2-2017:CC7.2",
        "soc2-2017:CC7.3",
        "nist-csf-2.0:DE.AE",
        "nist-csf-2.0:RS.AN",
    ],
    "attestation_created": ["iso27001-2022:A.5.35", "soc2-2017:CC2.1"],
    "review_recorded": ["iso27001-2022:A.5.35", "soc2-2017:CC2.1"],
    "impersonation.start": [
        "iso27001-2022:A.5.16",
        "iso27001-2022:A.5.18",
        "soc2-2017:CC6.3",
        "nist-csf-2.0:PR.AA",
    ],
    "impersonation.end": [
        "iso27001-2022:A.5.16",
        "iso27001-2022:A.5.18",
        "soc2-2017:CC6.3",
        "nist-csf-2.0:PR.AA",
    ],
}


class ComplianceExportError(ValueError):
    """Raised when a compliance export cannot be generated."""


class ComplianceServiceError(ValueError):
    """Raised when attestation or review service-layer validation fails."""


class DuplicateAttestationError(ComplianceServiceError):
    """Raised when an attestation already exists for the same bundle and period."""


def controls_for_event(action: str) -> list[str]:
    return CONTROL_MAPPINGS.get(action, [])


def controls_for_framework(controls: list[str], framework: str) -> list[str]:
    prefix = f"{framework}:"
    return [control.removeprefix(prefix) for control in controls if control.startswith(prefix)]


def export_bundle(customer_id: UUID, framework: str) -> dict[str, Any]:
    if framework not in SUPPORTED_FRAMEWORKS:
        raise ComplianceExportError(f"Unsupported compliance framework: {framework}")

    generated_at = datetime.now(UTC).isoformat()
    controls = _catalogue(framework)
    evidence = _evidence(customer_id, framework)
    evidence_counts = _evidence_counts(evidence)

    bundle = {
        "framework": framework,
        "customer_id": str(customer_id),
        "generated_at": generated_at,
        "controls": [
            {
                **control,
                "evidence_count": evidence_counts.get(control["control_id"], 0),
            }
            for control in controls
        ],
        "evidence": evidence,
        "audit_chain": _audit_chain_state(),
    }
    bundle["signature"] = {
        "algorithm": "HMAC-SHA256",
        "key_id": os.getenv("AETHERIX_COMPLIANCE_SIGNING_KEY_ID", "compliance-export-dev"),
        "value": _sign_bundle(bundle),
    }
    return bundle


def _catalogue(framework: str) -> list[dict[str, Any]]:
    with connection() as conn, conn.cursor() as cur:
        cur.execute(
            """
            select control_id, title, description
            from compliance_controls
            where framework = %s
            order by control_id
            """,
            (framework,),
        )
        return [dict(row) for row in cur.fetchall()]


def _evidence(customer_id: UUID, framework: str) -> list[dict[str, Any]]:
    evidence: list[dict[str, Any]] = []
    evidence.extend(_alert_evidence(customer_id, framework))
    evidence.extend(_security_alert_evidence(customer_id, framework))
    evidence.extend(_audit_evidence(customer_id, framework))
    evidence.extend(_policy_evidence(framework))
    evidence.extend(_evidence_event_records(customer_id, framework))
    return sorted(evidence, key=lambda item: item["created_at"], reverse=True)


def _alert_evidence(customer_id: UUID, framework: str) -> list[dict[str, Any]]:
    with connection() as conn, conn.cursor() as cur:
        cur.execute(
            """
            select id, created_at, status, payload, evidence_controls
            from alerts
            where customer_id = %s
              and jsonb_array_length(evidence_controls) > 0
            order by created_at desc
            """,
            (customer_id,),
        )
        rows = cur.fetchall()
    return [
        {
            "source_table": "alerts",
            "id": row["id"],
            "created_at": _iso(row["created_at"]),
            "summary": row["payload"].get("title", "DLP alert"),
            "status": row["status"],
            "controls": controls_for_framework(list(row["evidence_controls"]), framework),
        }
        for row in rows
        if controls_for_framework(list(row["evidence_controls"]), framework)
    ]


def _security_alert_evidence(customer_id: UUID, framework: str) -> list[dict[str, Any]]:
    with connection() as conn, conn.cursor() as cur:
        cur.execute(
            """
            select id, created_at, status, category, severity, evidence_controls
            from security_alerts
            where customer_id = %s
              and jsonb_array_length(evidence_controls) > 0
            order by created_at desc
            """,
            (customer_id,),
        )
        rows = cur.fetchall()
    return [
        {
            "source_table": "security_alerts",
            "id": str(row["id"]),
            "created_at": _iso(row["created_at"]),
            "summary": f"{row['category']} alert ({row['severity']})",
            "status": row["status"],
            "controls": controls_for_framework(list(row["evidence_controls"]), framework),
        }
        for row in rows
        if controls_for_framework(list(row["evidence_controls"]), framework)
    ]


def _audit_evidence(customer_id: UUID, framework: str) -> list[dict[str, Any]]:
    customer_resource = f"customer:{customer_id}"
    with connection() as conn, conn.cursor() as cur:
        cur.execute(
            """
            select seq, ts, actor, action, resource, chain_hash, evidence_controls
            from audit_log
            where (resource = %s or resource like %s)
              and jsonb_array_length(evidence_controls) > 0
            order by seq desc
            """,
            (customer_resource, f"{customer_resource}:%"),
        )
        rows = cur.fetchall()
    return [
        {
            "source_table": "audit_log",
            "id": str(row["seq"]),
            "created_at": _iso(row["ts"]),
            "summary": f"{row['action']} by {row['actor']}",
            "resource": row["resource"],
            "chain_hash": row["chain_hash"],
            "controls": controls_for_framework(list(row["evidence_controls"]), framework),
        }
        for row in rows
        if controls_for_framework(list(row["evidence_controls"]), framework)
    ]


def _policy_evidence(framework: str) -> list[dict[str, Any]]:
    with connection() as conn, conn.cursor() as cur:
        cur.execute(
            """
            select version, created_at, payload, evidence_controls
            from policy_documents
            where jsonb_array_length(evidence_controls) > 0
            order by version desc
            """
        )
        rows = cur.fetchall()
    return [
        {
            "source_table": "policy_documents",
            "id": str(row["version"]),
            "created_at": _iso(row["created_at"]),
            "summary": f"Policy promoted: {row['payload'].get('name', row['payload'].get('id', 'policy'))}",
            "policy_id": row["payload"].get("id"),
            "controls": controls_for_framework(list(row["evidence_controls"]), framework),
        }
        for row in rows
        if controls_for_framework(list(row["evidence_controls"]), framework)
    ]


def _evidence_event_records(customer_id: UUID, framework: str) -> list[dict[str, Any]]:
    with connection() as conn, conn.cursor() as cur:
        cur.execute(
            """
            select id, action, resource, actor, scope, payload, evidence_controls, created_at
            from evidence_events
            where (scope->>'customer_id' = %s)
              and jsonb_array_length(evidence_controls) > 0
            order by created_at desc
            """,
            (str(customer_id),),
        )
        rows = cur.fetchall()
    return [
        {
            "source_table": "evidence_events",
            "id": str(row["id"]),
            "created_at": _iso(row["created_at"]),
            "summary": f"{row['action']} on {row['resource']}",
            "actor": row["actor"],
            "controls": controls_for_framework(list(row["evidence_controls"]), framework),
        }
        for row in rows
        if controls_for_framework(list(row["evidence_controls"]), framework)
    ]


def _evidence_counts(evidence: list[dict[str, Any]]) -> dict[str, int]:
    counts: dict[str, int] = {}
    for item in evidence:
        for control in item["controls"]:
            counts[control] = counts.get(control, 0) + 1
    return counts


def _audit_chain_state() -> dict[str, Any]:
    with connection() as conn, conn.cursor() as cur:
        cur.execute("select count(*) as n, max(seq) as latest_seq from audit_log")
        count_row = cur.fetchone()
        cur.execute("select chain_hash from audit_log order by seq desc limit 1")
        hash_row = cur.fetchone()
    return {
        "record_count": int(count_row["n"]),
        "latest_seq": int(count_row["latest_seq"]) if count_row["latest_seq"] is not None else None,
        "latest_chain_hash": hash_row["chain_hash"] if hash_row else None,
    }


def _sign_bundle(bundle: dict[str, Any]) -> str:
    canonical = json.dumps(bundle, sort_keys=True, separators=(",", ":"), default=str)
    return hmac.new(_signing_key(), canonical.encode(), hashlib.sha256).hexdigest()


def _signing_key() -> bytes:
    key = os.getenv("AETHERIX_COMPLIANCE_SIGNING_KEY") or os.getenv("AETHERIX_POLICY_SIGNING_KEY") or "aetherix-dev-compliance-key"
    return key.encode()


def _iso(value: Any) -> str:
    if isinstance(value, datetime):
        return value.isoformat()
    return str(value)


def list_review_items(customer_id: UUID, framework: str, source_table: str) -> list[dict[str, Any]]:
    _ensure_supported_framework(framework)
    if source_table != "evidence_events":
        return []

    prefix = f"{framework}:"
    with connection() as conn, conn.cursor() as cur:
        cur.execute(
            """
            with evidence as (
                select
                    e.id::text as source_id,
                    e.created_at as evidence_created_at,
                    concat(e.action, ' on ', e.resource) as evidence_summary,
                    replace(control.value, %s, '') as control_id
                from evidence_events e
                cross join lateral jsonb_array_elements_text(e.evidence_controls) as control(value)
                where e.scope->>'customer_id' = %s
                                    and e.action not in ('attestation_created', 'review_recorded')
                  and control.value like %s
            )
            select
                evidence.source_id,
                evidence.evidence_created_at,
                evidence.evidence_summary,
                evidence.control_id,
                review.id,
                review.customer_id,
                review.source_table,
                review.framework,
                review.reviewed_by_account_id,
                review.reviewed_by_role,
                review.reviewed_by_name,
                review.decision,
                review.note,
                review.reviewed_at
            from evidence
            left join lateral (
                select *
                from compliance_reviews r
                where r.customer_id = %s
                  and r.source_table = 'evidence_events'
                  and r.source_id = evidence.source_id
                  and r.framework = %s
                  and r.control_id = evidence.control_id
                order by r.reviewed_at desc
                limit 1
            ) review on true
            order by evidence.evidence_created_at desc, evidence.control_id
            """,
            (prefix, str(customer_id), f"{prefix}%", customer_id, framework),
        )
        rows = cur.fetchall()

    items: list[dict[str, Any]] = []
    for row in rows:
        latest_review = None
        if row["id"] is not None:
            latest_review = {
                "id": row["id"],
                "customer_id": row["customer_id"],
                "source_table": "evidence_events",
                "source_id": row["source_id"],
                "framework": row["framework"],
                "control_id": row["control_id"],
                "reviewed_by_account_id": row["reviewed_by_account_id"],
                "reviewed_by_role": row["reviewed_by_role"],
                "reviewed_by_name": row["reviewed_by_name"],
                "decision": row["decision"],
                "note": row["note"],
                "reviewed_at": row["reviewed_at"],
            }
        items.append(
            {
                "source_table": "evidence_events",
                "source_id": row["source_id"],
                "framework": framework,
                "control_id": row["control_id"],
                "evidence_summary": row["evidence_summary"],
                "evidence_created_at": row["evidence_created_at"],
                "review_status": "completed" if latest_review else "pending",
                "latest_review": latest_review,
            }
        )
    return items


def create_review(
    *,
    customer_id: UUID,
    source_table: str,
    source_id: str,
    framework: str,
    control_id: str,
    decision: str,
    note: str | None,
    reviewed_by_account_id: UUID | None,
    reviewed_by_role: str,
    reviewed_by_name: str,
) -> dict[str, Any]:
    _ensure_supported_framework(framework)
    _ensure_evidence_source(customer_id, source_table, source_id, framework, control_id)

    review_id = uuid.uuid4()
    reviewed_at = datetime.now(UTC)

    with connection() as conn, conn.cursor() as cur:
        cur.execute(
            """
            insert into compliance_reviews (
                id, customer_id, source_table, source_id, framework, control_id,
                reviewed_by_account_id, reviewed_by_role, reviewed_by_name,
                decision, note, reviewed_at
            ) values (
                %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s
            )
            """,
            (
                review_id,
                customer_id,
                source_table,
                source_id,
                framework,
                control_id,
                reviewed_by_account_id,
                reviewed_by_role,
                reviewed_by_name,
                decision,
                note,
                reviewed_at,
            ),
        )

    record = {
        "id": review_id,
        "customer_id": customer_id,
        "source_table": source_table,
        "source_id": source_id,
        "framework": framework,
        "control_id": control_id,
        "reviewed_by_account_id": reviewed_by_account_id,
        "reviewed_by_role": reviewed_by_role,
        "reviewed_by_name": reviewed_by_name,
        "decision": decision,
        "note": note,
        "reviewed_at": reviewed_at,
    }
    _emit_compliance_event(
        customer_id=customer_id,
        action="review_recorded",
        resource=f"{source_table}:{source_id}",
        actor=reviewed_by_name,
        payload={"review_id": str(review_id), "framework": framework, "control_id": control_id, "decision": decision},
        evidence_controls=[f"{framework}:{control_id}"],
    )
    return record


def list_attestations(customer_id: UUID, framework: str, period_end: date | None = None) -> list[dict[str, Any]]:
    _ensure_supported_framework(framework)
    with connection() as conn, conn.cursor() as cur:
        cur.execute(
            """
            select
                id, customer_id, framework, period_start, period_end,
                attested_by_account_id, attested_role, attested_name,
                bundle_sha256, signature, signature_algo, statement, created_at
            from compliance_attestations
            where customer_id = %s and framework = %s
              and (%s::date is null or period_end = %s::date)
            order by created_at desc
            """,
            (customer_id, framework, period_end, period_end),
        )
        rows = [dict(row) for row in cur.fetchall()]
    count = _evidence_summary_count(customer_id, framework)
    return [{**row, "evidence_summary_count": count} for row in rows]


def create_attestation(
    *,
    customer_id: UUID,
    framework: str,
    period_start: date,
    period_end: date,
    attested_by_account_id: UUID | None,
    attested_role: str,
    attested_name: str,
    statement: str,
    bundle_sha256: str,
    signature: str,
    signature_algo: str,
) -> dict[str, Any]:
    _ensure_supported_framework(framework)
    if period_end < period_start:
        raise ComplianceServiceError("period_end must be on or after period_start")
    if not _bundle_exists(customer_id, framework, bundle_sha256):
        raise ComplianceServiceError("bundle_sha256 does not reference a known evidence bundle")

    attestation_id = uuid.uuid4()
    created_at = datetime.now(UTC)

    with connection() as conn, conn.cursor() as cur:
        cur.execute(
            """
            select id from compliance_attestations
            where customer_id = %s
              and framework = %s
              and period_start = %s
              and period_end = %s
              and bundle_sha256 = %s
            limit 1
            """,
            (customer_id, framework, period_start, period_end, bundle_sha256),
        )
        if cur.fetchone() is not None:
            raise DuplicateAttestationError("attestation already exists for this framework, period, and bundle")

        cur.execute(
            """
            insert into compliance_attestations (
                id, customer_id, framework, period_start, period_end,
                attested_by_account_id, attested_role, attested_name,
                bundle_sha256, signature, signature_algo, statement, created_at
            ) values (
                %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s
            )
            """,
            (
                attestation_id,
                customer_id,
                framework,
                period_start,
                period_end,
                attested_by_account_id,
                attested_role,
                attested_name,
                bundle_sha256,
                signature,
                signature_algo,
                statement,
                created_at,
            ),
        )

    count = _evidence_summary_count(customer_id, framework)
    record = {
        "id": attestation_id,
        "customer_id": customer_id,
        "framework": framework,
        "period_start": period_start,
        "period_end": period_end,
        "attested_by_account_id": attested_by_account_id,
        "attested_role": attested_role,
        "attested_name": attested_name,
        "bundle_sha256": bundle_sha256,
        "signature": signature,
        "signature_algo": signature_algo,
        "statement": statement,
        "created_at": created_at,
        "evidence_summary_count": count,
    }
    _emit_compliance_event(
        customer_id=customer_id,
        action="attestation_created",
        resource=f"compliance_attestations:{attestation_id}",
        actor=attested_name,
        payload={
            "attestation_id": str(attestation_id),
            "framework": framework,
            "period_start": period_start.isoformat(),
            "period_end": period_end.isoformat(),
            "bundle_sha256": bundle_sha256,
            "evidence_summary_count": count,
        },
        evidence_controls=controls_for_event("attestation_created"),
    )
    return record


def _ensure_supported_framework(framework: str) -> None:
    if framework not in SUPPORTED_FRAMEWORKS:
        raise ComplianceServiceError(f"Unsupported compliance framework: {framework}")


def _bundle_exists(customer_id: UUID, framework: str, bundle_sha256: str) -> bool:
    with connection() as conn, conn.cursor() as cur:
        cur.execute(
            """
            select 1
            from compliance_vault_references
            where customer_id = %s and framework = %s and sha256 = %s
            limit 1
            """,
            (customer_id, framework, bundle_sha256),
        )
        return cur.fetchone() is not None


def _ensure_evidence_source(customer_id: UUID, source_table: str, source_id: str, framework: str, control_id: str) -> None:
    full_control_id = f"{framework}:{control_id}"
    if source_table != "evidence_events":
        raise ComplianceServiceError("source_table is not supported for MVP review ingestion")
    with connection() as conn, conn.cursor() as cur:
        cur.execute(
            """
            select 1
            from evidence_events
            where id::text = %s
              and scope->>'customer_id' = %s
              and evidence_controls ? %s
            limit 1
            """,
            (source_id, str(customer_id), full_control_id),
        )
        if cur.fetchone() is None:
            raise ComplianceServiceError("review source does not exist for this tenant, framework, and control")


def _evidence_summary_count(customer_id: UUID, framework: str) -> int:
    prefix = f"{framework}:"
    with connection() as conn, conn.cursor() as cur:
        cur.execute(
            """
            select count(*) as n
            from evidence_events e
            where e.scope->>'customer_id' = %s
              and exists (
                  select 1
                  from jsonb_array_elements_text(e.evidence_controls) as control(value)
                  where control.value like %s
              )
            """,
            (str(customer_id), f"{prefix}%"),
        )
        row = cur.fetchone()
    return int(row["n"])


def _emit_compliance_event(
    *,
    customer_id: UUID,
    action: str,
    resource: str,
    actor: str,
    payload: dict[str, Any],
    evidence_controls: list[str],
) -> None:
    with connection() as conn, conn.cursor() as cur:
        cur.execute(
            """
            insert into evidence_events (
                id, action, resource, actor, scope, payload,
                evidence_controls, created_at
            ) values (
                %s, %s, %s, %s, %s::jsonb, %s::jsonb, %s::jsonb, %s
            )
            """,
            (
                uuid.uuid4(),
                action,
                resource,
                actor,
                json.dumps({"customer_id": str(customer_id)}),
                json.dumps(payload),
                json.dumps(evidence_controls),
                datetime.now(UTC),
            ),
        )


def list_vault_references(customer_id: UUID, framework: str) -> list[dict[str, Any]]:
    with connection() as conn, conn.cursor() as cur:
        cur.execute(
            """
            select id, customer_id, framework, vault_provider, reference_uri, bundle_hash, status, exported_at
            from compliance_vault_references
            where customer_id = %s and framework = %s
            order by exported_at desc
            """,
            (customer_id, framework),
        )
        return [dict(row) for row in cur.fetchall()]

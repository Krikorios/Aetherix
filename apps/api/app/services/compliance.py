"""Compliance Evidence Engine v0.

The engine maps platform events to compliance controls at write time and
exports tenant-scoped evidence bundles for auditor review.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
from datetime import UTC, datetime
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
    "policy.promote": ["iso27001-2022:A.5.12", "iso27001-2022:A.8.12", "soc2-2017:CC6.1", "gdpr:Art. 32"],
    "policy.simulate": ["iso27001-2022:A.8.12", "soc2-2017:CC6.1"],
    "policy_v2.create": ["iso27001-2022:A.5.12", "soc2-2017:CC6.1"],
    "policy_v2.simulate": ["iso27001-2022:A.8.12", "soc2-2017:CC6.1"],
    "policy_v2.promote": ["iso27001-2022:A.5.12", "iso27001-2022:A.8.12", "soc2-2017:CC6.1", "gdpr:Art. 32"],
    "policy_v2.assign": ["iso27001-2022:A.5.12", "soc2-2017:CC6.1"],
    "policy_v2.effective": ["iso27001-2022:A.8.16", "soc2-2017:CC7.2", "nist-csf-2.0:DE.CM"],
    "policy_v2.agent_fetch": ["iso27001-2022:A.8.16", "soc2-2017:CC7.2", "nist-csf-2.0:DE.CM"],
    "security.alert": ["iso27001-2022:A.8.16", "soc2-2017:CC7.2", "nist-csf-2.0:DE.CM"],
}


class ComplianceExportError(ValueError):
    """Raised when a compliance export cannot be generated."""


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
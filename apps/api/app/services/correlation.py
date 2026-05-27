"""Cross-module correlation engine (FIM ↔ EDR ↔ DLP).

The correlation engine wires the agent's independent detection streams
(file integrity monitoring, EDR YARA/IOC/behavior matches, DLP scans)
together at write time. When a new EDR-derived ``security_alerts`` row
references a file path or SHA-256 that a recent FIM event or DLP scan
also touched on the same agent — or vice versa — the engine:

1. Persists an edge in ``correlation_links`` so the console can render
   the supporting evidence on the alert detail view.
2. Uplifts the alert's severity one rung (medium→high, high→critical),
   recording the original severity in ``security_alerts.severity_uplifted_from``
   and a ``correlation`` block on the alert payload.
3. Writes a ``correlation.severity_uplift`` evidence event so auditor
   exports include the aggregation/analysis artefact (NIST CSF DE.AE,
   RS.AN; ISO 27001 A.5.25, A.8.16; SOC 2 CC7.2/CC7.3).

Three correlation types are supported:

  * ``file_path_match`` — same normalized file path on the same agent
    within the correlation window (FIM ↔ EDR).
  * ``sha256_match`` — same SHA-256 hash on the same agent within the
    correlation window (FIM ↔ EDR, DLP ↔ EDR).
  * ``process_path_match`` — same process path on the same agent within
    the correlation window (reserved for future behavioural pairs).

The engine is intentionally deterministic and SQL-only: no background
job, no broker. All directions are exercised inside the heartbeat or DLP
event transaction so a single ack settles the correlation and the
compliance trail together.
"""

from __future__ import annotations

import json
import os
import uuid
from datetime import UTC, datetime, timedelta
from typing import Any, Iterable
from uuid import UUID


# Default lookback window matches the agent heartbeat cadence (a few
# minutes) plus operator-visible alert dwell time. Override via env so
# noisy environments can widen the join without code changes.
DEFAULT_WINDOW_SECONDS = 600


def _window_seconds() -> int:
    raw = os.getenv("AETHERIX_CORRELATION_WINDOW_SECONDS")
    if not raw:
        return DEFAULT_WINDOW_SECONDS
    try:
        value = int(raw)
    except ValueError:
        return DEFAULT_WINDOW_SECONDS
    return max(1, value)


_SEVERITY_RANK = {"low": 0, "medium": 1, "high": 2, "critical": 3}
_SEVERITY_UPLIFT = {"low": "medium", "medium": "high", "high": "critical", "critical": "critical"}


def _normalize_path(path: str | None) -> str | None:
    """Lowercase + forward-slash canonicalisation for cross-platform joins.

    The agent reports POSIX-style paths on macOS/Linux and Windows-style
    paths on Windows. We normalise to the lowest-common-denominator so
    ``C:\\Users\\Alice\\evil.exe`` and ``c:/users/alice/evil.exe`` join.
    """

    if not path:
        return None
    stripped = path.strip()
    if not stripped:
        return None
    return stripped.replace("\\", "/").lower()


def persist_fim_event(
    cur: Any,
    *,
    customer_id: UUID,
    agent_id: str,
    event_type: str,
    file_path: str,
    sha256_hash: str | None,
    observed_at: datetime,
) -> tuple[uuid.UUID, str]:
    """Insert a fim_events row and return ``(id, normalized_path)``."""

    file_path_norm = _normalize_path(file_path) or file_path.lower()
    fim_id = uuid.uuid4()
    cur.execute(
        """
        insert into fim_events (
            id, customer_id, agent_id, event_type, file_path,
            file_path_norm, sha256_hash, observed_at, created_at
        ) values (%s, %s, %s, %s, %s, %s, %s, %s, %s)
        """,
        (
            fim_id,
            customer_id,
            agent_id,
            event_type,
            file_path,
            file_path_norm,
            sha256_hash,
            observed_at,
            datetime.now(UTC),
        ),
    )
    return fim_id, file_path_norm


def _query_fim_by_path(
    cur: Any, *, agent_id: str, customer_id: UUID, file_path_norm: str, cutoff: datetime, window_end: datetime, limit: int = 10
) -> list[dict]:
    cur.execute(
        """
        select id, event_type, file_path, sha256_hash, observed_at
        from fim_events
        where agent_id = %s
          and customer_id = %s
          and file_path_norm = %s
          and observed_at >= %s
          and observed_at <= %s
        order by observed_at desc
        limit %s
        """,
        (agent_id, customer_id, file_path_norm, cutoff, window_end, limit),
    )
    return list(cur.fetchall())


def _query_fim_by_sha256(
    cur: Any, *, agent_id: str, customer_id: UUID, sha256: str, cutoff: datetime, window_end: datetime, limit: int = 10
) -> list[dict]:
    cur.execute(
        """
        select id, event_type, file_path, sha256_hash, observed_at
        from fim_events
        where agent_id = %s
          and customer_id = %s
          and sha256_hash = %s
          and observed_at >= %s
          and observed_at <= %s
        order by observed_at desc
        limit %s
        """,
        (agent_id, customer_id, sha256, cutoff, window_end, limit),
    )
    return list(cur.fetchall())


def _query_dlp_by_sha256(
    cur: Any, *, agent_id: str | None, customer_id: UUID, sha256: str, cutoff: datetime, window_end: datetime, limit: int = 10
) -> list[dict]:
    if agent_id:
        cur.execute(
            """
            select id, source, action, entity_types, risk_band, sha256_hash, observed_at
            from dlp_events
            where customer_id = %s
              and sha256_hash = %s
              and endpoint_id = %s
              and observed_at >= %s
              and observed_at <= %s
            order by observed_at desc
            limit %s
            """,
            (customer_id, sha256, agent_id, cutoff, window_end, limit),
        )
    else:
        cur.execute(
            """
            select id, source, action, entity_types, risk_band, sha256_hash, observed_at
            from dlp_events
            where customer_id = %s
              and sha256_hash = %s
              and observed_at >= %s
              and observed_at <= %s
            order by observed_at desc
            limit %s
            """,
            (customer_id, sha256, cutoff, window_end, limit),
        )
    return list(cur.fetchall())


def _query_security_alerts_by_sha256(
    cur: Any, *, agent_id: str, customer_id: UUID, sha256: str, cutoff: datetime, window_end: datetime, limit: int = 10
) -> list[dict]:
    cur.execute(
        """
        select id, severity, payload, evidence_controls, severity_uplifted_from
        from security_alerts
        where agent_id = %s
          and customer_id = %s
          and status = 'new'
          and created_at >= %s
          and created_at <= %s
          and category in ('malware', 'behavior', 'anomaly')
          and (payload->>'file_sha256' = %s or payload->>'sha256_hash' = %s)
        order by created_at desc
        limit %s
        """,
        (agent_id, customer_id, cutoff, window_end, sha256, sha256, limit),
    )
    return list(cur.fetchall())


def _build_planned_link(
    row: dict, agent_id: str, correlation_type: str, window: int, kind: str = "fim_event"
) -> dict[str, Any]:
    if kind == "dlp_event":
        return {
            "related_kind": "dlp_event",
            "related_id": str(row["id"]),
            "correlation_type": correlation_type,
            "window_seconds": window,
            "evidence": {
                "source": row["source"],
                "action": row["action"],
                "entity_types": row["entity_types"],
                "risk_band": row["risk_band"],
                "sha256_hash": row["sha256_hash"],
                "observed_at": row["observed_at"].isoformat()
                if isinstance(row["observed_at"], datetime)
                else str(row["observed_at"]),
                "agent_id": agent_id,
            },
        }
    return {
        "related_kind": kind,
        "related_id": str(row["id"]),
        "correlation_type": correlation_type,
        "window_seconds": window,
        "evidence": {
            "file_path": row["file_path"],
            "event_type": row["event_type"],
            "sha256_hash": row["sha256_hash"],
            "observed_at": row["observed_at"].isoformat()
            if isinstance(row["observed_at"], datetime)
            else str(row["observed_at"]),
            "agent_id": agent_id,
        },
    }


def correlate_new_edr_alert(
    cur: Any,
    *,
    alert_id: uuid.UUID,
    customer_id: UUID,
    agent_id: str,
    file_path: str | None,
    severity: str,
    payload: dict[str, Any],
    evidence_controls: list[str],
    created_at: datetime,
) -> tuple[str, dict[str, Any], list[str], list[dict[str, Any]]]:
    """Look up recent FIM evidence for the same path/sha256 and uplift the alert.

    Returns the (possibly uplifted) ``severity``, the updated ``payload``,
    the updated ``evidence_controls``, and a list of *planned* link
    records. Because ``correlation_links`` has an FK to
    ``security_alerts(id)``, the caller must INSERT the alert first and
    then pass the planned links to :func:`record_planned_links` to
    persist them. The compliance ``correlation.severity_uplift`` event
    is emitted here so the trail is written even if the caller drops
    the alert insert on the floor.
    """

    file_path_norm = _normalize_path(file_path)
    sha256 = payload.get("file_sha256") or payload.get("sha256_hash") or None
    if not file_path_norm and not sha256:
        return severity, payload, evidence_controls, []

    window = _window_seconds()
    cutoff = created_at - timedelta(seconds=window)
    window_end = created_at + timedelta(seconds=window)

    seen_ids: set[str] = set()
    planned_links: list[dict[str, Any]] = []
    deduped_rows: list[dict] = []

    if file_path_norm:
        for row in _query_fim_by_path(cur, agent_id=agent_id, customer_id=customer_id, file_path_norm=file_path_norm, cutoff=cutoff, window_end=window_end):
            if str(row["id"]) not in seen_ids:
                seen_ids.add(str(row["id"]))
                deduped_rows.append(row)

    if sha256:
        for row in _query_fim_by_sha256(cur, agent_id=agent_id, customer_id=customer_id, sha256=sha256, cutoff=cutoff, window_end=window_end):
            if str(row["id"]) not in seen_ids:
                seen_ids.add(str(row["id"]))
                deduped_rows.append(row)

        for row in _query_dlp_by_sha256(cur, agent_id=agent_id, customer_id=customer_id, sha256=sha256, cutoff=cutoff, window_end=window_end):
            if str(row["id"]) not in seen_ids:
                seen_ids.add(str(row["id"]))
                deduped_rows.append(row)

    if not deduped_rows:
        return severity, payload, evidence_controls, []

    for row in deduped_rows:
        kind = "dlp_event" if "source" in row and "action" in row else "fim_event"
        if kind == "fim_event" and file_path_norm and _normalize_path(row["file_path"]) == file_path_norm:
            ctype = "sha256_match" if sha256 and row["sha256_hash"] == sha256 else "file_path_match"
        elif sha256 and row["sha256_hash"] == sha256:
            ctype = "sha256_match"
        elif kind == "fim_event":
            ctype = "file_path_match"
        else:
            continue
        planned_links.append(_build_planned_link(row, agent_id, ctype, window, kind=kind))

    uplifted = _SEVERITY_UPLIFT.get(severity, severity)
    payload = dict(payload)
    correlation_block = dict(payload.get("correlation") or {})
    if uplifted != severity:
        correlation_block["uplifted_from"] = severity
    correlation_block["window_seconds"] = window
    related = list(correlation_block.get("related") or [])
    for link in planned_links:
        related.append({k: link[k] for k in ("related_kind", "related_id", "correlation_type")})
    correlation_block["related"] = related
    payload["correlation"] = correlation_block

    evidence_controls = list(dict.fromkeys(
        list(evidence_controls) + _correlation_controls()
    ))

    if uplifted != severity:
        has_dlp = any(link.get("related_kind") == "dlp_event" for link in planned_links)
        has_fim = any(link.get("related_kind") == "fim_event" for link in planned_links)
        dir_parts = ["edr_to"]
        if has_fim:
            dir_parts.append("fim")
        if has_dlp:
            dir_parts.append("dlp")
        direction = "_".join(dir_parts) if len(dir_parts) > 1 else "edr_to_fim"
        _emit_uplift_event(
            customer_id=customer_id,
            alert_id=alert_id,
            agent_id=agent_id,
            file_path=file_path or "",
            before=severity,
            after=uplifted,
            direction=direction,
            related=planned_links,
            created_at=created_at,
        )
    return uplifted, payload, evidence_controls, planned_links


def record_planned_links(
    cur: Any,
    *,
    customer_id: UUID,
    security_alert_id: uuid.UUID,
    planned_links: list[dict[str, Any]],
    created_at: datetime,
) -> list[dict[str, Any]]:
    """Persist links returned by :func:`correlate_new_edr_alert`."""

    recorded: list[dict[str, Any]] = []
    for link in planned_links:
        recorded.append(
            _record_link(
                cur,
                customer_id=customer_id,
                security_alert_id=security_alert_id,
                related_kind=link["related_kind"],
                related_id=link["related_id"],
                correlation_type=link["correlation_type"],
                window_seconds=link["window_seconds"],
                evidence=link["evidence"],
                created_at=created_at,
            )
        )
    return recorded


def correlate_new_fim_event(
    cur: Any,
    *,
    fim_event_id: uuid.UUID,
    customer_id: UUID,
    agent_id: str,
    file_path: str,
    sha256_hash: str | None = None,
    observed_at: datetime,
) -> list[dict[str, Any]]:
    """Uplift recent open EDR-style security_alerts that share file path or sha256.

    Returns the list of recorded link records (one per uplifted alert).
    """

    file_path_norm = _normalize_path(file_path)
    if not file_path_norm and not sha256_hash:
        return []

    window = _window_seconds()
    cutoff_lo = observed_at - timedelta(seconds=window)
    cutoff_hi = observed_at + timedelta(seconds=window)
    cur.execute(
        """
        select id, severity, payload, evidence_controls, severity_uplifted_from
        from security_alerts
        where agent_id = %s
          and customer_id = %s
          and status = 'new'
          and created_at >= %s
          and created_at <= %s
          and category in ('malware', 'behavior', 'anomaly')
        """,
        (agent_id, customer_id, cutoff_lo, cutoff_hi),
    )
    candidates = list(cur.fetchall())
    if not candidates:
        return []

    recorded: list[dict[str, Any]] = []
    for row in candidates:
        payload = dict(row["payload"] or {})
        alert_path = payload.get("file_path") or payload.get("process_path")
        alert_sha = payload.get("file_sha256") or payload.get("sha256_hash")

        matches_path = _normalize_path(alert_path) == file_path_norm if file_path_norm else False
        matches_sha = bool(sha256_hash and alert_sha and sha256_hash == alert_sha)
        if not matches_path and not matches_sha:
            continue

        ctype = "sha256_match" if matches_sha and not matches_path else "file_path_match"

        link = _record_link(
            cur,
            customer_id=customer_id,
            security_alert_id=row["id"],
            related_kind="fim_event",
            related_id=str(fim_event_id),
            correlation_type=ctype,
            window_seconds=window,
            evidence={
                "file_path": file_path,
                "sha256_hash": sha256_hash,
                "observed_at": observed_at.isoformat(),
                "agent_id": agent_id,
            },
            created_at=observed_at,
        )
        recorded.append(link)

        current_severity = row["severity"]
        uplifted = _SEVERITY_UPLIFT.get(current_severity, current_severity)
        already_uplifted = row["severity_uplifted_from"] is not None

        correlation_block = dict(payload.get("correlation") or {})
        correlation_block["window_seconds"] = window
        related = list(correlation_block.get("related") or [])
        related.append(
            {
                "related_kind": "fim_event",
                "related_id": str(fim_event_id),
                "correlation_type": ctype,
            }
        )
        correlation_block["related"] = related

        new_controls = list(dict.fromkeys(
            list(row["evidence_controls"] or []) + _correlation_controls()
        ))

        if uplifted != current_severity and not already_uplifted:
            correlation_block["uplifted_from"] = current_severity
            payload["correlation"] = correlation_block
            cur.execute(
                """
                update security_alerts
                   set severity = %s,
                       severity_uplifted_from = %s,
                       payload = %s::jsonb,
                       evidence_controls = %s::jsonb
                 where id = %s
                """,
                (
                    uplifted,
                    current_severity,
                    json.dumps(payload),
                    json.dumps(new_controls),
                    row["id"],
                ),
            )
            _emit_uplift_event(
                customer_id=customer_id,
                alert_id=row["id"],
                agent_id=agent_id,
                file_path=file_path,
                before=current_severity,
                after=uplifted,
                direction="fim_to_edr",
                related=[link],
                created_at=observed_at,
            )
        else:
            payload["correlation"] = correlation_block
            cur.execute(
                """
                update security_alerts
                   set payload = %s::jsonb,
                       evidence_controls = %s::jsonb
                 where id = %s
                """,
                (
                    json.dumps(payload),
                    json.dumps(new_controls),
                    row["id"],
                ),
            )

    return recorded


def correlate_new_dlp_event(
    cur: Any,
    *,
    dlp_event_id: uuid.UUID,
    customer_id: UUID,
    agent_id: str | None,
    sha256_hash: str | None,
    observed_at: datetime,
) -> list[dict[str, Any]]:
    """Uplift recent open EDR-style security_alerts that share sha256 with a DLP event.

    DLP events (sensitive content detection) and EDR detections on the same
    file hash provide high-signal cross-modality evidence. Returns the list
    of recorded link records (one per uplifted alert).
    """

    if not sha256_hash:
        return []

    window = _window_seconds()
    cutoff_lo = observed_at - timedelta(seconds=window)
    cutoff_hi = observed_at + timedelta(seconds=window)

    candidates = _query_security_alerts_by_sha256(
        cur, agent_id=agent_id or "", customer_id=customer_id,
        sha256=sha256_hash, cutoff=cutoff_lo, window_end=cutoff_hi,
    )
    if not candidates:
        return []

    recorded: list[dict[str, Any]] = []
    for row in candidates:
        link = _record_link(
            cur,
            customer_id=customer_id,
            security_alert_id=row["id"],
            related_kind="dlp_event",
            related_id=str(dlp_event_id),
            correlation_type="sha256_match",
            window_seconds=window,
            evidence={
                "sha256_hash": sha256_hash,
                "observed_at": observed_at.isoformat(),
                "agent_id": agent_id,
            },
            created_at=observed_at,
        )
        recorded.append(link)

        current_severity = row["severity"]
        uplifted = _SEVERITY_UPLIFT.get(current_severity, current_severity)
        already_uplifted = row["severity_uplifted_from"] is not None
        payload = dict(row["payload"] or {})

        correlation_block = dict(payload.get("correlation") or {})
        correlation_block["window_seconds"] = window
        related = list(correlation_block.get("related") or [])
        related.append(
            {
                "related_kind": "dlp_event",
                "related_id": str(dlp_event_id),
                "correlation_type": "sha256_match",
            }
        )
        correlation_block["related"] = related

        new_controls = list(dict.fromkeys(
            list(row["evidence_controls"] or []) + _correlation_controls()
        ))

        if uplifted != current_severity and not already_uplifted:
            correlation_block["uplifted_from"] = current_severity
            payload["correlation"] = correlation_block
            cur.execute(
                """
                update security_alerts
                   set severity = %s,
                       severity_uplifted_from = %s,
                       payload = %s::jsonb,
                       evidence_controls = %s::jsonb
                 where id = %s
                """,
                (
                    uplifted,
                    current_severity,
                    json.dumps(payload),
                    json.dumps(new_controls),
                    row["id"],
                ),
            )
            _emit_uplift_event(
                customer_id=customer_id,
                alert_id=row["id"],
                agent_id=agent_id or "",
                file_path="",
                before=current_severity,
                after=uplifted,
                direction="dlp_to_edr",
                related=[link],
                created_at=observed_at,
            )
        else:
            payload["correlation"] = correlation_block
            cur.execute(
                """
                update security_alerts
                   set payload = %s::jsonb,
                       evidence_controls = %s::jsonb
                 where id = %s
                """,
                (
                    json.dumps(payload),
                    json.dumps(new_controls),
                    row["id"],
                ),
            )

    return recorded


def list_correlations_for_alert(alert_id: uuid.UUID) -> list[dict[str, Any]]:
    from app.db import connection

    with connection() as conn, conn.cursor() as cur:
        cur.execute(
            """
            select id, related_kind, related_id, correlation_type, score,
                   window_seconds, evidence, created_at
            from correlation_links
            where security_alert_id = %s
            order by created_at desc
            """,
            (alert_id,),
        )
        return [
            {
                "id": str(row["id"]),
                "related_kind": row["related_kind"],
                "related_id": row["related_id"],
                "correlation_type": row["correlation_type"],
                "score": float(row["score"]),
                "window_seconds": row["window_seconds"],
                "evidence": dict(row["evidence"] or {}),
                "created_at": row["created_at"].isoformat()
                if isinstance(row["created_at"], datetime)
                else str(row["created_at"]),
            }
            for row in cur.fetchall()
        ]


def list_correlations_for_dlp_event(dlp_event_id: uuid.UUID) -> list[dict[str, Any]]:
    """Return correlation_links rows where this dlp_event is the related signal."""
    from app.db import connection

    with connection() as conn, conn.cursor() as cur:
        cur.execute(
            """
            select cl.id, cl.security_alert_id, cl.correlation_type, cl.score,
                   cl.window_seconds, cl.evidence, cl.created_at,
                   sa.severity, sa.category, sa.status as alert_status
            from correlation_links cl
            join security_alerts sa on sa.id = cl.security_alert_id
            where cl.related_kind = 'dlp_event'
              and cl.related_id = %s
            order by cl.created_at desc
            """,
            (str(dlp_event_id),),
        )
        return [
            {
                "id": str(row["id"]),
                "security_alert_id": str(row["security_alert_id"]),
                "correlation_type": row["correlation_type"],
                "score": float(row["score"]),
                "window_seconds": row["window_seconds"],
                "evidence": dict(row["evidence"] or {}),
                "alert_severity": row["severity"],
                "alert_category": row["category"],
                "alert_status": row["alert_status"],
                "created_at": row["created_at"].isoformat()
                if isinstance(row["created_at"], datetime)
                else str(row["created_at"]),
            }
            for row in cur.fetchall()
        ]


def _record_link(
    cur: Any,
    *,
    customer_id: UUID,
    security_alert_id: uuid.UUID,
    related_kind: str,
    related_id: str,
    correlation_type: str,
    window_seconds: int,
    evidence: dict[str, Any],
    created_at: datetime,
) -> dict[str, Any]:
    link_id = uuid.uuid4()
    cur.execute(
        """
        insert into correlation_links (
            id, customer_id, security_alert_id, related_kind, related_id,
            correlation_type, score, window_seconds, evidence, created_at
        ) values (%s, %s, %s, %s, %s, %s, %s, %s, %s::jsonb, %s)
        """,
        (
            link_id,
            customer_id,
            security_alert_id,
            related_kind,
            related_id,
            correlation_type,
            1.0,
            window_seconds,
            json.dumps(evidence),
            created_at,
        ),
    )
    return {
        "id": str(link_id),
        "related_kind": related_kind,
        "related_id": related_id,
        "correlation_type": correlation_type,
        "evidence": evidence,
    }


def _correlation_controls() -> list[str]:
    # Local import keeps app.services.compliance free to depend on this
    # module in the future without a cycle.
    from app.services.compliance import controls_for_event

    return controls_for_event("correlation.severity_uplift")


def _emit_uplift_event(
    *,
    customer_id: UUID,
    alert_id: uuid.UUID,
    agent_id: str,
    file_path: str,
    before: str,
    after: str,
    direction: str,
    related: Iterable[dict[str, Any]],
    created_at: datetime,
) -> None:
    from app.services.compliance import _emit_compliance_event

    try:
        _emit_compliance_event(
            customer_id=customer_id,
            action="correlation.severity_uplift",
            resource=f"security_alert:{alert_id}",
            actor=f"correlation-engine:{agent_id}",
            payload={
                "alert_id": str(alert_id),
                "agent_id": agent_id,
                "file_path": file_path,
                "before_severity": before,
                "after_severity": after,
                "direction": direction,
                "related": [
                    {
                        "kind": link.get("related_kind"),
                        "id": link.get("related_id"),
                        "type": link.get("correlation_type"),
                    }
                    for link in related
                ],
                "occurred_at": created_at.isoformat(),
            },
            evidence_controls=_correlation_controls(),
        )
    except Exception:
        # Compliance emit is best-effort; never break the heartbeat path.
        pass

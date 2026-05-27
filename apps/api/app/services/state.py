import hashlib
import hmac
import json
import os
from datetime import UTC, datetime, timedelta

from app.db import connection
from app.schemas import AgentHeartbeat, Alert, DlpScanRequest, DlpScanResponse, Endpoint, Policy
from app.services.compliance import controls_for_event


OFFLINE_AFTER = timedelta(minutes=15)


class PolicyNotConfigured(RuntimeError):
    """Raised when no active policy document exists in the database."""


def active_policy() -> Policy:
    """Return the live :class:`Policy` summary.

    The policy is always derived from the currently active
    :class:`~app.schemas.PolicyDocument` in Postgres. If no document has
    been promoted yet, :class:`PolicyNotConfigured` is raised so the caller
    can surface a configuration error instead of silently substituting a
    default. There are no env-based fallbacks and no synthetic data.
    """

    # Local import to avoid a circular import with app.services.policy.
    from app.services.policy import active_policy_document, policy_summary_from

    document = active_policy_document()
    if document is None:
        raise PolicyNotConfigured(
            "No active policy document has been promoted. "
            "POST a draft to /policies/document before scanning or fetching the active policy."
        )
    return policy_summary_from(document)


def verify_heartbeat(heartbeat: AgentHeartbeat) -> None:
    # Enrolled agents always use the per-agent secret + nonce path. Local
    # import to avoid a circular import with app.services.enrollment.
    from app.services.enrollment import HeartbeatAuthError, verify_enrolled_heartbeat

    try:
        if verify_enrolled_heartbeat(heartbeat):
            return
    except HeartbeatAuthError as exc:
        raise ValueError(str(exc)) from exc

    # Legacy shared-secret path for un-enrolled (dev / pre-enrollment) agents.
    secret = os.getenv("AETHERIX_AGENT_SHARED_SECRET")
    if not secret:
        return

    if not heartbeat.signature:
        raise ValueError("Heartbeat signature is required")

    expected = _heartbeat_signature(heartbeat, secret)
    if not hmac.compare_digest(expected, heartbeat.signature):
        raise ValueError("Heartbeat signature is invalid")


def upsert_heartbeat(heartbeat: AgentHeartbeat) -> Endpoint:
    verify_heartbeat(heartbeat)
    payload = heartbeat.model_dump(mode="json")
    from app.services.customers import agent_tenant_context

    tenant = agent_tenant_context(heartbeat.agent_id)

    with connection() as conn, conn.cursor() as cur:
        cur.execute(
            """
            insert into heartbeats(agent_id, payload, updated_at, partner_id, customer_id, group_id)
            values (%s, %s::jsonb, %s, %s, %s, %s)
            on conflict(agent_id) do update
                set payload = excluded.payload,
                    updated_at = excluded.updated_at,
                    partner_id = excluded.partner_id,
                    customer_id = excluded.customer_id,
                    group_id = excluded.group_id
            """,
            (
                heartbeat.agent_id,
                json.dumps(payload, default=str),
                datetime.now(UTC),
                tenant["partner_id"],
                tenant["customer_id"],
                tenant["group_id"],
            ),
        )

    # Compliance Evidence mapping for new FIM events
    if heartbeat.fim_events and tenant["customer_id"]:
        from app.services.compliance import _emit_compliance_event, controls_for_event
        controls = controls_for_event("agent.fim_event")
        for event in heartbeat.fim_events:
            _emit_compliance_event(
                customer_id=tenant["customer_id"],
                action="agent.fim_event",
                resource=f"file:{event.file_path}",
                actor=f"agent:{heartbeat.agent_id}",
                payload=event.model_dump(mode="json"),
                evidence_controls=controls,
            )

    # Compliance Evidence mapping for new EDR events
    if heartbeat.edr_events and tenant["customer_id"]:
        import uuid
        from app.services.compliance import _emit_compliance_event, controls_for_event
        from app.services.ai_settings import summarize_alert
        from app.services import policy_v2 as policy_v2_service

        controls = controls_for_event("agent.edr_event")

        # Look up the effective `edr` policy module for this customer
        # exactly once per heartbeat. The module may contain a
        # ``responses`` map keyed by event kind that overrides the
        # hardcoded recommended_action below, and an ``enabled`` flag
        # that, if explicitly False, downgrades responses to monitor.
        try:
            effective_modules = policy_v2_service.system_effective_modules_for_customer(
                tenant["customer_id"],
                endpoint_id=heartbeat.agent_id,
            )
        except Exception:
            effective_modules = {}
        edr_module = dict(effective_modules.get("edr") or {})
        edr_enabled = bool(edr_module.get("enabled", True))
        edr_responses = dict(edr_module.get("responses") or {})

        for event in heartbeat.edr_events:
            # Emit compliance event
            _emit_compliance_event(
                customer_id=tenant["customer_id"],
                action="agent.edr_event",
                resource=f"process:{event.process_path or event.file_path or 'unknown'}",
                actor=f"agent:{heartbeat.agent_id}",
                payload=event.model_dump(mode="json"),
                evidence_controls=controls,
            )

            # Map category, recommended_action, and severity
            kind = event.kind
            category = "anomaly"
            recommended_action = "review"
            severity = "high"
            if kind == "yara_match":
                category = "malware"
                recommended_action = "quarantine"
                severity = "high"
            elif kind == "ioc_match":
                category = "malware"
                recommended_action = "quarantine"
                severity = "high"
            elif kind == "ransomware_canary":
                category = "behavior"
                recommended_action = "rollback"
                severity = "critical"
            elif kind == "suspicious_process_chain":
                category = "behavior"
                recommended_action = "kill_process"
                severity = "high"
            elif kind == "response_action":
                category = "response"
                recommended_action = event.action
                severity = "medium"

            # Policy override: if the effective `edr` module declares
            # a response action for this event kind, it wins. If the
            # module is explicitly disabled, downgrade to monitor so
            # operators see telemetry without staged enforcement.
            policy_action_override: str | None = None
            if not edr_enabled:
                policy_action_override = "monitor"
            else:
                value = edr_responses.get(kind)
                if isinstance(value, str) and value:
                    policy_action_override = value
            if policy_action_override:
                recommended_action = policy_action_override

            # Parse collected_at timestamp safely
            try:
                created_at = datetime.fromisoformat(event.collected_at)
            except Exception:
                created_at = datetime.now(UTC)

            alert_id = uuid.uuid4()
            payload_dict = event.model_dump(mode="json")
            response_status = (payload_dict.get("response") or {}).get("status")
            if response_status == "executed":
                payload_dict["action_state"] = "executed"
            elif response_status == "failed":
                payload_dict["action_state"] = "attempt_failed"
            elif event.action in {"monitor", "review"}:
                payload_dict["action_state"] = "staged"
            else:
                payload_dict["action_state"] = "attempted"

            # Try generating AI summary
            try:
                ai_summary = summarize_alert(
                    tenant["customer_id"],
                    {
                        "category": category,
                        "severity": severity,
                        "confidence": 95,
                        "recommended_action": recommended_action,
                        "payload": payload_dict,
                    },
                )
            except Exception:
                ai_summary = None

            # Insert alert into security_alerts
            with connection() as conn, conn.cursor() as cur:
                cur.execute(
                    """
                    insert into security_alerts (
                        id, customer_id, agent_id, category, severity, confidence, recommended_action, ai_summary, payload, status, created_at, evidence_controls
                    ) values (%s, %s, %s, %s, %s, %s, %s, %s, %s::jsonb, %s, %s, %s::jsonb)
                    """,
                    (
                        alert_id,
                        tenant["customer_id"],
                        heartbeat.agent_id,
                        category,
                        severity,
                        95,
                        recommended_action,
                        ai_summary,
                        json.dumps(payload_dict),
                        "new",
                        created_at,
                        json.dumps(controls),
                    ),
                )

    # Compliance Evidence mapping for CIS Benchmarking
    if heartbeat.cis_results and tenant["customer_id"]:
        from app.services.compliance import _emit_compliance_event, controls_for_event
        controls = controls_for_event("agent.cis_check")
        for result in heartbeat.cis_results:
            if result.status == "fail":
                _emit_compliance_event(
                    customer_id=tenant["customer_id"],
                    action="agent.cis_check",
                    resource=f"cis_rule:{result.rule_id}",
                    actor=f"agent:{heartbeat.agent_id}",
                    payload=result.model_dump(mode="json"),
                    evidence_controls=controls,
                )

    return _endpoint_from_heartbeat(heartbeat, _open_alert_count(heartbeat.agent_id))


def list_endpoints() -> list[Endpoint]:
    with connection() as conn, conn.cursor() as cur:
        cur.execute("select payload from heartbeats order by updated_at desc")
        rows = cur.fetchall()

    return [
        _endpoint_from_heartbeat(
            AgentHeartbeat.model_validate(row["payload"]),
            _open_alert_count(row["payload"]["agent_id"]),
        )
        for row in rows
    ]


def create_dlp_alert(request: DlpScanRequest, response: DlpScanResponse, policy: Policy) -> Alert | None:
    if not response.findings:
        return None

    entity_types = sorted({finding.entity_type for finding in response.findings})
    severity = _alert_severity(response, entity_types)
    created_at = datetime.now(UTC)
    source = request.source or "manual DLP scan"
    alert = Alert(
        id=_alert_id(created_at, request.endpoint_id, source, entity_types),
        title=f"DLP scan detected {', '.join(entity_types)}",
        severity=severity,
        endpoint_id=request.endpoint_id,
        recommended_action=_recommended_dlp_action(policy, response),
        created_at=created_at,
        source=source,
        entity_types=entity_types,
    )

    with connection() as conn, conn.cursor() as cur:
        cur.execute(
            """
            insert into alerts(id, payload, status, created_at, customer_id, evidence_controls)
            values (%s, %s::jsonb, %s, %s, %s, %s::jsonb)
            on conflict(id) do nothing
            """,
            (
                alert.id,
                json.dumps(alert.model_dump(mode="json"), default=str),
                alert.status,
                alert.created_at,
                request.customer_id,
                json.dumps(controls_for_event("dlp.scan")),
            ),
        )

    return alert


def list_alerts() -> list[Alert]:
    """Return every alert persisted in the database, newest first.

    Alerts are only created by explicit DLP scans (see :func:`create_dlp_alert`).
    Synthetic alerts derived from heartbeat signals are intentionally NOT
    returned here — the database is the single source of truth.
    """

    with connection() as conn, conn.cursor() as cur:
        cur.execute("select payload from alerts order by created_at desc")
        rows = cur.fetchall()

    return [Alert.model_validate(row["payload"]) for row in rows]


def acknowledge_alert(alert_id: str) -> Alert | None:
    with connection() as conn, conn.cursor() as cur:
        cur.execute("select payload from alerts where id = %s", (alert_id,))
        row = cur.fetchone()
        if row is None:
            return None

        alert = Alert.model_validate(row["payload"]).model_copy(update={"status": "acknowledged"})
        cur.execute(
            "update alerts set payload = %s::jsonb, status = %s where id = %s",
            (json.dumps(alert.model_dump(mode="json"), default=str), alert.status, alert.id),
        )
        cur.execute(
            """
            insert into acknowledged_alerts(id, acknowledged_at)
            values (%s, %s)
            on conflict(id) do update set acknowledged_at = excluded.acknowledged_at
            """,
            (alert.id, datetime.now(UTC)),
        )
        return alert


def _endpoint_from_heartbeat(heartbeat: AgentHeartbeat, open_alert_count: int) -> Endpoint:
    now = datetime.now(UTC)
    last_seen = heartbeat.collected_at if heartbeat.collected_at.tzinfo else heartbeat.collected_at.replace(tzinfo=UTC)
    is_offline = now - last_seen > OFFLINE_AFTER
    risk_score = _risk_score(heartbeat, open_alert_count, is_offline)
    status = "offline" if is_offline else "attention" if risk_score >= 50 else "healthy"

    return Endpoint(
        id=heartbeat.agent_id,
        hostname=heartbeat.hostname,
        os=heartbeat.os,
        status=status,
        risk_score=risk_score,
        last_seen=last_seen,
        policy_version=heartbeat.policy_version,
        agent_version=heartbeat.agent_version,
    )


def _risk_score(heartbeat: AgentHeartbeat, open_alert_count: int, is_offline: bool) -> int:
    signals = heartbeat.signals
    risk = 0
    risk += min(30, signals.blocked_events * 8)
    risk += min(30, signals.dlp_events * 6)
    risk += min(36, signals.pending_updates * 12)
    risk += min(40, open_alert_count * 10)

    if signals.cpu_percent is not None and signals.cpu_percent >= 90:
        risk += 8
    if signals.memory_percent is not None and signals.memory_percent >= 90:
        risk += 8
    if is_offline:
        risk += 50

    return min(100, risk)


def _open_alert_count(agent_id: str) -> int:
    with connection() as conn, conn.cursor() as cur:
        cur.execute(
            "select count(*) as n from alerts where status = 'open' and (payload->>'endpoint_id') = %s",
            (agent_id,),
        )
        row = cur.fetchone()
    return int(row["n"]) if row else 0


def _recommended_dlp_action(policy: Policy, response: DlpScanResponse | None = None) -> str:
    genai_sink = response is not None and "genai_sink_detected" in response.context_signals
    if policy.mode == "block" or (response is not None and response.action == "block"):
        return (
            "Block transfer to the generative AI destination and notify the endpoint user"
            if genai_sink
            else "Block transfer and notify the endpoint user"
        )
    if policy.mode == "review" or (response is not None and response.action == "review"):
        return (
            "Hold transfer for analyst approval; generative AI destination detected"
            if genai_sink
            else "Hold transfer for analyst approval"
        )
    return "Review finding and tune policy if this is expected business data"


def _alert_severity(response: DlpScanResponse, entity_types: list[str]) -> str:
    if response.risk_band in {"critical", "high"} or response.action == "block":
        return "high"
    if response.risk_band == "medium" or response.action == "review":
        return "medium"
    if "CREDIT_CARD" in entity_types:
        return "high"
    return "low"


def _alert_id(created_at: datetime, endpoint_id: str | None, source: str, entity_types: list[str]) -> str:
    digest = hashlib.sha256(f"{created_at.isoformat()}:{endpoint_id}:{source}:{','.join(entity_types)}".encode()).hexdigest()
    return f"dlp-{digest[:16]}"


def _heartbeat_signature(heartbeat: AgentHeartbeat, secret: str) -> str:
    message = f"{heartbeat.agent_id}:{heartbeat.hostname}:{heartbeat.collected_at.isoformat()}:{heartbeat.policy_version}"
    return hashlib.sha256(f"{message}:{secret}".encode()).hexdigest()

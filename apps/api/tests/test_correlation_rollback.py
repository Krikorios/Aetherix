"""Tests for rollback-action correlation.

Covers the evidence-chain path:
  ransomware_canary detection → severity uplift → rollback response_action
  → correlate_new_rollback_event → correlation_links (rollback_action type)

Happy paths:
  * Rollback response_action with rollback_file_paths → links to recent FIM events
  * Rollback response_action → links to recent DLP events on same endpoint
  * API endpoint returns rollback_action links with correct score/subtype

Negative path:
  * FIM events outside the correlation window are NOT linked
"""

from __future__ import annotations

import copy
import hashlib
import hmac
import json
import uuid
from datetime import UTC, datetime, timedelta
from pathlib import Path

from fastapi.testclient import TestClient

from app.db import connection
from app.main import app
from app.schemas import EdrEvent, FimEvent


def _load_vss_pipeline_fixture() -> dict[str, object]:
    fixture_path = Path(__file__).resolve().parents[0] / "fixtures/vss_readiness_pending_inbox_export.json"
    return json.loads(fixture_path.read_text())


# ---------------------------------------------------------------------------
# Helpers shared across all rollback tests
# ---------------------------------------------------------------------------


def _sign(
    secret: str,
    agent_id: str,
    hostname: str,
    os_name: str,
    collected_at: str,
    policy_version: str,
    nonce: int,
) -> str:
    msg = f"{agent_id}|{hostname}|{os_name}|{collected_at}|{policy_version}|{nonce}"
    return hmac.new(secret.encode(), msg.encode(), hashlib.sha256).hexdigest()


def _post_heartbeat(
    *,
    agent_id: str,
    nonce: int,
    collected_at: datetime,
    fim_events: list[FimEvent] | None = None,
    edr_events: list[EdrEvent] | None = None,
    rollback_readiness: dict[str, object] | None = None,
    secret: str = "e2e-endpoint-secret",
) -> dict:
    collected_at_str = collected_at.isoformat()
    payload = {
        "agent_id": agent_id,
        "hostname": "rb-test-host",
        "os": "linux",
        "policy_version": "policy-v1",
        "nonce": nonce,
        "collected_at": collected_at_str,
        "cpu_percent": 10.0,
        "memory_percent": 15.0,
        "fim_events": [e.model_dump(mode="json") for e in (fim_events or [])],
        "edr_events": [e.model_dump(mode="json") for e in (edr_events or [])],
    }
    if rollback_readiness is not None:
        payload["rollback_readiness"] = rollback_readiness
    payload["signature"] = _sign(
        secret, agent_id, "rb-test-host", "linux", collected_at_str, "policy-v1", nonce
    )
    client = TestClient(app)
    resp = client.post("/agent/heartbeat", json=payload)
    assert resp.status_code == 200, resp.text
    return resp.json()


def _fetch_alert(agent_id: str, category: str = "behavior") -> dict:
    with connection() as conn, conn.cursor() as cur:
        cur.execute(
            "select * from security_alerts where agent_id = %s and category = %s",
            (agent_id, category),
        )
        rows = cur.fetchall()
    assert len(rows) == 1, f"expected exactly 1 {category!r} alert, got {len(rows)}"
    return rows[0]


def _fetch_links(alert_id) -> list[dict]:
    with connection() as conn, conn.cursor() as cur:
        cur.execute(
            "select * from correlation_links where security_alert_id = %s",
            (alert_id,),
        )
        return list(cur.fetchall())


def _fetch_rollback_evidence_events() -> list[dict]:
    with connection() as conn, conn.cursor() as cur:
        cur.execute(
            "select * from evidence_events where action = 'correlation.rollback_recovery'",
        )
        return list(cur.fetchall())


def _seed_simulation(
    *,
    endpoint_id: str,
    simulation_id: str,
    candidate_set_hash: str,
    customer_id=None,
    valid_hours: int = 2,
) -> None:
    """Insert a rollback_simulations row so rollback-intent guard passes in tests."""
    valid_until = datetime.now(UTC) + timedelta(hours=valid_hours)
    with connection() as conn, conn.cursor() as cur:
        cur.execute(
            """
            insert into rollback_simulations (
                simulation_id, endpoint_id, candidate_set_hash,
                candidate_count, restorable_count, valid_until, customer_id
            ) values (%s, %s, %s, 3, 2, %s, %s)
            on conflict (simulation_id) do nothing
            """,
            (simulation_id, endpoint_id, candidate_set_hash, valid_until, customer_id),
        )

def _insert_dlp_event(
    *,
    customer_id,
    endpoint_id: str,
    sha256_hash: str,
    observed_at: datetime,
) -> uuid.UUID:
    """Insert a synthetic DLP event directly for rollback correlation tests."""
    dlp_id = uuid.uuid4()
    with connection() as conn, conn.cursor() as cur:
        cur.execute(
            """
            insert into dlp_events (
                id, customer_id, endpoint_id, source, action,
                entity_types, risk_band, sha256_hash,
                request_preview_hash, observed_at, created_at
            ) values (
                %s, %s, %s, %s, %s,
                %s::jsonb, %s, %s,
                %s, %s, %s
            )
            """,
            (
                dlp_id,
                customer_id,
                endpoint_id,
                "file_upload",
                "block",
                json.dumps(["pii"]),
                "high",
                sha256_hash,
                "preview-hash-placeholder",
                observed_at,
                observed_at,
            ),
        )
        conn.commit()
    return dlp_id


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


def test_rollback_correlates_with_prior_fim(
    tenant_hierarchy_factory, monkeypatch
) -> None:
    """A rollback response_action links to a recent FIM event on the same path."""
    monkeypatch.setenv("AETHERIX_CORRELATION_WINDOW_SECONDS", "300")
    agent_id = "agent-rollback-fim-001"
    tenant_hierarchy_factory(endpoint_id=agent_id)
    rollback_path = "/home/user/documents/report.docx"
    shared_hash = "a" * 64

    now = datetime.now(UTC).replace(microsecond=0)

    # 1. FIM event sees the file being modified (simulated ransomware encrypt).
    fim_time = now - timedelta(seconds=60)
    fim_event = FimEvent(
        event_type="modified",
        file_path=rollback_path,
        sha256_hash=shared_hash,
        timestamp=fim_time.isoformat(),
    )
    _post_heartbeat(agent_id=agent_id, nonce=1, collected_at=fim_time, fim_events=[fim_event])

    # 2. EDR ransomware_canary detection creates a behavior alert.
    canary_time = now - timedelta(seconds=45)
    canary_event = EdrEvent(
        kind="ransomware_canary",
        rule_id="RansomwareCanary",
        action="monitor",
        file_path=rollback_path,
        file_sha256=shared_hash,
        matched_indicator="CANARY",
        policy_version="policy-v1",
        collected_at=canary_time.isoformat(),
    )
    _post_heartbeat(agent_id=agent_id, nonce=2, collected_at=canary_time, edr_events=[canary_event])

    # Confirm the behavior alert was created.
    canary_alert = _fetch_alert(agent_id, category="behavior")

    # 3. Agent performs rollback and reports a response_action.
    rollback_time = now
    rollback_event = EdrEvent(
        kind="response_action",
        rule_id="RansomwareCanary",
        action="rollback",
        file_path=rollback_path,
        rollback_file_paths=[rollback_path],
        matched_indicator=str(canary_alert["id"]),
        policy_version="policy-v1",
        collected_at=rollback_time.isoformat(),
    )
    _post_heartbeat(
        agent_id=agent_id, nonce=3, collected_at=rollback_time, edr_events=[rollback_event]
    )

    # The rollback response_action creates a 'response' category alert;
    # correlate_new_rollback_event attaches links to that alert.
    rollback_alert = _fetch_alert(agent_id, category="response")

    # Verify correlation link was created.
    links = _fetch_links(rollback_alert["id"])
    rollback_links = [l for l in links if l["correlation_type"] == "rollback_action"]
    assert len(rollback_links) >= 1, (
        f"expected at least one rollback_action link, got {[l['correlation_type'] for l in links]}"
    )

    rb = rollback_links[0]
    assert rb["related_kind"] == "fim_event"
    assert rb["score"] == 0.95, f"rollback_action score should be 0.95, got {rb['score']}"
    assert rb["evidence"].get("correlation_subtype") == "rollback_action"
    assert rb["evidence"].get("rollback_path") == rollback_path

    # Verify compliance event emitted.
    evidence_events = _fetch_rollback_evidence_events()
    assert len(evidence_events) >= 1


def test_rollback_correlates_with_prior_dlp(
    tenant_hierarchy_factory, monkeypatch
) -> None:
    """A rollback response_action links to a recent DLP event on the same endpoint."""
    monkeypatch.setenv("AETHERIX_CORRELATION_WINDOW_SECONDS", "300")
    agent_id = "agent-rollback-dlp-001"
    tenant = tenant_hierarchy_factory(endpoint_id=agent_id)
    customer_id = tenant["customer_id"]
    rollback_path = "/home/user/sensitive/payroll.xlsx"
    shared_hash = "b" * 64

    now = datetime.now(UTC).replace(microsecond=0)

    # 1. Insert a DLP event directly.
    dlp_time = now - timedelta(seconds=90)
    dlp_id = _insert_dlp_event(
        customer_id=customer_id,
        endpoint_id=agent_id,
        sha256_hash=shared_hash,
        observed_at=dlp_time,
    )

    # 2. EDR ransomware_canary detection.
    canary_time = now - timedelta(seconds=50)
    canary_event = EdrEvent(
        kind="ransomware_canary",
        rule_id="RansomwareCanary",
        action="monitor",
        file_path=rollback_path,
        file_sha256=shared_hash,
        matched_indicator="CANARY2",
        policy_version="policy-v1",
        collected_at=canary_time.isoformat(),
    )
    _post_heartbeat(agent_id=agent_id, nonce=1, collected_at=canary_time, edr_events=[canary_event])

    canary_alert = _fetch_alert(agent_id, category="behavior")

    # 3. Rollback response_action.
    rollback_time = now
    rollback_event = EdrEvent(
        kind="response_action",
        rule_id="RansomwareCanary",
        action="rollback",
        file_path=rollback_path,
        rollback_file_paths=[rollback_path],
        matched_indicator=str(canary_alert["id"]),
        policy_version="policy-v1",
        collected_at=rollback_time.isoformat(),
    )
    _post_heartbeat(
        agent_id=agent_id, nonce=2, collected_at=rollback_time, edr_events=[rollback_event]
    )

    rollback_alert = _fetch_alert(agent_id, category="response")

    links = _fetch_links(rollback_alert["id"])
    rollback_links = [l for l in links if l["correlation_type"] == "rollback_action"]
    dlp_links = [l for l in rollback_links if l["related_kind"] == "dlp_event"]
    assert len(dlp_links) >= 1, (
        f"expected at least one rollback_action → dlp_event link, "
        f"all rollback_links: {rollback_links}"
    )

    dlp_link = dlp_links[0]
    assert dlp_link["score"] == 0.95
    assert dlp_link["evidence"].get("correlation_subtype") == "rollback_action"
    assert str(dlp_link["related_id"]) == str(dlp_id)


def test_rollback_no_match_outside_window(
    tenant_hierarchy_factory, monkeypatch
) -> None:
    """FIM events older than the correlation window are NOT linked to a rollback."""
    monkeypatch.setenv("AETHERIX_CORRELATION_WINDOW_SECONDS", "60")
    agent_id = "agent-rollback-window-001"
    tenant_hierarchy_factory(endpoint_id=agent_id)
    rollback_path = "/tmp/old-file.docx"

    now = datetime.now(UTC).replace(microsecond=0)

    # 1. FIM event — well outside the 60-second window.
    fim_time = now - timedelta(seconds=600)
    fim_event = FimEvent(
        event_type="modified",
        file_path=rollback_path,
        sha256_hash="c" * 64,
        timestamp=fim_time.isoformat(),
    )
    _post_heartbeat(agent_id=agent_id, nonce=1, collected_at=fim_time, fim_events=[fim_event])

    # 2. Ransomware alert (need to post it within window so the alert exists).
    canary_time = now - timedelta(seconds=10)
    canary_event = EdrEvent(
        kind="ransomware_canary",
        rule_id="LateCanary",
        action="monitor",
        file_path=rollback_path,
        file_sha256="c" * 64,
        matched_indicator="LATE_CANARY",
        policy_version="policy-v1",
        collected_at=canary_time.isoformat(),
    )
    _post_heartbeat(agent_id=agent_id, nonce=2, collected_at=canary_time, edr_events=[canary_event])

    canary_alert = _fetch_alert(agent_id, category="behavior")

    # 3. Rollback response_action now.
    rollback_event = EdrEvent(
        kind="response_action",
        rule_id="LateCanary",
        action="rollback",
        file_path=rollback_path,
        rollback_file_paths=[rollback_path],
        matched_indicator=str(canary_alert["id"]),
        policy_version="policy-v1",
        collected_at=now.isoformat(),
    )
    _post_heartbeat(agent_id=agent_id, nonce=3, collected_at=now, edr_events=[rollback_event])

    rollback_alert = _fetch_alert(agent_id, category="response")
    links = _fetch_links(rollback_alert["id"])
    rollback_links = [l for l in links if l["correlation_type"] == "rollback_action"]
    # The FIM event is outside the window so no rollback_action link to it.
    fim_rollback_links = [l for l in rollback_links if l["related_kind"] == "fim_event"]
    assert fim_rollback_links == [], (
        f"expected no rollback_action→fim_event link (FIM outside window), got {fim_rollback_links}"
    )


def test_rollback_correlation_endpoint_returns_links(
    tenant_hierarchy_factory, auth_headers, monkeypatch
) -> None:
    """GET /security-alerts/{id}/correlations returns rollback_action links with score."""
    monkeypatch.setenv("AETHERIX_CORRELATION_WINDOW_SECONDS", "300")
    agent_id = "agent-rollback-api-001"
    tenant = tenant_hierarchy_factory(endpoint_id=agent_id)
    admin_id = tenant["company_admin_id"]
    rollback_path = "/var/data/confidential.pdf"
    shared_hash = "d" * 64

    now = datetime.now(UTC).replace(microsecond=0)

    # 1. FIM event.
    fim_time = now - timedelta(seconds=60)
    fim_event = FimEvent(
        event_type="added",
        file_path=rollback_path,
        sha256_hash=shared_hash,
        timestamp=fim_time.isoformat(),
    )
    _post_heartbeat(agent_id=agent_id, nonce=1, collected_at=fim_time, fim_events=[fim_event])

    # 2. Ransomware canary alert.
    canary_time = now - timedelta(seconds=30)
    canary_event = EdrEvent(
        kind="ransomware_canary",
        rule_id="APICanary",
        action="monitor",
        file_path=rollback_path,
        file_sha256=shared_hash,
        matched_indicator="API_CANARY",
        policy_version="policy-v1",
        collected_at=canary_time.isoformat(),
    )
    _post_heartbeat(agent_id=agent_id, nonce=2, collected_at=canary_time, edr_events=[canary_event])

    canary_alert = _fetch_alert(agent_id, category="behavior")

    # 3. Rollback.
    rollback_event = EdrEvent(
        kind="response_action",
        rule_id="APICanary",
        action="rollback",
        file_path=rollback_path,
        rollback_file_paths=[rollback_path],
        matched_indicator=str(canary_alert["id"]),
        policy_version="policy-v1",
        collected_at=now.isoformat(),
    )
    _post_heartbeat(agent_id=agent_id, nonce=3, collected_at=now, edr_events=[rollback_event])

    # Use the response (rollback) alert id for the correlations endpoint.
    rollback_alert = _fetch_alert(agent_id, category="response")
    rollback_alert_id = rollback_alert["id"]

    # 4. Query the correlations endpoint.
    client = TestClient(app)
    headers = auth_headers(admin_id)
    resp = client.get(f"/security-alerts/{rollback_alert_id}/correlations", headers=headers)
    assert resp.status_code == 200, resp.text

    body = resp.json()
    assert body["alert_id"] == str(rollback_alert_id)
    assert "total_correlations" in body, "response should include total_correlations"

    rollback_links = [
        l for l in body["correlations"] if l["correlation_type"] == "rollback_action"
    ]
    assert len(rollback_links) >= 1, (
        f"expected at least one rollback_action in correlations, "
        f"got types: {[l['correlation_type'] for l in body['correlations']]}"
    )

    rb = rollback_links[0]
    assert rb["score"] == 0.95, f"expected score 0.95 for rollback_action, got {rb['score']}"
    assert rb["related_kind"] == "fim_event"
    assert rb["evidence"].get("correlation_subtype") == "rollback_action"


# ---------------------------------------------------------------------------
# New tests: severity uplift, rollback intent routes, E2E evidence
# ---------------------------------------------------------------------------


def _fetch_alert_by_id(alert_id) -> dict:
    with connection() as conn, conn.cursor() as cur:
        cur.execute("select * from security_alerts where id = %s", (alert_id,))
        row = cur.fetchone()
    assert row is not None, f"no security_alert with id={alert_id}"
    return row


def _fetch_evidence_events_by_action(action: str) -> list[dict]:
    with connection() as conn, conn.cursor() as cur:
        cur.execute(
            "select * from evidence_events where action = %s",
            (action,),
        )
        return list(cur.fetchall())


def test_rollback_uplifts_original_behavior_alert(
    tenant_hierarchy_factory, monkeypatch
) -> None:
    """correlate_new_rollback_event uplifts the original behavior alert one severity
    rung when matched_indicator points to its id, and records a rollback_action edge
    FROM that alert TO the rollback response alert."""
    monkeypatch.setenv("AETHERIX_CORRELATION_WINDOW_SECONDS", "300")
    agent_id = "agent-rollback-uplift-001"
    tenant_hierarchy_factory(endpoint_id=agent_id)
    rollback_path = "/home/user/critical/financials.xlsx"
    shared_hash = "e" * 64
    now = datetime.now(UTC).replace(microsecond=0)

    # 1. FIM witness event (ensures at least one correlation link exists so the
    #    uplift block inside correlate_new_rollback_event is reached).
    fim_event = FimEvent(
        event_type="modified",
        file_path=rollback_path,
        sha256_hash=shared_hash,
        timestamp=(now - timedelta(seconds=90)).isoformat(),
    )
    _post_heartbeat(
        agent_id=agent_id, nonce=1, collected_at=now - timedelta(seconds=90), fim_events=[fim_event]
    )

    # 2. Ransomware canary → creates the behavior alert we'll reference.
    canary_time = now - timedelta(seconds=40)
    canary_event = EdrEvent(
        kind="ransomware_canary",
        rule_id="RansomwareCanary",
        action="monitor",
        file_path=rollback_path,
        file_sha256=shared_hash,
        matched_indicator="UPLIFT_CANARY",
        policy_version="policy-v1",
        collected_at=canary_time.isoformat(),
    )
    _post_heartbeat(agent_id=agent_id, nonce=2, collected_at=canary_time, edr_events=[canary_event])

    canary_alert = _fetch_alert(agent_id, category="behavior")
    severity_before = canary_alert["severity"]
    _uplift_map = {"low": "medium", "medium": "high", "high": "critical", "critical": "critical"}
    expected_after = _uplift_map[severity_before]

    # 3. Rollback response_action with matched_indicator = original canary alert id.
    rollback_event = EdrEvent(
        kind="response_action",
        rule_id="RansomwareCanary",
        action="rollback",
        file_path=rollback_path,
        rollback_file_paths=[rollback_path],
        matched_indicator=str(canary_alert["id"]),
        policy_version="policy-v1",
        collected_at=now.isoformat(),
    )
    _post_heartbeat(agent_id=agent_id, nonce=3, collected_at=now, edr_events=[rollback_event])

    rollback_alert = _fetch_alert(agent_id, category="response")
    canary_after = _fetch_alert_by_id(canary_alert["id"])

    # Uplift only applies when the original severity has room to go up.
    if severity_before != "critical":
        assert canary_after["severity"] == expected_after, (
            f"expected severity {expected_after!r} after rollback uplift, "
            f"got {canary_after['severity']!r}"
        )
        assert canary_after["severity_uplifted_from"] == severity_before, (
            "severity_uplifted_from should record the pre-uplift severity"
        )

    # rollback_action edge FROM canary alert TO rollback alert.
    canary_links = _fetch_links(canary_alert["id"])
    rb_edges = [l for l in canary_links if l["related_kind"] == "rollback_action"]
    assert len(rb_edges) >= 1, (
        f"expected rollback_action edge from behavior alert, got {canary_links}"
    )
    assert str(rb_edges[0]["related_id"]) == str(rollback_alert["id"])


def test_rollback_intent_request_low_severity_queued_directly(
    tenant_hierarchy_factory, auth_headers
) -> None:
    """A medium-severity rollback intent is queued directly (no approval step)."""
    agent_id = "agent-rb-intent-low-001"
    tenant = tenant_hierarchy_factory(endpoint_id=agent_id)
    admin_id = tenant["company_admin_id"]
    client = TestClient(app)
    headers = auth_headers(admin_id)

    _seed_simulation(
        endpoint_id=agent_id,
        simulation_id="sim-low-001",
        candidate_set_hash="hash-low-001",
        customer_id=tenant["customer_id"],
    )
    valid_until = (datetime.now(UTC) + timedelta(hours=2)).isoformat()
    resp = client.post(
        f"/endpoints/{agent_id}/rollback-intent",
        json={
            "simulation_id": "sim-low-001",
            "candidate_set_hash": "hash-low-001",
            "affected_paths": ["/home/user/file.docx"],
            "recovery_point_id": "rp-low-001",
            "provider": "vss",
            "valid_until": valid_until,
            "severity_hint": "medium",
            "reason": "Test medium rollback",
        },
        headers=headers,
    )
    assert resp.status_code == 202, resp.text

    body = resp.json()
    assert body["status"] == "queued", f"medium severity should be queued, got {body['status']}"
    assert body["action"] == "rollback_intent"
    assert body["approval_required"] is False

    events = _fetch_evidence_events_by_action("endpoint.rollback.requested")
    assert len(events) >= 1, "endpoint.rollback.requested evidence event not written"


def test_rollback_intent_high_severity_awaiting_approval(
    tenant_hierarchy_factory, auth_headers
) -> None:
    """A high-severity rollback intent is placed in awaiting_approval status."""
    agent_id = "agent-rb-intent-high-001"
    tenant = tenant_hierarchy_factory(endpoint_id=agent_id)
    admin_id = tenant["company_admin_id"]
    client = TestClient(app)
    headers = auth_headers(admin_id)

    _seed_simulation(
        endpoint_id=agent_id,
        simulation_id="sim-high-001",
        candidate_set_hash="hash-high-001",
        customer_id=tenant["customer_id"],
    )
    valid_until = (datetime.now(UTC) + timedelta(hours=1)).isoformat()
    resp = client.post(
        f"/endpoints/{agent_id}/rollback-intent",
        json={
            "simulation_id": "sim-high-001",
            "candidate_set_hash": "hash-high-001",
            "affected_paths": ["/etc/passwd"],
            "recovery_point_id": "rp-high-001",
            "provider": "apfs",
            "valid_until": valid_until,
            "severity_hint": "high",
            "reason": "Confirmed ransomware",
        },
        headers=headers,
    )
    assert resp.status_code == 202, resp.text

    body = resp.json()
    assert body["status"] == "awaiting_approval", (
        f"high severity should require approval, got {body['status']}"
    )
    assert body["approval_required"] is True


def test_rollback_intent_approve_dual_auth(
    tenant_hierarchy_factory, auth_headers
) -> None:
    """Dual-operator model: self-approve is rejected (403); second account can approve.
    After approval the intent transitions to queued and endpoint.rollback.approved
    evidence is written."""
    from app.services import tenancy as _tenancy
    from app.schemas import AccountCreate, RoleAssignmentRequest

    agent_id = "agent-rb-intent-dual-001"
    tenant = tenant_hierarchy_factory(endpoint_id=agent_id)
    admin_id = tenant["company_admin_id"]
    customer_id = tenant["customer_id"]
    client = TestClient(app)
    headers_admin = auth_headers(admin_id)

    # Create a second company_admin for dual-operator approval.
    second_admin = _tenancy.create_account(
        AccountCreate(
            email="rb-second-admin@aetherix.test",
            full_name="Second Admin",
            initial_role=RoleAssignmentRequest(
                role_code="company_admin", customer_id=uuid.UUID(customer_id)
            ),
        )
    )
    headers_second = auth_headers(second_admin.id)

    _seed_simulation(
        endpoint_id=agent_id,
        simulation_id="sim-dual-001",
        candidate_set_hash="hash-dual-001",
        customer_id=customer_id,
    )
    valid_until = (datetime.now(UTC) + timedelta(hours=2)).isoformat()
    resp = client.post(
        f"/endpoints/{agent_id}/rollback-intent",
        json={
            "simulation_id": "sim-dual-001",
            "candidate_set_hash": "hash-dual-001",
            "affected_paths": ["/data/sensitive.db"],
            "recovery_point_id": "rp-dual-001",
            "provider": "btrfs",
            "valid_until": valid_until,
            "severity_hint": "high",
            "reason": "Dual-operator rollback",
        },
        headers=headers_admin,
    )
    assert resp.status_code == 202
    action_id = resp.json()["id"]

    # Self-approve must be rejected.
    resp_self = client.post(
        f"/endpoints/{agent_id}/rollback-intent/{action_id}/approve",
        json={"reason": "I approve myself"},
        headers=headers_admin,
    )
    assert resp_self.status_code == 403, (
        f"self-approve should be forbidden (403), got {resp_self.status_code}: {resp_self.text}"
    )

    # Second operator approves successfully.
    resp_approve = client.post(
        f"/endpoints/{agent_id}/rollback-intent/{action_id}/approve",
        json={"reason": "Verified by second operator"},
        headers=headers_second,
    )
    assert resp_approve.status_code == 200, resp_approve.text
    approved = resp_approve.json()
    assert approved["status"] == "queued", (
        f"after second-operator approval, action should be queued, got {approved['status']}"
    )

    approved_events = _fetch_evidence_events_by_action("endpoint.rollback.approved")
    assert len(approved_events) >= 1, "endpoint.rollback.approved evidence event not written"


def test_rollback_intent_deny_flow(
    tenant_hierarchy_factory, auth_headers
) -> None:
    """Denying an awaiting-approval rollback intent sets status=denied and
    writes endpoint.rollback.denied compliance evidence."""
    agent_id = "agent-rb-intent-deny-001"
    tenant = tenant_hierarchy_factory(endpoint_id=agent_id)
    admin_id = tenant["company_admin_id"]
    client = TestClient(app)
    headers = auth_headers(admin_id)

    _seed_simulation(
        endpoint_id=agent_id,
        simulation_id="sim-deny-001",
        candidate_set_hash="hash-deny-001",
        customer_id=tenant["customer_id"],
    )
    valid_until = (datetime.now(UTC) + timedelta(hours=2)).isoformat()
    resp = client.post(
        f"/endpoints/{agent_id}/rollback-intent",
        json={
            "simulation_id": "sim-deny-001",
            "candidate_set_hash": "hash-deny-001",
            "affected_paths": ["/home/user/work.docx"],
            "recovery_point_id": "rp-deny-001",
            "provider": "vss",
            "valid_until": valid_until,
            "severity_hint": "critical",
            "reason": "Requires denial test",
        },
        headers=headers,
    )
    assert resp.status_code == 202
    action_id = resp.json()["id"]

    resp_deny = client.post(
        f"/endpoints/{agent_id}/rollback-intent/{action_id}/deny",
        json={"reason": "Risk assessment rejected this recovery plan"},
        headers=headers,
    )
    assert resp_deny.status_code == 200, resp_deny.text
    denied = resp_deny.json()
    assert denied["status"] == "denied"

    denied_events = _fetch_evidence_events_by_action("endpoint.rollback.denied")
    assert len(denied_events) >= 1, "endpoint.rollback.denied evidence event not written"


def test_rollback_intent_expired_simulation_rejected(
    tenant_hierarchy_factory, auth_headers
) -> None:
    """A rollback intent with valid_until in the past is rejected with HTTP 400."""
    agent_id = "agent-rb-intent-expired-001"
    tenant = tenant_hierarchy_factory(endpoint_id=agent_id)
    admin_id = tenant["company_admin_id"]
    client = TestClient(app)
    headers = auth_headers(admin_id)

    expired_until = (datetime.now(UTC) - timedelta(hours=1)).isoformat()
    _seed_simulation(
        endpoint_id=agent_id,
        simulation_id="sim-exp-001",
        candidate_set_hash="hash-exp-001",
        customer_id=tenant["customer_id"],
        valid_hours=-2,
    )
    resp = client.post(
        f"/endpoints/{agent_id}/rollback-intent",
        json={
            "simulation_id": "sim-exp-001",
            "candidate_set_hash": "hash-exp-001",
            "affected_paths": ["/var/data/report.pdf"],
            "recovery_point_id": "rp-exp-001",
            "provider": "vss",
            "valid_until": expired_until,
            "severity_hint": "medium",
            "reason": "Expired simulation test",
        },
        headers=headers,
    )
    assert resp.status_code == 400, (
        f"expected 400 for expired simulation, got {resp.status_code}: {resp.text}"
    )
    assert "expired" in resp.json().get("detail", "").lower()


def test_rollback_e2e_execution_evidence(
    tenant_hierarchy_factory, monkeypatch
) -> None:
    """Full E2E: agent emits a rollback response_action heartbeat.

    Validates the complete evidence chain:
      1.  A 'response' category security alert is created.
      2.  correlate_new_rollback_event records rollback_action→fim_event links.
      3.  correlation.rollback_recovery compliance evidence is written.
      4.  endpoint.rollback.executed compliance evidence is written by state.py.
      5.  A rollback_action edge FROM the original behavior alert TO the response
          alert confirms the detection→rollback chain is traversable.
    """
    monkeypatch.setenv("AETHERIX_CORRELATION_WINDOW_SECONDS", "300")
    agent_id = "agent-rb-e2e-001"
    tenant_hierarchy_factory(endpoint_id=agent_id)
    rollback_path = "/home/user/e2e/encrypted_file.docx"
    shared_hash = "f" * 64
    now = datetime.now(UTC).replace(microsecond=0)

    # Step 1: FIM event witnesses the affected file being modified.
    fim_time = now - timedelta(seconds=120)
    _post_heartbeat(
        agent_id=agent_id,
        nonce=1,
        collected_at=fim_time,
        rollback_readiness={
            "provider_available": True,
            "provider_name": "vss",
            "provider_version": "1.0.0",
            "os_platform": "linux",
            "functional": True,
            "diagnosis": "probe_ok",
            "recovery_point_count": 3,
            "available_filesystems": ["/", "/home"],
            "service_available": True,
            "sufficient_privilege": True,
            "volume_capabilities": ["snapshots", "copy_on_write"],
            "snapshot_service_info": "vss:healthy",
            "privilege_boundary": "root",
            "recent_fim_paths": [rollback_path],
        },
        fim_events=[
            FimEvent(
                event_type="modified",
                file_path=rollback_path,
                sha256_hash=shared_hash,
                timestamp=fim_time.isoformat(),
            )
        ],
    )

    # Step 2: Ransomware canary detection creates behavior alert.
    canary_time = now - timedelta(seconds=60)
    _post_heartbeat(
        agent_id=agent_id,
        nonce=2,
        collected_at=canary_time,
        edr_events=[
            EdrEvent(
                kind="ransomware_canary",
                rule_id="E2ECanary",
                action="monitor",
                file_path=rollback_path,
                file_sha256=shared_hash,
                matched_indicator="E2E_CANARY",
                policy_version="policy-v1",
                collected_at=canary_time.isoformat(),
            )
        ],
    )
    behavior_alert = _fetch_alert(agent_id, category="behavior")

    # Step 3: Agent executes rollback and reports the result as response_action.
    # response dict carries simulation metadata for richer evidence.
    _post_heartbeat(
        agent_id=agent_id,
        nonce=3,
        collected_at=now,
        edr_events=[
            EdrEvent(
                kind="response_action",
                rule_id="E2ECanary",
                action="rollback",
                file_path=rollback_path,
                rollback_file_paths=[rollback_path],
                matched_indicator=str(behavior_alert["id"]),
                policy_version="policy-v1",
                collected_at=now.isoformat(),
                response={
                    "status": "completed",
                    "simulation_id": "sim-e2e-001",
                    "provider": "vss",
                    "candidate_set_hash": "hash-e2e-001",
                    "recovery_point_id": "rp-e2e-001",
                    "paths": [rollback_path],
                },
            )
        ],
    )

    # Assertion 1: response category alert created.
    rollback_alert = _fetch_alert(agent_id, category="response")
    assert rollback_alert is not None

    # Assertion 2: rollback_action → fim_event correlation links.
    links = _fetch_links(rollback_alert["id"])
    fim_links = [
        l for l in links
        if l["correlation_type"] == "rollback_action" and l["related_kind"] == "fim_event"
    ]
    assert len(fim_links) >= 1, (
        f"expected at least one rollback_action→fim_event link, got {links}"
    )
    assert fim_links[0]["score"] == 0.95

    # Assertion 3: correlation.rollback_recovery compliance evidence.
    recovery_events = _fetch_rollback_evidence_events()
    assert len(recovery_events) >= 1, "correlation.rollback_recovery evidence event not written"

    # Assertion 4: endpoint.rollback.executed compliance evidence (written by state.py).
    executed_events = _fetch_evidence_events_by_action("endpoint.rollback.executed")
    assert len(executed_events) >= 1, (
        "endpoint.rollback.executed evidence event should be written by state.py on completion"
    )
    executed = executed_events[0]
    assert executed["resource"] == f"endpoint:{agent_id}"
    controls = executed.get("evidence_controls") or []
    assert "nist-csf-2.0:RC.RP" in controls, (
        f"endpoint.rollback.executed should map to RC.RP, got {controls}"
    )

    # Assertion 5: rollback_action edge FROM behavior alert TO rollback alert.
    behavior_links = _fetch_links(behavior_alert["id"])
    rb_from_behavior = [l for l in behavior_links if l["related_kind"] == "rollback_action"]
    assert len(rb_from_behavior) >= 1, (
        f"expected rollback_action edge from behavior alert to response alert, "
        f"got behavior_links={behavior_links}"
    )
    assert str(rb_from_behavior[0]["related_id"]) == str(rollback_alert["id"])


def test_agent_rollback_uses_nested_response_decision_trace_for_correlation(
    tenant_hierarchy_factory, monkeypatch
) -> None:
    """Agent-originated rollback events carry provider traces in response.

    The heartbeat processor must use those nested correlation hints, not only
    top-level EdrEvent.decision_trace, so Agent 3 can link recovery back to FIM.
    """
    monkeypatch.setenv("AETHERIX_CORRELATION_WINDOW_SECONDS", "300")
    agent_id = "agent-rb-nested-trace-001"
    tenant_hierarchy_factory(endpoint_id=agent_id)
    rollback_path = "/home/user/e2e/nested_trace.docx"
    shared_hash = "1" * 64
    now = datetime.now(UTC).replace(microsecond=0)

    fim_time = now - timedelta(seconds=60)
    _post_heartbeat(
        agent_id=agent_id,
        nonce=1,
        collected_at=fim_time,
        fim_events=[
            FimEvent(
                event_type="modified",
                file_path=rollback_path,
                sha256_hash=shared_hash,
                timestamp=fim_time.isoformat(),
            )
        ],
    )

    canary_time = now - timedelta(seconds=30)
    _post_heartbeat(
        agent_id=agent_id,
        nonce=2,
        collected_at=canary_time,
        edr_events=[
            EdrEvent(
                kind="ransomware_canary",
                rule_id="NestedTraceCanary",
                action="monitor",
                file_path=rollback_path,
                file_sha256=shared_hash,
                matched_indicator="NESTED_TRACE_CANARY",
                policy_version="policy-v1",
                collected_at=canary_time.isoformat(),
            )
        ],
    )
    behavior_alert = _fetch_alert(agent_id, category="behavior")

    nested_trace = [
        "rollback_provider=vss",
        f"correlation_hint:fim_path={rollback_path}",
        f"correlation_hint:dlp_path={rollback_path}",
        "snapshot_device_mutated=false",
    ]
    _post_heartbeat(
        agent_id=agent_id,
        nonce=3,
        collected_at=now,
        edr_events=[
            EdrEvent(
                kind="response_action",
                rule_id="sim-nested-trace-001",
                action="rollback",
                matched_indicator=str(behavior_alert["id"]),
                policy_version="policy-v1",
                collected_at=now.isoformat(),
                response={
                    "action": "rollback",
                    "status": "executed",
                    "attempted_at": now.isoformat(),
                    "policy_version": "policy-v1",
                    "rule_id": "sim-nested-trace-001",
                    "target_pid": None,
                    "target_path": None,
                    "file_sha256": None,
                    "platform": "windows",
                    "platform_api": "vss",
                    "decision_trace": nested_trace,
                    "error": None,
                    "quarantine": None,
                    "quarantine_items": [],
                    "evidence_controls": ["nist-csf-2.0:RC.RP"],
                },
                rollback_evidence={
                    "status": "executed",
                    "decision_trace": nested_trace,
                    "evidence_controls": ["nist-csf-2.0:RC.RP"],
                    "provider": "vss",
                    "restored_paths": [{"path": rollback_path}],
                    "failed_paths": [],
                    "skipped_paths": [],
                },
            )
        ],
    )

    rollback_alert = _fetch_alert(agent_id, category="response")
    links = _fetch_links(rollback_alert["id"])
    assert any(
        link["correlation_type"] == "rollback_action" and link["related_kind"] == "fim_event"
        for link in links
    ), f"expected nested response decision_trace to create FIM link, got {links}"

    executed_events = _fetch_evidence_events_by_action("endpoint.rollback.executed")
    executed = next(event for event in executed_events if event["resource"] == f"endpoint:{agent_id}")
    assert f"correlation_hint:fim_path={rollback_path}" in executed["payload"].get(
        "decision_trace", []
    )


def test_rollback_pending_list_and_filters(
    tenant_hierarchy_factory, auth_headers
) -> None:
    """GET /rollback-intents/pending returns awaiting_approval rollback intents
    and supports customer filtering.
    """
    agent_id = "agent-rb-pending-001"
    tenant = tenant_hierarchy_factory(endpoint_id=agent_id)
    admin_id = tenant["company_admin_id"]
    customer_id = tenant["customer_id"]
    client = TestClient(app)
    headers_admin = auth_headers(admin_id)

    _seed_simulation(
        endpoint_id=agent_id,
        simulation_id="sim-pending-001",
        candidate_set_hash="hash-pending-001",
        customer_id=customer_id,
    )
    valid_until = (datetime.now(UTC) + timedelta(hours=2)).isoformat()
    resp = client.post(
        f"/endpoints/{agent_id}/rollback-intent",
        json={
            "simulation_id": "sim-pending-001",
            "candidate_set_hash": "hash-pending-001",
            "affected_paths": ["/data/sensitive.db"],
            "recovery_point_id": "rp-pending-001",
            "provider": "btrfs",
            "valid_until": valid_until,
            "severity_hint": "high",
            "reason": "Pending query test",
        },
        headers=headers_admin,
    )
    assert resp.status_code == 202

    # Query pending rollback intents
    resp_pending = client.get(
        "/rollback-intents/pending",
        headers=headers_admin,
    )
    assert resp_pending.status_code == 200, resp_pending.text
    items = resp_pending.json()
    assert len(items) >= 1
    # Check that our created action is present
    action_ids = [item["action"]["id"] for item in items]
    created_id = resp.json()["id"]
    assert created_id in action_ids

    # Check structure
    match = [item for item in items if item["action"]["id"] == created_id][0]
    assert match["endpoint_id"] == agent_id
    assert match["hostname"] is not None
    assert str(match["customer_id"]) == str(customer_id)

    # Test filtering with valid customer_id
    resp_filtered = client.get(
        f"/rollback-intents/pending?customer_id={customer_id}",
        headers=headers_admin,
    )
    assert resp_filtered.status_code == 200
    filtered_ids = [item["action"]["id"] for item in resp_filtered.json()]
    assert created_id in filtered_ids


def test_rollback_effective_policy_disabled_blocking(
    policy_v2_templates, tenant_hierarchy_factory, auth_headers
) -> None:
    """If the effective policy has ransomware_mitigation.rollback_approval set to 'disabled',
    all rollback queue, approve, and deny requests are blocked with 403.
    """
    from copy import deepcopy
    agent_id = "agent-rb-disabled-001"
    tenant = tenant_hierarchy_factory(endpoint_id=agent_id)
    admin_id = tenant["company_admin_id"]
    client = TestClient(app)
    headers = auth_headers(admin_id)

    # A second admin for dual-operator approval checks
    from app.services import tenancy as _tenancy
    from app.schemas import AccountCreate, RoleAssignmentRequest
    second_admin = _tenancy.create_account(
        AccountCreate(
            email="rb-dis-second-admin@aetherix.test",
            full_name="Second Admin",
            initial_role=RoleAssignmentRequest(
                role_code="company_admin", customer_id=uuid.UUID(tenant["customer_id"])
            ),
        )
    )
    headers_second = auth_headers(second_admin.id)

    # 1. Queue a high-severity rollback action while rollback is still enabled under default policy
    _seed_simulation(
        endpoint_id=agent_id,
        simulation_id="sim-pre-001",
        candidate_set_hash="hash-pre-001",
        customer_id=tenant["customer_id"],
    )
    resp_pre = client.post(
        f"/endpoints/{agent_id}/rollback-restore",
        json={
            "simulation_id": "sim-pre-001",
            "candidate_set_hash": "hash-pre-001",
            "affected_paths": ["/home/user/doc.xlsx"],
            "recovery_point_id": "rp-pre-001",
            "provider": "vss",
            "severity_hint": "high",
            "reason": "Before disabled policy",
        },
        headers=headers,
    )
    assert resp_pre.status_code == 202, resp_pre.text
    action_id = resp_pre.json()["id"]

    # 2. Create a policy where ransomware_mitigation has 'rollback_approval': 'disabled'
    modules = deepcopy(policy_v2_templates["minimal"])
    modules["ransomware_mitigation"] = {
        "enabled": True,
        "rollback_approval": "disabled",
    }

    # Helper function to create policy
    def _create_policy_v2(client, auth_headers, actor_id: str, name: str, partner_id: str, customer_id: str | None, modules: dict):
        response = client.post(
            "/policies",
            headers=auth_headers(actor_id),
            json={
                "schema_version": "2.0",
                "name": name,
                "scope": {
                    "partner_id": partner_id,
                    "customer_id": customer_id,
                    "group_id": None,
                    "endpoint_id": None,
                },
                "lineage": {
                    "parent_policy_id": None,
                    "inheritance_mode": "inherit_with_overrides",
                },
                "modules": modules,
                "white_label_names": {},
            },
        )
        assert response.status_code == 201, response.text
        return response.json()

    # Helper function to simulate and promote policy
    def _simulate_promote_v2(client, auth_headers, actor_id: str, policy_id: str):
        simulation = client.post(
            f"/policies/{policy_id}/simulate",
            headers=auth_headers(actor_id),
        )
        assert simulation.status_code == 200, simulation.text
        sim_body = simulation.json()

        promote = client.post(
            f"/policies/{policy_id}/promote",
            headers=auth_headers(actor_id),
            json={
                "simulation_id": sim_body["id"],
                "operator_approved": True,
                "approval_reason": "validated in end-to-end promotion test",
            },
        )
        assert promote.status_code == 200, promote.text
        return sim_body, promote.json()

    created = _create_policy_v2(
        client=client,
        auth_headers=auth_headers,
        actor_id=tenant["msp_id"],
        name="Disabled Rollback Policy",
        partner_id=tenant["partner_id"],
        customer_id=tenant["customer_id"],
        modules=modules,
    )
    policy_id = created["policy"]["id"]

    # 3. Simulate and promote:
    _simulate_promote_v2(client=client, auth_headers=auth_headers, actor_id=tenant["msp_id"], policy_id=policy_id)

    # 4. Assign to the customer
    assign = client.post(
        "/policies/assign",
        headers=auth_headers(tenant["msp_id"]),
        json={"policy_id": policy_id, "customer_id": tenant["customer_id"]},
    )
    assert assign.status_code == 201, assign.text

    # 5. Verify effective policy for the endpoint indeed has rollback_approval as disabled
    eff_res = client.get(
        f"/policies/effective?endpoint_id={agent_id}",
        headers=auth_headers(admin_id),
    )
    assert eff_res.status_code == 200, eff_res.text
    assert eff_res.json()["resolved_policy"]["modules"]["ransomware_mitigation"]["rollback_approval"] == "disabled"

    # 6. Attempting to approve the previously queued rollback-restore should be blocked with 403
    resp_approve = client.post(
        f"/endpoints/{agent_id}/rollback-restore/{action_id}/approve",
        json={"reason": "Approve test"},
        headers=headers_second,
    )
    assert resp_approve.status_code == 403, f"Expected 403 approved blocker, got {resp_approve.status_code}"
    assert "disabled" in resp_approve.json().get("detail", "").lower()

    # 7. Attempting to deny the previously queued rollback-restore should be blocked with 403
    resp_deny = client.post(
        f"/endpoints/{agent_id}/rollback-restore/{action_id}/deny",
        json={"reason": "Deny test"},
        headers=headers,
    )
    assert resp_deny.status_code == 403, f"Expected 403 deny blocker, got {resp_deny.status_code}"
    assert "disabled" in resp_deny.json().get("detail", "").lower()

    # 8. Attempting to queue a new rollback intent on this endpoint should be blocked with 403
    future_until = (datetime.now(UTC) + timedelta(hours=1)).isoformat()
    resp = client.post(
        f"/endpoints/{agent_id}/rollback-intent",
        json={
            "simulation_id": "sim-dis-001",
            "candidate_set_hash": "hash-dis-001",
            "affected_paths": ["/home/user/doc.xlsx"],
            "recovery_point_id": "rp-dis-001",
            "provider": "vss",
            "valid_until": future_until,
            "severity_hint": "medium",
            "reason": "Disabled test",
        },
        headers=headers,
    )
    assert resp.status_code == 403, f"Expected 403 since rollback is disabled, got {resp.status_code}: {resp.text}"
    assert "disabled" in resp.json().get("detail", "").lower()

    # 9. Attempting to queue a new rollback-restore on this endpoint should be blocked with 403
    resp_restore = client.post(
        f"/endpoints/{agent_id}/rollback-restore",
        json={
            "simulation_id": "sim-dis-002",
            "candidate_set_hash": "hash-dis-002",
            "affected_paths": ["/home/user/doc.xlsx"],
            "recovery_point_id": "rp-dis-002",
            "provider": "vss",
            "severity_hint": "medium",
            "reason": "Disabled test",
        },
        headers=headers,
    )
    assert resp_restore.status_code == 403, f"Expected 403 since rollback is disabled, got {resp_restore.status_code}: {resp_restore.text}"
    assert "disabled" in resp_restore.json().get("detail", "").lower()


def test_rollback_restore_flow_full(
    tenant_hierarchy_factory, auth_headers
) -> None:
    """End-to-end audit representation for the direct rollback-restore action.
    A high-severity rollback-restore queued, denied-self, approved by peer,
    and executed successfully under a dual-operator model.
    """
    from app.services import tenancy as _tenancy
    from app.schemas import AccountCreate, RoleAssignmentRequest

    agent_id = "agent-rb-restore-full-001"
    tenant = tenant_hierarchy_factory(endpoint_id=agent_id)
    admin_id = tenant["company_admin_id"]
    customer_id = tenant["customer_id"]
    client = TestClient(app)
    headers_admin = auth_headers(admin_id)

    # Create a second company_admin for dual-operator approval.
    second_admin = _tenancy.create_account(
        AccountCreate(
            email="rb-restore-second-admin@aetherix.test",
            full_name="Second Admin",
            initial_role=RoleAssignmentRequest(
                role_code="company_admin", customer_id=uuid.UUID(customer_id)
            ),
        )
    )
    headers_second = auth_headers(second_admin.id)

    # 1. Queue a high-severity rollback-restore action (requires approval)
    _seed_simulation(
        endpoint_id=agent_id,
        simulation_id="sim-restore-001",
        candidate_set_hash="hash-restore-001",
        customer_id=customer_id,
    )
    resp = client.post(
        f"/endpoints/{agent_id}/rollback-restore",
        json={
            "simulation_id": "sim-restore-001",
            "candidate_set_hash": "hash-restore-001",
            "affected_paths": ["/Users/user/docs/financial_data.xlsx"],
            "recovery_point_id": "rp-restore-001",
            "provider": "vss",
            "severity_hint": "high",
            "reason": "Request direct recovery",
        },
        headers=headers_admin,
    )
    assert resp.status_code == 202, resp.text
    body = resp.json()
    assert body["status"] == "awaiting_approval"
    action_id = body["id"]

    # 2. Verify it shows up in pending endpoint
    resp_pending = client.get(
        "/rollback-intents/pending",
        headers=headers_admin,
    )
    assert resp_pending.status_code == 200
    pending_items = resp_pending.json()
    assert any(x["action"]["id"] == action_id and x["action"]["action"] == "rollback_restore" for x in pending_items)

    # 3. Self-approval must be rejected.
    resp_self = client.post(
        f"/endpoints/{agent_id}/rollback-restore/{action_id}/approve",
        json={"reason": "Self-approved direct restore"},
        headers=headers_admin,
    )
    assert resp_self.status_code == 403

    # 4. Peer approval should succeed.
    resp_peer = client.post(
        f"/endpoints/{agent_id}/rollback-restore/{action_id}/approve",
        json={"reason": "Peer approved direct restore"},
        headers=headers_second,
    )
    assert resp_peer.status_code == 200
    approved = resp_peer.json()
    assert approved["status"] == "queued"

    # 5. Agent processes and completes the rollback-restore
    now = datetime.now(UTC).replace(microsecond=0)
    _post_heartbeat(
        agent_id=agent_id,
        nonce=1,
        collected_at=now,
        edr_events=[
            EdrEvent(
                kind="response_action",
                rule_id="ManualRecovery",
                action="rollback_restore",
                file_path="/Users/user/docs/financial_data.xlsx",
                rollback_file_paths=["/Users/user/docs/financial_data.xlsx"],
                matched_indicator=str(action_id),
                policy_version="policy-v1",
                collected_at=now.isoformat(),
                response={
                    "status": "completed",
                    "simulation_id": "sim-restore-001",
                    "provider": "vss",
                    "candidate_set_hash": "hash-restore-001",
                    "recovery_point_id": "rp-restore-001",
                    "paths": ["/Users/user/docs/financial_data.xlsx"],
                },
            )
        ],
    )

    # 6. Verify executed evidence event was correctly triggered
    executed_events = _fetch_evidence_events_by_action("endpoint.rollback.executed")
    assert any(x["resource"] == f"endpoint:{agent_id}" for x in executed_events)


def test_rollback_restore_flow_failed(
    tenant_hierarchy_factory, auth_headers
) -> None:
    """A direct rollback-restore with medium severity is queued directly,
    but fails on the agent side, recording endpoint.rollback.failed.
    """
    agent_id = "agent-rb-restore-fail-001"
    tenant = tenant_hierarchy_factory(endpoint_id=agent_id)
    admin_id = tenant["company_admin_id"]
    client = TestClient(app)
    headers_admin = auth_headers(admin_id)

    # 1. Queue a medium-severity rollback-restore action (queued directly)
    _seed_simulation(
        endpoint_id=agent_id,
        simulation_id="sim-fail-001",
        candidate_set_hash="hash-fail-001",
        customer_id=tenant["customer_id"],
    )
    resp = client.post(
        f"/endpoints/{agent_id}/rollback-restore",
        json={
            "simulation_id": "sim-fail-001",
            "candidate_set_hash": "hash-fail-001",
            "affected_paths": ["/Users/user/docs/critical.db"],
            "recovery_point_id": "rp-fail-001",
            "provider": "vss",
            "severity_hint": "medium",
            "reason": "Direct restore with VSS",
        },
        headers=headers_admin,
    )
    assert resp.status_code == 202, resp.text
    body = resp.json()
    assert body["status"] == "queued"
    action_id = body["id"]

    # 2. Agent reports execution failure in EDR response_action
    now = datetime.now(UTC).replace(microsecond=0)
    _post_heartbeat(
        agent_id=agent_id,
        nonce=1,
        collected_at=now,
        edr_events=[
            EdrEvent(
                kind="response_action",
                rule_id="ManualRecovery",
                action="rollback_restore",
                file_path="/Users/user/docs/critical.db",
                rollback_file_paths=["/Users/user/docs/critical.db"],
                matched_indicator=str(action_id),
                policy_version="policy-v1",
                collected_at=now.isoformat(),
                response={
                    "status": "failed",
                    "simulation_id": "sim-fail-001",
                    "provider": "vss",
                    "candidate_set_hash": "hash-fail-001",
                    "recovery_point_id": "rp-fail-001",
                    "error_message": "VSS snapshot store is corrupted or unmounted",
                },
            )
        ],
    )

    # 3. Verify failed evidence event was correctly triggered
    failed_events = _fetch_evidence_events_by_action("endpoint.rollback.failed")
    assert any(x["resource"] == f"endpoint:{agent_id}" for x in failed_events)
    matching_failed = [x for x in failed_events if x["resource"] == f"endpoint:{agent_id}"][0]
    payload = matching_failed.get("payload") or {}
    assert payload.get("status") == "failed"
    assert payload.get("error_message") == "VSS snapshot store is corrupted or unmounted"


def test_rollback_full_chain_lightweight_integration(
    tenant_hierarchy_factory, auth_headers
) -> None:
    """Exercises the complete rollback lifecycle:
    Canary detection -> staged restore action -> peer approval -> agent execution ack
    -> validation of evidence events + correlation links.
    """
    from app.services import tenancy as _tenancy
    from app.schemas import AccountCreate, RoleAssignmentRequest

    agent_id = "agent-rb-full-chain-001"
    tenant = tenant_hierarchy_factory(endpoint_id=agent_id)
    admin_id = tenant["company_admin_id"]
    customer_id = tenant["customer_id"]
    client = TestClient(app)
    headers_admin = auth_headers(admin_id)

    # Create a second company_admin for dual-operator approval.
    second_admin = _tenancy.create_account(
        AccountCreate(
            email="rb-full-second-admin@aetherix.test",
            full_name="Second Admin",
            initial_role=RoleAssignmentRequest(
                role_code="company_admin", customer_id=uuid.UUID(customer_id)
            ),
        )
    )
    headers_second = auth_headers(second_admin.id)

    rollback_path = "/home/user/documents/financial.xlsx"
    shared_hash = "f" * 64
    now = datetime.now(UTC).replace(microsecond=0)
    readiness_probe = {
        "provider_available": True,
        "provider_name": "vss",
        "provider_version": "1.0.0",
        "os_platform": "linux",
        "functional": True,
        "diagnosis": "probe_ok",
        "recovery_point_count": 3,
        "available_filesystems": ["/", "/home"],
        "service_available": True,
        "sufficient_privilege": True,
        "volume_capabilities": ["snapshots", "copy_on_write"],
        "snapshot_service_info": "vss:healthy",
        "privilege_boundary": "root",
        "recent_fim_paths": [rollback_path],
    }

    # 1. Post a FIM write/modify event on the path
    fim_time = now - timedelta(seconds=60)
    _post_heartbeat(
        agent_id=agent_id,
        nonce=1,
        collected_at=fim_time,
        rollback_readiness=readiness_probe,
        fim_events=[
            FimEvent(
                event_type="modified",
                file_path=rollback_path,
                sha256_hash=shared_hash,
                timestamp=fim_time.isoformat(),
            )
        ],
    )

    # 2. Post a simulated ransomware canary detection (EDR event)
    canary_time = now - timedelta(seconds=45)
    _post_heartbeat(
        agent_id=agent_id,
        nonce=2,
        collected_at=canary_time,
        rollback_readiness=readiness_probe,
        edr_events=[
            EdrEvent(
                kind="ransomware_canary",
                rule_id="RansomwareCanary",
                action="monitor",
                file_path=rollback_path,
                file_sha256=shared_hash,
                matched_indicator="CANARY",
                policy_version="policy-v1",
                collected_at=canary_time.isoformat(),
            )
        ],
    )

    # Fetch the generated alert
    canary_alert = _fetch_alert(agent_id, category="behavior")
    alert_id = canary_alert["id"]

    # 3. Queue a rollback restore request against the canary simulation (High severity)
    _seed_simulation(
        endpoint_id=agent_id,
        simulation_id="sim-full-chain-001",
        candidate_set_hash="hash-full-chain-001",
        customer_id=customer_id,
    )
    resp_queue = client.post(
        f"/endpoints/{agent_id}/rollback-restore",
        json={
            "simulation_id": "sim-full-chain-001",
            "candidate_set_hash": "hash-full-chain-001",
            "affected_paths": [rollback_path],
            "recovery_point_id": "rp-full-chain-001",
            "provider": "vss",
            "severity_hint": "high",
            "reason": "Lightweight E2E test",
        },
        headers=headers_admin,
    )
    assert resp_queue.status_code == 202, resp_queue.text
    action_id = resp_queue.json()["id"]

    requested_events = _fetch_evidence_events_by_action("endpoint.rollback.requested")
    assert any(x["resource"] == f"endpoint:{agent_id}" for x in requested_events)

    # Pending inbox should include expanded rollback_readiness probe data.
    resp_pending = client.get("/rollback-intents/pending", headers=headers_admin)
    assert resp_pending.status_code == 200, resp_pending.text
    pending_item = next((x for x in resp_pending.json() if x["action"]["id"] == action_id), None)
    assert pending_item is not None, "queued rollback action should be visible in pending inbox"
    readiness = pending_item.get("rollback_readiness") or {}
    assert readiness.get("functional") is True
    assert readiness.get("volume_capabilities") == ["snapshots", "copy_on_write"]
    assert readiness.get("recent_fim_paths") == [rollback_path]

    # 4. Peer approval (dual operator)
    resp_approve = client.post(
        f"/endpoints/{agent_id}/rollback-restore/{action_id}/approve",
        json={"reason": "Approved by peer"},
        headers=headers_second,
    )
    assert resp_approve.status_code == 200, resp_approve.text

    approved_events = _fetch_evidence_events_by_action("endpoint.rollback.approved")
    assert any(x["resource"] == f"endpoint:{agent_id}" for x in approved_events)

    # 5. Agent processes and completed heartbeat execution ack
    # We report both rollback_restore (matching action_id to update status)
    # and rollback (matching behavior alert_id to perform cross-module correlation)
    ack_time = now
    _post_heartbeat(
        agent_id=agent_id,
        nonce=3,
        collected_at=ack_time,
        edr_events=[
            EdrEvent(
                kind="response_action",
                rule_id="RansomwareCanary",
                action="rollback_restore",
                file_path=rollback_path,
                rollback_file_paths=[rollback_path],
                matched_indicator=str(action_id),
                policy_version="policy-v1",
                collected_at=ack_time.isoformat(),
                response={
                    "status": "completed",
                    "simulation_id": "sim-full-chain-001",
                    "provider": "vss",
                    "candidate_set_hash": "hash-full-chain-001",
                    "recovery_point_id": "rp-full-chain-001",
                    "paths": [rollback_path],
                },
            ),
            EdrEvent(
                kind="response_action",
                rule_id="RansomwareCanary",
                action="rollback",
                file_path=rollback_path,
                rollback_file_paths=[rollback_path],
                matched_indicator=str(alert_id),
                policy_version="policy-v1",
                collected_at=ack_time.isoformat(),
                response={
                    "status": "completed",
                    "simulation_id": "sim-full-chain-001",
                    "provider": "vss",
                    "candidate_set_hash": "hash-full-chain-001",
                    "recovery_point_id": "rp-full-chain-001",
                    "paths": [rollback_path],
                },
            ),
        ],
    )

    # 6. Verify evidence events + correlation links
    executed_events = _fetch_evidence_events_by_action("endpoint.rollback.executed")
    assert any(x["resource"] == f"endpoint:{agent_id}" for x in executed_events)

    # Verify correlation link matches on the original alert
    links = _fetch_links(alert_id)
    assert len(links) >= 1, "expected rollback action correlation link"
    assert any(l["correlation_type"] == "rollback_action" for l in links)

    # Verify compliance correlation event was emitted
    corr_events = _fetch_rollback_evidence_events()
    assert any((x.get("payload") or {}).get("agent_id") == agent_id for x in corr_events), (
        "expected correlation.rollback_recovery compliance event carrying agent_id"
    )


def test_vss_fixture_pending_inbox_export_chain(
    tenant_hierarchy_factory, auth_headers
) -> None:
    """Fixture-backed smoke test for pending inbox and execution evidence payloads.

    Uses realistic VSS-shaped readiness data to validate the pending inbox and
    endpoint.rollback.executed evidence path before more provider features land.
    """

    fixture = _load_vss_pipeline_fixture()
    agent = fixture["agent"]
    readiness = fixture["rollback_readiness"]
    restore_request = copy.deepcopy(fixture["rollback_restore_request"])
    expected_metadata = restore_request["provider_metadata"]

    tenant = tenant_hierarchy_factory(endpoint_id=agent["id"])
    admin_id = tenant["company_admin_id"]
    customer_id = tenant["customer_id"]
    client = TestClient(app)
    headers_admin = auth_headers(admin_id)

    now = datetime.now(UTC).replace(microsecond=0)
    _post_heartbeat(
        agent_id=agent["id"],
        nonce=1,
        collected_at=now - timedelta(seconds=60),
        rollback_readiness=readiness,
        fim_events=[
            FimEvent(
                event_type="modified",
                file_path=restore_request["affected_paths"][0],
                sha256_hash="7" * 64,
                timestamp=(now - timedelta(seconds=60)).isoformat(),
            )
        ],
    )

    _seed_simulation(
        endpoint_id=agent["id"],
        simulation_id=restore_request["simulation_id"],
        candidate_set_hash=restore_request["candidate_set_hash"],
        customer_id=customer_id,
    )
    queue = client.post(
        f"/endpoints/{agent['id']}/rollback-restore",
        json=restore_request,
        headers=headers_admin,
    )
    assert queue.status_code == 202, queue.text
    action_id = queue.json()["id"]

    pending = client.get(
        f"/rollback-intents/pending?customer_id={customer_id}",
        headers=headers_admin,
    )
    assert pending.status_code == 200, pending.text
    pending_item = next((x for x in pending.json() if x["action"]["id"] == action_id), None)
    assert pending_item is not None
    assert pending_item["action"]["payload"]["provider_metadata"] == expected_metadata
    assert pending_item["action"]["payload"]["rollback_readiness"]["provider_metadata"] == expected_metadata
    assert pending_item["rollback_readiness"]["provider_metadata"] == expected_metadata
    assert pending_item["rollback_readiness"]["vss_probe_details"]["service_state"] == "running"

    _post_heartbeat(
        agent_id=agent["id"],
        nonce=2,
        collected_at=now,
        rollback_readiness=readiness,
        edr_events=[
            EdrEvent(
                kind="response_action",
                rule_id="RansomwareCanary",
                action="rollback_restore",
                file_path=restore_request["affected_paths"][0],
                rollback_file_paths=restore_request["affected_paths"],
                matched_indicator=str(action_id),
                policy_version="policy-v1",
                collected_at=now.isoformat(),
                response={
                    "status": "completed",
                    "simulation_id": restore_request["simulation_id"],
                    "provider": restore_request["provider"],
                    "provider_metadata": expected_metadata,
                    "candidate_set_hash": restore_request["candidate_set_hash"],
                    "recovery_point_id": restore_request["recovery_point_id"],
                    "paths": restore_request["affected_paths"],
                },
            )
        ],
    )

    executed_events = _fetch_evidence_events_by_action("endpoint.rollback.executed")
    executed = next((x for x in executed_events if x["resource"] == f"endpoint:{agent['id']}"), None)
    assert executed is not None
    payload = executed.get("payload") or {}
    assert payload.get("provider_metadata") == expected_metadata
    assert payload.get("rollback_readiness", {}).get("provider_metadata") == expected_metadata
    assert payload.get("rollback_readiness", {}).get("vss_probe_details", {}).get("writers_total") == 2

import uuid
import hmac
import hashlib
from datetime import UTC, datetime

import pytest
from fastapi.testclient import TestClient

from app.db import connection
from app.main import app
from app.schemas import AgentHeartbeat, AgentSignals, EdrEvent
from app.services.state import upsert_heartbeat


def test_edr_heartbeat_creates_security_alerts(tenant_hierarchy_factory, monkeypatch) -> None:
    # 1. Setup tenant with enrolled agent
    agent_id = "test-agent-edr-001"
    tenant = tenant_hierarchy_factory(endpoint_id=agent_id)
    secret = "e2e-endpoint-secret"

    collected_at = datetime.now(UTC).replace(microsecond=0)
    collected_at_str = collected_at.isoformat()

    # Define EDR event payload
    edr_event = EdrEvent(
        kind="yara_match",
        rule_id="SuspiciousString",
        action="monitor",
        file_path="/tmp/malicious.exe",
        file_sha256="cf27e2bc4c59ff122144d88612fe13cfcd27e2bc4c59ff122144d88612fe13cf",
        matched_indicator="AETHERIX_TEST_EICAR",
        policy_version="policy-v1",
        collected_at=collected_at_str,
    )

    # 2. Construct signed heartbeat containing EDR events
    heartbeat_payload = {
        "agent_id": agent_id,
        "hostname": "e2e-host",
        "os": "linux",
        "collected_at": collected_at_str,
        "policy_version": "policy-v1",
        "agent_version": "0.1.0",
        "nonce": 1,
        "signals": {
            "blocked_events": 0,
            "dlp_events": 0,
            "pending_updates": 0,
            "cpu_percent": 5.0,
            "memory_percent": 12.0,
        },
        "edr_events": [edr_event.model_dump(mode="json")],
    }

    # Generate signature using hmac and pipe separators
    message = f"{agent_id}|e2e-host|linux|{collected_at_str}|policy-v1|1"
    signature = hmac.new(secret.encode(), message.encode(), hashlib.sha256).hexdigest()
    heartbeat_payload["signature"] = signature

    # 3. Post heartbeat to control plane
    client = TestClient(app)
    response = client.post("/agent/heartbeat", json=heartbeat_payload)
    assert response.status_code == 200

    # 4. Verify EDR event was inserted into security_alerts
    with connection() as conn, conn.cursor() as cur:
        cur.execute(
            "select * from security_alerts where agent_id = %s and category = 'malware'",
            (agent_id,),
        )
        alerts = cur.fetchall()
        assert len(alerts) == 1
        alert = alerts[0]
        assert alert["category"] == "malware"
        assert alert["recommended_action"] == "quarantine"
        assert alert["severity"] == "high"
        assert alert["status"] == "new"
        assert alert["payload"]["file_path"] == "/tmp/malicious.exe"


def test_behavior_detections_endpoint(tenant_hierarchy_factory, auth_headers) -> None:
    # 1. Setup tenant
    tenant = tenant_hierarchy_factory(endpoint_id="agent-behavior-001")
    admin_id = tenant["company_admin_id"]
    customer_id = tenant["customer_id"]

    # Insert a pre-existing malware alert
    alert_id = uuid.uuid4()
    with connection() as conn, conn.cursor() as cur:
        cur.execute(
            """
            insert into security_alerts (
                id, customer_id, agent_id, category, severity, confidence, recommended_action, payload, status, created_at, evidence_controls
            ) values (%s, %s, 'agent-behavior-001', 'malware', 'high', 95, 'quarantine', '{"file":"x"}'::jsonb, 'new', now(), '[]'::jsonb)
            """,
            (alert_id, customer_id),
        )

    # 2. Request behavior detections through console auth headers
    client = TestClient(app)
    headers = auth_headers(admin_id)
    response = client.get(f"/behavior/detections?customer_id={customer_id}", headers=headers)
    assert response.status_code == 200
    results = response.json()
    assert len(results) >= 1
    assert any(str(r["id"]) == str(alert_id) for r in results)


def test_stage_behavior_action_targets_correct_agent(tenant_hierarchy_factory, auth_headers) -> None:
    # 1. Setup tenant
    agent_id = "agent-action-001"
    tenant = tenant_hierarchy_factory(endpoint_id=agent_id)
    admin_id = tenant["company_admin_id"]
    customer_id = tenant["customer_id"]

    client = TestClient(app)
    headers = auth_headers(admin_id)

    # 2. Stage behavior action using correct agent endpoint_id
    alert_id = str(uuid.uuid4())
    payload = {
        "detection_id": alert_id,
        "customer_id": customer_id,
        "endpoint_id": agent_id,
        "action": "quarantine",
    }

    response = client.post("/behavior/action", json=payload, headers=headers)
    assert response.status_code == 200
    res_data = response.json()
    assert res_data["status"] in ("queued", "awaiting_approval")

    # 3. Check if action in database is registered against target agent ID rather than the alert ID
    with connection() as conn, conn.cursor() as cur:
        cur.execute(
            "select endpoint_id, status from module_actions where endpoint_id = %s",
            (agent_id,),
        )
        actions = cur.fetchall()
        assert len(actions) == 1
        assert actions[0]["endpoint_id"] == agent_id


def test_stage_behavior_action_resolves_and_extracts_telemetry(tenant_hierarchy_factory, auth_headers) -> None:
    import json
    # 1. Setup tenant
    agent_id = "agent-action-resolve-001"
    tenant = tenant_hierarchy_factory(endpoint_id=agent_id)
    admin_id = tenant["company_admin_id"]
    customer_id = tenant["customer_id"]

    # Insert a security alert with process PID and file path
    alert_id = uuid.uuid4()
    alert_payload = {
        "process_pid": 1234,
        "file_path": "/var/log/malicious_script.sh",
        "kind": "suspicious_process_chain",
    }
    with connection() as conn, conn.cursor() as cur:
        cur.execute(
            """
            insert into security_alerts (
                id, customer_id, agent_id, category, severity, confidence, recommended_action, payload, status, created_at, evidence_controls
            ) values (%s, %s, %s, 'behavior', 'high', 95, 'kill_process', %s::jsonb, 'new', now(), '[]'::jsonb)
            """,
            (alert_id, customer_id, agent_id, json.dumps(alert_payload)),
        )

    client = TestClient(app)
    headers = auth_headers(admin_id)

    # 2. Stage behavior action passing only detection_id (alert_id) and NO endpoint_id / target details
    payload = {
        "detection_id": str(alert_id),
        "customer_id": customer_id,
        "action": "kill_process",
    }

    response = client.post("/behavior/action", json=payload, headers=headers)
    assert response.status_code == 200
    res_data = response.json()
    assert res_data["status"] == "queued"  # Auto-queued!

    # 3. Check if action in database is registered against real target agent ID and has target_pid injected in payload
    with connection() as conn, conn.cursor() as cur:
        cur.execute(
            "select endpoint_id, status, payload from module_actions where endpoint_id = %s",
            (agent_id,),
        )
        actions = cur.fetchall()
        assert len(actions) == 1
        action_row = actions[0]
        assert action_row["endpoint_id"] == agent_id
        assert action_row["status"] == "queued"
        
        action_payload = action_row["payload"] or {}
        assert action_payload.get("target_pid") == 1234
        assert action_payload.get("target_path") == "/var/log/malicious_script.sh"

    # 4. Check if the agent can poll this action via GET /agent/actions using its secret
    with connection() as conn, conn.cursor() as cur:
        cur.execute("select secret from enrolled_agents where agent_id = %s", (agent_id,))
        agent_secret = cur.fetchone()["secret"]

    response = client.get(
        f"/agent/actions?endpoint_id={agent_id}&token={agent_secret}"
    )
    assert response.status_code == 200
    polled = response.json()
    assert len(polled) == 1
    assert polled[0]["action"] == "kill_process"


def test_stage_quarantine_action_resolves_and_extracts_telemetry(tenant_hierarchy_factory, auth_headers) -> None:
    import json
    # 1. Setup tenant
    agent_id = "agent-quarantine-resolve-001"
    tenant = tenant_hierarchy_factory(endpoint_id=agent_id)
    admin_id = tenant["company_admin_id"]
    customer_id = tenant["customer_id"]

    # Insert a security alert with process PID and file path suitable for quarantine
    alert_id = uuid.uuid4()
    alert_payload = {
        "process_pid": 5678,
        "file_path": "/tmp/infected_binary.exe",
        "kind": "yara_match",
    }
    with connection() as conn, conn.cursor() as cur:
        cur.execute(
            """
            insert into security_alerts (
                id, customer_id, agent_id, category, severity, confidence, recommended_action, payload, status, created_at, evidence_controls
            ) values (%s, %s, %s, 'malware', 'high', 95, 'quarantine', %s::jsonb, 'new', now(), '[]'::jsonb)
            """,
            (alert_id, customer_id, agent_id, json.dumps(alert_payload)),
        )

    client = TestClient(app)
    headers = auth_headers(admin_id)

    # 2. Stage quarantine action passing only item_id (alert_id) and NO endpoint_id / target details
    payload = {
        "action": "quarantine",
    }

    response = client.post(f"/quarantine/{alert_id}/action", json=payload, headers=headers)
    assert response.status_code == 200
    res_data = response.json()
    assert res_data["status"] == "queued"  # Auto-queued!

    # 3. Check if action in database is registered against real target agent ID and has target_path injected in payload
    with connection() as conn, conn.cursor() as cur:
        cur.execute(
            "select endpoint_id, status, payload from module_actions where endpoint_id = %s",
            (agent_id,),
        )
        actions = cur.fetchall()
        assert len(actions) == 1
        action_row = actions[0]
        assert action_row["endpoint_id"] == agent_id
        assert action_row["status"] == "queued"
        
        action_payload = action_row["payload"] or {}
        assert action_payload.get("target_pid") == 5678
        assert action_payload.get("target_path") == "/tmp/infected_binary.exe"


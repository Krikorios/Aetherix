"""Tests for the remote EDR quarantine management surface (2026-05-27).

Covers the control-plane work delivered in Agent 3's cycle:
  - operator-facing POST /endpoints/{id}/quarantine-list
  - operator-facing POST /endpoints/{id}/quarantine-restore (severity-gated)
  - dual-operator approval flow for high/critical restores
  - agent ack with response evidence body
  - quarantine inventory snapshot upsert
  - GET /endpoints/{id}/response-actions surface for the console
  - compliance evidence emitted for agent.response_action via heartbeat
"""
from __future__ import annotations

import hashlib
import hmac
import uuid
from datetime import UTC, datetime

from fastapi.testclient import TestClient

from app.db import connection
from app.main import app


def _agent_secret(agent_id: str) -> str:
    with connection() as conn, conn.cursor() as cur:
        cur.execute("select secret from enrolled_agents where agent_id = %s", (agent_id,))
        return cur.fetchone()["secret"]


def test_quarantine_list_queues_action_with_evidence_controls(
    tenant_hierarchy_factory, auth_headers
) -> None:
    agent_id = "agent-qlist-001"
    tenant = tenant_hierarchy_factory(endpoint_id=agent_id)
    admin_id = tenant["company_admin_id"]
    client = TestClient(app)

    response = client.post(
        f"/endpoints/{agent_id}/quarantine-list",
        json={"reason": "audit sweep"},
        headers=auth_headers(admin_id),
    )
    assert response.status_code == 200, response.text
    data = response.json()
    assert data["action"] == "quarantine_list"
    assert data["status"] == "queued"
    assert data["approval_required"] is False
    assert "iso27001-2022:A.8.16" in data["evidence_controls"]
    assert data["requested_by"] == admin_id

    with connection() as conn, conn.cursor() as cur:
        cur.execute(
            "select customer_id, requested_by from module_actions where id = %s",
            (uuid.UUID(data["id"]),),
        )
        row = cur.fetchone()
        assert str(row["customer_id"]) == tenant["customer_id"]
        assert str(row["requested_by"]) == admin_id


def test_quarantine_restore_low_severity_queues_directly(
    tenant_hierarchy_factory, auth_headers
) -> None:
    agent_id = "agent-qrestore-low-001"
    tenant = tenant_hierarchy_factory(endpoint_id=agent_id)
    client = TestClient(app)

    response = client.post(
        f"/endpoints/{agent_id}/quarantine-restore",
        json={
            "quarantine_id": "qr-abc",
            "target_path": "/tmp/restored.bin",
            "severity_hint": "low",
            "reason": "false positive cleared",
        },
        headers=auth_headers(tenant["company_admin_id"]),
    )
    assert response.status_code == 200, response.text
    data = response.json()
    assert data["status"] == "queued"
    assert data["approval_required"] is False
    assert data["payload"]["quarantine_id"] == "qr-abc"
    assert data["payload"]["target_path"] == "/tmp/restored.bin"


def test_quarantine_restore_critical_requires_dual_approval(
    tenant_hierarchy_factory, auth_headers
) -> None:
    agent_id = "agent-qrestore-crit-001"
    tenant = tenant_hierarchy_factory(endpoint_id=agent_id)
    requester_id = tenant["company_admin_id"]
    # Create a second operator (MSP partner has incidents edit by default)
    second_operator_id = tenant["msp_id"]
    client = TestClient(app)

    # 1. Request restore at critical severity -> awaiting_approval.
    response = client.post(
        f"/endpoints/{agent_id}/quarantine-restore",
        json={"quarantine_id": "qr-crit", "severity_hint": "critical", "reason": "DR"},
        headers=auth_headers(requester_id),
    )
    assert response.status_code == 200, response.text
    queued = response.json()
    assert queued["status"] == "awaiting_approval"
    assert queued["approval_required"] is True
    action_id = queued["id"]

    # 2. Requester cannot approve their own action.
    self_approve = client.post(
        f"/endpoints/{agent_id}/quarantine-restore/{action_id}/approve",
        headers=auth_headers(requester_id),
    )
    assert self_approve.status_code == 403

    # 3. A distinct operator approves and transitions to queued.
    approve = client.post(
        f"/endpoints/{agent_id}/quarantine-restore/{action_id}/approve",
        headers=auth_headers(second_operator_id),
    )
    assert approve.status_code == 200, approve.text
    approved = approve.json()
    assert approved["status"] == "queued"
    assert approved["approved_by"] == second_operator_id
    assert approved["approved_at"] is not None

    # 4. Agent now sees it in /agent/actions.
    secret = _agent_secret(agent_id)
    polled = client.get(f"/agent/actions?endpoint_id={agent_id}&token={secret}")
    assert polled.status_code == 200
    polled_actions = polled.json()
    assert any(a["id"] == action_id for a in polled_actions)


def test_agent_ack_with_result_persists_quarantine_inventory(
    tenant_hierarchy_factory, auth_headers
) -> None:
    agent_id = "agent-qack-001"
    tenant = tenant_hierarchy_factory(endpoint_id=agent_id)
    client = TestClient(app)

    queue_resp = client.post(
        f"/endpoints/{agent_id}/quarantine-list",
        json={"reason": "console refresh"},
        headers=auth_headers(tenant["company_admin_id"]),
    )
    assert queue_resp.status_code == 200
    action_id = queue_resp.json()["id"]

    secret = _agent_secret(agent_id)
    items = [
        # Mirror agent/src/edr/mod.rs::QuarantineListItem serialization
        # so the console-typed schema sees the same field names the
        # agent actually emits.
        {
            "quarantine_id": "q-1",
            "original_path": "/tmp/evil.bin",
            "stored_path": "/var/lib/aetherix/quarantine/q-1",
            "sha256_hash": "a" * 64,
            "rule_id": "test_rule",
            "file_size": 1024,
            "quarantined_at": datetime.now(UTC).isoformat(),
            "severity_hint": "high",
            "can_restore": True,
            "restore_requires_approval": True,
            "approval_hint": "high-severity restore requires dual approval",
            "encrypted": True,
            "manifest_hash": "b" * 64,
        }
    ]
    ack = client.post(
        f"/agent/actions/{action_id}/ack?endpoint_id={agent_id}&token={secret}",
        json={
            "status": "completed",
            "result": {
                "status": "executed",
                "quarantine_items": items,
            },
        },
    )
    assert ack.status_code == 200, ack.text
    acked = ack.json()
    assert acked["status"] == "completed"
    assert acked["result"]["quarantine_items"][0]["quarantine_id"] == "q-1"

    inventory = client.get(
        f"/endpoints/{agent_id}/quarantine-inventory",
        headers=auth_headers(tenant["company_admin_id"]),
    )
    assert inventory.status_code == 200, inventory.text
    inv = inventory.json()
    assert inv["endpoint_id"] == agent_id
    assert len(inv["items"]) == 1
    item = inv["items"][0]
    assert item["quarantine_id"] == "q-1"
    # Agent field names survive the round trip through the typed schema.
    assert item["sha256_hash"] == "a" * 64
    assert item["file_size"] == 1024
    assert item["can_restore"] is True
    assert item["restore_requires_approval"] is True
    assert item["severity_hint"] == "high"
    assert item["approval_hint"].startswith("high-severity")
    assert inv["source_action_id"] == action_id

    history = client.get(
        f"/endpoints/{agent_id}/response-actions",
        headers=auth_headers(tenant["company_admin_id"]),
    )
    assert history.status_code == 200
    history_rows = history.json()
    assert any(
        row["id"] == action_id and row["status"] == "completed" for row in history_rows
    )


def test_heartbeat_response_action_links_back_to_module_action(
    tenant_hierarchy_factory, auth_headers
) -> None:
    """When the agent reports a response_action via heartbeat (without
    POSTing to /agent/actions/ack), state.py uses matched_indicator to
    backfill module_actions.result + status."""
    agent_id = "agent-qhb-001"
    tenant = tenant_hierarchy_factory(endpoint_id=agent_id)
    client = TestClient(app)

    queue_resp = client.post(
        f"/endpoints/{agent_id}/quarantine-restore",
        json={"quarantine_id": "qr-x", "severity_hint": "low"},
        headers=auth_headers(tenant["company_admin_id"]),
    )
    assert queue_resp.status_code == 200
    action_id = queue_resp.json()["id"]

    secret = _agent_secret(agent_id)
    collected_at = datetime.now(UTC).replace(microsecond=0)
    collected_at_str = collected_at.isoformat()
    response_evidence = {
        "status": "executed",
        "action": "quarantine_restore",
        "executed_at": collected_at_str,
        "restored_path": "/tmp/restored.bin",
    }
    edr_event = {
        "kind": "response_action",
        "rule_id": "remote_action",
        "action": "quarantine_restore",
        "matched_indicator": action_id,
        "policy_version": "policy-v1",
        "collected_at": collected_at_str,
        "response": response_evidence,
    }
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
            "cpu_percent": 1.0,
            "memory_percent": 5.0,
        },
        "edr_events": [edr_event],
    }
    message = f"{agent_id}|e2e-host|linux|{collected_at_str}|policy-v1|1"
    heartbeat_payload["signature"] = hmac.new(
        secret.encode(), message.encode(), hashlib.sha256
    ).hexdigest()

    hb = client.post("/agent/heartbeat", json=heartbeat_payload)
    assert hb.status_code == 200, hb.text

    with connection() as conn, conn.cursor() as cur:
        cur.execute(
            "select status, result from module_actions where id = %s",
            (uuid.UUID(action_id),),
        )
        row = cur.fetchone()
        assert row["status"] == "completed"
        assert row["result"]["status"] == "executed"
        assert row["result"]["restored_path"] == "/tmp/restored.bin"

        # Response-action heartbeat must emit a compliance event with
        # the richer recovery/IR control set (not just detection).
        cur.execute(
            "select evidence_controls from evidence_events "
            "where action = 'agent.response_action' "
            "and scope->>'customer_id' = %s",
            (tenant["customer_id"],),
        )
        comp = cur.fetchone()
        assert comp is not None
        assert "nist-csf-2.0:RS.MI" in comp["evidence_controls"]
        assert "soc2-2017:CC7.5" in comp["evidence_controls"]


def test_quarantine_restore_deny_records_reason_and_evidence(
    tenant_hierarchy_factory, auth_headers
) -> None:
    agent_id = "agent-qdeny-001"
    tenant = tenant_hierarchy_factory(endpoint_id=agent_id)
    requester_id = tenant["company_admin_id"]
    second_operator_id = tenant["msp_id"]
    client = TestClient(app)

    queued = client.post(
        f"/endpoints/{agent_id}/quarantine-restore",
        json={"quarantine_id": "qr-deny", "severity_hint": "high", "reason": "ticket-42"},
        headers=auth_headers(requester_id),
    )
    assert queued.status_code == 200
    action_id = queued.json()["id"]

    # Requester cannot deny their own action either — same dual-auth wall
    # we use for approval would be confusing here, but denial is allowed
    # because it's the safer outcome. We still require the operator to
    # have incidents:edit on the customer.
    deny = client.post(
        f"/endpoints/{agent_id}/quarantine-restore/{action_id}/deny",
        json={"reason": "not a false positive"},
        headers=auth_headers(second_operator_id),
    )
    assert deny.status_code == 200, deny.text
    denied = deny.json()
    assert denied["status"] == "denied"
    assert denied["payload"]["denial_reason"] == "not a false positive"
    assert denied["payload"]["denied_by"] == second_operator_id

    # Re-denying / approving a denied action must 409.
    again = client.post(
        f"/endpoints/{agent_id}/quarantine-restore/{action_id}/approve",
        headers=auth_headers(second_operator_id),
    )
    assert again.status_code == 409

    # Compliance evidence event written with the operator-side controls.
    with connection() as conn, conn.cursor() as cur:
        cur.execute(
            "select evidence_controls, payload from evidence_events "
            "where action = 'endpoint.quarantine.restore_denied' "
            "and scope->>'customer_id' = %s",
            (tenant["customer_id"],),
        )
        row = cur.fetchone()
        assert row is not None
        assert "nist-csf-2.0:RS.AN" in row["evidence_controls"]
        assert row["payload"]["reason"] == "not a false positive"


def test_quarantine_restore_approve_accepts_reason_and_emits_evidence(
    tenant_hierarchy_factory, auth_headers
) -> None:
    agent_id = "agent-qapprove-001"
    tenant = tenant_hierarchy_factory(endpoint_id=agent_id)
    requester_id = tenant["company_admin_id"]
    second_operator_id = tenant["msp_id"]
    client = TestClient(app)

    queued = client.post(
        f"/endpoints/{agent_id}/quarantine-restore",
        json={"quarantine_id": "qr-approve", "severity_hint": "critical"},
        headers=auth_headers(requester_id),
    )
    action_id = queued.json()["id"]

    approved = client.post(
        f"/endpoints/{agent_id}/quarantine-restore/{action_id}/approve",
        json={"reason": "validated by IR lead"},
        headers=auth_headers(second_operator_id),
    )
    assert approved.status_code == 200, approved.text
    body = approved.json()
    assert body["status"] == "queued"
    assert body["payload"]["approval_reason"] == "validated by IR lead"

    with connection() as conn, conn.cursor() as cur:
        cur.execute(
            "select evidence_controls, payload from evidence_events "
            "where action = 'endpoint.quarantine.restore_approved' "
            "and scope->>'customer_id' = %s",
            (tenant["customer_id"],),
        )
        row = cur.fetchone()
        assert row is not None
        # Separation-of-duties + recovery controls.
        assert "iso27001-2022:A.5.18" in row["evidence_controls"]
        assert "soc2-2017:CC6.3" in row["evidence_controls"]
        assert row["payload"]["approved_by"] == second_operator_id
        assert row["payload"]["requested_by"] == requester_id


def test_response_actions_supports_action_and_status_filters(
    tenant_hierarchy_factory, auth_headers
) -> None:
    agent_id = "agent-qfilter-001"
    tenant = tenant_hierarchy_factory(endpoint_id=agent_id)
    admin_id = tenant["company_admin_id"]
    client = TestClient(app)

    client.post(
        f"/endpoints/{agent_id}/quarantine-list",
        json={},
        headers=auth_headers(admin_id),
    )
    client.post(
        f"/endpoints/{agent_id}/quarantine-restore",
        json={"quarantine_id": "qr-f1", "severity_hint": "low"},
        headers=auth_headers(admin_id),
    )
    client.post(
        f"/endpoints/{agent_id}/quarantine-restore",
        json={"quarantine_id": "qr-f2", "severity_hint": "critical"},
        headers=auth_headers(admin_id),
    )

    only_restore = client.get(
        f"/endpoints/{agent_id}/response-actions?action=quarantine_restore",
        headers=auth_headers(admin_id),
    )
    assert only_restore.status_code == 200
    rows = only_restore.json()
    assert rows and all(r["action"] == "quarantine_restore" for r in rows)

    awaiting = client.get(
        f"/endpoints/{agent_id}/response-actions?action=quarantine_restore&status=awaiting_approval",
        headers=auth_headers(admin_id),
    )
    assert awaiting.status_code == 200
    awaiting_rows = awaiting.json()
    assert len(awaiting_rows) == 1
    assert awaiting_rows[0]["payload"]["quarantine_id"] == "qr-f2"

    invalid = client.get(
        f"/endpoints/{agent_id}/response-actions?status=bogus",
        headers=auth_headers(admin_id),
    )
    assert invalid.status_code == 400


def test_pending_quarantine_restores_returns_scoped_inbox(
    tenant_hierarchy_factory, auth_headers
) -> None:
    agent_id = "agent-qpending-001"
    tenant = tenant_hierarchy_factory(endpoint_id=agent_id)
    admin_id = tenant["company_admin_id"]
    client = TestClient(app)

    # One awaiting-approval restore + one already-queued (low severity)
    # restore — only the awaiting one should appear in the inbox.
    awaiting = client.post(
        f"/endpoints/{agent_id}/quarantine-restore",
        json={"quarantine_id": "qr-pending", "severity_hint": "high"},
        headers=auth_headers(admin_id),
    )
    assert awaiting.status_code == 200
    awaiting_id = awaiting.json()["id"]

    client.post(
        f"/endpoints/{agent_id}/quarantine-restore",
        json={"quarantine_id": "qr-direct", "severity_hint": "low"},
        headers=auth_headers(admin_id),
    )

    inbox = client.get(
        "/quarantine-restores/pending",
        headers=auth_headers(admin_id),
    )
    assert inbox.status_code == 200, inbox.text
    rows = inbox.json()
    matching = [r for r in rows if r["action"]["id"] == awaiting_id]
    assert len(matching) == 1
    entry = matching[0]
    assert entry["endpoint_id"] == agent_id
    assert entry["action"]["status"] == "awaiting_approval"
    assert entry["hostname"] is not None
    assert str(entry["customer_id"]) == tenant["customer_id"]

    # customer_id filter narrows to that tenant.
    scoped = client.get(
        f"/quarantine-restores/pending?customer_id={tenant['customer_id']}",
        headers=auth_headers(admin_id),
    )
    assert scoped.status_code == 200
    scoped_ids = {r["action"]["id"] for r in scoped.json()}
    assert awaiting_id in scoped_ids


def test_quarantine_inventory_accepts_legacy_field_aliases(
    tenant_hierarchy_factory, auth_headers
) -> None:
    """An older agent build (or Agent 2 mocks) that sends ``sha256`` /
    ``size_bytes`` must still round-trip cleanly through the typed
    schema."""
    agent_id = "agent-qalias-001"
    tenant = tenant_hierarchy_factory(endpoint_id=agent_id)
    admin_id = tenant["company_admin_id"]
    client = TestClient(app)

    queue_resp = client.post(
        f"/endpoints/{agent_id}/quarantine-list",
        json={},
        headers=auth_headers(admin_id),
    )
    assert queue_resp.status_code == 200
    action_id = queue_resp.json()["id"]

    secret = _agent_secret(agent_id)
    ack = client.post(
        f"/agent/actions/{action_id}/ack?endpoint_id={agent_id}&token={secret}",
        json={
            "status": "completed",
            "result": {
                "status": "executed",
                "quarantine_items": [
                    {
                        "quarantine_id": "q-legacy",
                        "original_path": "/tmp/legacy.bin",
                        "sha256": "c" * 64,
                        "size_bytes": 2048,
                        "severity_hint": "medium",
                    }
                ],
            },
        },
    )
    assert ack.status_code == 200, ack.text

    inv = client.get(
        f"/endpoints/{agent_id}/quarantine-inventory",
        headers=auth_headers(admin_id),
    ).json()
    item = inv["items"][0]
    # Aliases populate the canonical field names.
    assert item["sha256_hash"] == "c" * 64
    assert item["file_size"] == 2048
    # Defaults apply for omitted fields.
    assert item["can_restore"] is True
    assert item["restore_requires_approval"] is False
    assert item["encrypted"] is False

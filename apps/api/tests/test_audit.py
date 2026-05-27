from datetime import UTC, datetime
from hashlib import sha256

from fastapi.testclient import TestClient

from app import db as app_db
from app.main import app
from app.services import audit, jwt_tokens, tenancy


def _owner_auth_header() -> dict[str, str]:
    owner = tenancy.ensure_platform_owner("audit-owner@aetherix.test", "Audit Owner")
    token, _ = jwt_tokens.issue(str(owner.id))
    return {"Authorization": f"Bearer {token}"}


def test_scan_writes_audit_record_without_storing_raw_text(promote_default_policy) -> None:
    promote_default_policy(mode="block", entities=["EMAIL_ADDRESS"])

    client = TestClient(app)
    scan_response = client.post(
        "/dlp/scan",
        json={"text": "Email admin@example.com about the audit.", "source": "test scan"},
    )
    assert scan_response.status_code == 200

    audit_response = client.get("/audit", params={"action": "dlp.scan"}, headers=_owner_auth_header())
    assert audit_response.status_code == 200
    records = audit_response.json()
    assert len(records) == 1
    record = records[0]

    assert record["actor"] == "operator"
    assert record["resource"] == "endpoint:unknown"
    assert "admin@example.com" not in str(record)
    assert record["before_hash"] is not None
    assert record["after_hash"] is not None
    assert record["chain_hash"] != record["before_hash"]


def test_rejected_heartbeat_is_audited(monkeypatch) -> None:
    monkeypatch.setenv("AETHERIX_AGENT_SHARED_SECRET", "test-secret")

    payload = {
        "agent_id": "agent-test",
        "hostname": "ws-1",
        "os": "darwin",
        "collected_at": datetime.now(UTC).replace(microsecond=0).isoformat(),
        "policy_version": "policy-v1",
        "signature": "invalid",
        "signals": {"blocked_events": 0, "dlp_events": 0, "pending_updates": 0},
    }

    client = TestClient(app)
    assert client.post("/agent/heartbeat", json=payload).status_code == 401

    records = client.get("/audit", params={"action": "agent.heartbeat.rejected"}, headers=_owner_auth_header()).json()
    assert len(records) == 1
    assert records[0]["actor"] == "agent:agent-test"
    assert records[0]["resource"] == "agent:agent-test"


def test_chain_detects_tampering() -> None:
    audit.record(action="test.one", resource="r:1", actor="system")
    audit.record(action="test.two", resource="r:2", actor="system")
    audit.record(action="test.three", resource="r:3", actor="system")

    ok, first_bad = audit.verify_chain()
    assert ok is True
    assert first_bad is None

    # Tamper directly in the database. Append-only is a convention; the
    # hash chain is what makes tampering detectable.
    with app_db.connection() as conn, conn.cursor() as cur:
        cur.execute("update audit_log set action = 'test.tampered' where seq = 2")

    ok, first_bad = audit.verify_chain()
    assert ok is False
    assert first_bad == 2


def test_signed_heartbeat_writes_audit(monkeypatch) -> None:
    secret = "test-secret"
    collected_at = datetime.now(UTC).replace(microsecond=0).isoformat()
    monkeypatch.setenv("AETHERIX_AGENT_SHARED_SECRET", secret)

    payload = {
        "agent_id": "agent-test",
        "hostname": "ws-1",
        "os": "darwin",
        "collected_at": collected_at,
        "policy_version": "policy-v1",
        "agent_version": "0.1.0",
        "signals": {"blocked_events": 0, "dlp_events": 0, "pending_updates": 0},
    }
    message = f"{payload['agent_id']}:{payload['hostname']}:{payload['collected_at']}:{payload['policy_version']}:{secret}"
    payload["signature"] = sha256(message.encode()).hexdigest()

    client = TestClient(app)
    assert client.post("/agent/heartbeat", json=payload).status_code == 200

    records = client.get("/audit", params={"action": "agent.heartbeat"}, headers=_owner_auth_header()).json()
    assert len(records) == 1
    assert records[0]["actor"] == "agent:agent-test"

    verify = client.get("/audit/verify", headers=_owner_auth_header()).json()
    assert verify["ok"] is True
    assert verify["first_bad_seq"] is None

from datetime import UTC, datetime
from hashlib import sha256

from fastapi.testclient import TestClient

from app.main import app


def test_signed_heartbeat_is_accepted(monkeypatch) -> None:
    secret = "test-secret"
    collected_at = datetime.now(UTC).replace(microsecond=0).isoformat()
    monkeypatch.setenv("AETHERIX_AGENT_SHARED_SECRET", secret)

    payload = _heartbeat_payload(collected_at)
    payload["signature"] = _signature(payload, secret)

    response = TestClient(app).post("/agent/heartbeat", json=payload)

    assert response.status_code == 200
    assert response.json()["id"] == "agent-test"


def test_invalid_heartbeat_signature_is_rejected(monkeypatch) -> None:
    collected_at = datetime.now(UTC).replace(microsecond=0).isoformat()
    monkeypatch.setenv("AETHERIX_AGENT_SHARED_SECRET", "test-secret")

    payload = _heartbeat_payload(collected_at)
    payload["signature"] = "invalid"

    response = TestClient(app).post("/agent/heartbeat", json=payload)

    assert response.status_code == 401
    assert response.json()["detail"] == "Heartbeat signature is invalid"


def _heartbeat_payload(collected_at: str) -> dict[str, object]:
    return {
        "agent_id": "agent-test",
        "hostname": "workstation-01",
        "os": "darwin",
        "collected_at": collected_at,
        "policy_version": "policy-v1",
        "agent_version": "0.1.0",
        "signals": {
            "blocked_events": 0,
            "dlp_events": 0,
            "pending_updates": 0,
            "cpu_percent": 12.5,
            "memory_percent": 31.0,
        },
    }


def _signature(payload: dict[str, object], secret: str) -> str:
    message = f"{payload['agent_id']}:{payload['hostname']}:{payload['collected_at']}:{payload['policy_version']}:{secret}"
    return sha256(message.encode()).hexdigest()

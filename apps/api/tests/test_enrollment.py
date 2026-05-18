from datetime import UTC, datetime

from fastapi.testclient import TestClient

from app.main import app
from app.services.enrollment import enrolled_heartbeat_signature
from app.schemas import AgentHeartbeat


def _client(monkeypatch) -> TestClient:
    # Make sure the legacy shared-secret path is NOT silently accepting things
    # for enrolled agents during these tests.
    monkeypatch.delenv("AETHERIX_AGENT_SHARED_SECRET", raising=False)
    return TestClient(app)


def _enroll(client: TestClient) -> dict:
    token_response = client.post("/enrollment/tokens", json={"note": "lab", "ttl_seconds": 600})
    assert token_response.status_code == 201, token_response.text
    token = token_response.json()["token"]

    enroll_response = client.post(
        "/agent/enroll",
        json={
            "enrollment_token": token,
            "hostname": "lab-host-1",
            "os": "macOS 14",
        },
    )
    assert enroll_response.status_code == 201, enroll_response.text
    return enroll_response.json()


def _signed_heartbeat(agent_id: str, secret: str, *, nonce: int, collected_at: datetime) -> dict:
    body = AgentHeartbeat(
        agent_id=agent_id,
        hostname="lab-host-1",
        os="macOS 14",
        collected_at=collected_at,
        policy_version="policy-local",
        nonce=nonce,
    )
    signature = enrolled_heartbeat_signature(body, secret)
    payload = body.model_dump(mode="json")
    payload["signature"] = signature
    return payload


def test_enrollment_token_is_single_use(monkeypatch) -> None:
    client = _client(monkeypatch)
    token = client.post("/enrollment/tokens", json={}).json()["token"]

    first = client.post(
        "/agent/enroll",
        json={"enrollment_token": token, "hostname": "h1", "os": "linux"},
    )
    second = client.post(
        "/agent/enroll",
        json={"enrollment_token": token, "hostname": "h2", "os": "linux"},
    )

    assert first.status_code == 201
    assert second.status_code == 400
    assert "already been used" in second.json()["detail"]


def test_enroll_returns_agent_secret_exactly_once(monkeypatch) -> None:
    client = _client(monkeypatch)
    enrolled = _enroll(client)

    assert enrolled["agent_id"].startswith("agent-")
    assert len(enrolled["agent_secret"]) >= 32
    assert "enrolled_at" in enrolled

    endpoints = client.get("/endpoints").json()
    assert all("agent_secret" not in str(e) for e in endpoints)


def test_enrolled_heartbeat_accepted_with_valid_signature(monkeypatch) -> None:
    client = _client(monkeypatch)
    enrolled = _enroll(client)

    payload = _signed_heartbeat(
        enrolled["agent_id"],
        enrolled["agent_secret"],
        nonce=1,
        collected_at=datetime.now(UTC),
    )
    response = client.post("/agent/heartbeat", json=payload)
    assert response.status_code == 200, response.text
    assert response.json()["id"] == enrolled["agent_id"]


def test_enrolled_heartbeat_rejected_when_secret_wrong(monkeypatch) -> None:
    client = _client(monkeypatch)
    enrolled = _enroll(client)

    payload = _signed_heartbeat(
        enrolled["agent_id"],
        "not-the-real-secret",
        nonce=1,
        collected_at=datetime.now(UTC),
    )
    response = client.post("/agent/heartbeat", json=payload)
    assert response.status_code == 401
    assert "signature" in response.json()["detail"].lower()


def test_enrolled_heartbeat_rejects_replay(monkeypatch) -> None:
    client = _client(monkeypatch)
    enrolled = _enroll(client)
    now = datetime.now(UTC)

    first = client.post(
        "/agent/heartbeat",
        json=_signed_heartbeat(enrolled["agent_id"], enrolled["agent_secret"], nonce=5, collected_at=now),
    )
    assert first.status_code == 200

    replay = client.post(
        "/agent/heartbeat",
        json=_signed_heartbeat(enrolled["agent_id"], enrolled["agent_secret"], nonce=5, collected_at=now),
    )
    assert replay.status_code == 401
    assert "nonce" in replay.json()["detail"].lower()

    lower = client.post(
        "/agent/heartbeat",
        json=_signed_heartbeat(enrolled["agent_id"], enrolled["agent_secret"], nonce=4, collected_at=now),
    )
    assert lower.status_code == 401

    next_ok = client.post(
        "/agent/heartbeat",
        json=_signed_heartbeat(enrolled["agent_id"], enrolled["agent_secret"], nonce=6, collected_at=now),
    )
    assert next_ok.status_code == 200


def test_enrolled_heartbeat_requires_nonce_and_signature(monkeypatch) -> None:
    client = _client(monkeypatch)
    enrolled = _enroll(client)

    bare = {
        "agent_id": enrolled["agent_id"],
        "hostname": "lab-host-1",
        "os": "macOS 14",
        "collected_at": datetime.now(UTC).isoformat(),
        "policy_version": "policy-local",
    }
    response = client.post("/agent/heartbeat", json=bare)
    assert response.status_code == 401
    detail = response.json()["detail"].lower()
    assert "nonce" in detail or "signature" in detail


def test_enroll_writes_audit_record_without_leaking_secret(monkeypatch) -> None:
    client = _client(monkeypatch)
    enrolled = _enroll(client)

    records = client.get("/audit", params={"action": "agent.enroll"}).json()
    assert len(records) == 1
    record = records[0]
    assert record["resource"] == f"agent:{enrolled['agent_id']}"
    assert enrolled["agent_secret"] not in str(record)

from fastapi.testclient import TestClient

from app.main import app


def _client(monkeypatch) -> TestClient:
    monkeypatch.delenv("AETHERIX_AGENT_SHARED_SECRET", raising=False)
    return TestClient(app)


def _enroll(client: TestClient) -> dict:
    token_response = client.post("/enrollment/tokens", json={"note": "dlp evidence", "ttl_seconds": 600})
    assert token_response.status_code == 201, token_response.text
    token = token_response.json()["token"]

    enroll_response = client.post(
        "/agent/enroll",
        json={
            "enrollment_token": token,
            "hostname": "dlp-host-1",
            "os": "macOS 14",
        },
    )
    assert enroll_response.status_code == 201, enroll_response.text
    return enroll_response.json()


def test_agent_dlp_evidence_accepts_valid_agent_token(monkeypatch) -> None:
    client = _client(monkeypatch)
    enrolled = _enroll(client)

    payload = {
        "action_type": "paste_blocked",
        "decision": "block",
        "destination": "claude.ai",
        "label_detected": "restricted",
        "content_hash": "sha256:9a1b2c3d4e",
        "policy_version": "hash-v2-1",
        "endpoint_id": enrolled["agent_id"],
        "event_type": "paste",
        "policy_action_field": "paste_sensitive",
        "process_name": "chrome",
    }
    response = client.post(
        "/agent/dlp-evidence",
        params={"endpoint_id": enrolled["agent_id"]},
        headers={"Authorization": f"Bearer {enrolled['agent_secret']}"},
        json=payload,
    )
    assert response.status_code == 200, response.text
    body = response.json()
    assert body["action"] == "dlp.paste_blocked"
    assert body["resource"] == f"endpoint:{enrolled['agent_id']}"
    assert body["payload"]["destination"] == "claude.ai"


def test_agent_dlp_evidence_rejects_invalid_token(monkeypatch) -> None:
    client = _client(monkeypatch)
    enrolled = _enroll(client)

    payload = {
        "action_type": "genai_copy_detected",
        "decision": "review",
        "destination": "chatgpt.com",
        "label_detected": "confidential",
        "content_hash": "sha256:badcafe",
        "policy_version": "hash-v2-2",
        "endpoint_id": enrolled["agent_id"],
        "event_type": "copy",
        "policy_action_field": "copy_to_genai",
        "process_name": "edge",
    }
    response = client.post(
        "/agent/dlp-evidence",
        params={"endpoint_id": enrolled["agent_id"]},
        headers={"Authorization": "Bearer wrong-token"},
        json=payload,
    )
    assert response.status_code == 401
    assert "invalid agent token" in response.json()["detail"]

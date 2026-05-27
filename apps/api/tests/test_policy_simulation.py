from fastapi.testclient import TestClient

from app.main import app
from app.services import jwt_tokens, tenancy


def _owner_headers() -> dict[str, str]:
    owner = tenancy.ensure_platform_owner("policy-sim-owner@aetherix.test", "Policy Sim Owner")
    token, _ = jwt_tokens.issue(str(owner.id))
    return {"Authorization": f"Bearer {token}"}


def _simulation_payload(rules: list[dict] | None = None, mode: str = "block") -> dict:
    return {
        "draft": {
            "name": "Draft for sim",
            "mode_default": mode,
            "escalate_at": "high",
            "genai_guardrail": True,
            "rules": rules
            if rules is not None
            else [{"id": "pii.email", "kind": "entity", "entity_type": "EMAIL_ADDRESS", "action": "block"}],
        },
        "samples": [
            {"text": "Email ops@example.com please.", "source": "doc"},
            {"text": "No PII here.", "source": "doc"},
            {"text": "Call 212-555-0100 today.", "source": "doc"},
        ],
    }


def test_simulation_returns_per_sample_diff(promote_default_policy) -> None:
    promote_default_policy(mode="monitor", entities=["EMAIL_ADDRESS"])

    client = TestClient(app)
    headers = _owner_headers()
    response = client.post("/policies/document/simulate", headers=headers, json=_simulation_payload())
    assert response.status_code == 200
    body = response.json()

    assert body["summary"]["total"] == 3
    assert body["summary"]["would_block"] == 1
    assert body["summary"]["would_allow"] == 2
    assert body["summary"]["would_review"] == 0

    first = body["results"][0]
    assert first["before"]["action"] == "allow"
    assert first["after"]["action"] == "block"
    assert first["changed"] is True
    assert first["after"]["entity_types"] == ["EMAIL_ADDRESS"]


def test_simulation_does_not_mutate_active_policy(promote_default_policy) -> None:
    promote_default_policy(mode="monitor", entities=["EMAIL_ADDRESS"])

    client = TestClient(app)
    headers = _owner_headers()
    before = client.get("/policies/active", headers=headers).json()
    before_document = client.get("/policies/document", headers=headers).json()
    client.post("/policies/document/simulate", headers=headers, json=_simulation_payload())
    after = client.get("/policies/active", headers=headers).json()
    after_document = client.get("/policies/document", headers=headers).json()

    assert before == after
    assert before_document == after_document


def test_simulation_writes_audit_record(promote_default_policy) -> None:
    promote_default_policy(mode="monitor", entities=["EMAIL_ADDRESS"])

    client = TestClient(app)
    headers = _owner_headers()
    client.post("/policies/document/simulate", headers=headers, json=_simulation_payload())

    records = client.get("/audit", params={"action": "policy.simulate"}, headers=headers).json()
    assert len(records) == 1
    token = headers["Authorization"].split(" ", 1)[1]
    claims = jwt_tokens.verify(token)
    assert records[0]["actor"] == claims["sub"]
    assert records[0]["resource"] == "policy:draft"
    # Raw sample text must not leak into the audit record.
    assert "ops@example.com" not in str(records[0])


def test_simulation_unchanged_when_draft_matches_active(promote_default_policy) -> None:
    promote_default_policy(mode="block", entities=["EMAIL_ADDRESS"])

    client = TestClient(app)
    body = client.post("/policies/document/simulate", headers=_owner_headers(), json=_simulation_payload()).json()
    assert body["summary"]["changed"] == 0
    assert all(result["changed"] is False for result in body["results"])


def test_simulation_returns_409_without_active_policy() -> None:
    response = TestClient(app).post(
        "/policies/document/simulate",
        headers=_owner_headers(),
        json=_simulation_payload(),
    )
    assert response.status_code == 409

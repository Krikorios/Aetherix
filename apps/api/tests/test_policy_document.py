from fastapi.testclient import TestClient

from app.main import app
from app.services import policy as policy_service
from app.schemas import PolicyDocument
from app.services import jwt_tokens, tenancy


def _owner_headers() -> dict[str, str]:
    owner = tenancy.ensure_platform_owner("policy-doc-owner@aetherix.test", "Policy Doc Owner")
    token, _ = jwt_tokens.issue(str(owner.id))
    return {"Authorization": f"Bearer {token}"}


def _signed_draft() -> dict:
    return {
        "name": "Block emails",
        "mode_default": "block",
        "escalate_at": "high",
        "genai_guardrail": True,
        "rules": [
            {"id": "pii.email", "kind": "entity", "entity_type": "EMAIL_ADDRESS", "action": "block"},
        ],
    }


def test_promotion_creates_signed_versioned_document(monkeypatch) -> None:
    monkeypatch.setenv("AETHERIX_POLICY_SIGNING_KEY", "unit-test-key")

    client = TestClient(app)
    headers = _owner_headers()
    response = client.post("/policies/document", headers=headers, json=_signed_draft())
    assert response.status_code == 201
    body = response.json()
    assert body["version"] == 1
    assert body["id"].startswith("policy-")
    assert body["signature"]
    assert body["signed_by"] == "control-plane-dev"

    response2 = client.post("/policies/document", headers=headers, json=_signed_draft())
    assert response2.status_code == 201
    assert response2.json()["version"] == 2

    history = client.get("/policies/documents", headers=headers).json()
    assert [d["version"] for d in history] == [2, 1]


def test_signature_verifies_with_matching_key(monkeypatch) -> None:
    monkeypatch.setenv("AETHERIX_POLICY_SIGNING_KEY", "unit-test-key")

    client = TestClient(app)
    raw = client.post("/policies/document", headers=_owner_headers(), json=_signed_draft()).json()
    document = PolicyDocument.model_validate(raw)

    assert policy_service.verify_document(document) is True

    monkeypatch.setenv("AETHERIX_POLICY_SIGNING_KEY", "different-key")
    assert policy_service.verify_document(document) is False


def test_active_policy_derives_from_document(monkeypatch) -> None:
    monkeypatch.setenv("AETHERIX_POLICY_SIGNING_KEY", "unit-test-key")

    client = TestClient(app)
    headers = _owner_headers()
    client.post("/policies/document", headers=headers, json=_signed_draft())

    active = client.get("/policies/active", headers=headers).json()
    assert active["mode"] == "block"
    assert active["protected_entities"] == ["EMAIL_ADDRESS"]
    assert active["id"].startswith("policy-")


def test_scan_uses_promoted_document(monkeypatch) -> None:
    monkeypatch.setenv("AETHERIX_POLICY_SIGNING_KEY", "unit-test-key")

    client = TestClient(app)
    headers = _owner_headers()
    client.post("/policies/document", headers=headers, json=_signed_draft())

    scan = client.post(
        "/dlp/scan",
        json={"text": "Mail us at ops@example.com", "source": "test"},
    ).json()
    assert scan["action"] == "block"
    assert [f["entity_type"] for f in scan["findings"]] == ["EMAIL_ADDRESS"]


def test_promotion_writes_audit_record(monkeypatch) -> None:
    monkeypatch.setenv("AETHERIX_POLICY_SIGNING_KEY", "unit-test-key")

    client = TestClient(app)
    headers = _owner_headers()
    client.post("/policies/document", headers=headers, json=_signed_draft())

    records = client.get("/audit", params={"action": "policy.promote"}, headers=headers).json()
    assert len(records) == 1
    token = headers["Authorization"].split(" ", 1)[1]
    claims = jwt_tokens.verify(token)
    assert records[0]["actor"] == claims["sub"]
    assert records[0]["resource"].startswith("policy:policy-")
    assert records[0]["before_hash"] is None
    assert records[0]["after_hash"] is not None

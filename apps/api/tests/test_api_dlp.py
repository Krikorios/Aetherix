from fastapi.testclient import TestClient

from app.main import app


def test_scan_route_uses_active_policy_mode(promote_default_policy) -> None:
    promote_default_policy(mode="block", entities=["EMAIL_ADDRESS"])

    client = TestClient(app)
    response = client.post(
        "/dlp/scan",
        json={
            "text": "Send the report to admin@example.com before the audit.",
            "source": "test scan",
        },
    )

    assert response.status_code == 200
    payload = response.json()
    assert payload["action"] == "block"
    assert [finding["entity_type"] for finding in payload["findings"]] == ["EMAIL_ADDRESS"]


def test_scan_route_allows_unprotected_findings(promote_default_policy) -> None:
    promote_default_policy(mode="block", entities=["CREDIT_CARD"])

    client = TestClient(app)
    response = client.post(
        "/dlp/scan",
        json={
            "text": "Send the report to admin@example.com before the audit.",
            "source": "test scan",
        },
    )

    assert response.status_code == 200
    payload = response.json()
    assert payload["action"] == "allow"
    assert payload["findings"] == []


def test_scan_route_returns_409_without_active_policy() -> None:
    client = TestClient(app)
    response = client.post(
        "/dlp/scan",
        json={"text": "admin@example.com", "source": "test"},
    )

    assert response.status_code == 409
    assert "policy" in response.json()["detail"].lower()


def test_active_policy_route_returns_409_without_promoted_document() -> None:
    response = TestClient(app).get("/policies/active")
    assert response.status_code == 409

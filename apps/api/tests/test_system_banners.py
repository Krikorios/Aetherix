from datetime import UTC, datetime, timedelta

from fastapi.testclient import TestClient

from app.main import app
from app.schemas import AccountCreate
from app.services import tenancy


client = TestClient(app)


def test_platform_owner_can_publish_and_disable_banner(auth_headers):
    owner = tenancy.ensure_platform_owner("owner-banners@aetherix.test", "Banner Owner")
    headers = auth_headers(str(owner.id))

    response = client.post(
        "/system/banners",
        headers=headers,
        json={
            "message": "Scheduled maintenance tonight.",
            "link_label": "Release Notes",
            "link_url": "https://example.com/release-notes",
            "severity": "warning",
            "ends_at": (datetime.now(UTC) + timedelta(days=1)).isoformat(),
        },
    )

    assert response.status_code == 201
    banner = response.json()
    assert banner["message"] == "Scheduled maintenance tonight."

    active = client.get("/system/banners", headers=headers)
    assert active.status_code == 200
    assert [item["id"] for item in active.json()] == [banner["id"]]

    delete_response = client.delete(f"/system/banners/{banner['id']}", headers=headers)
    assert delete_response.status_code == 204

    active_after_delete = client.get("/system/banners", headers=headers)
    assert active_after_delete.status_code == 200
    assert active_after_delete.json() == []


def test_non_owner_cannot_publish_banner(auth_headers):
    account = tenancy.create_account(
        AccountCreate(
            email="viewer-banners@aetherix.test",
            full_name="Banner Viewer",
            password="Password123!",
        )
    )

    response = client.post(
        "/system/banners",
        headers=auth_headers(str(account.id)),
        json={"message": "Should not publish", "severity": "warning"},
    )

    assert response.status_code == 403

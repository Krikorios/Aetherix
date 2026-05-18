from urllib.parse import parse_qs, urlparse

from fastapi.testclient import TestClient

from app.main import app


def test_customer_quick_create_generates_installers_and_quick_links(monkeypatch) -> None:
    monkeypatch.setenv("AETHERIX_PUBLIC_URL", "https://console.test")
    client = TestClient(app)

    response = client.post(
        "/customers/quick-create",
        json={
            "name": "Northwind Dental",
            "industry": "Healthcare",
            "country": "US",
            "company_size": "11-50",
            "platforms": ["windows_msi", "macos_pkg"],
            "installer_ttl_seconds": 3600,
            "created_by": "msp-admin",
        },
    )

    assert response.status_code == 201, response.text
    body = response.json()
    customer = body["customer"]
    assert customer["name"] == "Northwind Dental"
    assert customer["customer_number"].startswith("CUST-")
    assert customer["assigned_policy_name"] == "SMB Baseline Protection"
    assert body["assignment"]["policy_name"] == "SMB Baseline Protection"

    installers = body["installers"]
    assert [installer["platform"] for installer in installers] == ["windows_msi", "macos_pkg"]
    assert all(installer["status"] == "ready" for installer in installers)
    assert all(installer["enrollment_token"] for installer in installers)
    assert installers[0]["install_profile"]["customer_id"] == customer["id"]
    assert installers[0]["install_profile"]["profile_signature"]

    links = body["quick_deploy_links"]
    assert len(links) == 2
    assert links[0]["url"].startswith("https://console.test/quick-deploy/")
    assert "secret_hash" not in str(links)


def test_quick_deploy_link_mints_tenant_bound_enrollment_token(monkeypatch) -> None:
    monkeypatch.setenv("AETHERIX_PUBLIC_URL", "https://console.test")
    client = TestClient(app)

    created = client.post(
        "/customers/quick-create",
        json={"name": "Contoso Plumbing", "platforms": ["linux_deb"]},
    ).json()
    link = created["quick_deploy_links"][0]
    parsed = urlparse(link["url"])
    secret = parse_qs(parsed.query)["secret"][0]

    manifest_response = client.get(f"/quick-deploy/{link['id']}", params={"secret": secret})
    assert manifest_response.status_code == 200, manifest_response.text
    manifest = manifest_response.json()
    assert manifest["customer"]["id"] == created["customer"]["id"]
    assert manifest["installer"]["install_profile"]["platform"] == "linux_deb"
    assert manifest["enrollment_token"]

    enrollment = client.post(
        "/agent/enroll",
        json={
            "enrollment_token": manifest["enrollment_token"],
            "hostname": "front-desk-01",
            "os": "linux",
        },
    )
    assert enrollment.status_code == 201, enrollment.text
    enrolled = enrollment.json()
    assert enrolled["customer_id"] == created["customer"]["id"]
    assert enrolled["policy_package_id"] == created["assignment"]["policy_package_id"]

    policy = client.get(f"/agent/{enrolled['agent_id']}/policy")
    assert policy.status_code == 200, policy.text
    assert policy.json()["name"] == "SMB Baseline Protection"
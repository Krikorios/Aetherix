import io
import json
import tarfile
import uuid
from urllib.parse import parse_qs, urlparse

from fastapi.testclient import TestClient

from app import db as app_db
from app.main import app
from app.schemas import AccountCreate, RoleAssignmentRequest
from app.services import tenancy


def _bootstrap_owner_headers(auth_headers) -> dict[str, str]:
    owner = tenancy.ensure_platform_owner("owner@aetherix.test", "Owner")
    return auth_headers(str(owner.id))


def _make_partner_customer(name: str = "Scoped Co") -> tuple[uuid.UUID, uuid.UUID]:
    partner_id = uuid.uuid4()
    customer_id = uuid.uuid4()
    with app_db.connection() as conn, conn.cursor() as cur:
        cur.execute(
            """
            insert into partners (id, name, slug, deployment_mode, created_at, tier)
            values (%s, %s, %s, 'cloud', now(), 'msp')
            """,
            (partner_id, f"Partner {name}", f"p-{partner_id.hex[:8]}"),
        )
        cur.execute(
            """
            insert into customers (id, partner_id, customer_number, name, status, created_by, created_at)
            values (%s, %s, %s, %s, 'active', 'tests', now())
            """,
            (customer_id, partner_id, f"C-{customer_id.hex[:8]}", name),
        )
    return partner_id, customer_id


def test_customer_quick_create_generates_installers_and_quick_links(monkeypatch, auth_headers) -> None:
    monkeypatch.setenv("AETHERIX_PUBLIC_URL", "https://console.test")
    client = TestClient(app)

    response = client.post(
        "/customers/quick-create",
        headers=_bootstrap_owner_headers(auth_headers),
        json={
            "name": "Northwind Dental",
            "company_type": "partner",
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
    assert customer["company_type"] == "partner"
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


def test_quick_deploy_link_mints_tenant_bound_enrollment_token(monkeypatch, auth_headers) -> None:
    monkeypatch.setenv("AETHERIX_PUBLIC_URL", "https://console.test")
    client = TestClient(app)

    created = client.post(
        "/customers/quick-create",
        headers=_bootstrap_owner_headers(auth_headers),
        json={"name": "Contoso Plumbing", "platforms": ["linux_deb"]},
    ).json()
    link = created["quick_deploy_links"][0]
    parsed = urlparse(link["url"])
    secret = parse_qs(parsed.query)["secret"][0]

    download_response = client.get(f"/quick-deploy/{link['id']}", params={"secret": secret})
    assert download_response.status_code == 200, download_response.text
    assert download_response.headers["content-type"] == "application/octet-stream"
    assert "aetherix-agent-linux_deb.tar.gz" in download_response.headers["content-disposition"]

    with tarfile.open(fileobj=io.BytesIO(download_response.content), mode="r:gz") as archive:
        profile_file = archive.extractfile("install-profile.json")
        assert profile_file is not None
        manifest = json.loads(profile_file.read().decode("utf-8"))

    assert manifest["customer_id"] == created["customer"]["id"]
    assert manifest["platform"] == "linux_deb"
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


def test_existing_customer_can_be_updated_and_regenerate_artifacts(monkeypatch, auth_headers) -> None:
    monkeypatch.setenv("AETHERIX_PUBLIC_URL", "https://console.test")
    client = TestClient(app)
    headers = _bootstrap_owner_headers(auth_headers)

    created = client.post(
        "/customers/quick-create",
        headers=headers,
        json={"name": "Legacy Office", "platforms": ["windows_msi"]},
    ).json()
    customer_id = created["customer"]["id"]
    policy_package_id = created["assignment"]["policy_package_id"]

    updated = client.put(
        f"/customers/{customer_id}",
        headers=headers,
        json={
            "name": "Legacy Office Updated",
            "industry": "Legal",
            "country": "CA",
            "company_size": "51-250",
            "policy_package_id": policy_package_id,
            "updated_by": "msp-admin",
        },
    )
    assert updated.status_code == 200, updated.text
    assert updated.json()["name"] == "Legacy Office Updated"
    assert updated.json()["assigned_policy_package_id"] == policy_package_id

    installers = client.post(
        f"/customers/{customer_id}/installers",
        headers=headers,
        json={"platforms": ["windows_exe", "linux_rpm"], "created_by": "msp-admin"},
    )
    assert installers.status_code == 201, installers.text
    assert [installer["platform"] for installer in installers.json()] == ["windows_exe", "linux_rpm"]

    links = client.post(
        f"/customers/{customer_id}/quick-deploy",
        headers=headers,
        json={"platforms": ["windows_exe", "linux_rpm"], "created_by": "msp-admin"},
    )
    assert links.status_code == 201, links.text
    assert [link["platform"] for link in links.json()] == ["windows_exe", "linux_rpm"]


def test_legacy_customer_routes_require_auth() -> None:
    response = TestClient(app).get("/customers")
    assert response.status_code == 401


def test_legacy_customer_detail_respects_scope(auth_headers) -> None:
    partner_a, _ = _make_partner_customer("A")
    _, foreign_customer = _make_partner_customer("B")
    msp = tenancy.create_account(
        AccountCreate(
            email="msp-legacy@partner.test",
            full_name="MSP Legacy",
            initial_role=RoleAssignmentRequest(role_code="msp_partner", partner_id=partner_a),
        )
    )

    response = TestClient(app).get(
        f"/customers/{foreign_customer}",
        headers=auth_headers(str(msp.id)),
    )
    assert response.status_code == 403
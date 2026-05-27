"""Tests for the Companies + Licensing endpoints and RBAC scoping."""

from __future__ import annotations

import uuid
from datetime import UTC, date, datetime

from fastapi.testclient import TestClient

from app import db as app_db
from app.main import app
from app.schemas import AccountCreate, CompanyLicenseAssign, RoleAssignmentRequest
from app.services import licensing, tenancy


client = TestClient(app)


def _platform_owner() -> str:
    return str(tenancy.ensure_platform_owner("owner@menagenix.test", "Owner").id)


def _make_partner(slug: str = "p1") -> uuid.UUID:
    partner_id = uuid.uuid4()
    with app_db.connection() as conn, conn.cursor() as cur:
        cur.execute(
            """
            insert into partners (id, name, slug, deployment_mode, created_at, tier)
            values (%s, %s, %s, 'cloud', %s, 'msp')
            """,
            (partner_id, f"Partner {slug}", f"{slug}-{partner_id.hex[:6]}", datetime.now(UTC)),
        )
    return partner_id


def _make_customer(partner_id: uuid.UUID, name: str = "Acme") -> uuid.UUID:
    customer_id = uuid.uuid4()
    with app_db.connection() as conn, conn.cursor() as cur:
        cur.execute(
            """
            insert into customers (
                id, partner_id, customer_number, name, status, created_by, created_at
            ) values (%s, %s, %s, %s, 'active', 'tests', %s)
            """,
            (customer_id, partner_id, f"C-{customer_id.hex[:8]}", name, datetime.now(UTC)),
        )
    return customer_id


# --- Subscription catalog --------------------------------------------------


def test_default_catalog_seeded_via_endpoint(auth_headers):
    owner_id = _platform_owner()
    response = client.get("/subscriptions", headers=auth_headers(owner_id))
    assert response.status_code == 200
    skus = {s["sku"] for s in response.json()}
    assert {"core", "core-plus-xdr", "enterprise"}.issubset(skus)


def test_subscription_creation_requires_licensing_manage(auth_headers):
    owner_id = _platform_owner()
    partner_id = _make_partner()
    customer_id = _make_customer(partner_id)
    viewer = tenancy.create_account(
        AccountCreate(
            email="v@example.com",
            full_name="Viewer",
            initial_role=RoleAssignmentRequest(
                role_code="company_viewer", customer_id=customer_id
            ),
        )
    )
    payload = {
        "sku": "custom-1",
        "display_name": "Custom",
        "tier": "core",
    }
    deny = client.post(
        "/subscriptions",
        headers=auth_headers(str(viewer.id)),
        json=payload,
    )
    assert deny.status_code == 403

    allow = client.post(
        "/subscriptions",
        headers=auth_headers(owner_id),
        json=payload,
    )
    assert allow.status_code == 201, allow.text


# --- Companies scope filtering ---------------------------------------------


def test_companies_list_scope_for_platform_owner(auth_headers):
    owner_id = _platform_owner()
    licensing.ensure_default_catalog()
    p1 = _make_partner("p1")
    p2 = _make_partner("p2")
    c1 = _make_customer(p1, "Alpha")
    c2 = _make_customer(p2, "Beta")

    response = client.get("/companies", headers=auth_headers(owner_id))
    assert response.status_code == 200
    ids = {c["id"] for c in response.json()}
    assert str(c1) in ids and str(c2) in ids


def test_company_summary_includes_license_without_per_company_route(auth_headers):
    owner_id = _platform_owner()
    licensing.ensure_default_catalog()
    partner_id = _make_partner("summary")
    customer_id = _make_customer(partner_id, "SummaryCo")
    licensing.assign_license(
        customer_id,
        CompanyLicenseAssign(subscription_sku="core", total_seats=12),
        actor=owner_id,
    )

    response = client.get("/companies/summary", headers=auth_headers(owner_id))
    assert response.status_code == 200, response.text
    body = response.json()
    rows = body["items"]
    assert body["total"] >= 1
    summary = next(row for row in rows if row["customer"]["id"] == str(customer_id))
    assert summary["customer"]["name"] == "SummaryCo"
    assert summary["license"]["subscription_sku"] == "core"
    assert summary["license"]["products"]


def test_company_summary_applies_search_status_and_pagination(auth_headers):
    owner_id = _platform_owner()
    partner_id = _make_partner("summary-page")
    first = _make_customer(partner_id, "Page Alpha")
    second = _make_customer(partner_id, "Page Beta")
    client.post(
        "/companies/bulk-status",
        headers=auth_headers(owner_id),
        json={"ids": [str(second)], "status": "archived"},
    )

    response = client.get(
        "/companies/summary?q=Page&status=active&limit=1&offset=0",
        headers=auth_headers(owner_id),
    )
    assert response.status_code == 200, response.text
    body = response.json()
    assert body["total"] == 1
    assert body["limit"] == 1
    assert body["offset"] == 0
    assert [row["customer"]["id"] for row in body["items"]] == [str(first)]


def test_bulk_company_status_updates_visible_companies(auth_headers):
    owner_id = _platform_owner()
    partner_id = _make_partner("bulk-status")
    first = _make_customer(partner_id, "Bulk One")
    second = _make_customer(partner_id, "Bulk Two")

    response = client.post(
        "/companies/bulk-status",
        headers=auth_headers(owner_id),
        json={"ids": [str(first), str(second)], "status": "suspended"},
    )
    assert response.status_code == 200, response.text
    assert response.json() == {"ok_count": 2, "failures": []}

    statuses = {
        row["id"]: row["status"]
        for row in client.get("/companies", headers=auth_headers(owner_id)).json()
    }
    assert statuses[str(first)] == "suspended"
    assert statuses[str(second)] == "suspended"


def test_companies_list_scope_for_msp_partner(auth_headers):
    p1 = _make_partner("alpha")
    p2 = _make_partner("beta")
    c1 = _make_customer(p1, "AlphaCo")
    c2 = _make_customer(p2, "BetaCo")
    msp = tenancy.create_account(
        AccountCreate(
            email="msp@example.com",
            full_name="MSP",
            initial_role=RoleAssignmentRequest(
                role_code="msp_partner", partner_id=p1
            ),
        )
    )
    response = client.get("/companies", headers=auth_headers(str(msp.id)))
    assert response.status_code == 200
    ids = {c["id"] for c in response.json()}
    assert str(c1) in ids
    assert str(c2) not in ids


def test_msp_cannot_access_company_outside_partner(auth_headers):
    p1 = _make_partner("a")
    p2 = _make_partner("b")
    foreign_customer = _make_customer(p2)
    msp = tenancy.create_account(
        AccountCreate(
            email="msp2@example.com",
            full_name="MSP",
            initial_role=RoleAssignmentRequest(
                role_code="msp_partner", partner_id=p1
            ),
        )
    )
    response = client.get(
        f"/companies/{foreign_customer}",
        headers=auth_headers(str(msp.id)),
    )
    assert response.status_code == 403


# --- License assignment ----------------------------------------------------


def test_assign_license_creates_products_and_records_audit(auth_headers):
    owner_id = _platform_owner()
    partner_id = _make_partner()
    customer_id = _make_customer(partner_id)
    licensing.ensure_default_catalog()

    payload = CompanyLicenseAssign(
        subscription_sku="core",
        payment_plan="annual",
        total_seats=50,
        reserved_seats=10,
        addons=["semantic_dlp", "xdr"],
        auto_renewal=True,
        minimum_usage=5,
    ).model_dump()

    response = client.put(
        f"/companies/{customer_id}/license",
        headers=auth_headers(owner_id),
        json=payload,
    )
    assert response.status_code == 200, response.text
    body = response.json()
    assert body["subscription_sku"] == "core"
    assert body["total_seats"] == 50
    assert body["reserved_seats"] == 10
    assert set(body["addons"]) == {"semantic_dlp", "xdr"}
    product_codes = {p["product_code"] for p in body["products"]}
    assert {"endpoint_security", "semantic_dlp", "xdr"}.issubset(product_codes)
    assert body["license_key"].startswith("AETHX-")


def test_assign_license_rejects_unknown_addon(auth_headers):
    owner_id = _platform_owner()
    partner_id = _make_partner()
    customer_id = _make_customer(partner_id)
    licensing.ensure_default_catalog()

    payload = CompanyLicenseAssign(
        subscription_sku="core",
        total_seats=10,
        addons=["does_not_exist"],
    ).model_dump()
    response = client.put(
        f"/companies/{customer_id}/license",
        headers=auth_headers(owner_id),
        json=payload,
    )
    assert response.status_code == 400


def test_get_license_null_when_unassigned(auth_headers):
    owner_id = _platform_owner()
    partner_id = _make_partner()
    customer_id = _make_customer(partner_id)
    response = client.get(
        f"/companies/{customer_id}/license",
        headers=auth_headers(owner_id),
    )
    assert response.status_code == 200
    assert response.json() is None


def test_get_license_contract_returns_json_null_when_unassigned(auth_headers):
    """Contract: unassigned license returns JSON null (HTTP 200), not 404."""

    owner_id = _platform_owner()
    partner_id = _make_partner()
    customer_id = _make_customer(partner_id)

    response = client.get(
        f"/companies/{customer_id}/license",
        headers=auth_headers(owner_id),
    )

    assert response.status_code == 200
    assert response.headers["content-type"].startswith("application/json")
    assert response.text.strip() == "null"


def test_get_license_contract_returns_license_object_when_assigned(auth_headers):
    """Contract: assigned license returns a JSON object with key fields."""

    owner_id = _platform_owner()
    partner_id = _make_partner()
    customer_id = _make_customer(partner_id)
    licensing.ensure_default_catalog()
    client.put(
        f"/companies/{customer_id}/license",
        headers=auth_headers(owner_id),
        json=CompanyLicenseAssign(subscription_sku="core", total_seats=25).model_dump(),
    ).raise_for_status()

    response = client.get(
        f"/companies/{customer_id}/license",
        headers=auth_headers(owner_id),
    )

    assert response.status_code == 200
    body = response.json()
    assert isinstance(body, dict)
    assert body["customer_id"] == str(customer_id)
    assert body["subscription_sku"] == "core"
    assert body["status"] == "active"
    assert isinstance(body["products"], list)


def test_company_viewer_cannot_modify_license_but_can_view(auth_headers):
    owner_id = _platform_owner()
    partner_id = _make_partner()
    customer_id = _make_customer(partner_id)
    licensing.ensure_default_catalog()

    # Owner assigns the license
    client.put(
        f"/companies/{customer_id}/license",
        headers=auth_headers(owner_id),
        json=CompanyLicenseAssign(subscription_sku="core", total_seats=10).model_dump(),
    ).raise_for_status()

    viewer = tenancy.create_account(
        AccountCreate(
            email="cview@example.com",
            full_name="CView",
            initial_role=RoleAssignmentRequest(
                role_code="company_viewer", customer_id=customer_id
            ),
        )
    )
    view = client.get(
        f"/companies/{customer_id}/license",
        headers=auth_headers(str(viewer.id)),
    )
    assert view.status_code == 200

    modify = client.put(
        f"/companies/{customer_id}/license",
        headers=auth_headers(str(viewer.id)),
        json=CompanyLicenseAssign(subscription_sku="core", total_seats=20).model_dump(),
    )
    assert modify.status_code == 403


def test_usage_endpoint_returns_recorded_rows(auth_headers):
    owner_id = _platform_owner()
    partner_id = _make_partner()
    customer_id = _make_customer(partner_id)
    licensing.ensure_default_catalog()
    licensing.assign_license(
        customer_id,
        CompanyLicenseAssign(subscription_sku="core", total_seats=10),
        actor="tests",
    )
    licensing.record_daily_usage(
        customer_id, "endpoint_security", day=date(2026, 5, 1), active_seats=7
    )
    licensing.record_daily_usage(
        customer_id, "endpoint_security", day=date(2026, 5, 2), active_seats=9
    )

    response = client.get(
        f"/companies/{customer_id}/license/usage?since=2026-05-01&until=2026-05-31",
        headers=auth_headers(owner_id),
    )
    assert response.status_code == 200
    rows = response.json()
    assert len(rows) == 2
    assert rows[0]["active_seats"] == 7
    assert rows[1]["active_seats"] == 9

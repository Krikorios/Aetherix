"""Tests for accounts, role assignments, RBAC, and /me."""

from __future__ import annotations

import uuid
from datetime import UTC, datetime

import pytest
from fastapi.testclient import TestClient

from app import db as app_db
from app.main import app
from app.schemas import AccountCreate, RoleAssignmentRequest
from app.services import tenancy


client = TestClient(app)


def _platform_owner() -> str:
    account = tenancy.ensure_platform_owner("owner@menagenix.test", "Owner One")
    return str(account.id)


def _make_partner() -> uuid.UUID:
    partner_id = uuid.uuid4()
    with app_db.connection() as conn, conn.cursor() as cur:
        cur.execute(
            """
            insert into partners (id, name, slug, deployment_mode, created_at, tier)
            values (%s, %s, %s, 'cloud', %s, 'msp')
            """,
            (partner_id, f"Partner {partner_id}", f"p-{partner_id.hex[:8]}", datetime.now(UTC)),
        )
    return partner_id


def _make_customer(partner_id: uuid.UUID) -> uuid.UUID:
    customer_id = uuid.uuid4()
    with app_db.connection() as conn, conn.cursor() as cur:
        cur.execute(
            """
            insert into customers (
                id, partner_id, customer_number, name, status, created_by, created_at
            ) values (%s, %s, %s, %s, 'active', 'tests', %s)
            """,
            (customer_id, partner_id, f"C-{customer_id.hex[:8]}", "Acme", datetime.now(UTC)),
        )
    return customer_id


def test_roles_are_seeded():
    roles = {r.code for r in tenancy.list_roles()}
    assert roles == {
        "platform_owner",
        "msp_partner",
        "company_admin",
        "company_tech",
        "company_viewer",
    }


def test_create_account_and_initial_role():
    account = tenancy.create_account(
        AccountCreate(email="alice@example.com", full_name="Alice")
    )
    assert account.status == "invited"
    assert account.roles == []

    fetched = tenancy.get_account(account.id)
    assert fetched is not None
    assert fetched.email == "alice@example.com"


def test_platform_owner_assignment_must_be_unscoped():
    account = tenancy.create_account(
        AccountCreate(email="bob@example.com", full_name="Bob")
    )
    with pytest.raises(tenancy.TenancyError):
        tenancy.assign_role(
            account.id,
            RoleAssignmentRequest(role_code="platform_owner", partner_id=uuid.uuid4()),
            granted_by="tests",
        )


def test_msp_partner_assignment_requires_partner_id():
    account = tenancy.create_account(
        AccountCreate(email="carol@example.com", full_name="Carol")
    )
    with pytest.raises(tenancy.TenancyError):
        tenancy.assign_role(
            account.id,
            RoleAssignmentRequest(role_code="msp_partner"),
            granted_by="tests",
        )


def test_company_role_requires_customer_id():
    account = tenancy.create_account(
        AccountCreate(email="dave@example.com", full_name="Dave")
    )
    with pytest.raises(tenancy.TenancyError):
        tenancy.assign_role(
            account.id,
            RoleAssignmentRequest(role_code="company_admin"),
            granted_by="tests",
        )


def test_has_permission_platform_owner_sees_everything():
    account = tenancy.ensure_platform_owner("owner@menagenix.test", "Owner")
    partner_id = _make_partner()
    customer_id = _make_customer(partner_id)

    assert tenancy.has_permission(account, "companies", "manage")
    assert tenancy.has_permission(
        account, "companies", "manage", partner_id=partner_id
    )
    assert tenancy.has_permission(
        account, "accounts", "manage", customer_id=customer_id
    )


def test_has_permission_msp_partner_scoped_to_partner():
    partner_a = _make_partner()
    partner_b = _make_partner()
    account = tenancy.create_account(
        AccountCreate(
            email="msp@example.com",
            full_name="MSP",
            initial_role=RoleAssignmentRequest(
                role_code="msp_partner", partner_id=partner_a
            ),
        )
    )

    assert tenancy.has_permission(
        account, "companies", "manage", partner_id=partner_a
    )
    assert not tenancy.has_permission(
        account, "companies", "manage", partner_id=partner_b
    )


def test_has_permission_company_admin_scoped_to_customer():
    partner_id = _make_partner()
    customer_a = _make_customer(partner_id)
    customer_b = _make_customer(partner_id)
    account = tenancy.create_account(
        AccountCreate(
            email="admin@example.com",
            full_name="Admin",
            initial_role=RoleAssignmentRequest(
                role_code="company_admin", customer_id=customer_a
            ),
        )
    )

    assert tenancy.has_permission(
        account, "accounts", "manage", customer_id=customer_a
    )
    assert not tenancy.has_permission(
        account, "accounts", "manage", customer_id=customer_b
    )
    # company_admin only has view on companies, not manage
    assert tenancy.has_permission(
        account, "companies", "view", customer_id=customer_a
    )
    assert not tenancy.has_permission(
        account, "companies", "manage", customer_id=customer_a
    )


def test_compute_scope_reflects_assignments():
    partner_id = _make_partner()
    customer_id = _make_customer(partner_id)
    account = tenancy.create_account(
        AccountCreate(
            email="multi@example.com",
            full_name="Multi",
            initial_role=RoleAssignmentRequest(
                role_code="msp_partner", partner_id=partner_id
            ),
        )
    )
    tenancy.assign_role(
        account.id,
        RoleAssignmentRequest(role_code="company_tech", customer_id=customer_id),
        granted_by="tests",
    )
    refreshed = tenancy.get_account(account.id)
    assert refreshed is not None
    scope = tenancy.compute_scope(refreshed)
    assert scope.is_platform is False
    assert partner_id in scope.partner_ids
    assert customer_id in scope.customer_ids


# --- HTTP-level checks ------------------------------------------------------


def test_me_requires_account_header():
    response = client.get("/me")
    assert response.status_code == 401


def test_me_returns_permissions_and_scope():
    owner_id = _platform_owner()
    response = client.get("/me", headers={"X-Aetherix-Account": owner_id})
    assert response.status_code == 200, response.text
    body = response.json()
    assert body["permissions"]["companies"] == "manage"
    assert body["scope"]["is_platform"] is True


def test_accounts_endpoint_blocks_low_privilege_caller():
    partner_id = _make_partner()
    customer_id = _make_customer(partner_id)
    viewer = tenancy.create_account(
        AccountCreate(
            email="viewer@example.com",
            full_name="Viewer",
            initial_role=RoleAssignmentRequest(
                role_code="company_viewer", customer_id=customer_id
            ),
        )
    )
    response = client.get(
        "/accounts", headers={"X-Aetherix-Account": str(viewer.id)}
    )
    assert response.status_code == 403


def test_accounts_create_via_api():
    owner_id = _platform_owner()
    response = client.post(
        "/accounts",
        headers={"X-Aetherix-Account": owner_id},
        json={"email": "new@example.com", "full_name": "New User"},
    )
    assert response.status_code == 201, response.text
    body = response.json()
    assert body["account"]["email"] == "new@example.com"
    assert body["account"]["status"] == "invited"
    # Default delivery is email — invite_url must not be exposed.
    assert body["delivery"] == "email"
    assert body["invite_url"] is None


def test_accounts_create_with_link_delivery_returns_invite_url():
    owner_id = _platform_owner()
    response = client.post(
        "/accounts",
        headers={"X-Aetherix-Account": owner_id},
        json={
            "email": "link-invite@example.com",
            "full_name": "Link Invite",
            "delivery": "link",
        },
    )
    assert response.status_code == 201, response.text
    body = response.json()
    assert body["delivery"] == "link"
    assert body["invite_url"], "invite_url should be returned for link delivery"
    assert "/#/invite/" in body["invite_url"]
    assert body["invite_expires_at"] is not None

    token = body["invite_url"].rsplit("/", 1)[-1]
    accept = client.post(
        "/auth/accept-invite",
        json={"token": token, "password": "SetMyP@ssw0rd!"},
    )
    assert accept.status_code == 200, accept.text
    activated = accept.json()
    assert activated["status"] == "active"
    assert activated["email"] == "link-invite@example.com"

    # Token must be single-use.
    second = client.post(
        "/auth/accept-invite",
        json={"token": token, "password": "AnotherP@ss1!"},
    )
    assert second.status_code == 400


def test_assign_role_via_api():
    owner_id = _platform_owner()
    target = tenancy.create_account(
        AccountCreate(email="target@example.com", full_name="Target")
    )
    partner_id = _make_partner()
    customer_id = _make_customer(partner_id)
    response = client.post(
        f"/accounts/{target.id}/roles",
        headers={"X-Aetherix-Account": owner_id},
        json={"role_code": "company_admin", "customer_id": str(customer_id)},
    )
    assert response.status_code == 201, response.text
    assignment = response.json()
    assert assignment["role_code"] == "company_admin"
    assert assignment["customer_id"] == str(customer_id)


def test_delete_account_removes_account_and_roles():
    owner_id = _platform_owner()
    target = tenancy.create_account(
        AccountCreate(email="delete-me@example.com", full_name="Delete Me")
    )
    partner_id = _make_partner()
    customer_id = _make_customer(partner_id)
    tenancy.assign_role(
        target.id,
        RoleAssignmentRequest(role_code="company_admin", customer_id=customer_id),
        granted_by=owner_id,
    )

    response = client.delete(
        f"/accounts/{target.id}",
        headers={"X-Aetherix-Account": owner_id},
    )
    assert response.status_code == 204, response.text
    assert tenancy.get_account(target.id) is None

    with app_db.connection() as conn, conn.cursor() as cur:
        cur.execute(
            "select count(*) as n from account_roles where account_id = %s",
            (target.id,),
        )
        assert cur.fetchone()["n"] == 0


def test_delete_account_blocks_self_delete():
    owner_id = _platform_owner()
    response = client.delete(
        f"/accounts/{owner_id}",
        headers={"X-Aetherix-Account": owner_id},
    )
    assert response.status_code == 400
    assert tenancy.get_account(uuid.UUID(owner_id)) is not None


def test_delete_account_returns_404_for_unknown_id():
    owner_id = _platform_owner()
    response = client.delete(
        f"/accounts/{uuid.uuid4()}",
        headers={"X-Aetherix-Account": owner_id},
    )
    assert response.status_code == 404


def test_bulk_delete_accounts_reports_successes_and_self_delete_failure():
    owner_id = _platform_owner()
    first = tenancy.create_account(
        AccountCreate(email="bulk-delete-1@example.com", full_name="Bulk One")
    )
    second = tenancy.create_account(
        AccountCreate(email="bulk-delete-2@example.com", full_name="Bulk Two")
    )

    response = client.post(
        "/accounts/bulk-delete",
        headers={"X-Aetherix-Account": owner_id},
        json={"ids": [str(first.id), owner_id, str(second.id)]},
    )
    assert response.status_code == 200, response.text
    body = response.json()
    assert body["ok_count"] == 2
    assert body["failures"] == [
        {"id": owner_id, "error": "cannot delete your own account"}
    ]
    assert tenancy.get_account(first.id) is None
    assert tenancy.get_account(second.id) is None
    assert tenancy.get_account(uuid.UUID(owner_id)) is not None


def test_delete_company_purges_children():
    owner_id = _platform_owner()
    partner_id = _make_partner()
    customer_id = _make_customer(partner_id)

    # Seed a few child rows across the cleanup tables.
    with app_db.connection() as conn, conn.cursor() as cur:
        cur.execute(
            """
            insert into customer_groups (id, customer_id, name, created_at)
            values (%s, %s, %s, %s)
            """,
            (uuid.uuid4(), customer_id, "g1", datetime.now(UTC)),
        )
        cur.execute(
            """
            insert into enrollment_tokens (token_hash, customer_id, created_at, expires_at)
            values (%s, %s, %s, %s)
            """,
            (
                f"hash-{uuid.uuid4().hex}",
                customer_id,
                datetime.now(UTC),
                datetime.now(UTC),
            ),
        )

    response = client.delete(
        f"/companies/{customer_id}",
        headers={"X-Aetherix-Account": owner_id},
    )
    assert response.status_code == 204, response.text

    with app_db.connection() as conn, conn.cursor() as cur:
        cur.execute("select count(*) as n from customers where id = %s", (customer_id,))
        assert cur.fetchone()["n"] == 0
        cur.execute(
            "select count(*) as n from customer_groups where customer_id = %s",
            (customer_id,),
        )
        assert cur.fetchone()["n"] == 0
        cur.execute(
            "select count(*) as n from enrollment_tokens where customer_id = %s",
            (customer_id,),
        )
        assert cur.fetchone()["n"] == 0


def test_delete_company_returns_404_for_unknown_id():
    owner_id = _platform_owner()
    response = client.delete(
        f"/companies/{uuid.uuid4()}",
        headers={"X-Aetherix-Account": owner_id},
    )
    assert response.status_code == 404

"""Tests for the P0/P1 audit remediation:

* JWT bearer authentication via ``/auth/login`` + ``/auth/totp/verify``.
* Privilege-escalation guard on role assignments (no actor may grant a
  role they cannot themselves grant).
* Tenant-scoped account listing — MSP partners see only their own customers.
* Platform-only access to the subscription SKU catalog.
* Subscription lifecycle: trial → active → cancel (period-end + immediate).
* Webhook signature verification + dispatch.
* Entitlement enforcement: a canceled subscription reduces a customer to
  core-only modules, so policy writes that enable add-on modules fail.
"""

from __future__ import annotations

import hmac
import json
import os
import uuid
from datetime import UTC, datetime
from hashlib import sha256

import pytest
from fastapi.testclient import TestClient

from app import db as app_db
from app.main import app
from app.schemas import (
    AccountCreate,
    CompanyLicenseAssign,
    RoleAssignmentRequest,
    SubscriptionCreate,
)
from app.services import jwt_tokens, licensing, subscriptions, tenancy


client = TestClient(app)


# ---------------------------------------------------------------------------
# Fixtures / helpers
# ---------------------------------------------------------------------------


def _platform_owner_account():
    return tenancy.ensure_platform_owner("owner@aetherix.test", "Owner One")


def _make_partner() -> uuid.UUID:
    partner_id = uuid.uuid4()
    with app_db.connection() as conn, conn.cursor() as cur:
        cur.execute(
            """
            insert into partners (id, name, slug, deployment_mode, created_at, tier)
            values (%s, %s, %s, 'cloud', %s, 'msp')
            """,
            (
                partner_id,
                f"Partner {partner_id}",
                f"p-{partner_id.hex[:8]}",
                datetime.now(UTC),
            ),
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
            (
                customer_id,
                partner_id,
                f"C-{customer_id.hex[:8]}",
                "Acme",
                datetime.now(UTC),
            ),
        )
    return customer_id


def _seed_default_catalog() -> None:
    licensing.ensure_default_catalog()


# ---------------------------------------------------------------------------
# Phase 1 — JWT bearer authentication
# ---------------------------------------------------------------------------


def test_jwt_bearer_token_authenticates_me_endpoint():
    """A fresh JWT minted by jwt_tokens.issue authenticates /me."""

    owner = _platform_owner_account()
    token, _ = jwt_tokens.issue(str(owner.id))

    response = client.get("/me", headers={"Authorization": f"Bearer {token}"})
    assert response.status_code == 200
    body = response.json()
    assert body["account"]["id"] == str(owner.id)


def test_missing_bearer_token_is_rejected():
    """Requests without Authorization bearer token are rejected."""

    _platform_owner_account()
    response = client.get("/me")
    assert response.status_code == 401


def test_invalid_bearer_token_is_rejected():
    _platform_owner_account()
    response = client.get(
        "/me", headers={"Authorization": "Bearer not.a.valid.jwt"}
    )
    assert response.status_code == 401


# ---------------------------------------------------------------------------
# Phase 2 — privilege escalation guard
# ---------------------------------------------------------------------------


def test_company_admin_cannot_grant_platform_owner():
    """A company_admin must not be able to escalate any account."""

    _platform_owner_account()  # bootstrap
    partner_id = _make_partner()
    customer_id = _make_customer(partner_id)

    admin = tenancy.create_account(
        AccountCreate(
            email="admin@acme.test",
            full_name="Acme Admin",
            initial_role=RoleAssignmentRequest(
                role_code="company_admin", customer_id=customer_id
            ),
        )
    )
    target = tenancy.create_account(
        AccountCreate(email="victim@acme.test", full_name="Victim")
    )

    with pytest.raises(tenancy.TenancyError):
        tenancy.assign_role(
            target.id,
            RoleAssignmentRequest(role_code="platform_owner"),
            granted_by=str(admin.id),
            actor=admin,
        )


def test_msp_partner_cannot_grant_platform_owner():
    _platform_owner_account()
    partner_id = _make_partner()
    msp = tenancy.create_account(
        AccountCreate(
            email="msp@partner.test",
            full_name="MSP One",
            initial_role=RoleAssignmentRequest(
                role_code="msp_partner", partner_id=partner_id
            ),
        )
    )
    target = tenancy.create_account(
        AccountCreate(email="victim2@acme.test", full_name="Victim2")
    )
    with pytest.raises(tenancy.TenancyError):
        tenancy.assign_role(
            target.id,
            RoleAssignmentRequest(role_code="platform_owner"),
            granted_by=str(msp.id),
            actor=msp,
        )


def test_msp_partner_cannot_create_partner_role_in_other_partner():
    _platform_owner_account()
    partner_a = _make_partner()
    partner_b = _make_partner()
    msp = tenancy.create_account(
        AccountCreate(
            email="msp-a@partner.test",
            full_name="MSP A",
            initial_role=RoleAssignmentRequest(
                role_code="msp_partner", partner_id=partner_a
            ),
        )
    )
    target = tenancy.create_account(
        AccountCreate(email="x@partner.test", full_name="x")
    )
    with pytest.raises(tenancy.TenancyError):
        tenancy.assign_role(
            target.id,
            RoleAssignmentRequest(role_code="msp_partner", partner_id=partner_b),
            granted_by=str(msp.id),
            actor=msp,
        )


def test_platform_owner_can_still_grant_anything():
    owner = _platform_owner_account()
    partner_id = _make_partner()
    target = tenancy.create_account(
        AccountCreate(email="elevated@aetherix.test", full_name="X")
    )
    assignment = tenancy.assign_role(
        target.id,
        RoleAssignmentRequest(role_code="msp_partner", partner_id=partner_id),
        granted_by=str(owner.id),
        actor=owner,
    )
    assert assignment.role_code == "msp_partner"


# ---------------------------------------------------------------------------
# Phase 2 — global SKU catalog is platform-only
# ---------------------------------------------------------------------------


def test_msp_partner_cannot_create_subscription_sku(auth_headers):
    _platform_owner_account()
    partner_id = _make_partner()
    msp = tenancy.create_account(
        AccountCreate(
            email="msp-sku@partner.test",
            full_name="MSP",
            initial_role=RoleAssignmentRequest(
                role_code="msp_partner", partner_id=partner_id
            ),
        )
    )
    response = client.post(
        "/subscriptions",
        headers=auth_headers(str(msp.id)),
        json={"sku": "evil-sku", "display_name": "Evil", "tier": "core"},
    )
    assert response.status_code == 403


def test_platform_owner_can_create_subscription_sku(auth_headers):
    owner = _platform_owner_account()
    response = client.post(
        "/subscriptions",
        headers=auth_headers(str(owner.id)),
        json={"sku": "platform-only", "display_name": "P", "tier": "core"},
    )
    assert response.status_code in (200, 201), response.text


# ---------------------------------------------------------------------------
# Phase 3 — tenant-scoped account listing
# ---------------------------------------------------------------------------


def test_msp_partner_account_listing_is_scoped(auth_headers):
    _platform_owner_account()
    partner_a = _make_partner()
    partner_b = _make_partner()
    cust_a = _make_customer(partner_a)
    cust_b = _make_customer(partner_b)

    msp_a = tenancy.create_account(
        AccountCreate(
            email="msp-scope@partner.test",
            full_name="MSP A",
            initial_role=RoleAssignmentRequest(
                role_code="msp_partner", partner_id=partner_a
            ),
        )
    )
    # An account that belongs to partner_a's customer — should be visible.
    own_admin = tenancy.create_account(
        AccountCreate(
            email="own-admin@cust-a.test",
            full_name="Own",
            initial_role=RoleAssignmentRequest(
                role_code="company_admin", customer_id=cust_a
            ),
        )
    )
    # An account that belongs to partner_b's customer — must NOT be visible.
    other_admin = tenancy.create_account(
        AccountCreate(
            email="other-admin@cust-b.test",
            full_name="Other",
            initial_role=RoleAssignmentRequest(
                role_code="company_admin", customer_id=cust_b
            ),
        )
    )

    response = client.get(
        "/accounts", headers=auth_headers(str(msp_a.id))
    )
    assert response.status_code == 200
    ids = {a["id"] for a in response.json()}
    assert str(own_admin.id) in ids
    assert str(other_admin.id) not in ids
    # MSP partners must not see platform owners or themselves elevated.
    for entry in response.json():
        codes = {role["role_code"] for role in entry.get("roles", [])}
        assert "platform_owner" not in codes


def test_msp_partner_cannot_fetch_account_outside_scope(auth_headers):
    _platform_owner_account()
    partner_a = _make_partner()
    partner_b = _make_partner()
    cust_b = _make_customer(partner_b)
    msp_a = tenancy.create_account(
        AccountCreate(
            email="msp-scope2@partner.test",
            full_name="MSP",
            initial_role=RoleAssignmentRequest(
                role_code="msp_partner", partner_id=partner_a
            ),
        )
    )
    target = tenancy.create_account(
        AccountCreate(
            email="t@cust-b.test",
            full_name="T",
            initial_role=RoleAssignmentRequest(
                role_code="company_admin", customer_id=cust_b
            ),
        )
    )
    response = client.get(
        f"/accounts/{target.id}", headers=auth_headers(str(msp_a.id))
    )
    assert response.status_code == 404


# ---------------------------------------------------------------------------
# Phase 4 — subscription lifecycle
# ---------------------------------------------------------------------------


def test_subscription_lifecycle_trial_subscribe_cancel():
    _platform_owner_account()
    _seed_default_catalog()
    partner_id = _make_partner()
    customer_id = _make_customer(partner_id)

    trial = subscriptions.start_trial(
        customer_id,
        payload=__build_trial_request(sku="core", days=14, seats=5),
    )
    assert trial.status == "trialing"
    assert trial.trial_ends_at is not None

    active = subscriptions.subscribe(
        customer_id,
        payload=__build_subscribe_request(sku="core", seats=10),
    )
    assert active.status == "active"
    assert active.id == trial.id  # same row reused

    scheduled = subscriptions.cancel(
        customer_id,
        payload=__build_cancel_request(at_period_end=True),
    )
    assert scheduled.cancel_at_period_end is True
    assert scheduled.status == "active"

    immediate = subscriptions.cancel(
        customer_id,
        payload=__build_cancel_request(at_period_end=False),
    )
    assert immediate.status == "canceled"
    assert immediate.canceled_at is not None

    events = subscriptions.list_events(customer_id)
    kinds = [e.kind for e in events]
    assert "trial_started" in kinds
    assert "subscribed" in kinds
    assert "cancel_scheduled" in kinds
    assert "canceled" in kinds


def test_subscription_webhook_signature_verification():
    secret = "test-webhook-secret-" + uuid.uuid4().hex
    os.environ["AETHERIX_WEBHOOK_SECRET"] = secret
    try:
        body = b'{"event_kind": "renewal.succeeded", "data": {}}'
        good = hmac.new(secret.encode(), body, sha256).hexdigest()
        assert subscriptions.verify_webhook_signature(body, good) is True
        assert subscriptions.verify_webhook_signature(body, "bad") is False
        assert subscriptions.verify_webhook_signature(body, None) is False
    finally:
        os.environ.pop("AETHERIX_WEBHOOK_SECRET", None)


def test_subscription_webhook_endpoint_rejects_bad_signature():
    response = client.post(
        "/webhooks/billing/mock",
        content=b'{"event_kind": "ping", "data": {}}',
        headers={
            "Content-Type": "application/json",
            "X-Aetherix-Webhook-Signature": "nope",
        },
    )
    assert response.status_code == 401


def test_subscription_webhook_endpoint_marks_renewed():
    _platform_owner_account()
    _seed_default_catalog()
    partner_id = _make_partner()
    customer_id = _make_customer(partner_id)
    subscriptions.subscribe(
        customer_id,
        payload=__build_subscribe_request(sku="core", seats=2),
    )

    secret = "wh-secret-" + uuid.uuid4().hex
    os.environ["AETHERIX_WEBHOOK_SECRET"] = secret
    try:
        body = json.dumps(
            {
                "event_kind": "renewal.succeeded",
                "data": {"customer_id": str(customer_id), "period_days": 30},
            }
        ).encode("utf-8")
        signature = hmac.new(secret.encode(), body, sha256).hexdigest()
        response = client.post(
            "/webhooks/billing/mock",
            content=body,
            headers={
                "Content-Type": "application/json",
                "X-Aetherix-Webhook-Signature": signature,
            },
        )
        assert response.status_code == 202, response.text
    finally:
        os.environ.pop("AETHERIX_WEBHOOK_SECRET", None)

    instance = subscriptions.get_subscription_for(customer_id)
    assert instance is not None
    assert instance.status == "active"
    events = subscriptions.list_events(customer_id)
    assert any(e.kind == "renewed" and e.source == "webhook" for e in events)


# ---------------------------------------------------------------------------
# Phase 5 — entitlement enforcement gated by subscription status
# ---------------------------------------------------------------------------


def test_canceled_subscription_forces_core_only_entitlements():
    """A fully-canceled subscription must reduce the customer to core modules."""

    _platform_owner_account()
    _seed_default_catalog()
    # Seed a richer SKU so the legacy company_license grants an add-on.
    licensing.create_subscription(
        SubscriptionCreate(
            sku="full",
            display_name="Full",
            tier="advanced",
            core_features=["antimalware"],
            available_addons=["semantic_dlp"],
        )
    )
    partner_id = _make_partner()
    customer_id = _make_customer(partner_id)
    licensing.assign_license(
        customer_id,
        CompanyLicenseAssign(
            subscription_sku="full", total_seats=5, addons=["semantic_dlp"]
        ),
        actor="tests",
    )

    # With no subscription_instance, entitlements include the add-on.
    from app.services import policy_v2

    entitled = policy_v2._licensed_modules(customer_id)
    assert "semantic_dlp" in entitled

    # Now cancel via the lifecycle and re-check.
    subscriptions.subscribe(
        customer_id,
        payload=__build_subscribe_request(sku="full", seats=5),
    )
    subscriptions.cancel(
        customer_id,
        payload=__build_cancel_request(at_period_end=False),
    )

    after = policy_v2._licensed_modules(customer_id)
    assert "semantic_dlp" not in after
    # Core keys remain available regardless.
    assert after  # never empty


# ---------------------------------------------------------------------------
# Tiny payload builders so we do not depend on schema constructor names
# changing later.
# ---------------------------------------------------------------------------


def __build_trial_request(*, sku: str, days: int, seats: int):
    from app.schemas import StartTrialRequest

    return StartTrialRequest(subscription_sku=sku, trial_days=days, seats=seats)


def __build_subscribe_request(*, sku: str, seats: int):
    from app.schemas import SubscribeRequest

    return SubscribeRequest(subscription_sku=sku, seats=seats, provider="manual")


def __build_cancel_request(*, at_period_end: bool):
    from app.schemas import CancelSubscriptionRequest

    return CancelSubscriptionRequest(at_period_end=at_period_end)

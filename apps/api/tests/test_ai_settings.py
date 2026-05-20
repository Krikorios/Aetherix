"""Tests for per-company AI provider settings + DLP resolver integration."""

from __future__ import annotations

import uuid
from datetime import UTC, datetime

import pytest
from fastapi.testclient import TestClient

from app import db as app_db
from app.main import app
from app.schemas import (
    AccountCreate,
    CompanyLicenseAssign,
    CustomerAiSettingsUpdate,
    RoleAssignmentRequest,
    SubscriptionCreate,
)
from app.services import ai_settings as ai_settings_service
from app.services import licensing, tenancy
from app.services.ai_settings import AiSettingsError


client = TestClient(app)


def _platform_owner_id() -> str:
    return str(tenancy.ensure_platform_owner("owner@aetherix.test", "Owner").id)


def _make_partner() -> uuid.UUID:
    pid = uuid.uuid4()
    with app_db.connection() as conn, conn.cursor() as cur:
        cur.execute(
            """
            insert into partners (id, name, slug, deployment_mode, created_at, tier)
            values (%s, %s, %s, 'cloud', %s, 'msp')
            """,
            (pid, "AI Partner", f"ai-{pid.hex[:6]}", datetime.now(UTC)),
        )
    return pid


def _make_customer(partner_id: uuid.UUID) -> uuid.UUID:
    cid = uuid.uuid4()
    with app_db.connection() as conn, conn.cursor() as cur:
        cur.execute(
            """
            insert into customers (
                id, partner_id, customer_number, name, status, created_by, created_at
            ) values (%s, %s, %s, %s, 'active', 'tests', %s)
            """,
            (cid, partner_id, f"C-{cid.hex[:8]}", "AI Test Co", datetime.now(UTC)),
        )
    return cid


def _grant_byo_tier(customer_id: uuid.UUID, owner_id: str, sku: str) -> None:
    """Give a customer an active license whose subscription includes ai_tier:byo."""

    licensing.ensure_default_catalog()
    licensing.create_subscription(
        SubscriptionCreate(
            sku=sku,
            display_name=f"BYO AI {sku}",
            tier="enterprise",
            core_features=["ai_tier:byo"],
        )
    )
    licensing.assign_license(
        customer_id,
        CompanyLicenseAssign(subscription_sku=sku, total_seats=5),
        actor=owner_id,
    )


# --- Provider catalog ------------------------------------------------------


def test_provider_catalog_seeded():
    providers = ai_settings_service.list_providers()
    slugs = {p.slug for p in providers}
    assert {"disabled", "aetherix-hosted", "openai", "azure-openai", "anthropic", "ollama"}.issubset(slugs)


def test_providers_route_requires_auth():
    deny = client.get("/ai/providers")
    assert deny.status_code in (401, 403)
    allow = client.get("/ai/providers", headers={"X-Aetherix-Account": _platform_owner_id()})
    assert allow.status_code == 200
    assert any(p["slug"] == "openai" for p in allow.json())


# --- Upsert + gating -------------------------------------------------------


def test_upsert_disabled_provider_does_not_require_key():
    partner_id = _make_partner()
    customer_id = _make_customer(partner_id)
    settings = ai_settings_service.upsert_settings(
        customer_id,
        CustomerAiSettingsUpdate(
            provider_slug="disabled",
            model="none",
            enabled=False,
        ),
        actor_id=None,
    )
    assert settings.provider_slug == "disabled"
    assert settings.has_api_key is False


def test_upsert_byo_provider_requires_key_when_enabled():
    owner_id = _platform_owner_id()
    partner_id = _make_partner()
    customer_id = _make_customer(partner_id)
    _grant_byo_tier(customer_id, owner_id, "ai-byo-keyreq")

    with pytest.raises(AiSettingsError, match="requires an API key"):
        ai_settings_service.upsert_settings(
            customer_id,
            CustomerAiSettingsUpdate(
                provider_slug="openai",
                model="gpt-4o-mini",
                enabled=True,
            ),
            actor_id=None,
        )

    settings = ai_settings_service.upsert_settings(
        customer_id,
        CustomerAiSettingsUpdate(
            provider_slug="openai",
            model="gpt-4o-mini",
            api_key="sk-test-1234567890",
            enabled=True,
        ),
        actor_id=None,
    )
    assert settings.has_api_key is True
    assert settings.api_key_last4 == "7890"


def test_subscription_ai_tier_none_blocks_enable():
    owner_id = _platform_owner_id()
    licensing.ensure_default_catalog()
    licensing.create_subscription(
        SubscriptionCreate(
            sku="ai-none",
            display_name="No AI",
            tier="core",
            core_features=["ai_tier:none"],
        )
    )
    partner_id = _make_partner()
    customer_id = _make_customer(partner_id)
    licensing.assign_license(
        customer_id,
        CompanyLicenseAssign(subscription_sku="ai-none", total_seats=5),
        actor=owner_id,
    )
    with pytest.raises(AiSettingsError, match="does not include AI"):
        ai_settings_service.upsert_settings(
            customer_id,
            CustomerAiSettingsUpdate(
                provider_slug="openai",
                model="gpt-4o-mini",
                api_key="sk-xxx-1234",
                enabled=True,
            ),
            actor_id=None,
        )


def test_subscription_ai_tier_hosted_blocks_byo_provider():
    owner_id = _platform_owner_id()
    licensing.ensure_default_catalog()
    licensing.create_subscription(
        SubscriptionCreate(
            sku="ai-hosted",
            display_name="Hosted AI",
            tier="advanced",
            core_features=["ai_tier:hosted"],
        )
    )
    partner_id = _make_partner()
    customer_id = _make_customer(partner_id)
    licensing.assign_license(
        customer_id,
        CompanyLicenseAssign(subscription_sku="ai-hosted", total_seats=5),
        actor=owner_id,
    )
    with pytest.raises(AiSettingsError, match="hosted AI"):
        ai_settings_service.upsert_settings(
            customer_id,
            CustomerAiSettingsUpdate(
                provider_slug="openai",
                model="gpt-4o-mini",
                api_key="sk-xxx-1234",
                enabled=True,
            ),
            actor_id=None,
        )

    # Hosted is permitted under the same tier.
    ok = ai_settings_service.upsert_settings(
        customer_id,
        CustomerAiSettingsUpdate(
            provider_slug="aetherix-hosted",
            model="aetherix-default",
            enabled=True,
        ),
        actor_id=None,
    )
    assert ok.enabled is True


# --- Resolver --------------------------------------------------------------


def test_resolver_returns_none_when_disabled():
    partner_id = _make_partner()
    customer_id = _make_customer(partner_id)
    ai_settings_service.upsert_settings(
        customer_id,
        CustomerAiSettingsUpdate(
            provider_slug="disabled",
            model="none",
            enabled=False,
        ),
        actor_id=None,
    )
    assert ai_settings_service.resolve_for_customer(customer_id) is None


def test_resolver_returns_decrypted_key():
    owner_id = _platform_owner_id()
    partner_id = _make_partner()
    customer_id = _make_customer(partner_id)
    _grant_byo_tier(customer_id, owner_id, "ai-byo-resolver")
    ai_settings_service.upsert_settings(
        customer_id,
        CustomerAiSettingsUpdate(
            provider_slug="openai",
            model="gpt-4o-mini",
            api_key="sk-super-secret-key-xyz",
            enabled=True,
        ),
        actor_id=None,
    )
    config = ai_settings_service.resolve_for_customer(customer_id)
    assert config is not None
    assert config.provider_slug == "openai"
    assert config.model == "gpt-4o-mini"
    assert config.api_key == "sk-super-secret-key-xyz"
    assert config.endpoint == "https://api.openai.com/v1"


def test_resolver_returns_none_for_unknown_customer():
    assert ai_settings_service.resolve_for_customer(uuid.uuid4()) is None
    assert ai_settings_service.resolve_for_customer(None) is None


# --- API endpoint round-trip ----------------------------------------------


def test_company_ai_endpoints_round_trip():
    owner_id = _platform_owner_id()
    partner_id = _make_partner()
    customer_id = _make_customer(partner_id)
    _grant_byo_tier(customer_id, owner_id, "ai-byo-route")

    headers = {"X-Aetherix-Account": owner_id}

    empty = client.get(f"/companies/{customer_id}/ai", headers=headers)
    assert empty.status_code == 200
    assert empty.json() is None

    put = client.put(
        f"/companies/{customer_id}/ai",
        headers=headers,
        json={
            "provider_slug": "openai",
            "model": "gpt-4o-mini",
            "api_key": "sk-route-test-9999",
            "enabled": True,
        },
    )
    assert put.status_code == 200, put.text
    body = put.json()
    assert body["provider_slug"] == "openai"
    assert body["enabled"] is True
    assert body["has_api_key"] is True
    assert body["api_key_last4"] == "9999"
    # Never expose ciphertext.
    assert "api_key_ciphertext" not in body
    assert "api_key" not in body

    deleted = client.delete(f"/companies/{customer_id}/ai", headers=headers)
    assert deleted.status_code == 204
    after = client.get(f"/companies/{customer_id}/ai", headers=headers)
    assert after.json() is None


def test_company_ai_requires_manage_to_update():
    owner_id = _platform_owner_id()  # noqa: F841 - ensure default policies/roles exist
    partner_id = _make_partner()
    customer_id = _make_customer(partner_id)
    viewer = tenancy.create_account(
        AccountCreate(
            email="viewer-ai@example.com",
            full_name="Viewer",
            initial_role=RoleAssignmentRequest(
                role_code="company_viewer", customer_id=customer_id
            ),
        )
    )
    deny = client.put(
        f"/companies/{customer_id}/ai",
        headers={"X-Aetherix-Account": str(viewer.id)},
        json={
            "provider_slug": "disabled",
            "model": "none",
            "enabled": False,
        },
    )
    assert deny.status_code == 403

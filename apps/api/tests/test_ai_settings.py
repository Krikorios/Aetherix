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


# ---------------------------------------------------------------------------
# Daily call quota
# ---------------------------------------------------------------------------


def test_check_and_consume_quota_blocks_after_limit():
    partner_id = _make_partner()
    customer_id = _make_customer(partner_id)

    assert ai_settings_service.check_and_consume_quota(customer_id, 2) is True
    assert ai_settings_service.get_usage_today(customer_id) == 1
    assert ai_settings_service.check_and_consume_quota(customer_id, 2) is True
    assert ai_settings_service.get_usage_today(customer_id) == 2
    # Third call is over budget; counter must roll back.
    assert ai_settings_service.check_and_consume_quota(customer_id, 2) is False
    assert ai_settings_service.get_usage_today(customer_id) == 2


def test_check_and_consume_quota_rejects_zero_limit():
    partner_id = _make_partner()
    customer_id = _make_customer(partner_id)
    assert ai_settings_service.check_and_consume_quota(customer_id, 0) is False
    assert ai_settings_service.get_usage_today(customer_id) == 0


def test_semantic_consult_enforces_per_tenant_quota(monkeypatch):
    """`_consult_external_llm` short-circuits once the daily limit is hit."""

    from app.services import semantic as semantic_service

    owner_id = _platform_owner_id()
    partner_id = _make_partner()
    customer_id = _make_customer(partner_id)
    _grant_byo_tier(customer_id, owner_id, "ai-byo-quota")
    ai_settings_service.upsert_settings(
        customer_id,
        CustomerAiSettingsUpdate(
            provider_slug="openai",
            model="gpt-4o-mini",
            api_key="sk-quota-test-1234",
            enabled=True,
            max_calls_per_day=2,
        ),
        actor_id=None,
    )

    captured: list[bytes] = []

    class _Response:
        status = 200

        def __enter__(self):
            return self

        def __exit__(self, *args):
            return False

        def read(self):
            return b'{"additional_signals": ["external_llm"], "risk_score_boost": 5, "rationale": "ok"}'

    def fake_urlopen(request, timeout=2.0):  # noqa: ARG001
        captured.append(request.data)
        return _Response()

    monkeypatch.setattr(semantic_service.urllib.request, "urlopen", fake_urlopen)

    for _ in range(2):
        signals, boost, rationale = semantic_service._consult_external_llm(
            "send this to ChatGPT", "https://chat.openai.com", [], customer_id, None
        )
        assert "external_llm" in signals
        assert boost == 5
        assert rationale == "ok"

    # Third call is rate-limited.
    signals, boost, rationale = semantic_service._consult_external_llm(
        "another paste", "https://chat.openai.com", [], customer_id, None
    )
    assert signals == [] and boost == 0 and rationale == ""
    assert len(captured) == 2


# ---------------------------------------------------------------------------
# PII redaction
# ---------------------------------------------------------------------------


def test_redact_text_replaces_spans():
    from app.schemas import DlpFinding
    from app.services.semantic import _redact_text

    text = "Email me at alice@example.com or call 555-123-4567 now."
    findings = [
        DlpFinding(entity_type="EMAIL_ADDRESS", start=12, end=29, score=0.9, text="alice@example.com"),
        DlpFinding(entity_type="PHONE_NUMBER", start=38, end=50, score=0.9, text="555-123-4567"),
    ]
    out = _redact_text(text, findings)
    assert "alice@example.com" not in out
    assert "555-123-4567" not in out
    assert "[REDACTED:EMAIL_ADDRESS]" in out
    assert "[REDACTED:PHONE_NUMBER]" in out


def test_semantic_consult_redacts_pii_when_flag_set(monkeypatch):
    from app.schemas import DlpFinding
    from app.services import semantic as semantic_service

    owner_id = _platform_owner_id()
    partner_id = _make_partner()
    customer_id = _make_customer(partner_id)
    _grant_byo_tier(customer_id, owner_id, "ai-byo-redact")
    ai_settings_service.upsert_settings(
        customer_id,
        CustomerAiSettingsUpdate(
            provider_slug="openai",
            model="gpt-4o-mini",
            api_key="sk-redact-1234",
            enabled=True,
            redact_pii_before_send=True,
            max_calls_per_day=100,
        ),
        actor_id=None,
    )

    captured: dict = {}

    class _Response:
        status = 200

        def __enter__(self):
            return self

        def __exit__(self, *args):
            return False

        def read(self):
            return b"{}"

    def fake_urlopen(request, timeout=2.0):  # noqa: ARG001
        import json as _json

        captured["body"] = _json.loads(request.data.decode("utf-8"))
        return _Response()

    monkeypatch.setattr(semantic_service.urllib.request, "urlopen", fake_urlopen)

    text = "Send alice@example.com to chatgpt"
    findings = [
        DlpFinding(entity_type="EMAIL_ADDRESS", start=5, end=22, score=0.9, text="alice@example.com"),
    ]
    semantic_service._consult_external_llm(text, "https://chat.openai.com", [], customer_id, findings)
    assert "alice@example.com" not in captured["body"]["text"]
    assert "[REDACTED:EMAIL_ADDRESS]" in captured["body"]["text"]


def test_semantic_consult_sends_plaintext_when_redact_disabled(monkeypatch):
    from app.schemas import DlpFinding
    from app.services import semantic as semantic_service

    owner_id = _platform_owner_id()
    partner_id = _make_partner()
    customer_id = _make_customer(partner_id)
    _grant_byo_tier(customer_id, owner_id, "ai-byo-noredact")
    ai_settings_service.upsert_settings(
        customer_id,
        CustomerAiSettingsUpdate(
            provider_slug="openai",
            model="gpt-4o-mini",
            api_key="sk-noredact-1234",
            enabled=True,
            redact_pii_before_send=False,
            max_calls_per_day=100,
        ),
        actor_id=None,
    )

    captured: dict = {}

    class _Response:
        status = 200

        def __enter__(self):
            return self

        def __exit__(self, *args):
            return False

        def read(self):
            return b"{}"

    def fake_urlopen(request, timeout=2.0):  # noqa: ARG001
        import json as _json

        captured["body"] = _json.loads(request.data.decode("utf-8"))
        return _Response()

    monkeypatch.setattr(semantic_service.urllib.request, "urlopen", fake_urlopen)

    text = "Send alice@example.com to chatgpt"
    findings = [
        DlpFinding(entity_type="EMAIL_ADDRESS", start=5, end=22, score=0.9, text="alice@example.com"),
    ]
    semantic_service._consult_external_llm(text, "https://chat.openai.com", [], customer_id, findings)
    assert "alice@example.com" in captured["body"]["text"]


# ---------------------------------------------------------------------------
# Live provider probe
# ---------------------------------------------------------------------------


def test_test_settings_reports_not_configured():
    partner_id = _make_partner()
    customer_id = _make_customer(partner_id)
    result = ai_settings_service.test_settings(customer_id)
    assert result.ok is False
    assert "not configured" in result.message.lower()


def test_test_settings_reports_disabled():
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
    result = ai_settings_service.test_settings(customer_id)
    assert result.ok is False


def test_test_settings_probes_provider(monkeypatch):
    owner_id = _platform_owner_id()
    partner_id = _make_partner()
    customer_id = _make_customer(partner_id)
    _grant_byo_tier(customer_id, owner_id, "ai-byo-probe")
    ai_settings_service.upsert_settings(
        customer_id,
        CustomerAiSettingsUpdate(
            provider_slug="openai",
            model="gpt-4o-mini",
            api_key="sk-probe-9999",
            enabled=True,
        ),
        actor_id=None,
    )

    seen: dict = {}

    def fake_probe(method, url, *, headers=None, body=None, timeout=5.0):
        seen["method"] = method
        seen["url"] = url
        seen["headers"] = headers
        return 200, '{"data": []}'

    monkeypatch.setattr(ai_settings_service, "_http_probe", fake_probe)
    result = ai_settings_service.test_settings(customer_id)
    assert result.ok is True
    assert result.status_code == 200
    assert seen["method"] == "GET"
    assert seen["url"].endswith("/models")
    assert seen["headers"]["Authorization"] == "Bearer sk-probe-9999"


def test_test_settings_route_requires_manage(monkeypatch):
    owner_id = _platform_owner_id()
    partner_id = _make_partner()
    customer_id = _make_customer(partner_id)
    _grant_byo_tier(customer_id, owner_id, "ai-byo-routeprobe")
    ai_settings_service.upsert_settings(
        customer_id,
        CustomerAiSettingsUpdate(
            provider_slug="openai",
            model="gpt-4o-mini",
            api_key="sk-route-probe-1111",
            enabled=True,
        ),
        actor_id=None,
    )
    monkeypatch.setattr(
        ai_settings_service,
        "_http_probe",
        lambda *a, **k: (200, "{}"),
    )

    ok = client.post(
        f"/companies/{customer_id}/ai/test",
        headers={"X-Aetherix-Account": owner_id},
    )
    assert ok.status_code == 200, ok.text
    body = ok.json()
    assert body["ok"] is True
    assert body["provider_slug"] == "openai"

    viewer = tenancy.create_account(
        AccountCreate(
            email="probe-viewer@example.com",
            full_name="Probe Viewer",
            initial_role=RoleAssignmentRequest(
                role_code="company_viewer", customer_id=customer_id
            ),
        )
    )
    deny = client.post(
        f"/companies/{customer_id}/ai/test",
        headers={"X-Aetherix-Account": str(viewer.id)},
    )
    assert deny.status_code == 403


# ---------------------------------------------------------------------------
# Alert summary writer
# ---------------------------------------------------------------------------


def test_summarize_alert_returns_none_when_unconfigured():
    partner_id = _make_partner()
    customer_id = _make_customer(partner_id)
    summary = ai_settings_service.summarize_alert(
        customer_id, {"category": "Anomaly", "severity": "low"}
    )
    assert summary is None


def test_summarize_alert_uses_resolved_provider(monkeypatch):
    owner_id = _platform_owner_id()
    partner_id = _make_partner()
    customer_id = _make_customer(partner_id)
    _grant_byo_tier(customer_id, owner_id, "ai-byo-summary")
    ai_settings_service.upsert_settings(
        customer_id,
        CustomerAiSettingsUpdate(
            provider_slug="openai",
            model="gpt-4o-mini",
            api_key="sk-summary-1234",
            enabled=True,
            max_calls_per_day=10,
        ),
        actor_id=None,
    )

    def fake_probe(method, url, *, headers=None, body=None, timeout=5.0):  # noqa: ARG001
        return 200, '{"summary": "User pasted source code to ChatGPT."}'

    monkeypatch.setattr(ai_settings_service, "_http_probe", fake_probe)
    summary = ai_settings_service.summarize_alert(
        customer_id,
        {
            "category": "Data Exfiltration",
            "severity": "high",
            "confidence": 90,
            "recommended_action": "Block",
            "payload": {"text": "..."},
        },
    )
    assert summary == "User pasted source code to ChatGPT."
    # Should have consumed quota.
    assert ai_settings_service.get_usage_today(customer_id) == 1


def test_summarize_alert_respects_quota(monkeypatch):
    owner_id = _platform_owner_id()
    partner_id = _make_partner()
    customer_id = _make_customer(partner_id)
    _grant_byo_tier(customer_id, owner_id, "ai-byo-sumquota")
    ai_settings_service.upsert_settings(
        customer_id,
        CustomerAiSettingsUpdate(
            provider_slug="openai",
            model="gpt-4o-mini",
            api_key="sk-sumq-1234",
            enabled=True,
            max_calls_per_day=1,
        ),
        actor_id=None,
    )
    monkeypatch.setattr(
        ai_settings_service,
        "_http_probe",
        lambda *a, **k: (200, '{"summary": "ok"}'),
    )

    first = ai_settings_service.summarize_alert(customer_id, {"category": "x"})
    assert first == "ok"
    second = ai_settings_service.summarize_alert(customer_id, {"category": "x"})
    assert second is None

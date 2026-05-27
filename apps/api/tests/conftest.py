"""Shared test fixtures.

Tests connect to a real Postgres instance — the API has no SQLite or
in-memory fallback. Set ``AETHERIX_TEST_DATABASE_URL`` to point at a
disposable database (the ``docker-compose.yml`` at the repository root
provides one on ``localhost:5432``).

Every test runs against a freshly truncated schema so they remain
order-independent.
"""

from __future__ import annotations

import os
import uuid
from copy import deepcopy
from datetime import UTC, datetime

import pytest

from app import db as app_db
from app.schemas import AccountCreate, CompanyLicenseAssign, RoleAssignmentRequest
from app.services import jwt_tokens, licensing, tenancy


_TEST_URL_DEFAULT = "postgresql://aetherix:aetherix@127.0.0.1:55432/aetherix_test"


@pytest.fixture(scope="session", autouse=True)
def _configure_database_url() -> None:
    os.environ["AETHERIX_DATABASE_URL"] = os.environ.get(
        "AETHERIX_TEST_DATABASE_URL", _TEST_URL_DEFAULT
    )
    app_db.reset_pool()
    app_db.init_schema()


@pytest.fixture
def auth_headers():
    """Return helper that mints bearer-auth headers for a given account id."""

    def _headers(account_id: str | uuid.UUID, **extra: str) -> dict[str, str]:
        token, _ = jwt_tokens.issue(str(account_id))
        headers = {"Authorization": f"Bearer {token}"}
        headers.update(extra)
        return headers

    return _headers


@pytest.fixture(autouse=True)
def _truncate_tables() -> None:
    """Wipe every table before each test so tests are isolated."""

    with app_db.connection() as conn, conn.cursor() as cur:
        cur.execute(
            """
            truncate table
                heartbeats,
                alerts,
                acknowledged_alerts,
                enrollment_tokens,
                enrolled_agents,
                quick_deploy_links,
                installer_builds,
                policy_assignments,
                policy_packages,
                custom_detection_rules,
                customer_groups,
                license_usage_daily,
                license_products,
                company_licenses,
                subscription_events,
                subscription_instances,
                billing_customers,
                subscriptions,
                system_banners,
                impersonation_sessions,
                account_roles,
                accounts,
                customer_ai_settings,
                customer_ai_usage_daily,
                reports,
                integrations,
                customers,
                partners,
                policy_assignments_v2,
                policy_simulations,
                policy_promotions,
                policy_versions,
                policy_documents_v2,
                evidence_events,
                compliance_reviews,
                compliance_attestations,
                compliance_vault_references,
                policy_documents,
                drp_findings,
                drp_assets,
                easm_exposures,
                easm_assets,
                audit_log,
                recovery_codes,
                login_challenges,
                oauth2_states,
                oauth2_identities,
                oauth2_providers
            restart identity cascade
            """
        )
    yield


@pytest.fixture
def promote_default_policy():
    """Promote a minimal active policy. Returns the resulting document.

    Use this in tests that previously relied on the removed env-based
    fallback (``AETHERIX_POLICY_MODE`` / ``AETHERIX_PROTECTED_ENTITIES``).
    """

    from app.schemas import PolicyDocumentDraft, PolicyRule
    from app.services.policy import promote_policy_document

    def _promote(
        *,
        mode: str = "monitor",
        entities: list[str] | None = None,
        genai_guardrail: bool = True,
        escalate_at: str = "high",
    ):
        rules = [
            PolicyRule(id=f"pii.{entity.lower()}", kind="entity", entity_type=entity, action="block")
            for entity in (entities or ["EMAIL_ADDRESS", "PHONE_NUMBER", "CREDIT_CARD"])
        ]
        draft = PolicyDocumentDraft(
            name="Test policy",
            mode_default=mode,
            escalate_at=escalate_at,
            genai_guardrail=genai_guardrail,
            rules=rules,
        )
        return promote_policy_document(draft, actor="tests")

    return _promote


def _required_v2_modules() -> dict[str, dict]:
    modules = {
        "general": {"enabled": True, "agent_update_channel": "stable"},
        "tenant_scope": {"enabled": True},
        "entitlements": {"enabled": True},
        "deployment_profile": {"enabled": True},
        "antimalware": {"enabled": True, "response": {"action": "review"}},
        "behavior_monitoring": {"enabled": True, "high_confidence_action": "review"},
        "anti_exploit": {"enabled": True, "high_confidence_action": "review"},
        "ransomware_mitigation": {"enabled": True, "rollback_approval": "operator_required"},
        "firewall": {"enabled": True},
        "network_protection": {"enabled": True, "network_attack_signature_action": "review"},
        "web_protection": {"enabled": True, "sensitive_upload_action": "review"},
        "classification_labeling": {"enabled": False},
        "semantic_dlp": {
            "enabled": False,
            "sensitivity_labels": ["Public", "Internal", "Confidential", "Restricted"],
            "genai_destinations": ["copilot", "claude", "gemini", "chatgpt", "custom"],
            "actions": {
                "paste_sensitive": "review",
                "upload_restricted": "block",
                "copy_to_genai": "review",
            },
            "detectors": {
                "presidio": True,
                "llm_semantic": True,
                "custom_classifiers": [],
            },
        },
        "genai_guardrails": {
            "enabled": False,
            "destinations": ["copilot", "claude", "gemini", "chatgpt", "custom"],
            "browser_enforcement": True,
            "endpoint_enforcement": True,
            "actions": {
                "paste_sensitive": "review",
                "upload_restricted": "block",
                "copy_to_genai": "review",
            },
        },
        "device_control": {"enabled": True},
        "siem_hids": {"enabled": False},
        "integrity_monitoring": {"enabled": False},
        "vulnerability_inventory": {"enabled": False},
        "digital_risk_protection": {"enabled": False},
        "external_attack_surface_management": {"enabled": False},
        "threat_intelligence": {"enabled": False},
        "takedown_workflows": {"enabled": False},
        "incident_correlation": {"enabled": False},
        "agentic_response": {"enabled": False},
        "ai_settings": {"enabled": False},
        "ai_reports": {"enabled": False},
        "compliance_evidence": {"enabled": True},
        "integrations": {"enabled": True},
        "platform_observability": {"enabled": True},
        "white_label": {"enabled": True},
    }
    return modules


@pytest.fixture
def policy_v2_templates() -> dict[str, dict]:
    minimal = _required_v2_modules()

    strict = deepcopy(minimal)
    strict["antimalware"]["response"] = {"action": "block"}
    strict["network_protection"]["network_attack_signature_action"] = "block"
    strict["web_protection"]["sensitive_upload_action"] = "block"
    strict["ransomware_mitigation"]["auto_isolate_on_high_confidence"] = True

    genai_focused = deepcopy(minimal)
    genai_focused["classification_labeling"]["enabled"] = True
    genai_focused["semantic_dlp"]["enabled"] = True
    genai_focused["semantic_dlp"]["actions"] = {
        "paste_sensitive": "review",
        "upload_restricted": "block",
        "copy_to_genai": "block",
    }
    genai_focused["semantic_dlp"]["detectors"] = {
        "presidio": True,
        "llm_semantic": True,
        "custom_classifiers": ["finance", "source_code"],
    }
    genai_focused["genai_guardrails"]["enabled"] = True
    genai_focused["genai_guardrails"]["actions"] = {
        "paste_sensitive": "review",
        "upload_restricted": "block",
        "copy_to_genai": "block",
    }

    drp_enabled = deepcopy(minimal)
    drp_enabled["digital_risk_protection"] = {"enabled": True}
    drp_enabled["external_attack_surface_management"] = {"enabled": True}
    drp_enabled["threat_intelligence"] = {"enabled": True}
    drp_enabled["takedown_workflows"] = {"enabled": True}

    return {
        "minimal": minimal,
        "strict": strict,
        "genai_focused": genai_focused,
        "drp_enabled": drp_enabled,
    }


@pytest.fixture
def tenant_hierarchy_factory():
    def _factory(*, addons: list[str] | None = None, endpoint_id: str = "endpoint-e2e-001") -> dict[str, str]:
        owner = tenancy.ensure_platform_owner("owner-policy-e2e@aetherix.test", "Policy E2E Owner")
        partner_id = uuid.uuid4()
        customer_id = uuid.uuid4()
        group_id = uuid.uuid4()
        now = datetime.now(UTC)

        with app_db.connection() as conn, conn.cursor() as cur:
            cur.execute(
                """
                insert into partners (id, name, slug, deployment_mode, created_at, tier)
                values (%s, %s, %s, 'cloud', %s, 'msp')
                """,
                (partner_id, "E2E MSP", f"e2e-{partner_id.hex[:6]}", now),
            )
            cur.execute(
                """
                insert into customers (id, partner_id, customer_number, name, status, created_by, created_at)
                values (%s, %s, %s, %s, 'active', 'tests', %s)
                """,
                (customer_id, partner_id, f"E2E-{customer_id.hex[:8]}", "E2E Customer", now),
            )
            cur.execute(
                """
                insert into customer_groups (id, customer_id, name, created_at)
                values (%s, %s, 'Engineering', %s)
                """,
                (group_id, customer_id, now),
            )
            cur.execute(
                """
                insert into enrolled_agents (
                    agent_id, hostname, os, secret, enrolled_at, last_nonce, revoked,
                    partner_id, customer_id, group_id, policy_package_id
                ) values (%s, 'e2e-host', 'linux', %s, %s, 0, false, %s, %s, %s, null)
                """,
                (endpoint_id, "e2e-endpoint-secret", now, partner_id, customer_id, group_id),
            )

        licensing.ensure_default_catalog()
        licensing.assign_license(
            customer_id,
            CompanyLicenseAssign(
                subscription_sku="core",
                total_seats=50,
                addons=addons or [],
            ),
            actor=str(owner.id),
        )

        msp = tenancy.create_account(
            AccountCreate(
                email=f"msp-{partner_id.hex[:6]}@aetherix.test",
                full_name="MSP Partner",
                initial_role=RoleAssignmentRequest(role_code="msp_partner", partner_id=partner_id),
            )
        )
        company_admin = tenancy.create_account(
            AccountCreate(
                email=f"admin-{customer_id.hex[:6]}@aetherix.test",
                full_name="Company Admin",
                initial_role=RoleAssignmentRequest(role_code="company_admin", customer_id=customer_id),
            )
        )

        return {
            "owner_id": str(owner.id),
            "msp_id": str(msp.id),
            "company_admin_id": str(company_admin.id),
            "partner_id": str(partner_id),
            "customer_id": str(customer_id),
            "group_id": str(group_id),
            "endpoint_id": endpoint_id,
            "endpoint_token": "e2e-endpoint-secret",
        }

    return _factory

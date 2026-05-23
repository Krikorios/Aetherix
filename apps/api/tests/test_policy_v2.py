from __future__ import annotations

import uuid
import time
from datetime import UTC, datetime

from fastapi.testclient import TestClient

from app import db as app_db
from app.main import app
from app.schemas import CompanyLicenseAssign
from app.services import licensing, tenancy


client = TestClient(app)


def _platform_owner() -> str:
    return str(tenancy.ensure_platform_owner("policy-owner@aetherix.test", "Policy Owner").id)


def _make_partner(slug: str = "p-v2") -> uuid.UUID:
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


def _make_customer(partner_id: uuid.UUID, name: str = "PolicyV2Co") -> uuid.UUID:
    customer_id = uuid.uuid4()
    with app_db.connection() as conn, conn.cursor() as cur:
        cur.execute(
            """
            insert into customers (
                id, partner_id, customer_number, name, status, created_by, created_at
            ) values (%s, %s, %s, %s, 'active', 'tests', %s)
            """,
            (customer_id, partner_id, f"PV2-{customer_id.hex[:8]}", name, datetime.now(UTC)),
        )
    return customer_id


def _base_modules() -> dict[str, dict]:
    return {
        "general": {"enabled": True},
        "tenant_scope": {"enabled": True},
        "entitlements": {"enabled": True},
        "deployment_profile": {"enabled": True},
        "antimalware": {"enabled": True, "response": {"action": "review"}},
        "behavior_monitoring": {"enabled": True},
        "anti_exploit": {"enabled": True},
        "ransomware_mitigation": {"enabled": True, "rollback_approval": "operator_required"},
        "firewall": {"enabled": True},
        "network_protection": {"enabled": True},
        "web_protection": {"enabled": True},
        "classification_labeling": {"enabled": False},
        "semantic_dlp": {"enabled": False},
        "genai_guardrails": {"enabled": False},
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


def test_policy_v2_create_simulate_promote_gate() -> None:
    owner_id = _platform_owner()
    partner_id = _make_partner("gate")
    customer_id = _make_customer(partner_id)

    modules = _base_modules()
    modules["antimalware"] = {"enabled": True, "response": {"action": "block"}}

    create = client.post(
        "/policies",
        headers={"X-Aetherix-Account": owner_id},
        json={
            "schema_version": "2.0",
            "name": "Gate Test Policy",
            "scope": {"partner_id": str(partner_id), "customer_id": str(customer_id)},
            "lineage": {"parent_policy_id": None, "inheritance_mode": "inherit_with_overrides"},
            "modules": modules,
            "white_label_names": {},
        },
    )
    assert create.status_code == 201, create.text
    policy_id = create.json()["policy"]["id"]

    simulation = client.post(
        f"/policies/{policy_id}/simulate",
        headers={"X-Aetherix-Account": owner_id},
    )
    assert simulation.status_code == 200, simulation.text
    simulation_body = simulation.json()
    assert simulation_body["summary"]["approval_required"] is True
    simulation_id = simulation_body["id"]

    denied_promote = client.post(
        f"/policies/{policy_id}/promote",
        headers={"X-Aetherix-Account": owner_id},
        json={"simulation_id": simulation_id, "operator_approved": False},
    )
    assert denied_promote.status_code == 400

    allowed_promote = client.post(
        f"/policies/{policy_id}/promote",
        headers={"X-Aetherix-Account": owner_id},
        json={
            "simulation_id": simulation_id,
            "operator_approved": True,
            "approval_reason": "validated in tenant sandbox",
        },
    )
    assert allowed_promote.status_code == 200, allowed_promote.text
    assert allowed_promote.json()["status"] == "active"

    with app_db.connection() as conn, conn.cursor() as cur:
        cur.execute(
            "select count(*) as n from policy_promotions where policy_id = %s",
            (policy_id,),
        )
        promotions_count = int(cur.fetchone()["n"])
        cur.execute(
            "select count(*) as n from evidence_events where action in ('policy_v2.create', 'policy_v2.simulate', 'policy_v2.promote')"
        )
        evidence_count = int(cur.fetchone()["n"])

    assert promotions_count == 1
    assert evidence_count == 3


def test_policy_v2_assignment_and_effective_resolution() -> None:
    owner_id = _platform_owner()
    partner_id = _make_partner("effective")
    customer_id = _make_customer(partner_id, "EffectiveCo")
    licensing.ensure_default_catalog()
    licensing.assign_license(
        customer_id,
        CompanyLicenseAssign(subscription_sku="core", total_seats=10),
        actor=owner_id,
    )

    create = client.post(
        "/policies",
        headers={"X-Aetherix-Account": owner_id},
        json={
            "schema_version": "2.0",
            "name": "Effective Policy",
            "scope": {"partner_id": str(partner_id), "customer_id": str(customer_id)},
            "lineage": {"parent_policy_id": None, "inheritance_mode": "inherit_with_overrides"},
            "modules": _base_modules(),
            "white_label_names": {"semantic_dlp": "Sensitive Data Guard"},
        },
    )
    assert create.status_code == 201, create.text
    policy_id = create.json()["policy"]["id"]

    assign = client.post(
        "/policies/assign",
        headers={"X-Aetherix-Account": owner_id},
        json={"policy_id": policy_id, "customer_id": str(customer_id)},
    )
    assert assign.status_code == 201, assign.text

    effective = client.get(
        f"/policies/effective?customer_id={customer_id}",
        headers={"X-Aetherix-Account": owner_id},
    )
    assert effective.status_code == 200, effective.text
    body = effective.json()
    assert body["assignments_applied"]
    modules = body["resolved_policy"]["modules"]
    assert modules["antimalware"]["enabled"] is True
    assert modules["digital_risk_protection"]["locked"] is True


def test_agent_policy_fetch_returns_entitled_effective_policy() -> None:
    owner_id = _platform_owner()
    partner_id = _make_partner("agent")
    customer_id = _make_customer(partner_id, "AgentFetchCo")
    licensing.ensure_default_catalog()
    licensing.assign_license(
        customer_id,
        CompanyLicenseAssign(subscription_sku="core", total_seats=25),
        actor=owner_id,
    )

    endpoint_id = "agent-endpoint-001"
    endpoint_secret = "agent-token-001"
    with app_db.connection() as conn, conn.cursor() as cur:
        cur.execute(
            """
            insert into enrolled_agents (
                agent_id, hostname, os, secret, enrolled_at, last_nonce, revoked,
                partner_id, customer_id, group_id, policy_package_id
            ) values (
                %s, 'host-a1', 'linux', %s, %s, 0, false,
                %s, %s, null, null
            )
            """,
            (endpoint_id, endpoint_secret, datetime.now(UTC), partner_id, customer_id),
        )

    create = client.post(
        "/policies",
        headers={"X-Aetherix-Account": owner_id},
        json={
            "schema_version": "2.0",
            "name": "Agent Effective Policy",
            "scope": {"partner_id": str(partner_id), "customer_id": str(customer_id)},
            "lineage": {"parent_policy_id": None, "inheritance_mode": "inherit_with_overrides"},
            "modules": _base_modules(),
            "white_label_names": {},
        },
    )
    assert create.status_code == 201, create.text
    policy_id = create.json()["policy"]["id"]

    assign = client.post(
        "/policies/assign",
        headers={"X-Aetherix-Account": owner_id},
        json={"policy_id": policy_id, "endpoint_id": endpoint_id, "customer_id": str(customer_id)},
    )
    assert assign.status_code == 201, assign.text

    response = client.get(
        f"/agent/policy?endpoint_id={endpoint_id}",
        headers={"Authorization": f"Bearer {endpoint_secret}"},
    )
    assert response.status_code == 200, response.text
    body = response.json()
    assert body["endpoint_id"] == endpoint_id
    assert body["policy_version_hash"]
    assert body["resolved_policy"]["modules"]["antimalware"]["enabled"] is True
    assert body["resolved_policy"]["modules"]["digital_risk_protection"]["locked"] is True


def test_policy_v2_list_and_get_routes() -> None:
    owner_id = _platform_owner()
    partner_id = _make_partner("list")
    customer_id = _make_customer(partner_id, "ListCo")

    create = client.post(
        "/policies",
        headers={"X-Aetherix-Account": owner_id},
        json={
            "schema_version": "2.0",
            "name": "List/Get Policy",
            "scope": {"partner_id": str(partner_id), "customer_id": str(customer_id)},
            "lineage": {"parent_policy_id": None, "inheritance_mode": "inherit_with_overrides"},
            "modules": _base_modules(),
            "white_label_names": {},
        },
    )
    assert create.status_code == 201, create.text
    policy_id = create.json()["policy"]["id"]

    listing = client.get("/policies", headers={"X-Aetherix-Account": owner_id})
    assert listing.status_code == 200
    assert any(item["id"] == policy_id for item in listing.json()["items"])

    detail = client.get(f"/policies/{policy_id}", headers={"X-Aetherix-Account": owner_id})
    assert detail.status_code == 200, detail.text
    assert detail.json()["policy"]["id"] == policy_id


def test_policy_v2_assignment_blocks_unlicensed_modules() -> None:
    owner_id = _platform_owner()
    partner_id = _make_partner("lock")
    customer_id = _make_customer(partner_id, "LockedAddonCo")
    licensing.ensure_default_catalog()
    licensing.assign_license(
        customer_id,
        CompanyLicenseAssign(subscription_sku="core", total_seats=10),
        actor=owner_id,
    )

    modules = _base_modules()
    modules["semantic_dlp"] = {"enabled": True, "mode": "block"}

    create = client.post(
        "/policies",
        headers={"X-Aetherix-Account": owner_id},
        json={
            "schema_version": "2.0",
            "name": "Unlicensed Add-on Policy",
            "scope": {"partner_id": str(partner_id)},
            "lineage": {"parent_policy_id": None, "inheritance_mode": "inherit_with_overrides"},
            "modules": modules,
            "white_label_names": {},
        },
    )
    assert create.status_code == 201, create.text
    policy_id = create.json()["policy"]["id"]

    assign = client.post(
        "/policies/assign",
        headers={"X-Aetherix-Account": owner_id},
        json={"policy_id": policy_id, "customer_id": str(customer_id)},
    )
    assert assign.status_code == 400
    assert "required add-on entitlements" in assign.json()["detail"]


def test_policy_v2_promote_requires_latest_simulation() -> None:
    owner_id = _platform_owner()
    partner_id = _make_partner("stale-sim")
    customer_id = _make_customer(partner_id, "StaleSimCo")

    create = client.post(
        "/policies",
        headers={"X-Aetherix-Account": owner_id},
        json={
            "schema_version": "2.0",
            "name": "Stale Simulation",
            "scope": {"partner_id": str(partner_id), "customer_id": str(customer_id)},
            "lineage": {"parent_policy_id": None, "inheritance_mode": "inherit_with_overrides"},
            "modules": _base_modules(),
            "white_label_names": {},
        },
    )
    assert create.status_code == 201, create.text
    policy_id = create.json()["policy"]["id"]

    first_sim = client.post(
        f"/policies/{policy_id}/simulate",
        headers={"X-Aetherix-Account": owner_id},
    )
    assert first_sim.status_code == 200, first_sim.text

    first_promote = client.post(
        f"/policies/{policy_id}/promote",
        headers={"X-Aetherix-Account": owner_id},
        json={
            "simulation_id": first_sim.json()["id"],
            "operator_approved": True,
            "approval_reason": "initial approval",
        },
    )
    assert first_promote.status_code == 200, first_promote.text

    stale_promote = client.post(
        f"/policies/{policy_id}/promote",
        headers={"X-Aetherix-Account": owner_id},
        json={
            "simulation_id": first_sim.json()["id"],
            "operator_approved": True,
            "approval_reason": "reusing stale simulation",
        },
    )
    assert stale_promote.status_code == 400
    assert "not in a promotable state" in stale_promote.json()["detail"]


def test_policy_v2_simulation_full_envelope_under_500ms() -> None:
    owner_id = _platform_owner()
    partner_id = _make_partner("perf")
    customer_id = _make_customer(partner_id, "PerfCo")
    licensing.ensure_default_catalog()
    licensing.assign_license(
        customer_id,
        CompanyLicenseAssign(subscription_sku="core", total_seats=20, addons=["semantic_dlp"]),
        actor=owner_id,
    )

    modules = _base_modules()
    modules["semantic_dlp"] = {
        "enabled": True,
        "sensitivity_labels": ["Public", "Internal", "Confidential", "Restricted"],
        "genai_destinations": ["copilot", "claude", "gemini", "chatgpt"],
        "actions": {
            "paste_sensitive": "review",
            "upload_restricted": "block",
            "copy_to_genai": "block",
        },
        "detectors": {
            "presidio": True,
            "llm_semantic": True,
            "custom_classifiers": ["finance", "source_code"],
        },
    }
    modules["genai_guardrails"] = {
        "enabled": True,
        "destinations": ["copilot", "claude", "gemini", "chatgpt"],
        "browser_enforcement": True,
        "endpoint_enforcement": True,
        "actions": {
            "paste_sensitive": "review",
            "upload_restricted": "block",
            "copy_to_genai": "block",
        },
    }

    create = client.post(
        "/policies",
        headers={"X-Aetherix-Account": owner_id},
        json={
            "schema_version": "2.0",
            "name": "Perf Envelope",
            "scope": {"partner_id": str(partner_id), "customer_id": str(customer_id)},
            "lineage": {"parent_policy_id": None, "inheritance_mode": "inherit_with_overrides"},
            "modules": modules,
            "white_label_names": {},
        },
    )
    assert create.status_code == 201, create.text
    policy_id = create.json()["policy"]["id"]

    started = time.perf_counter()
    simulation = client.post(
        f"/policies/{policy_id}/simulate",
        headers={"X-Aetherix-Account": owner_id},
    )
    elapsed = time.perf_counter() - started

    assert simulation.status_code == 200, simulation.text
    assert elapsed < 0.5


def test_policy_v2_semantic_dlp_structure_normalized() -> None:
    owner_id = _platform_owner()
    partner_id = _make_partner("semantic-structure")
    customer_id = _make_customer(partner_id, "SemanticStructureCo")
    licensing.ensure_default_catalog()
    licensing.assign_license(
        customer_id,
        CompanyLicenseAssign(
            subscription_sku="core",
            addons=["semantic_dlp"],
            total_seats=12,
        ),
        actor=owner_id,
    )

    modules = _base_modules()
    modules["semantic_dlp"] = {
        "enabled": True,
        "sensitivity_labels_csv": "Public, Internal, Confidential, Restricted",
        "genai_destinations_csv": "copilot, claude, gemini, chatgpt, custom",
        "paste_sensitive_action": "review",
        "upload_restricted_action": "block",
        "copy_to_genai_action": "review",
        "presidio_detector": True,
        "llm_semantic_detector": True,
        "custom_classifiers_csv": "source_code, customer_financial",
    }
    modules["genai_guardrails"] = {
        "enabled": True,
        "destinations_csv": "copilot, claude, gemini, chatgpt, custom",
        "browser_enforcement": True,
        "endpoint_enforcement": True,
        "paste_sensitive_action": "review",
        "upload_restricted_action": "block",
        "copy_to_genai_action": "review",
    }

    create = client.post(
        "/policies",
        headers={"X-Aetherix-Account": owner_id},
        json={
            "schema_version": "2.0",
            "name": "Semantic DLP Structured Policy",
            "scope": {"partner_id": str(partner_id), "customer_id": str(customer_id)},
            "lineage": {"parent_policy_id": None, "inheritance_mode": "inherit_with_overrides"},
            "modules": modules,
            "white_label_names": {},
        },
    )
    assert create.status_code == 201, create.text
    policy_id = create.json()["policy"]["id"]

    detail = client.get(f"/policies/{policy_id}", headers={"X-Aetherix-Account": owner_id})
    assert detail.status_code == 200, detail.text
    semantic = detail.json()["latest_version"]["payload"]["modules"]["semantic_dlp"]
    guardrails = detail.json()["latest_version"]["payload"]["modules"]["genai_guardrails"]

    assert semantic["actions"]["upload_restricted"] == "block"
    assert semantic["detectors"]["presidio"] is True
    assert semantic["detectors"]["llm_semantic"] is True
    assert semantic["detectors"]["custom_classifiers"] == ["source_code", "customer_financial"]
    assert "Restricted" in semantic["sensitivity_labels"]
    assert guardrails["browser_enforcement"] is True
    assert guardrails["endpoint_enforcement"] is True
    assert guardrails["actions"]["upload_restricted"] == "block"


def test_policy_v2_semantic_dlp_simulation_reports_contextual_impact() -> None:
    owner_id = _platform_owner()
    partner_id = _make_partner("semantic-sim")
    customer_id = _make_customer(partner_id, "SemanticSimCo")
    licensing.ensure_default_catalog()
    licensing.assign_license(
        customer_id,
        CompanyLicenseAssign(
            subscription_sku="core",
            addons=["semantic_dlp"],
            total_seats=20,
        ),
        actor=owner_id,
    )

    modules = _base_modules()
    modules["semantic_dlp"] = {
        "enabled": True,
        "actions": {
            "paste_sensitive": "review",
            "upload_restricted": "block",
            "copy_to_genai": "review",
        },
        "sensitivity_labels": ["Public", "Internal", "Confidential", "Restricted"],
        "genai_destinations": ["copilot", "claude", "gemini", "chatgpt", "custom"],
        "detectors": {
            "presidio": True,
            "llm_semantic": True,
            "custom_classifiers": ["source_code"],
        },
    }
    modules["genai_guardrails"] = {
        "enabled": True,
        "browser_enforcement": True,
        "endpoint_enforcement": True,
        "destinations": ["copilot", "claude", "gemini", "chatgpt", "custom"],
        "actions": {
            "paste_sensitive": "review",
            "upload_restricted": "block",
            "copy_to_genai": "review",
        },
    }

    create = client.post(
        "/policies",
        headers={"X-Aetherix-Account": owner_id},
        json={
            "schema_version": "2.0",
            "name": "Semantic DLP Simulation Policy",
            "scope": {"partner_id": str(partner_id), "customer_id": str(customer_id)},
            "lineage": {"parent_policy_id": None, "inheritance_mode": "inherit_with_overrides"},
            "modules": modules,
            "white_label_names": {},
        },
    )
    assert create.status_code == 201, create.text
    policy_id = create.json()["policy"]["id"]

    simulation = client.post(
        f"/policies/{policy_id}/simulate",
        headers={"X-Aetherix-Account": owner_id},
    )
    assert simulation.status_code == 200, simulation.text
    body = simulation.json()

    semantic_outcome = next(item for item in body["outcomes"] if item["module"] == "semantic_dlp")
    guardrail_outcome = next(item for item in body["outcomes"] if item["module"] == "genai_guardrails")

    assert body["summary"]["approval_required"] is True
    assert body["summary"]["would_block"] >= 2
    assert semantic_outcome["risk_delta"] > 0
    assert "block" in semantic_outcome["destructive_actions"]
    assert any(note.startswith("semantic_action:upload_restricted:block") for note in semantic_outcome["notes"])
    assert any(note.startswith("guarded_destinations:") for note in guardrail_outcome["notes"])

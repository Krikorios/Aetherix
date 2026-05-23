from __future__ import annotations

import time
import uuid
from copy import deepcopy

from fastapi.testclient import TestClient

from app import db as app_db
from app.main import app


client = TestClient(app)


def _create_policy(*, actor_id: str, name: str, partner_id: str, customer_id: str | None, modules: dict, parent_policy_id: str | None = None):
    response = client.post(
        "/policies",
        headers={"X-Aetherix-Account": actor_id},
        json={
            "schema_version": "2.0",
            "name": name,
            "scope": {
                "partner_id": partner_id,
                "customer_id": customer_id,
                "group_id": None,
                "endpoint_id": None,
            },
            "lineage": {
                "parent_policy_id": parent_policy_id,
                "inheritance_mode": "inherit_with_overrides",
            },
            "modules": modules,
            "white_label_names": {},
        },
    )
    assert response.status_code == 201, response.text
    return response.json()


def _simulate_promote(*, actor_id: str, policy_id: str, approve: bool = True):
    simulation = client.post(
        f"/policies/{policy_id}/simulate",
        headers={"X-Aetherix-Account": actor_id},
    )
    assert simulation.status_code == 200, simulation.text
    sim_body = simulation.json()

    promote = client.post(
        f"/policies/{policy_id}/promote",
        headers={"X-Aetherix-Account": actor_id},
        json={
            "simulation_id": sim_body["id"],
            "operator_approved": approve,
            "approval_reason": "validated in end-to-end promotion test" if approve else None,
        },
    )
    return sim_body, promote


def test_flow_a_msp_creates_simulates_promotes_assigns_policy(policy_v2_templates, tenant_hierarchy_factory):
    tenant = tenant_hierarchy_factory(addons=["semantic_dlp"])
    modules = deepcopy(policy_v2_templates["genai_focused"])

    created = _create_policy(
        actor_id=tenant["msp_id"],
        name="Flow A MSP Policy",
        partner_id=tenant["partner_id"],
        customer_id=tenant["customer_id"],
        modules=modules,
    )
    policy_id = created["policy"]["id"]

    simulation = client.post(
        f"/policies/{policy_id}/simulate",
        headers={"X-Aetherix-Account": tenant["msp_id"]},
    )
    assert simulation.status_code == 200, simulation.text
    sim = simulation.json()
    assert sim["summary"]["risk_delta_total"] > 0
    assert sim["summary"]["modules_with_destructive_actions"] >= 1

    promotion = client.post(
        f"/policies/{policy_id}/promote",
        headers={"X-Aetherix-Account": tenant["msp_id"]},
        json={
            "simulation_id": sim["id"],
            "operator_approved": True,
            "approval_reason": "approved by MSP operator",
        },
    )
    assert promotion.status_code == 200, promotion.text

    assign = client.post(
        "/policies/assign",
        headers={"X-Aetherix-Account": tenant["msp_id"]},
        json={"policy_id": policy_id, "customer_id": tenant["customer_id"]},
    )
    assert assign.status_code == 201, assign.text

    effective = client.get(
        f"/policies/effective?customer_id={tenant['customer_id']}",
        headers={"X-Aetherix-Account": tenant["company_admin_id"]},
    )
    assert effective.status_code == 200, effective.text
    resolved = effective.json()["resolved_policy"]["modules"]
    assert resolved["semantic_dlp"]["enabled"] is True
    assert resolved["genai_guardrails"]["enabled"] is True
    assert effective.json()["policy_ids_applied"]

    with app_db.connection() as conn, conn.cursor() as cur:
        cur.execute(
            """
            select count(*) as n
            from evidence_events
            where action in ('policy_v2.create', 'policy_v2.simulate', 'policy_v2.promote', 'policy_v2.assign', 'policy_v2.effective')
              and scope->>'customer_id' = %s
            """,
            (tenant["customer_id"],),
        )
        assert int(cur.fetchone()["n"]) >= 5


def test_flow_b_company_admin_creates_group_override_and_endpoint_inherits(policy_v2_templates, tenant_hierarchy_factory):
    tenant = tenant_hierarchy_factory(addons=["semantic_dlp"])

    base_policy = _create_policy(
        actor_id=tenant["msp_id"],
        name="Flow B Base",
        partner_id=tenant["partner_id"],
        customer_id=tenant["customer_id"],
        modules=deepcopy(policy_v2_templates["minimal"]),
    )
    base_policy_id = base_policy["policy"]["id"]
    _, promote_base = _simulate_promote(actor_id=tenant["msp_id"], policy_id=base_policy_id, approve=True)
    assert promote_base.status_code == 200, promote_base.text

    assign_customer = client.post(
        "/policies/assign",
        headers={"X-Aetherix-Account": tenant["msp_id"]},
        json={"policy_id": base_policy_id, "customer_id": tenant["customer_id"]},
    )
    assert assign_customer.status_code == 201, assign_customer.text

    override_modules = deepcopy(policy_v2_templates["genai_focused"])
    override_modules["genai_guardrails"]["actions"]["copy_to_genai"] = "block"

    override = _create_policy(
        actor_id=tenant["company_admin_id"],
        name="Flow B Group Override",
        partner_id=tenant["partner_id"],
        customer_id=tenant["customer_id"],
        modules=override_modules,
        parent_policy_id=base_policy_id,
    )
    override_policy_id = override["policy"]["id"]

    simulate_override = client.post(
        f"/policies/{override_policy_id}/simulate",
        headers={"X-Aetherix-Account": tenant["company_admin_id"]},
    )
    assert simulate_override.status_code == 200, simulate_override.text

    assign_group = client.post(
        "/policies/assign",
        headers={"X-Aetherix-Account": tenant["company_admin_id"]},
        json={
            "policy_id": override_policy_id,
            "policy_version": 1,
            "customer_id": tenant["customer_id"],
            "group_id": tenant["group_id"],
        },
    )
    assert assign_group.status_code == 201, assign_group.text

    effective = client.get(
        f"/policies/effective?endpoint_id={tenant['endpoint_id']}",
        headers={"X-Aetherix-Account": tenant["company_admin_id"]},
    )
    assert effective.status_code == 200, effective.text
    modules = effective.json()["resolved_policy"]["modules"]
    assert modules["genai_guardrails"]["actions"]["copy_to_genai"] == "block"


def test_flow_c_agent_fetch_returns_effective_entitled_modules(policy_v2_templates, tenant_hierarchy_factory):
    tenant = tenant_hierarchy_factory(addons=[])
    modules = deepcopy(policy_v2_templates["minimal"])

    created = _create_policy(
        actor_id=tenant["owner_id"],
        name="Flow C Agent Fetch",
        partner_id=tenant["partner_id"],
        customer_id=tenant["customer_id"],
        modules=modules,
    )
    policy_id = created["policy"]["id"]
    _, promoted = _simulate_promote(actor_id=tenant["owner_id"], policy_id=policy_id, approve=True)
    assert promoted.status_code == 200, promoted.text

    token_response = client.post(
        "/enrollment/tokens",
        json={
            "partner_id": tenant["partner_id"],
            "customer_id": tenant["customer_id"],
            "group_id": tenant["group_id"],
            "note": "flow-c",
        },
    )
    assert token_response.status_code == 201
    enroll = client.post(
        "/agent/enroll",
        json={
            "enrollment_token": token_response.json()["token"],
            "hostname": "new-flow-c-host",
            "os": "linux",
        },
    )
    assert enroll.status_code == 201, enroll.text

    endpoint_id = enroll.json()["agent_id"]
    endpoint_secret = enroll.json()["agent_secret"]

    assign_endpoint = client.post(
        "/policies/assign",
        headers={"X-Aetherix-Account": tenant["owner_id"]},
        json={"policy_id": policy_id, "endpoint_id": endpoint_id, "customer_id": tenant["customer_id"]},
    )
    assert assign_endpoint.status_code == 201, assign_endpoint.text

    fetch = client.get(
        f"/agent/policy?endpoint_id={endpoint_id}",
        headers={"Authorization": f"Bearer {endpoint_secret}"},
    )
    assert fetch.status_code == 200, fetch.text
    resolved = fetch.json()["resolved_policy"]["modules"]
    assert "semantic_dlp" in resolved
    assert "genai_guardrails" in resolved
    assert resolved["semantic_dlp"]["enabled"] is False
    assert resolved["semantic_dlp"]["locked"] is True


def test_flow_d_destructive_gate_requires_simulation_and_approval(policy_v2_templates, tenant_hierarchy_factory):
    tenant = tenant_hierarchy_factory(addons=["semantic_dlp"])
    modules = deepcopy(policy_v2_templates["strict"])
    modules["semantic_dlp"]["enabled"] = True
    modules["genai_guardrails"]["enabled"] = True

    created = _create_policy(
        actor_id=tenant["owner_id"],
        name="Flow D Gate",
        partner_id=tenant["partner_id"],
        customer_id=tenant["customer_id"],
        modules=modules,
    )
    policy_id = created["policy"]["id"]

    no_sim = client.post(
        f"/policies/{policy_id}/promote",
        headers={"X-Aetherix-Account": tenant["owner_id"]},
        json={"simulation_id": str(uuid.uuid4()), "operator_approved": True, "approval_reason": "manual"},
    )
    assert no_sim.status_code == 400
    assert "simulation not found" in no_sim.json()["detail"]

    sim = client.post(
        f"/policies/{policy_id}/simulate",
        headers={"X-Aetherix-Account": tenant["owner_id"]},
    )
    assert sim.status_code == 200, sim.text
    sim_body = sim.json()
    assert sim_body["summary"]["approval_required"] is True

    denied = client.post(
        f"/policies/{policy_id}/promote",
        headers={"X-Aetherix-Account": tenant["owner_id"]},
        json={"simulation_id": sim_body["id"], "operator_approved": False},
    )
    assert denied.status_code == 400

    approved = client.post(
        f"/policies/{policy_id}/promote",
        headers={"X-Aetherix-Account": tenant["owner_id"]},
        json={
            "simulation_id": sim_body["id"],
            "operator_approved": True,
            "approval_reason": "approved after simulation review",
        },
    )
    assert approved.status_code == 200, approved.text

    with app_db.connection() as conn, conn.cursor() as cur:
        cur.execute(
            """
            select count(*) as n
            from evidence_events
            where action = 'policy_v2.promote'
              and scope->>'customer_id' = %s
            """,
            (tenant["customer_id"],),
        )
        assert int(cur.fetchone()["n"]) >= 1


def test_edge_cases_invalid_json_schema_and_agent_token_rejected(policy_v2_templates, tenant_hierarchy_factory):
    tenant = tenant_hierarchy_factory(addons=["semantic_dlp"])
    broken = deepcopy(policy_v2_templates["minimal"])
    broken["semantic_dlp"]["enabled"] = True
    broken["semantic_dlp"]["actions"]["upload_restricted"] = "deny"

    response = client.post(
        "/policies",
        headers={"X-Aetherix-Account": tenant["owner_id"]},
        json={
            "schema_version": "2.0",
            "name": "Broken Semantic Config",
            "scope": {"partner_id": tenant["partner_id"], "customer_id": tenant["customer_id"]},
            "lineage": {"parent_policy_id": None, "inheritance_mode": "inherit_with_overrides"},
            "modules": broken,
            "white_label_names": {},
        },
    )
    assert response.status_code == 400
    assert "upload_restricted" in response.json()["detail"]

    invalid_agent = client.get(
        f"/agent/policy?endpoint_id={tenant['endpoint_id']}",
        headers={"Authorization": "Bearer expired-or-invalid-token"},
    )
    assert invalid_agent.status_code == 401


def test_edge_case_deep_inheritance_and_full_simulation_performance(policy_v2_templates, tenant_hierarchy_factory):
    tenant = tenant_hierarchy_factory(addons=["semantic_dlp"])

    global_policy = _create_policy(
        actor_id=tenant["owner_id"],
        name="Global Base",
        partner_id=tenant["partner_id"],
        customer_id=None,
        modules=deepcopy(policy_v2_templates["minimal"]),
    )
    global_policy_id = global_policy["policy"]["id"]
    _, promoted_global = _simulate_promote(actor_id=tenant["owner_id"], policy_id=global_policy_id, approve=True)
    assert promoted_global.status_code == 200

    customer_override_modules = deepcopy(policy_v2_templates["genai_focused"])
    customer_override = _create_policy(
        actor_id=tenant["owner_id"],
        name="Customer Override",
        partner_id=tenant["partner_id"],
        customer_id=tenant["customer_id"],
        modules=customer_override_modules,
        parent_policy_id=global_policy_id,
    )
    customer_policy_id = customer_override["policy"]["id"]

    start = time.perf_counter()
    sim = client.post(
        f"/policies/{customer_policy_id}/simulate",
        headers={"X-Aetherix-Account": tenant["owner_id"]},
    )
    elapsed = time.perf_counter() - start
    assert sim.status_code == 200, sim.text
    assert elapsed < 0.5

    _, promoted_customer = _simulate_promote(actor_id=tenant["owner_id"], policy_id=customer_policy_id, approve=True)
    assert promoted_customer.status_code == 200

    assign_partner = client.post(
        "/policies/assign",
        headers={"X-Aetherix-Account": tenant["owner_id"]},
        json={"policy_id": global_policy_id, "partner_id": tenant["partner_id"]},
    )
    assert assign_partner.status_code == 201, assign_partner.text

    assign_customer = client.post(
        "/policies/assign",
        headers={"X-Aetherix-Account": tenant["owner_id"]},
        json={"policy_id": customer_policy_id, "customer_id": tenant["customer_id"]},
    )
    assert assign_customer.status_code == 201, assign_customer.text

    endpoint_policy = _create_policy(
        actor_id=tenant["owner_id"],
        name="Endpoint Tightening",
        partner_id=tenant["partner_id"],
        customer_id=tenant["customer_id"],
        modules=deepcopy(policy_v2_templates["strict"]),
        parent_policy_id=customer_policy_id,
    )
    endpoint_policy_id = endpoint_policy["policy"]["id"]
    _, promoted_endpoint = _simulate_promote(actor_id=tenant["owner_id"], policy_id=endpoint_policy_id, approve=True)
    assert promoted_endpoint.status_code == 200

    assign_endpoint = client.post(
        "/policies/assign",
        headers={"X-Aetherix-Account": tenant["owner_id"]},
        json={"policy_id": endpoint_policy_id, "endpoint_id": tenant["endpoint_id"], "customer_id": tenant["customer_id"]},
    )
    assert assign_endpoint.status_code == 201, assign_endpoint.text

    effective = client.get(
        f"/policies/effective?endpoint_id={tenant['endpoint_id']}",
        headers={"X-Aetherix-Account": tenant["owner_id"]},
    )
    assert effective.status_code == 200, effective.text
    assert len(effective.json()["assignments_applied"]) >= 3

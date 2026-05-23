from __future__ import annotations

from copy import deepcopy

from fastapi.testclient import TestClient

from app import db as app_db
from app.main import app


client = TestClient(app)


def test_semantic_and_guardrail_canonical_structure_is_persisted(policy_v2_templates, tenant_hierarchy_factory):
    tenant = tenant_hierarchy_factory(addons=["semantic_dlp"])
    modules = deepcopy(policy_v2_templates["genai_focused"])
    modules["semantic_dlp"].pop("sensitivity_labels", None)
    modules["semantic_dlp"]["sensitivity_labels_csv"] = "Public, Internal, Confidential, Restricted"
    modules["semantic_dlp"]["genai_destinations_csv"] = "copilot, claude"
    modules["semantic_dlp"]["custom_classifiers_csv"] = "finance, source_code"

    created = client.post(
        "/policies",
        headers={"X-Aetherix-Account": tenant["owner_id"]},
        json={
            "schema_version": "2.0",
            "name": "Semantic Canonical",
            "scope": {"partner_id": tenant["partner_id"], "customer_id": tenant["customer_id"]},
            "lineage": {"parent_policy_id": None, "inheritance_mode": "inherit_with_overrides"},
            "modules": modules,
            "white_label_names": {},
        },
    )
    assert created.status_code == 201, created.text

    detail = client.get(
        f"/policies/{created.json()['policy']['id']}",
        headers={"X-Aetherix-Account": tenant["owner_id"]},
    )
    assert detail.status_code == 200, detail.text
    semantic = detail.json()["latest_version"]["payload"]["modules"]["semantic_dlp"]
    guardrails = detail.json()["latest_version"]["payload"]["modules"]["genai_guardrails"]

    assert semantic["actions"]["upload_restricted"] == "block"
    assert semantic["detectors"]["presidio"] is True
    assert semantic["detectors"]["llm_semantic"] is True
    assert isinstance(semantic["detectors"]["custom_classifiers"], list)
    assert "Restricted" in semantic["sensitivity_labels"]
    assert isinstance(guardrails["destinations"], list)


def test_simulation_impact_includes_semantic_and_genai_actions(policy_v2_templates, tenant_hierarchy_factory):
    tenant = tenant_hierarchy_factory(addons=["semantic_dlp"])
    modules = deepcopy(policy_v2_templates["genai_focused"])

    created = client.post(
        "/policies",
        headers={"X-Aetherix-Account": tenant["owner_id"]},
        json={
            "schema_version": "2.0",
            "name": "Semantic Impact",
            "scope": {"partner_id": tenant["partner_id"], "customer_id": tenant["customer_id"]},
            "lineage": {"parent_policy_id": None, "inheritance_mode": "inherit_with_overrides"},
            "modules": modules,
            "white_label_names": {},
        },
    )
    assert created.status_code == 201, created.text

    policy_id = created.json()["policy"]["id"]
    simulation = client.post(
        f"/policies/{policy_id}/simulate",
        headers={"X-Aetherix-Account": tenant["owner_id"]},
    )
    assert simulation.status_code == 200, simulation.text
    body = simulation.json()
    assert body["summary"]["risk_delta_total"] > 0

    by_module = {item["module"]: item for item in body["outcomes"]}
    semantic = by_module["semantic_dlp"]
    guardrails = by_module["genai_guardrails"]

    assert semantic["enabled"] is True
    assert any(note.startswith("semantic_action:upload_restricted:block") for note in semantic["notes"])
    assert any(note.startswith("detector:presidio") for note in semantic["notes"])
    assert any(note.startswith("detector:llm_semantic") for note in semantic["notes"])
    assert any(note.startswith("enforcement:browser") for note in guardrails["notes"])
    assert any(note.startswith("enforcement:endpoint") for note in guardrails["notes"])


def test_invalid_semantic_action_configuration_is_rejected(policy_v2_templates, tenant_hierarchy_factory):
    tenant = tenant_hierarchy_factory(addons=["semantic_dlp"])
    modules = deepcopy(policy_v2_templates["genai_focused"])
    modules["semantic_dlp"]["actions"]["copy_to_genai"] = "deny"

    response = client.post(
        "/policies",
        headers={"X-Aetherix-Account": tenant["owner_id"]},
        json={
            "schema_version": "2.0",
            "name": "Invalid Detector",
            "scope": {"partner_id": tenant["partner_id"], "customer_id": tenant["customer_id"]},
            "lineage": {"parent_policy_id": None, "inheritance_mode": "inherit_with_overrides"},
            "modules": modules,
            "white_label_names": {},
        },
    )
    assert response.status_code == 400
    assert "copy_to_genai" in response.json()["detail"]


def test_semantic_policy_actions_emit_evidence_with_controls(policy_v2_templates, tenant_hierarchy_factory):
    tenant = tenant_hierarchy_factory(addons=["semantic_dlp"])
    modules = deepcopy(policy_v2_templates["genai_focused"])

    create = client.post(
        "/policies",
        headers={"X-Aetherix-Account": tenant["owner_id"]},
        json={
            "schema_version": "2.0",
            "name": "Evidence Semantic",
            "scope": {"partner_id": tenant["partner_id"], "customer_id": tenant["customer_id"]},
            "lineage": {"parent_policy_id": None, "inheritance_mode": "inherit_with_overrides"},
            "modules": modules,
            "white_label_names": {},
        },
    )
    assert create.status_code == 201, create.text
    policy_id = create.json()["policy"]["id"]

    sim = client.post(
        f"/policies/{policy_id}/simulate",
        headers={"X-Aetherix-Account": tenant["owner_id"]},
    )
    assert sim.status_code == 200, sim.text

    promote = client.post(
        f"/policies/{policy_id}/promote",
        headers={"X-Aetherix-Account": tenant["owner_id"]},
        json={
            "simulation_id": sim.json()["id"],
            "operator_approved": True,
            "approval_reason": "semantic policy approved",
        },
    )
    assert promote.status_code == 200, promote.text

    assign = client.post(
        "/policies/assign",
        headers={"X-Aetherix-Account": tenant["owner_id"]},
        json={"policy_id": policy_id, "customer_id": tenant["customer_id"]},
    )
    assert assign.status_code == 201, assign.text

    with app_db.connection() as conn, conn.cursor() as cur:
        cur.execute(
            """
            select action, evidence_controls
            from evidence_events
            where scope->>'customer_id' = %s
              and action in ('policy_v2.create', 'policy_v2.simulate', 'policy_v2.promote', 'policy_v2.assign')
            order by created_at asc
            """,
            (tenant["customer_id"],),
        )
        rows = cur.fetchall()

    actions = [row["action"] for row in rows]
    assert actions == [
        "policy_v2.create",
        "policy_v2.simulate",
        "policy_v2.promote",
        "policy_v2.assign",
    ]
    for row in rows:
        controls = list(row["evidence_controls"])
        assert controls
        assert any(control.startswith("iso27001-2022:") for control in controls)

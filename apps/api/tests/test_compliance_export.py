from __future__ import annotations

import uuid
from datetime import UTC, datetime
from copy import deepcopy

from fastapi.testclient import TestClient

from app import db as app_db
from app.main import app
from app.schemas import AccountCreate, CompanyLicenseAssign, RoleAssignmentRequest
from app.services import licensing, tenancy


def _make_customer() -> uuid.UUID:
    partner_id = uuid.uuid4()
    customer_id = uuid.uuid4()
    now = datetime.now(UTC)
    with app_db.connection() as conn, conn.cursor() as cur:
        cur.execute(
            """
            insert into partners (id, name, slug, deployment_mode, created_at)
            values (%s, 'Test MSP', %s, 'cloud', %s)
            """,
            (partner_id, f"msp-{partner_id.hex[:8]}", now),
        )
        cur.execute(
            """
            insert into customers (id, partner_id, customer_number, name, status, created_by, created_at)
            values (%s, %s, %s, 'Audit Customer', 'active', 'tests', %s)
            """,
            (customer_id, partner_id, f"C-{customer_id.hex[:8]}", now),
        )
    return customer_id


def test_compliance_export_contains_signed_iso_evidence(promote_default_policy) -> None:
    customer_id = _make_customer()
    promote_default_policy(mode="block", entities=["EMAIL_ADDRESS"])

    client = TestClient(app)
    scan_response = client.post(
        "/dlp/scan",
        json={
            "text": "Email the audit file to privacy@example.com.",
            "source": "browser:chatgpt",
            "customer_id": str(customer_id),
        },
    )
    assert scan_response.status_code == 200

    response = client.get(
        "/compliance/export",
        params={"customer_id": str(customer_id), "framework": "iso27001-2022"},
    )
    assert response.status_code == 200
    bundle = response.json()

    assert bundle["framework"] == "iso27001-2022"
    assert bundle["customer_id"] == str(customer_id)
    assert bundle["signature"]["algorithm"] == "HMAC-SHA256"
    assert len(bundle["signature"]["value"]) == 64
    assert bundle["audit_chain"]["record_count"] >= 1

    evidence_sources = {item["source_table"] for item in bundle["evidence"]}
    assert "alerts" in evidence_sources
    assert "policy_documents" in evidence_sources

    controls_with_evidence = {
        control["control_id"]
        for control in bundle["controls"]
        if control["evidence_count"] > 0
    }
    assert {"A.5.12", "A.8.12"}.issubset(controls_with_evidence)


def test_compliance_export_rejects_unknown_framework() -> None:
    customer_id = _make_customer()
    response = TestClient(app).get(
        "/compliance/export",
        params={"customer_id": str(customer_id), "framework": "unknown"},
    )
    assert response.status_code == 400


def test_compliance_export_includes_policy_v2_evidence_events(policy_v2_templates) -> None:
    owner = tenancy.ensure_platform_owner("compliance-owner@aetherix.test", "Compliance Owner")
    partner_id = uuid.uuid4()
    customer_id = uuid.uuid4()
    now = datetime.now(UTC)

    with app_db.connection() as conn, conn.cursor() as cur:
        cur.execute(
            """
            insert into partners (id, name, slug, deployment_mode, created_at, tier)
            values (%s, 'Compliance MSP', %s, 'cloud', %s, 'msp')
            """,
            (partner_id, f"cmp-{partner_id.hex[:8]}", now),
        )
        cur.execute(
            """
            insert into customers (id, partner_id, customer_number, name, status, created_by, created_at)
            values (%s, %s, %s, 'Compliance Customer', 'active', 'tests', %s)
            """,
            (customer_id, partner_id, f"CMP-{customer_id.hex[:8]}", now),
        )

    licensing.ensure_default_catalog()
    licensing.assign_license(
        customer_id,
        CompanyLicenseAssign(subscription_sku="core", total_seats=20, addons=["semantic_dlp"]),
        actor=str(owner.id),
    )

    msp = tenancy.create_account(
        AccountCreate(
            email="compliance-msp@aetherix.test",
            full_name="Compliance MSP",
            initial_role=RoleAssignmentRequest(role_code="msp_partner", partner_id=partner_id),
        )
    )

    modules = deepcopy(policy_v2_templates["genai_focused"])
    create = TestClient(app).post(
        "/policies",
        headers={"X-Aetherix-Account": str(msp.id)},
        json={
            "schema_version": "2.0",
            "name": "Compliance Flow Policy",
            "scope": {"partner_id": str(partner_id), "customer_id": str(customer_id)},
            "lineage": {"parent_policy_id": None, "inheritance_mode": "inherit_with_overrides"},
            "modules": modules,
            "white_label_names": {},
        },
    )
    assert create.status_code == 201, create.text
    policy_id = create.json()["policy"]["id"]

    simulation = TestClient(app).post(
        f"/policies/{policy_id}/simulate",
        headers={"X-Aetherix-Account": str(msp.id)},
    )
    assert simulation.status_code == 200, simulation.text

    promotion = TestClient(app).post(
        f"/policies/{policy_id}/promote",
        headers={"X-Aetherix-Account": str(msp.id)},
        json={
            "simulation_id": simulation.json()["id"],
            "operator_approved": True,
            "approval_reason": "compliance evidence check",
        },
    )
    assert promotion.status_code == 200, promotion.text

    assign = TestClient(app).post(
        "/policies/assign",
        headers={"X-Aetherix-Account": str(msp.id)},
        json={"policy_id": policy_id, "customer_id": str(customer_id)},
    )
    assert assign.status_code == 201, assign.text

    effective = TestClient(app).get(
        f"/policies/effective?customer_id={customer_id}",
        headers={"X-Aetherix-Account": str(msp.id)},
    )
    assert effective.status_code == 200, effective.text

    export = TestClient(app).get(
        "/compliance/export",
        params={"customer_id": str(customer_id), "framework": "iso27001-2022"},
    )
    assert export.status_code == 200, export.text
    bundle = export.json()

    evidence_events = [
        item for item in bundle["evidence"] if item["source_table"] == "evidence_events"
    ]
    summaries = "\n".join(item["summary"] for item in evidence_events)
    assert "policy_v2.create" in summaries
    assert "policy_v2.simulate" in summaries
    assert "policy_v2.promote" in summaries
    assert "policy_v2.assign" in summaries
    assert "policy_v2.effective" in summaries

    controls_with_evidence = {
        control["control_id"]
        for control in bundle["controls"]
        if control["evidence_count"] > 0
    }
    assert "A.5.12" in controls_with_evidence
    assert "A.8.12" in controls_with_evidence


def test_compliance_v0_5_reviews_and_attestation_workflow() -> None:
    owner = tenancy.ensure_platform_owner("compliance-v5@aetherix.test", "Compliance Owner v0.5")
    customer_id = _make_customer()
    client = TestClient(app)
    headers = {"X-Aetherix-Account": str(owner.id)}

    r_list = client.get(
        f"/compliance/reviews?customer_id={customer_id}&framework=iso27001-2022",
        headers=headers,
    )
    assert r_list.status_code == 200
    assert len(r_list.json()) == 0

    review_create = client.post(
        f"/compliance/reviews?customer_id={customer_id}",
        headers=headers,
        json={
            "framework": "iso27001-2022",
            "control_id": "A.5.12",
            "status": "reviewed",
            "notes": "Validated semantic policies",
        },
    )
    assert review_create.status_code == 200
    res = review_create.json()
    assert res["status"] == "reviewed"
    assert res["notes"] == "Validated semantic policies"
    assert res["reviewed_by"] == owner.email

    r_list2 = client.get(
        f"/compliance/reviews?customer_id={customer_id}&framework=iso27001-2022",
        headers=headers,
    )
    assert r_list2.status_code == 200
    assert len(r_list2.json()) == 1

    a_list = client.get(
        f"/compliance/attestations?customer_id={customer_id}&framework=iso27001-2022",
        headers=headers,
    )
    assert a_list.status_code == 200
    assert len(a_list.json()) == 0

    attest_create = client.post(
        f"/compliance/attestations?customer_id={customer_id}",
        headers=headers,
        json={
            "framework": "iso27001-2022",
            "notes": "Signed off on Q2 2026",
        },
    )
    assert attest_create.status_code == 200
    res_a = attest_create.json()
    assert res_a["status"] == "active"
    assert res_a["notes"] == "Signed off on Q2 2026"
    assert len(res_a["bundle_hash"]) == 64

    a_list2 = client.get(
        f"/compliance/attestations?customer_id={customer_id}&framework=iso27001-2022",
        headers=headers,
    )
    assert a_list2.status_code == 200
    assert len(a_list2.json()) == 1

    vault_list = client.get(
        f"/compliance/vault?customer_id={customer_id}&framework=iso27001-2022",
        headers=headers,
    )
    assert vault_list.status_code == 200
    assert len(vault_list.json()) == 1
    vault_item = vault_list.json()[0]
    assert vault_item["status"] == "sealed"
    assert vault_item["vault_provider"] == "Azure Immutable Blob Storage (WORM Policy)"
    assert vault_item["bundle_hash"] == res_a["bundle_hash"]
    assert "https://" in vault_item["reference_uri"]

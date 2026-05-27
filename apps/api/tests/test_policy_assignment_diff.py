from __future__ import annotations

import uuid
from datetime import UTC, datetime

from fastapi.testclient import TestClient

from app import db as app_db
from app.main import app
from app.schemas import CompanyLicenseAssign
from app.services import licensing, tenancy


client = TestClient(app)


def _platform_owner() -> str:
    return str(tenancy.ensure_platform_owner("policy-diff-owner@aetherix.test", "Policy Diff Owner").id)


def _make_partner(slug: str = "p-diff") -> uuid.UUID:
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


def _make_customer(partner_id: uuid.UUID, name: str = "PolicyDiffCo") -> uuid.UUID:
    customer_id = uuid.uuid4()
    with app_db.connection() as conn, conn.cursor() as cur:
        cur.execute(
            """
            insert into customers (
                id, partner_id, customer_number, name, status, created_by, created_at
            ) values (%s, %s, %s, %s, 'active', 'tests', %s)
            """,
            (customer_id, partner_id, f"PDIFF-{customer_id.hex[:8]}", name, datetime.now(UTC)),
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


def _create_enrolled_agent(agent_id: str, partner_id: uuid.UUID, customer_id: uuid.UUID, secret: str = "agent-secret") -> None:
    with app_db.connection() as conn, conn.cursor() as cur:
        cur.execute(
            """
            insert into enrolled_agents (
                agent_id, hostname, os, secret, enrolled_at, last_nonce, revoked,
                partner_id, customer_id, group_id, policy_package_id
            ) values (
                %s, 'host-diff', 'linux', %s, %s, 0, false,
                %s, %s, null, null
            )
            """,
            (agent_id, secret, datetime.now(UTC), partner_id, customer_id),
        )


def test_assignment_list_reports_drift_and_apply_clears_it(auth_headers) -> None:
    owner_id = _platform_owner()
    partner_id = _make_partner("assignment-diff")
    customer_id = _make_customer(partner_id, "AssignmentDiffCo")

    licensing.ensure_default_catalog()
    licensing.assign_license(
        customer_id,
        CompanyLicenseAssign(subscription_sku="core", total_seats=50),
        actor=owner_id,
    )

    _create_enrolled_agent("agent-diff-001", partner_id, customer_id)

    create = client.post(
        "/policies",
        headers=auth_headers(owner_id),
        json={
            "schema_version": "2.0",
            "name": "Assignment Diff Policy",
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
        headers=auth_headers(owner_id),
        json={"policy_id": policy_id, "customer_id": str(customer_id)},
    )
    assert assign.status_code == 201, assign.text
    assignment_id = assign.json()["id"]

    listing_before = client.get(
        "/policy/assignments",
        headers=auth_headers(owner_id),
    )
    assert listing_before.status_code == 200, listing_before.text
    before_item = next(item for item in listing_before.json() if item["id"] == assignment_id)
    assert before_item["endpoint_count"] == 1
    assert before_item["drift_count"] == 1
    assert before_item["pending_diff"]
    assert before_item["last_diff"] is None

    apply_res = client.post(
        f"/policy/assignments/{assignment_id}/apply",
        headers=auth_headers(owner_id),
        json={},
    )
    assert apply_res.status_code == 200, apply_res.text
    assert apply_res.json()["status"] == "applied"

    listing_after = client.get(
        "/policy/assignments",
        headers=auth_headers(owner_id),
    )
    assert listing_after.status_code == 200, listing_after.text
    after_item = next(item for item in listing_after.json() if item["id"] == assignment_id)
    assert after_item["endpoint_count"] == 1
    assert after_item["drift_count"] == 0
    assert after_item["pending_diff"] is None
    assert after_item["last_diff"] is not None

    with app_db.connection() as conn, conn.cursor() as cur:
        cur.execute(
            """
            select count(*) as n
            from evidence_events
            where action = 'policy_v2.apply_diff'
              and payload->>'assignment_id' = %s
            """,
            (assignment_id,),
        )
        evidence_count = int(cur.fetchone()["n"])
        cur.execute(
            """
            select count(*) as n
            from policy_acks
            where endpoint_id = %s
            """,
            ("agent-diff-001",),
        )
        ack_count = int(cur.fetchone()["n"])

    assert evidence_count >= 1
    assert ack_count >= 1

from __future__ import annotations

import json
import hashlib
import hmac
import uuid
from copy import deepcopy
from datetime import UTC, datetime
from pathlib import Path

from fastapi.testclient import TestClient

from app import db as app_db
from app.main import app
from app.schemas import AccountCreate, CompanyLicenseAssign, RoleAssignmentRequest
from app.services import jwt_tokens, licensing, tenancy


def _enroll_agent(agent_id: str, customer_id: uuid.UUID) -> None:
    now = datetime.now(UTC)
    with app_db.connection() as conn, conn.cursor() as cur:
        cur.execute(
            """
            insert into enrolled_agents (agent_id, customer_id, hostname, os, secret, enrolled_at, last_nonce, revoked)
            values (%s, %s, %s, 'windows', 'e2e-endpoint-secret', %s, 0, false)
            """,
            (agent_id, customer_id, agent_id, now),
        )


def _heartbeat_signature(agent_id: str, collected_at: str, nonce: int) -> str:
    message = f"{agent_id}|vss-guard-host|windows|{collected_at}|policy-vss-guard|{nonce}"
    return hmac.new(b"e2e-endpoint-secret", message.encode(), hashlib.sha256).hexdigest()


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


def _load_vss_fixture() -> dict[str, object]:
    fixture_path = Path(__file__).resolve().parents[3] / "apps/console/src/test/fixtures/vss-smoke.json"
    return json.loads(fixture_path.read_text())


def test_compliance_export_contains_signed_iso_evidence(promote_default_policy) -> None:
    customer_id = _make_customer()
    promote_default_policy(mode="block", entities=["EMAIL_ADDRESS"])
    owner = tenancy.ensure_platform_owner("compliance-owner-iso@aetherix.test", "Compliance Owner ISO")
    token, _ = jwt_tokens.issue(str(owner.id))

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
        headers={"Authorization": f"Bearer {token}"},
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
    owner = tenancy.ensure_platform_owner("compliance-owner-unknown@aetherix.test", "Compliance Owner Unknown")
    token, _ = jwt_tokens.issue(str(owner.id))
    response = TestClient(app).get(
        "/compliance/export",
        headers={"Authorization": f"Bearer {token}"},
        params={"customer_id": str(customer_id), "framework": "unknown"},
    )
    assert response.status_code == 400


def test_compliance_export_includes_policy_v2_evidence_events(policy_v2_templates, auth_headers) -> None:
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
        headers=auth_headers(str(msp.id)),
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
        headers=auth_headers(str(msp.id)),
    )
    assert simulation.status_code == 200, simulation.text

    promotion = TestClient(app).post(
        f"/policies/{policy_id}/promote",
        headers=auth_headers(str(msp.id)),
        json={
            "simulation_id": simulation.json()["id"],
            "operator_approved": True,
            "approval_reason": "compliance evidence check",
        },
    )
    assert promotion.status_code == 200, promotion.text

    assign = TestClient(app).post(
        "/policies/assign",
        headers=auth_headers(str(msp.id)),
        json={"policy_id": policy_id, "customer_id": str(customer_id)},
    )
    assert assign.status_code == 201, assign.text

    effective = TestClient(app).get(
        f"/policies/effective?customer_id={customer_id}",
        headers=auth_headers(str(msp.id)),
    )
    assert effective.status_code == 200, effective.text

    export = TestClient(app).get(
        "/compliance/export",
        headers=auth_headers(str(msp.id)),
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


def test_compliance_v0_5_reviews_and_attestation_workflow(auth_headers) -> None:
    owner = tenancy.ensure_platform_owner("compliance-v5@aetherix.test", "Compliance Owner v0.5")
    customer_id = _make_customer()
    client = TestClient(app)
    headers = auth_headers(str(owner.id), **{"X-Aetherix-Customer": str(customer_id)})
    evidence_id = uuid.uuid4()
    bundle_sha256 = "a" * 64
    now = datetime.now(UTC)

    with app_db.connection() as conn, conn.cursor() as cur:
        cur.execute(
            """
            insert into evidence_events (id, action, resource, actor, scope, payload, evidence_controls, created_at)
            values (%s, 'dlp.scan', 'browser:chatgpt', 'agent', %s::jsonb, '{}'::jsonb, %s::jsonb, %s)
            """,
            (
                evidence_id,
                f'{ {"customer_id": str(customer_id)} }'.replace("'", '"'),
                '["iso27001-2022:A.5.12"]',
                now,
            ),
        )
        cur.execute(
            """
            insert into compliance_vault_references (
                id, customer_id, source_table, source_id, framework, storage_kind, storage_uri, sha256, byte_size, created_at
            ) values (%s, %s, 'evidence_events', %s, 'iso27001-2022', 'filesystem', %s, %s, 128, %s)
            """,
            (uuid.uuid4(), customer_id, str(evidence_id), f"file:///tmp/{bundle_sha256}.json", bundle_sha256, now),
        )

    r_list = client.get(
        "/compliance/reviews?framework=iso27001-2022&source_table=evidence_events",
        headers=headers,
    )
    assert r_list.status_code == 200
    assert r_list.json()[0]["review_status"] == "pending"

    review_create = client.post(
        "/compliance/reviews",
        headers=headers,
        json={
            "source_table": "evidence_events",
            "source_id": str(evidence_id),
            "framework": "iso27001-2022",
            "control_id": "A.5.12",
            "decision": "accept",
            "note": "Validated semantic policies",
            "reviewed_by_role": "CISO",
            "reviewed_by_name": "Compliance Owner v0.5",
        },
    )
    assert review_create.status_code == 201
    res = review_create.json()
    assert res["decision"] == "accept"
    assert res["note"] == "Validated semantic policies"
    assert res["reviewed_by_account_id"] == str(owner.id)

    r_list2 = client.get(
        "/compliance/reviews?framework=iso27001-2022&source_table=evidence_events",
        headers=headers,
    )
    assert r_list2.status_code == 200
    assert r_list2.json()[0]["review_status"] == "completed"

    a_list = client.get(
        "/compliance/attestations?framework=iso27001-2022&period_end=2026-05-31",
        headers=headers,
    )
    assert a_list.status_code == 200
    assert len(a_list.json()) == 0

    attest_create = client.post(
        "/compliance/attestations",
        headers=headers,
        json={
            "framework": "iso27001-2022",
            "period_start": "2026-05-01",
            "period_end": "2026-05-31",
            "attested_role": "CISO",
            "attested_name": "Compliance Owner v0.5",
            "statement": "Signed off on May ISO 27001 evidence.",
            "bundle_sha256": bundle_sha256,
            "signature": "signed-attestation-value",
            "signature_algo": "hmac-sha256",
        },
    )
    assert attest_create.status_code == 201
    res_a = attest_create.json()
    assert res_a["attested_role"] == "CISO"
    assert res_a["bundle_sha256"] == bundle_sha256
    assert res_a["evidence_summary_count"] >= 1

    a_list2 = client.get(
        "/compliance/attestations?framework=iso27001-2022&period_end=2026-05-31",
        headers=headers,
    )
    assert a_list2.status_code == 200
    assert len(a_list2.json()) == 1


def test_compliance_export_includes_rollback_evidence_events(auth_headers) -> None:
    owner = tenancy.ensure_platform_owner("compliance-rollback@aetherix.test", "Compliance Owner Rollback")
    customer_id = _make_customer()
    client = TestClient(app)
    headers = auth_headers(str(owner.id), **{"X-Aetherix-Customer": str(customer_id)})
    now = datetime.now(UTC)

    # Insert a full set of rollback and correlation evidence events
    events = [
        ("endpoint.rollback.simulation_requested", '["iso27001-2022:A.8.16", "soc2-2017:CC7.2"]'),
        ("endpoint.rollback.rollback_requested", '["iso27001-2022:A.5.25", "soc2-2017:CC6.3"]'),
        ("endpoint.rollback.rollback_approved", '["iso27001-2022:A.5.16", "soc2-2017:CC6.3"]'),
        ("endpoint.rollback.rollback_denied", '["iso27001-2022:A.5.25", "soc2-2017:CC6.3"]'),
        ("endpoint.rollback.rollback_executed", '["iso27001-2022:A.12.4.1", "soc2-2017:CC7.5"]'),
        ("endpoint.rollback.rollback_failed", '["iso27001-2022:A.12.6.1", "soc2-2017:CC7.4"]'),
        ("endpoint.rollback.rollback_refused", '["iso27001-2022:A.12.6.1", "soc2-2017:CC7.4"]'),
        ("endpoint.rollback.scope_narrowed", '["iso27001-2022:A.12.4.2", "soc2-2017:CC7.3"]'),
        ("endpoint.rollback.unsafe_overwrite_confirmed", '["iso27001-2022:A.5.25", "soc2-2017:CC6.3"]'),
        ("correlation.rollback_simulation", '["iso27001-2022:A.8.12", "soc2-2017:CC6.1"]'),
        ("correlation.rollback_attempted", '["iso27001-2022:A.8.8", "soc2-2017:CC7.4"]'),
        ("correlation.rollback_triggered", '["iso27001-2022:A.8.8", "soc2-2017:CC7.4"]'),
    ]

    with app_db.connection() as conn, conn.cursor() as cur:
        for action, controls in events:
            cur.execute(
                """
                insert into evidence_events (id, action, resource, actor, scope, payload, evidence_controls, created_at)
                values (%s, %s, 'endpoint:test', 'agent', %s::jsonb, '{}'::jsonb, %s::jsonb, %s)
                """,
                (
                    uuid.uuid4(),
                    action,
                    f'{ {"customer_id": str(customer_id)} }'.replace("'", '"'),
                    controls,
                    now,
                ),
            )

    # 1. Fetch compliance export for ISO-27001
    resp_iso = client.get(
        "/compliance/export",
        headers={"Authorization": f"Bearer {jwt_tokens.issue(str(owner.id))[0]}"},
        params={"customer_id": str(customer_id), "framework": "iso27001-2022"},
    )
    assert resp_iso.status_code == 200, resp_iso.text
    bundle_iso = resp_iso.json()

    evidence_actions = {item["summary"].split(" on ")[0] for item in bundle_iso["evidence"]}
    for action, _ in events:
        assert any(action in summary for summary in evidence_actions), f"expected {action} in compliance evidence summaries"

    # Verify A.8.16 (monitoring activities) has evidence counts
    controls_iso = {c["control_id"]: c for c in bundle_iso["controls"]}
    assert controls_iso["A.8.16"]["evidence_count"] >= 1

    # 2. Fetch compliance export for SOC2
    resp_soc = client.get(
        "/compliance/export",
        headers={"Authorization": f"Bearer {jwt_tokens.issue(str(owner.id))[0]}"},
        params={"customer_id": str(customer_id), "framework": "soc2-2017"},
    )
    assert resp_soc.status_code == 200, resp_soc.text
    bundle_soc = resp_soc.json()

    controls_soc = {c["control_id"]: c for c in bundle_soc["controls"]}
    assert controls_soc["CC6.1"]["evidence_count"] >= 1
    assert controls_soc["CC7.2"]["evidence_count"] >= 1


def test_vss_provider_metadata_survives_export_and_pending_inbox(auth_headers) -> None:
    owner = tenancy.ensure_platform_owner("compliance-vss-guard@aetherix.test", "Compliance VSS Guard")
    customer_id = _make_customer()
    agent_id = "agent-vss-guard-001"
    client = TestClient(app)
    headers = auth_headers(str(owner.id), **{"X-Aetherix-Customer": str(customer_id)})
    _enroll_agent(agent_id, customer_id)
    collected_at = datetime.now(UTC).isoformat()

    fixture = _load_vss_fixture()
    vss_metadata = fixture["provider_metadata"]
    readiness = fixture["rollback_readiness"]
    request_payload = fixture["rollback_restore_request"]

    heartbeat = client.post(
        "/agent/heartbeat",
        json={
            "agent_id": agent_id,
            "hostname": "vss-guard-host",
            "os": "windows",
            "policy_version": "policy-vss-guard",
            "nonce": 1,
            "collected_at": collected_at,
            "signature": _heartbeat_signature(agent_id, collected_at, 1),
            "signals": {"cpu_percent": 5, "memory_percent": 10},
            "rollback_readiness": readiness,
        },
    )
    assert heartbeat.status_code == 200, heartbeat.text

    queue = client.post(
        f"/endpoints/{agent_id}/rollback-restore",
        headers=headers,
        json=request_payload,
    )
    assert queue.status_code == 202, queue.text
    action_id = queue.json()["id"]

    pending = client.get("/rollback-intents/pending", headers=headers)
    assert pending.status_code == 200, pending.text
    pending_item = next((item for item in pending.json() if item["action"]["id"] == action_id), None)
    assert pending_item is not None
    assert pending_item["action"]["payload"]["provider_metadata"] == vss_metadata
    assert pending_item["rollback_readiness"]["provider_metadata"] == vss_metadata

    export = client.get(
        "/compliance/export",
        headers={"Authorization": f"Bearer {jwt_tokens.issue(str(owner.id))[0]}"},
        params={"customer_id": str(customer_id), "framework": "iso27001-2022"},
    )
    assert export.status_code == 200, export.text
    evidence_item = next(
        item for item in export.json()["evidence"]
        if item["source_table"] == "evidence_events"
        and item["payload"].get("action_id") == action_id
    )
    assert evidence_item["payload"]["provider"] == "vss"
    assert evidence_item["payload"]["provider_metadata"] == vss_metadata

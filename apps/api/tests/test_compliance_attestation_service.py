from __future__ import annotations

import json
import uuid
from datetime import UTC, datetime

from fastapi.testclient import TestClient

from app import db as app_db
from app.main import app
from app.services import jwt_tokens
from app.services import tenancy


def _make_customer(name: str = "Compliance Customer") -> uuid.UUID:
    partner_id = uuid.uuid4()
    customer_id = uuid.uuid4()
    now = datetime.now(UTC)
    with app_db.connection() as conn, conn.cursor() as cur:
        cur.execute(
            """
            insert into partners (id, name, slug, deployment_mode, created_at)
            values (%s, 'Compliance MSP', %s, 'cloud', %s)
            """,
            (partner_id, f"cmp-{partner_id.hex[:8]}", now),
        )
        cur.execute(
            """
            insert into customers (id, partner_id, customer_number, name, status, created_by, created_at)
            values (%s, %s, %s, %s, 'active', 'tests', %s)
            """,
            (customer_id, partner_id, f"CMP-{customer_id.hex[:8]}", name, now),
        )
    return customer_id


def _headers(customer_id: uuid.UUID) -> dict[str, str]:
    owner = tenancy.ensure_platform_owner("attestation-owner@aetherix.test", "Attestation Owner")
    token, _ = jwt_tokens.issue(str(owner.id))
    return {
        "Authorization": f"Bearer {token}",
        "X-Aetherix-Customer": str(customer_id),
    }


def _seed_evidence_bundle(customer_id: uuid.UUID, *, control_id: str = "A.5.12", bundle_sha256: str = "b" * 64) -> uuid.UUID:
    evidence_id = uuid.uuid4()
    now = datetime.now(UTC)
    with app_db.connection() as conn, conn.cursor() as cur:
        cur.execute(
            """
            insert into evidence_events (id, action, resource, actor, scope, payload, evidence_controls, created_at)
            values (%s, 'dlp.scan', 'browser:chatgpt', 'agent', %s::jsonb, '{}'::jsonb, %s::jsonb, %s)
            """,
            (
                evidence_id,
                json.dumps({"customer_id": str(customer_id)}),
                json.dumps([f"iso27001-2022:{control_id}"]),
                now,
            ),
        )
        cur.execute(
            """
            insert into compliance_vault_references (
                id, customer_id, source_table, source_id, framework, storage_kind, storage_uri, sha256, byte_size, created_at
            ) values (%s, %s, 'evidence_events', %s, 'iso27001-2022', 'filesystem', %s, %s, 512, %s)
            """,
            (uuid.uuid4(), customer_id, str(evidence_id), f"file:///tmp/{bundle_sha256}.json", bundle_sha256, now),
        )
    return evidence_id


def _attestation_payload(bundle_sha256: str = "b" * 64) -> dict[str, str]:
    return {
        "framework": "iso27001-2022",
        "period_start": "2026-05-01",
        "period_end": "2026-05-31",
        "attested_role": "CISO",
        "attested_name": "Avery Audit",
        "statement": "I attest that this evidence bundle is complete for the stated ISO 27001 period.",
        "bundle_sha256": bundle_sha256,
        "signature": "local-hmac-signature",
        "signature_algo": "hmac-sha256",
    }


def test_create_attestation_happy_path_returns_201() -> None:
    customer_id = _make_customer()
    _seed_evidence_bundle(customer_id)

    response = TestClient(app).post(
        "/compliance/attestations",
        headers=_headers(customer_id),
        json=_attestation_payload(),
    )

    assert response.status_code == 201, response.text
    body = response.json()
    assert body["framework"] == "iso27001-2022"
    assert body["bundle_sha256"] == "b" * 64
    assert body["evidence_summary_count"] == 1


def test_attestation_rejects_invalid_framework() -> None:
    customer_id = _make_customer()
    _seed_evidence_bundle(customer_id)
    payload = _attestation_payload()
    payload["framework"] = "pci-dss"

    response = TestClient(app).post(
        "/compliance/attestations",
        headers=_headers(customer_id),
        json=payload,
    )

    assert response.status_code == 422


def test_duplicate_attestation_is_prevented() -> None:
    customer_id = _make_customer()
    _seed_evidence_bundle(customer_id)
    client = TestClient(app)
    headers = _headers(customer_id)

    first = client.post("/compliance/attestations", headers=headers, json=_attestation_payload())
    second = client.post("/compliance/attestations", headers=headers, json=_attestation_payload())

    assert first.status_code == 201, first.text
    assert second.status_code == 409


def test_attestation_requires_existing_bundle_sha256() -> None:
    customer_id = _make_customer()

    response = TestClient(app).post(
        "/compliance/attestations",
        headers=_headers(customer_id),
        json=_attestation_payload("c" * 64),
    )

    assert response.status_code == 400
    assert "bundle_sha256" in response.json()["detail"]


def test_attestation_list_is_tenant_isolated() -> None:
    customer_a = _make_customer("Tenant A")
    customer_b = _make_customer("Tenant B")
    _seed_evidence_bundle(customer_a, bundle_sha256="d" * 64)
    _seed_evidence_bundle(customer_b, bundle_sha256="e" * 64)
    client = TestClient(app)

    assert client.post(
        "/compliance/attestations",
        headers=_headers(customer_a),
        json=_attestation_payload("d" * 64),
    ).status_code == 201
    assert client.post(
        "/compliance/attestations",
        headers=_headers(customer_b),
        json=_attestation_payload("e" * 64),
    ).status_code == 201

    response = client.get(
        "/compliance/attestations?framework=iso27001-2022&period_end=2026-05-31",
        headers=_headers(customer_a),
    )

    assert response.status_code == 200, response.text
    rows = response.json()
    assert len(rows) == 1
    assert rows[0]["customer_id"] == str(customer_a)
    assert rows[0]["bundle_sha256"] == "d" * 64


def test_review_queue_and_append_only_review_recording() -> None:
    customer_id = _make_customer()
    evidence_id = _seed_evidence_bundle(customer_id)
    client = TestClient(app)
    headers = _headers(customer_id)

    pending = client.get(
        "/compliance/reviews?framework=iso27001-2022&source_table=evidence_events",
        headers=headers,
    )
    assert pending.status_code == 200, pending.text
    assert pending.json()[0]["review_status"] == "pending"

    created = client.post(
        "/compliance/reviews",
        headers=headers,
        json={
            "source_table": "evidence_events",
            "source_id": str(evidence_id),
            "framework": "iso27001-2022",
            "control_id": "A.5.12",
            "decision": "needs_more",
            "note": "Need an operator screenshot before final acceptance.",
            "reviewed_by_role": "Compliance Analyst",
            "reviewed_by_name": "Avery Audit",
        },
    )
    assert created.status_code == 201, created.text

    completed = client.get(
        "/compliance/reviews?framework=iso27001-2022&source_table=evidence_events",
        headers=headers,
    )
    assert completed.status_code == 200, completed.text
    item = completed.json()[0]
    assert item["review_status"] == "completed"
    assert item["latest_review"]["decision"] == "needs_more"

    with app_db.connection() as conn, conn.cursor() as cur:
        cur.execute("select count(*) as n from compliance_reviews where source_id = %s", (str(evidence_id),))
        assert cur.fetchone()["n"] == 1
        cur.execute("select action from evidence_events where action = 'review_recorded'")
        assert cur.fetchone()["action"] == "review_recorded"

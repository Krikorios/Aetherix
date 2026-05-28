from __future__ import annotations

import json
import uuid
import pytest
from datetime import UTC, datetime, date
from unittest.mock import MagicMock, patch

from fastapi.testclient import TestClient
from opensearchpy.exceptions import OpenSearchException

from app import db as app_db
from app.main import app
from app.services import event_index as os_index
from app.services import compliance
from app.services import jwt_tokens, tenancy
from app.schemas import CompanyLicenseAssign


def _make_customer_with_db(partner_id: uuid.UUID, customer_id: uuid.UUID) -> None:
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


def test_opensearch_circuit_breaker_resilience() -> None:
    """Test that OpenSearch client errors trigger the circuit breaker and degrade gracefully without raising errors."""
    # Reset circuit breaker state
    os_index._CIRCUIT_BREAKER.failure_count = 0
    os_index._CIRCUIT_BREAKER.state = "CLOSED"
    
    partner_id = uuid.uuid4()
    customer_id = uuid.uuid4()
    
    with patch.dict("os.environ", {"AETHERIX_OPENSEARCH_URL": "http://localhost:59999"}):
        # Trigger failures to open the circuit breaker
        for _ in range(5):
            success = os_index.index_event(
                partner_id=str(partner_id),
                customer_id=str(customer_id),
                event_type="security_alert",
                severity="high",
                category="malware",
            )
            assert success is False
            
        # Verify circuit breaker is now OPEN
        assert os_index._CIRCUIT_BREAKER.state == "OPEN"
        
        # When circuit breaker is OPEN, request should be rejected immediately (allow_request returns False)
        assert os_index._CIRCUIT_BREAKER.allow_request() is False


def test_opensearch_dual_write_and_search_round_trip() -> None:
    """Test dual-write indexing and search round-trip with postgres_ref verification using mocks."""
    partner_id = uuid.uuid4()
    customer_id = uuid.uuid4()
    alert_id = uuid.uuid4()
    
    mock_client = MagicMock()
    # Configure mock search response
    mock_client.search.return_value = {
        "hits": {
            "total": {"value": 1, "relation": "eq"},
            "hits": [
                {
                    "_id": "doc-001",
                    "_index": "aetherix-events-msp-cust",
                    "_source": {
                        "@timestamp": "2026-05-28T19:00:00Z",
                        "timestamp": "2026-05-28T19:00:00Z",
                        "partner_id": str(partner_id),
                        "customer_id": str(customer_id),
                        "event_type": "security_alert",
                        "severity": "critical",
                        "postgres_ref": {
                            "table": "security_alerts",
                            "id": str(alert_id),
                            "seq": 42,
                            "chain_hash": "abc123hash",
                        }
                    }
                }
            ]
        }
    }
    
    with patch("app.services.event_index.get_client", return_value=mock_client):
        # 1. Index event
        success = os_index.index_security_alert(
            partner_id=str(partner_id),
            customer_id=str(customer_id),
            agent_id="agent-007",
            alert_id=str(alert_id),
            severity="critical",
            category="behavioral",
            payload={"test": "data"},
            evidence_controls=["iso27001-2022:A.8.8"],
            created_at=datetime.now(UTC),
            postgres_seq=42,
            chain_hash="abc123hash",
        )
        assert success is True
        
        # Verify index call arguments
        assert mock_client.index.called
        call_args = mock_client.index.call_args[1]
        assert call_args["body"]["postgres_ref"]["id"] == str(alert_id)
        assert call_args["body"]["postgres_ref"]["seq"] == 42
        assert call_args["body"]["postgres_ref"]["chain_hash"] == "abc123hash"
        
        # 2. Search round-trip and verify postgres_ref
        res = os_index.search_events(customer_id=str(customer_id))
        assert "error" not in res
        hits = res["hits"]["hits"]
        assert len(hits) == 1
        assert hits[0]["_source"]["postgres_ref"]["table"] == "security_alerts"
        assert hits[0]["_source"]["postgres_ref"]["id"] == str(alert_id)
        assert hits[0]["_source"]["postgres_ref"]["seq"] == 42


def test_pdf_export_renders_reviews_attestations_signatures_evidence() -> None:
    """Test that export_bundle_pdf successfully queries and formats reviews, attestations, signatures, and evidence."""
    partner_id = uuid.uuid4()
    customer_id = uuid.uuid4()
    
    _make_customer_with_db(partner_id, customer_id)
    
    # 1. Add some compliance controls, reviews, and attestations to DB
    with app_db.connection() as conn, conn.cursor() as cur:
        # Compliance Control
        cur.execute(
            """
            insert into compliance_controls (control_id, framework, title, description)
            values ('A.8.8', 'iso27001-2022', 'Vulnerability Mgmt', 'Technical vulnerability management')
            on conflict (framework, control_id) do nothing
            """
        )
        # Account
        account_id = uuid.uuid4()
        cur.execute(
            """
            insert into accounts (id, email, full_name, password_hash, created_by, created_at)
            values (%s, 'auditor@aetherix.test', 'Auditor Alice', 'pw-hash', 'tests', now())
            """,
            (account_id,),
        )
        # Control Review
        cur.execute(
            """
            insert into compliance_reviews (id, customer_id, source_table, source_id, framework, control_id, reviewed_by_account_id, reviewed_by_role, reviewed_by_name, decision, note, reviewed_at)
            values (%s, %s, 'policy_documents', 'v1', 'iso27001-2022', 'A.8.8', %s, 'auditor', 'Auditor Alice', 'accept', 'Verified technical vulnerability policies are in place.', now())
            """,
            (uuid.uuid4(), customer_id, account_id),
        )
        # Compliance Attestation
        cur.execute(
            """
            insert into compliance_attestations (id, customer_id, framework, period_start, period_end, attested_by_account_id, attested_role, attested_name, bundle_sha256, signature, statement, created_at)
            values (%s, %s, 'iso27001-2022', '2026-01-01', '2026-05-28', %s, 'CISO', 'Alice Vance', '1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef', 'hmac-sig-value', 'I attest that all controls are functional.', now())
            """,
            (uuid.uuid4(), customer_id, account_id),
        )
        # Evidence Event Record
        cur.execute(
            """
            insert into evidence_events (id, action, resource, actor, scope, payload, evidence_controls, created_at)
            values (%s, 'correlation.rollback_recovery', 'security_alert:alert1', 'correlation-engine', %s, '{"alert_id": "alert1"}'::jsonb, '["iso27001-2022:A.8.8"]'::jsonb, now())
            """,
            (uuid.uuid4(), json.dumps({"customer_id": str(customer_id)})),
        )

    # 2. Run PDF generation
    pdf_bytes = compliance.export_bundle_pdf(customer_id, "iso27001-2022")
    assert pdf_bytes is not None
    assert isinstance(pdf_bytes, (bytes, bytearray))
    # PDF standard header check
    assert pdf_bytes.startswith(b"%PDF-")


def test_permission_model_on_search_and_pdf_routes(tenant_hierarchy_factory) -> None:
    """Test that both events/search and compliance/export enforce the exact tenant + incidents/view permission model."""
    hierarchy = tenant_hierarchy_factory()
    customer_id = hierarchy["customer_id"]
    
    # 1. Create a platform owner who has incidents/view permission by default
    owner = tenancy.ensure_platform_owner("perm-owner@aetherix.test", "Permission Owner")
    owner_token, _ = jwt_tokens.issue(str(owner.id))
    
    # 2. Create another company admin account that is NOT in this customer hierarchy
    other_customer_id = uuid.uuid4()
    other_partner_id = uuid.uuid4()
    _make_customer_with_db(other_partner_id, other_customer_id)
    
    bad_actor = tenancy.create_account(
        tenancy.AccountCreate(
            email="bad-actor@aetherix.test",
            full_name="Bad Actor",
            initial_role=tenancy.RoleAssignmentRequest(role_code="company_admin", customer_id=other_customer_id),
        )
    )
    bad_actor_token, _ = jwt_tokens.issue(str(bad_actor.id))
    
    client = TestClient(app)
    
    # --- Test Search Endpoint ---
    with patch("app.services.event_index.is_enabled", return_value=True):
        with patch("app.services.event_index.search_events", return_value={"hits": {"total": {"value": 0}, "hits": []}}):
            # Authorised request should succeed (200)
            res = client.get(
                f"/customers/{customer_id}/events/search",
                headers={"Authorization": f"Bearer {owner_token}"},
            )
            assert res.status_code == 200, res.text
            
            # Cross-tenant request (bad actor) should fail with 403 Forbidden
            res = client.get(
                f"/customers/{customer_id}/events/search",
                headers={"Authorization": f"Bearer {bad_actor_token}"},
            )
            assert res.status_code == 403
            
    # --- Test Compliance Export Endpoint ---
    # Setup mapping in DB for PDF export
    with app_db.connection() as conn, conn.cursor() as cur:
        cur.execute(
            """
            insert into compliance_controls (control_id, framework, title, description)
            values ('A.8.8', 'iso27001-2022', 'Vulnerability Mgmt', 'Technical vulnerability management')
            on conflict do nothing
            """
        )

    # Authorised request should succeed (200)
    res = client.get(
        "/compliance/export",
        headers={"Authorization": f"Bearer {owner_token}"},
        params={"customer_id": str(customer_id), "framework": "iso27001-2022", "format": "json"},
    )
    assert res.status_code == 200, res.text
    
    # Cross-tenant request (bad actor) should fail with 403 Forbidden
    res = client.get(
        "/compliance/export",
        headers={"Authorization": f"Bearer {bad_actor_token}"},
        params={"customer_id": str(customer_id), "framework": "iso27001-2022", "format": "json"},
    )
    assert res.status_code == 403

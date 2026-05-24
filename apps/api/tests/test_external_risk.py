"""Tests for DRP findings and EASM exposures endpoints."""

from __future__ import annotations

import uuid
from datetime import UTC, datetime

from fastapi.testclient import TestClient

from app import db as app_db
from app.main import app
from app.services import tenancy


client = TestClient(app)


def _platform_owner() -> str:
    return str(tenancy.ensure_platform_owner("drp-owner@aetherix.test", "DRP Owner").id)


def _make_partner(slug: str = "drp") -> uuid.UUID:
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


def _make_customer(partner_id: uuid.UUID, name: str = "DRPCo") -> uuid.UUID:
    customer_id = uuid.uuid4()
    with app_db.connection() as conn, conn.cursor() as cur:
        cur.execute(
            """
            insert into customers (
                id, partner_id, customer_number, name, status, created_by, created_at
            ) values (%s, %s, %s, %s, 'active', 'tests', %s)
            """,
            (customer_id, partner_id, f"DRP-{customer_id.hex[:8]}", name, datetime.now(UTC)),
        )
    return customer_id


# --- DRP Findings -----------------------------------------------------------

def test_drp_findings_list_empty() -> None:
    owner_id = _platform_owner()
    partner_id = _make_partner()
    customer_id = _make_customer(partner_id)

    resp = client.get(
        f"/drp/findings?customer_id={customer_id}",
        headers={"X-Aetherix-Account": owner_id},
    )
    assert resp.status_code == 200, resp.text
    assert resp.json() == []


def test_drp_finding_create_and_list() -> None:
    owner_id = _platform_owner()
    partner_id = _make_partner()
    customer_id = _make_customer(partner_id)

    created = client.post(
        f"/drp/findings?customer_id={customer_id}",
        headers={"X-Aetherix-Account": owner_id},
        json={
            "asset_display_name": "aetherix-security.com",
            "asset_type": "domain",
            "finding_type": "typosquatting",
            "title": "Typosquatting: aetherix-securit.com",
            "summary": "Close-match domain registered 2026-05-22",
            "source": "passive-dns",
            "severity": "high",
            "risk_score": 80,
            "confidence_score": 92,
            "evidence_links": ["https://virustotal.com/gui/domain/aetherix-securit.com"],
        },
    )
    assert created.status_code == 201, created.text
    finding = created.json()
    assert finding["status"] == "new"
    assert finding["finding_type"] == "typosquatting"
    assert finding["severity"] == "high"
    assert finding["customer_id"] == str(customer_id)
    assert finding["asset_display_name"] == "aetherix-security.com"
    assert finding["evidence_links"] == ["https://virustotal.com/gui/domain/aetherix-securit.com"]

    listed = client.get(
        f"/drp/findings?customer_id={customer_id}",
        headers={"X-Aetherix-Account": owner_id},
    )
    assert listed.status_code == 200, listed.text
    assert [f["id"] for f in listed.json()] == [finding["id"]]


def test_drp_finding_validate() -> None:
    owner_id = _platform_owner()
    partner_id = _make_partner("drpval")
    customer_id = _make_customer(partner_id, "DRPValCo")

    created = client.post(
        f"/drp/findings?customer_id={customer_id}",
        headers={"X-Aetherix-Account": owner_id},
        json={
            "asset_display_name": "@Aetherix_Official",
            "asset_type": "social_account",
            "finding_type": "impersonation",
            "title": "Impersonating account @Aetherix_Security_Help",
            "summary": "Twitter/X account mimicking official brand handle",
            "source": "social-media-scan",
            "severity": "critical",
            "risk_score": 95,
            "confidence_score": 88,
        },
    )
    assert created.status_code == 201, created.text
    finding_id = created.json()["id"]

    validated = client.post(
        f"/drp/findings/{finding_id}/validate",
        headers={"X-Aetherix-Account": owner_id},
    )
    assert validated.status_code == 200, validated.text
    assert validated.json()["status"] == "reviewing"


def test_drp_finding_takedown() -> None:
    owner_id = _platform_owner()
    partner_id = _make_partner("drptd")
    customer_id = _make_customer(partner_id, "DRPTdCo")

    created = client.post(
        f"/drp/findings?customer_id={customer_id}",
        headers={"X-Aetherix-Account": owner_id},
        json={
            "asset_display_name": "aetherix-phish.com",
            "asset_type": "domain",
            "finding_type": "phishing",
            "title": "Phishing site aetherix-phish.com",
            "summary": "Active phishing page cloning login portal",
            "source": "threat-intel",
            "severity": "critical",
            "risk_score": 98,
            "confidence_score": 97,
        },
    )
    assert created.status_code == 201, created.text
    finding_id = created.json()["id"]

    takedown = client.post(
        f"/drp/findings/{finding_id}/takedown",
        headers={"X-Aetherix-Account": owner_id},
    )
    assert takedown.status_code == 200, takedown.text
    assert takedown.json()["status"] == "confirmed"


def test_drp_finding_not_found() -> None:
    owner_id = _platform_owner()
    resp = client.post(
        f"/drp/findings/{uuid.uuid4()}/validate",
        headers={"X-Aetherix-Account": owner_id},
    )
    assert resp.status_code == 400


def test_drp_findings_status_filter() -> None:
    owner_id = _platform_owner()
    partner_id = _make_partner("drpflt")
    customer_id = _make_customer(partner_id, "DRPFltCo")

    # Create one new finding and one that will be validated
    for i in range(2):
        client.post(
            f"/drp/findings?customer_id={customer_id}",
            headers={"X-Aetherix-Account": owner_id},
            json={
                "asset_display_name": f"brand-{i}.com",
                "asset_type": "domain",
                "finding_type": "brand_abuse",
                "title": f"Brand abuse #{i}",
                "summary": f"Abuse finding #{i}",
                "source": "osint",
                "severity": "medium",
                "risk_score": 50,
                "confidence_score": 70,
            },
        )

    all_findings = client.get(
        f"/drp/findings?customer_id={customer_id}",
        headers={"X-Aetherix-Account": owner_id},
    )
    assert all_findings.status_code == 200
    assert len(all_findings.json()) == 2

    # Validate first finding
    finding_id = all_findings.json()[0]["id"]
    client.post(
        f"/drp/findings/{finding_id}/validate",
        headers={"X-Aetherix-Account": owner_id},
    )

    reviewing = client.get(
        f"/drp/findings?customer_id={customer_id}&status=reviewing",
        headers={"X-Aetherix-Account": owner_id},
    )
    assert reviewing.status_code == 200
    assert len(reviewing.json()) == 1
    assert reviewing.json()[0]["id"] == finding_id


# --- EASM Exposures ---------------------------------------------------------

def test_easm_exposures_list_empty() -> None:
    owner_id = _platform_owner()
    partner_id = _make_partner("easm")
    customer_id = _make_customer(partner_id, "EASMCo")

    resp = client.get(
        f"/easm/exposures?customer_id={customer_id}",
        headers={"X-Aetherix-Account": owner_id},
    )
    assert resp.status_code == 200, resp.text
    assert resp.json() == []


def test_easm_exposure_create_and_list() -> None:
    owner_id = _platform_owner()
    partner_id = _make_partner("easmcr")
    customer_id = _make_customer(partner_id, "EASMCrCo")

    created = client.post(
        f"/easm/exposures?customer_id={customer_id}",
        headers={"X-Aetherix-Account": owner_id},
        json={
            "asset_display_name": "webmail.example-corp.net",
            "asset_type": "subdomain",
            "exposure_type": "misconfiguration",
            "title": "Expired SSL certificate on webmail",
            "summary": "SSL cert expired 2026-04-01, clients see security warning",
            "severity": "medium",
            "risk_score": 55,
            "confidence_score": 90,
            "ip_address": "192.0.2.45",
            "fqdn": "webmail.example-corp.net",
            "cloud_provider": "AWS",
            "open_ports": [443, 80],
            "tags": ["ssl", "certificate"],
        },
    )
    assert created.status_code == 201, created.text
    exp = created.json()
    assert exp["status"] == "new"
    assert exp["exposure_type"] == "misconfiguration"
    assert exp["severity"] == "medium"
    assert exp["asset_display_name"] == "webmail.example-corp.net"
    assert exp["open_ports"] == [443, 80]
    assert exp["tags"] == ["ssl", "certificate"]

    listed = client.get(
        f"/easm/exposures?customer_id={customer_id}",
        headers={"X-Aetherix-Account": owner_id},
    )
    assert listed.status_code == 200, listed.text
    assert [e["id"] for e in listed.json()] == [exp["id"]]


def test_easm_exposure_investigate() -> None:
    owner_id = _platform_owner()
    partner_id = _make_partner("easminv")
    customer_id = _make_customer(partner_id, "EASMInvCo")

    created = client.post(
        f"/easm/exposures?customer_id={customer_id}",
        headers={"X-Aetherix-Account": owner_id},
        json={
            "asset_display_name": "ftp.backup.corp.net",
            "asset_type": "subdomain",
            "exposure_type": "exposed_service",
            "title": "FTP service exposed with anonymous login",
            "summary": "Anonymous FTP accessible from internet on port 21",
            "severity": "high",
            "risk_score": 82,
            "confidence_score": 85,
            "ip_address": "203.0.113.78",
            "open_ports": [21],
            "tags": ["ftp", "anonymous"],
        },
    )
    assert created.status_code == 201, created.text
    exposure_id = created.json()["id"]

    investigated = client.post(
        f"/easm/exposures/{exposure_id}/investigate",
        headers={"X-Aetherix-Account": owner_id},
    )
    assert investigated.status_code == 200, investigated.text
    assert investigated.json()["status"] == "investigating"


def test_easm_exposure_remediate() -> None:
    owner_id = _platform_owner()
    partner_id = _make_partner("easmrem")
    customer_id = _make_customer(partner_id, "EASMRemCo")

    created = client.post(
        f"/easm/exposures?customer_id={customer_id}",
        headers={"X-Aetherix-Account": owner_id},
        json={
            "asset_display_name": "admin.legacy.corp.net",
            "asset_type": "subdomain",
            "exposure_type": "unpatched_vulnerability",
            "title": "CVE-2024-1234 on admin panel",
            "summary": "Unpatched RCE vulnerability on admin panel subdomain",
            "severity": "critical",
            "risk_score": 95,
            "confidence_score": 99,
            "fqdn": "admin.legacy.corp.net",
        },
    )
    assert created.status_code == 201, created.text
    exposure_id = created.json()["id"]

    remediated = client.post(
        f"/easm/exposures/{exposure_id}/remediate",
        headers={"X-Aetherix-Account": owner_id},
    )
    assert remediated.status_code == 200, remediated.text
    assert remediated.json()["status"] == "remediated"


def test_easm_exposure_not_found() -> None:
    owner_id = _platform_owner()
    resp = client.post(
        f"/easm/exposures/{uuid.uuid4()}/investigate",
        headers={"X-Aetherix-Account": owner_id},
    )
    assert resp.status_code == 400


def test_easm_exposure_status_filter() -> None:
    owner_id = _platform_owner()
    partner_id = _make_partner("easmflt")
    customer_id = _make_customer(partner_id, "EASMFltCo")

    for i in range(3):
        client.post(
            f"/easm/exposures?customer_id={customer_id}",
            headers={"X-Aetherix-Account": owner_id},
            json={
                "asset_display_name": f"host{i}.corp.net",
                "asset_type": "subdomain",
                "exposure_type": "shadow_it",
                "title": f"Shadow IT asset #{i}",
                "summary": f"Undocumented asset #{i}",
                "severity": "low",
                "risk_score": 20,
                "confidence_score": 60,
            },
        )

    all_exp = client.get(
        f"/easm/exposures?customer_id={customer_id}",
        headers={"X-Aetherix-Account": owner_id},
    )
    assert len(all_exp.json()) == 3

    # Investigate one
    exposure_id = all_exp.json()[0]["id"]
    client.post(
        f"/easm/exposures/{exposure_id}/investigate",
        headers={"X-Aetherix-Account": owner_id},
    )

    investigating = client.get(
        f"/easm/exposures?customer_id={customer_id}&status=investigating",
        headers={"X-Aetherix-Account": owner_id},
    )
    assert investigating.status_code == 200
    assert len(investigating.json()) == 1
    assert investigating.json()[0]["id"] == exposure_id


def test_drp_and_easm_audit_logged() -> None:
    owner_id = _platform_owner()
    partner_id = _make_partner("drpaudit")
    customer_id = _make_customer(partner_id, "AuditCo")

    finding_resp = client.post(
        f"/drp/findings?customer_id={customer_id}",
        headers={"X-Aetherix-Account": owner_id},
        json={
            "asset_display_name": "brand.example.com",
            "asset_type": "domain",
            "finding_type": "brand_abuse",
            "title": "Brand abuse on brand.example.com",
            "summary": "Unauthorised brand usage detected",
            "source": "osint",
            "severity": "medium",
            "risk_score": 50,
            "confidence_score": 75,
        },
    )
    assert finding_resp.status_code == 201

    exposure_resp = client.post(
        f"/easm/exposures?customer_id={customer_id}",
        headers={"X-Aetherix-Account": owner_id},
        json={
            "asset_display_name": "api.example.com",
            "asset_type": "domain",
            "exposure_type": "exposed_service",
            "title": "Unauthenticated API endpoint",
            "summary": "REST API accessible without credentials",
            "severity": "high",
            "risk_score": 75,
            "confidence_score": 80,
        },
    )
    assert exposure_resp.status_code == 201

    with app_db.connection() as conn, conn.cursor() as cur:
        cur.execute(
            "select count(*) as n from audit_log where action in ('drp.finding.create', 'easm.exposure.create')"
        )
        assert cur.fetchone()["n"] == 2

from __future__ import annotations

import uuid
from datetime import UTC, datetime

from fastapi.testclient import TestClient

from app import db as app_db
from app.main import app
from app.services import tenancy


client = TestClient(app)


def _platform_owner() -> str:
    return str(tenancy.ensure_platform_owner("rules-owner@aetherix.test", "Rules Owner").id)


def _make_partner(slug: str = "rules") -> uuid.UUID:
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


def _make_customer(partner_id: uuid.UUID, name: str = "RulesCo") -> uuid.UUID:
    customer_id = uuid.uuid4()
    with app_db.connection() as conn, conn.cursor() as cur:
        cur.execute(
            """
            insert into customers (
                id, partner_id, customer_number, name, status, created_by, created_at
            ) values (%s, %s, %s, %s, 'active', 'tests', %s)
            """,
            (customer_id, partner_id, f"RULE-{customer_id.hex[:8]}", name, datetime.now(UTC)),
        )
    return customer_id


def test_detection_rule_create_simulate_promote_and_list(auth_headers) -> None:
    owner_id = _platform_owner()
    partner_id = _make_partner()
    customer_id = _make_customer(partner_id)

    created = client.post(
        "/detection-rules",
        headers=auth_headers(owner_id),
        json={
            "customer_id": str(customer_id),
            "name": "Suspicious PowerShell DownloadString",
            "description": "Detect staged PowerShell downloads.",
            "severity": "high",
            "query": "process.name == 'powershell.exe' && process.command_line.contains('.DownloadString')",
            "mitre_attacks": ["T1059.001", "T1105"],
        },
    )
    assert created.status_code == 201, created.text
    rule = created.json()
    assert rule["status"] == "draft"
    assert rule["partner_id"] == str(partner_id)
    assert rule["customer_id"] == str(customer_id)

    listed = client.get(
        f"/detection-rules?customer_id={customer_id}",
        headers=auth_headers(owner_id),
    )
    assert listed.status_code == 200, listed.text
    assert [item["id"] for item in listed.json()] == [rule["id"]]

    blocked_promotion = client.post(
        f"/detection-rules/{rule['id']}/promote",
        headers=auth_headers(owner_id),
    )
    assert blocked_promotion.status_code == 400

    simulation = client.post(
        f"/detection-rules/{rule['id']}/simulate",
        headers=auth_headers(owner_id),
    )
    assert simulation.status_code == 200, simulation.text
    assert simulation.json()["rule"]["status"] == "simulated"
    assert simulation.json()["matched_events"] >= 1

    promotion = client.post(
        f"/detection-rules/{rule['id']}/promote",
        headers=auth_headers(owner_id),
    )
    assert promotion.status_code == 200, promotion.text
    assert promotion.json()["rule"]["status"] == "active"

    with app_db.connection() as conn, conn.cursor() as cur:
        cur.execute(
            "select count(*) as n from audit_log where action in ('detection_rule.create', 'detection_rule.simulate', 'detection_rule.promote')"
        )
        assert cur.fetchone()["n"] == 3

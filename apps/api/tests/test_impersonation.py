"""End-to-end tests for the impersonation lifecycle."""

from __future__ import annotations

import uuid
from datetime import UTC, datetime

import pytest
from fastapi.testclient import TestClient

from app import db as app_db
from app.main import app
from app.schemas import AccountCreate, RoleAssignmentRequest
from app.services import jwt_tokens, tenancy

client = TestClient(app)


def _platform_owner() -> tenancy.Account:
    return tenancy.ensure_platform_owner(
        "imperson-owner@aetherix.test", "Impersonation Owner"
    )


def _make_partner(slug: str = "imp") -> uuid.UUID:
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


def _make_customer(partner_id: uuid.UUID, name: str = "ImpCo") -> uuid.UUID:
    customer_id = uuid.uuid4()
    with app_db.connection() as conn, conn.cursor() as cur:
        cur.execute(
            """
            insert into customers (
                id, partner_id, customer_number, name, status, created_by, created_at
            ) values (%s, %s, %s, %s, 'active', 'tests', %s)
            """,
            (customer_id, partner_id, f"IMP-{customer_id.hex[:8]}", name, datetime.now(UTC)),
        )
    return customer_id


def auth(account_id) -> dict[str, str]:
    token, _ = jwt_tokens.issue(str(account_id))
    return {"Authorization": f"Bearer {token}"}


def test_platform_owner_can_start_and_end_impersonation_session() -> None:
    owner = _platform_owner()
    target = tenancy.create_account(
        AccountCreate(email="opsuser@aetherix.test", full_name="Ops User")
    )

    response = client.post(
        f"/accounts/{target.id}/impersonate",
        headers=auth(owner.id),
        json={"reason": "investigating support ticket #4521", "ttl_seconds": 600},
    )
    assert response.status_code == 201, response.text
    body = response.json()
    assert body["session"]["target_account_id"] == str(target.id)
    assert body["session"]["actor_account_id"] == str(owner.id)
    assert body["session"]["ended_at"] is None
    token = body["token"]
    assert isinstance(token, str) and token.count(".") == 2
    claims = jwt_tokens.verify(token)
    assert claims["sub"] == str(target.id)
    assert claims["impersonation_session_id"] == body["session"]["id"]
    assert claims["impersonator_account_id"] == str(owner.id)

    # The minted token acts as the target — /me returns the target.
    me = client.get("/me", headers={"Authorization": f"Bearer {token}"})
    assert me.status_code == 200, me.text
    assert me.json()["account"]["id"] == str(target.id)

    # End the session.
    session_id = body["session"]["id"]
    end = client.post(
        f"/impersonation/{session_id}/end",
        headers=auth(owner.id),
    )
    assert end.status_code == 200, end.text
    assert end.json()["session"]["ended_at"] is not None

    # Idempotent: ending again returns the same session, not an error.
    end_again = client.post(
        f"/impersonation/{session_id}/end",
        headers=auth(owner.id),
    )
    assert end_again.status_code == 200, end_again.text

    # Listing surfaces the session for the owner.
    listing = client.get("/impersonation", headers=auth(owner.id))
    assert listing.status_code == 200, listing.text
    sessions = listing.json()["sessions"]
    assert any(s["id"] == session_id for s in sessions)


def test_impersonation_requires_reason_and_rejects_self() -> None:
    owner = _platform_owner()

    response = client.post(
        f"/accounts/{owner.id}/impersonate",
        headers=auth(owner.id),
        json={"reason": "looking around"},
    )
    assert response.status_code == 400
    assert "yourself" in response.json()["detail"].lower()

    target = tenancy.create_account(
        AccountCreate(email="missing-reason@aetherix.test", full_name="No Reason"),
    )
    response = client.post(
        f"/accounts/{target.id}/impersonate",
        headers=auth(owner.id),
        json={"reason": "x"},
    )
    assert response.status_code == 400
    assert "reason" in response.json()["detail"].lower()


def test_non_platform_owner_without_impersonate_manage_is_rejected() -> None:
    _platform_owner()  # bootstrap
    partner_id = _make_partner("noperm")
    customer_id = _make_customer(partner_id)

    actor = tenancy.create_account(
        AccountCreate(
            email="viewer@noperm.test",
            full_name="Viewer",
            initial_role=RoleAssignmentRequest(
                role_code="company_admin", customer_id=customer_id
            ),
        )
    )
    target = tenancy.create_account(
        AccountCreate(email="targetnoperm@noperm.test", full_name="Target"),
    )

    response = client.post(
        f"/accounts/{target.id}/impersonate",
        headers=auth(actor.id),
        json={"reason": "investigating something"},
    )
    # company_admin does not have impersonate=manage at platform scope.
    assert response.status_code in (403, 404)


def test_only_originating_actor_or_owner_can_end_session() -> None:
    owner = _platform_owner()
    target = tenancy.create_account(
        AccountCreate(email="stranger-target@aetherix.test", full_name="Stranger Target"),
    )
    # owner starts a session
    started = client.post(
        f"/accounts/{target.id}/impersonate",
        headers=auth(owner.id),
        json={"reason": "owner-initiated investigation"},
    )
    assert started.status_code == 201
    session_id = started.json()["session"]["id"]

    # An unrelated account tries to end it.
    stranger = tenancy.create_account(
        AccountCreate(email="random@aetherix.test", full_name="Random"),
    )
    bad_end = client.post(
        f"/impersonation/{session_id}/end",
        headers=auth(stranger.id),
    )
    assert bad_end.status_code == 403

    # Target themselves cannot end it either (they didn't start it).
    target_end = client.post(
        f"/impersonation/{session_id}/end",
        headers=auth(target.id),
    )
    assert target_end.status_code == 403

    # Owner can.
    owner_end = client.post(
        f"/impersonation/{session_id}/end",
        headers=auth(owner.id),
    )
    assert owner_end.status_code == 200


def test_impersonation_emits_audit_and_evidence_chain() -> None:
    owner = _platform_owner()
    target = tenancy.create_account(
        AccountCreate(email="evidencetarget@aetherix.test", full_name="Evidence Target"),
    )

    started = client.post(
        f"/accounts/{target.id}/impersonate",
        headers=auth(owner.id),
        json={"reason": "evidence chain check"},
    )
    assert started.status_code == 201
    session_id = started.json()["session"]["id"]

    ended = client.post(
        f"/impersonation/{session_id}/end",
        headers=auth(owner.id),
    )
    assert ended.status_code == 200

    with app_db.connection() as conn, conn.cursor() as cur:
        cur.execute(
            """
            select action, evidence_controls
            from audit_log
            where action in ('impersonation.start', 'impersonation.end')
            order by seq asc
            """
        )
        audit_rows = cur.fetchall()
        cur.execute(
            """
            select action, evidence_controls
            from evidence_events
            where action in ('impersonation.start', 'impersonation.end')
            order by created_at asc
            """
        )
        evidence_rows = cur.fetchall()

    audit_actions = [row["action"] for row in audit_rows]
    assert audit_actions == ["impersonation.start", "impersonation.end"]
    # Audit rows carry the ISO/SOC mappings declared in compliance.CONTROL_MAPPINGS
    for row in audit_rows:
        controls = row["evidence_controls"] or []
        assert any(str(tag).startswith("iso27001-2022:A.5.18") for tag in controls)
        assert any(str(tag).startswith("soc2-2017:CC6.3") for tag in controls)

    evidence_actions = [row["action"] for row in evidence_rows]
    assert evidence_actions == ["impersonation.start", "impersonation.end"]
    for row in evidence_rows:
        controls = row["evidence_controls"] or []
        assert any(str(tag).startswith("iso27001-2022:A.5.18") for tag in controls)


def test_active_only_listing_filters_ended_sessions() -> None:
    owner = _platform_owner()
    target = tenancy.create_account(
        AccountCreate(email="listfilter@aetherix.test", full_name="Listing Target"),
    )

    a = client.post(
        f"/accounts/{target.id}/impersonate",
        headers=auth(owner.id),
        json={"reason": "session A long enough reason"},
    ).json()["session"]["id"]
    b = client.post(
        f"/accounts/{target.id}/impersonate",
        headers=auth(owner.id),
        json={"reason": "session B long enough reason"},
    ).json()["session"]["id"]
    # End A.
    client.post(f"/impersonation/{a}/end", headers=auth(owner.id))

    active = client.get(
        "/impersonation",
        headers=auth(owner.id),
        params={"active_only": True},
    )
    assert active.status_code == 200
    active_ids = {s["id"] for s in active.json()["sessions"]}
    assert b in active_ids
    assert a not in active_ids

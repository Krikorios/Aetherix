"""Rollback simulation query API + recency guard tests.

Covers:
1.  GET /endpoints/{id}/rollback-simulations returns stored simulations.
2.  GET /endpoints/{id}/rollback-simulations/{simulation_id} returns detail.
3.  GET .../{simulation_id} → 404 if not found.
4.  include_expired=false filters out expired simulations.
5.  queue_rollback_intent → 400 when no simulation in DB.
6.  queue_rollback_intent → succeeds after simulation is posted.
7.  approve_rollback_intent → 409 if simulation has since expired.
"""

from __future__ import annotations

import json
import uuid
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from app.db import connection
from app.main import app


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _load_fixture() -> dict:
    p = Path(__file__).resolve().parent / "fixtures/vss_readiness_pending_inbox_export.json"
    return json.loads(p.read_text())


def _post_simulation(
    *,
    payload: dict,
    endpoint_id: str,
    token: str,
    client: TestClient,
):
    return client.post(
        "/agent/rollback-simulation",
        json=payload,
        params={"endpoint_id": endpoint_id},
        headers={"Authorization": f"Bearer {token}"},
    )


def _sim_payload(
    *,
    simulation_id: str | None = None,
    candidate_set_hash: str | None = None,
    valid_hours: float = 2.0,
    overrides: dict | None = None,
) -> dict:
    fixture = _load_fixture()
    base = fixture["simulate_restore_output"].copy()
    base["simulation_id"] = simulation_id or f"sim-query-{uuid.uuid4().hex[:8]}"
    base["candidate_set_hash"] = candidate_set_hash or "hash-query-001"
    base["valid_until"] = (datetime.now(UTC) + timedelta(hours=valid_hours)).isoformat()
    if overrides:
        base.update(overrides)
    return base


def _post_rollback_intent(
    *,
    client: TestClient,
    endpoint_id: str,
    headers: dict,
    simulation_id: str,
    candidate_set_hash: str,
    valid_hours: float = 2.0,
    severity_hint: str = "medium",
):
    valid_until = (datetime.now(UTC) + timedelta(hours=valid_hours)).isoformat()
    return client.post(
        f"/endpoints/{endpoint_id}/rollback-intent",
        json={
            "simulation_id": simulation_id,
            "candidate_set_hash": candidate_set_hash,
            "affected_paths": ["/home/user/test.xlsx"],
            "recovery_point_id": "rp-query-001",
            "provider": "vss",
            "valid_until": valid_until,
            "severity_hint": severity_hint,
            "reason": "query guard test",
        },
        headers=headers,
    )


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


def test_list_simulations_returns_stored(tenant_hierarchy_factory, auth_headers) -> None:
    """GET /endpoints/{id}/rollback-simulations returns stored simulations."""
    fixture = _load_fixture()
    agent = fixture["agent"]
    token = agent["secret"]
    endpoint_id = agent["id"]

    tenant = tenant_hierarchy_factory(endpoint_id=endpoint_id)
    admin_id = tenant["company_admin_id"]
    client = TestClient(app)
    headers = auth_headers(admin_id)

    sim_id = f"sim-list-{uuid.uuid4().hex[:8]}"
    payload = _sim_payload(simulation_id=sim_id, candidate_set_hash="hash-list-001")
    resp_post = _post_simulation(payload=payload, endpoint_id=endpoint_id, token=token, client=client)
    assert resp_post.status_code == 201, resp_post.text

    resp = client.get(f"/endpoints/{endpoint_id}/rollback-simulations", headers=headers)
    assert resp.status_code == 200, resp.text
    items = resp.json()
    assert isinstance(items, list)
    assert any(s["simulation_id"] == sim_id for s in items)


def test_get_simulation_detail(tenant_hierarchy_factory, auth_headers) -> None:
    """GET /endpoints/{id}/rollback-simulations/{simulation_id} returns detail with decision_trace."""
    fixture = _load_fixture()
    agent = fixture["agent"]
    token = agent["secret"]
    endpoint_id = agent["id"]

    tenant = tenant_hierarchy_factory(endpoint_id=endpoint_id)
    admin_id = tenant["company_admin_id"]
    client = TestClient(app)
    headers = auth_headers(admin_id)

    sim_id = f"sim-detail-{uuid.uuid4().hex[:8]}"
    payload = _sim_payload(simulation_id=sim_id, candidate_set_hash="hash-detail-001")
    resp_post = _post_simulation(payload=payload, endpoint_id=endpoint_id, token=token, client=client)
    assert resp_post.status_code == 201, resp_post.text

    resp = client.get(
        f"/endpoints/{endpoint_id}/rollback-simulations/{sim_id}",
        headers=headers,
    )
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["simulation_id"] == sim_id
    assert "decision_trace" in body
    assert "skipped_paths" in body


def test_get_simulation_not_found(tenant_hierarchy_factory, auth_headers) -> None:
    """GET .../rollback-simulations/{simulation_id} → 404 if not found."""
    fixture = _load_fixture()
    agent = fixture["agent"]
    endpoint_id = agent["id"]

    tenant = tenant_hierarchy_factory(endpoint_id=endpoint_id)
    admin_id = tenant["company_admin_id"]
    client = TestClient(app)
    headers = auth_headers(admin_id)

    resp = client.get(
        f"/endpoints/{endpoint_id}/rollback-simulations/sim-does-not-exist",
        headers=headers,
    )
    assert resp.status_code == 404, resp.text


def test_list_simulations_exclude_expired(tenant_hierarchy_factory, auth_headers) -> None:
    """include_expired=false (default) filters out expired simulations."""
    fixture = _load_fixture()
    agent = fixture["agent"]
    token = agent["secret"]
    endpoint_id = agent["id"]

    tenant = tenant_hierarchy_factory(endpoint_id=endpoint_id)
    admin_id = tenant["company_admin_id"]
    client = TestClient(app)
    headers = auth_headers(admin_id)

    # Post an expired simulation directly to DB
    expired_id = f"sim-expired-{uuid.uuid4().hex[:8]}"
    with connection() as conn, conn.cursor() as cur:
        cur.execute(
            """
            insert into rollback_simulations
                (simulation_id, endpoint_id, candidate_set_hash, candidate_count,
                 restorable_count, skipped_paths, destructive, valid_until,
                 decision_trace, provider, recovery_point_id, affected_paths,
                 customer_id, created_at)
            values (%s, %s, %s, 3, 2, '[]', false, %s, '[]', 'vss', 'rp-x', '[]', null, now())
            on conflict (simulation_id) do nothing
            """,
            (
                expired_id,
                endpoint_id,
                "hash-expired-001",
                datetime.now(UTC) - timedelta(hours=2),
            ),
        )

    # Post a valid simulation via agent route
    valid_id = f"sim-valid-{uuid.uuid4().hex[:8]}"
    payload = _sim_payload(simulation_id=valid_id, candidate_set_hash="hash-valid-001")
    _post_simulation(payload=payload, endpoint_id=endpoint_id, token=token, client=client)

    # Default (include_expired=false) should NOT include expired
    resp_default = client.get(
        f"/endpoints/{endpoint_id}/rollback-simulations",
        headers=headers,
    )
    assert resp_default.status_code == 200
    ids_default = [s["simulation_id"] for s in resp_default.json()]
    assert valid_id in ids_default
    assert expired_id not in ids_default

    # include_expired=true should include both
    resp_all = client.get(
        f"/endpoints/{endpoint_id}/rollback-simulations?include_expired=true",
        headers=headers,
    )
    assert resp_all.status_code == 200
    ids_all = [s["simulation_id"] for s in resp_all.json()]
    assert expired_id in ids_all
    assert valid_id in ids_all


def test_queue_intent_blocked_without_simulation(tenant_hierarchy_factory, auth_headers) -> None:
    """queue_rollback_intent → 400 when no simulation in DB."""
    agent_id = f"agent-guard-no-sim-{uuid.uuid4().hex[:8]}"
    tenant = tenant_hierarchy_factory(endpoint_id=agent_id)
    admin_id = tenant["company_admin_id"]
    client = TestClient(app)
    headers = auth_headers(admin_id)

    resp = _post_rollback_intent(
        client=client,
        endpoint_id=agent_id,
        headers=headers,
        simulation_id="sim-guard-missing",
        candidate_set_hash="hash-guard-missing",
    )
    assert resp.status_code == 400, resp.text
    assert "simulation" in resp.json().get("detail", "").lower()


def test_queue_intent_succeeds_after_simulation_posted(
    tenant_hierarchy_factory, auth_headers
) -> None:
    """queue_rollback_intent → succeeds after simulation is posted by agent."""
    fixture = _load_fixture()
    agent = fixture["agent"]
    token = agent["secret"]
    endpoint_id = agent["id"]

    tenant = tenant_hierarchy_factory(endpoint_id=endpoint_id)
    admin_id = tenant["company_admin_id"]
    client = TestClient(app)
    headers = auth_headers(admin_id)

    sim_id = f"sim-guard-pass-{uuid.uuid4().hex[:8]}"
    candidate_hash = f"hash-guard-pass-{uuid.uuid4().hex[:8]}"
    payload = _sim_payload(simulation_id=sim_id, candidate_set_hash=candidate_hash)
    resp_sim = _post_simulation(payload=payload, endpoint_id=endpoint_id, token=token, client=client)
    assert resp_sim.status_code == 201, resp_sim.text

    resp_intent = _post_rollback_intent(
        client=client,
        endpoint_id=endpoint_id,
        headers=headers,
        simulation_id=sim_id,
        candidate_set_hash=candidate_hash,
        severity_hint="medium",
    )
    assert resp_intent.status_code == 202, resp_intent.text
    assert resp_intent.json()["status"] == "queued"


def test_approve_intent_blocked_if_simulation_expired(
    tenant_hierarchy_factory, auth_headers
) -> None:
    """approve_rollback_intent → 409 if simulation has since expired at approval time."""
    from app.services import tenancy as _tenancy
    from app.schemas import AccountCreate, RoleAssignmentRequest

    fixture = _load_fixture()
    agent = fixture["agent"]
    token = agent["secret"]
    endpoint_id = agent["id"]

    tenant = tenant_hierarchy_factory(endpoint_id=endpoint_id)
    admin_id = tenant["company_admin_id"]
    customer_id = tenant["customer_id"]
    client = TestClient(app)
    headers = auth_headers(admin_id)

    second_admin = _tenancy.create_account(
        AccountCreate(
            email=f"guard-second-{uuid.uuid4().hex[:8]}@aetherix.test",
            full_name="Guard Second Admin",
            initial_role=RoleAssignmentRequest(
                role_code="company_admin", customer_id=uuid.UUID(customer_id)
            ),
        )
    )
    headers_second = auth_headers(second_admin.id)

    # Post a simulation that expires in the future (for intent-queuing)
    sim_id = f"sim-approve-guard-{uuid.uuid4().hex[:8]}"
    candidate_hash = f"hash-approve-guard-{uuid.uuid4().hex[:8]}"
    payload = _sim_payload(simulation_id=sim_id, candidate_set_hash=candidate_hash, valid_hours=2)
    resp_sim = _post_simulation(payload=payload, endpoint_id=endpoint_id, token=token, client=client)
    assert resp_sim.status_code == 201, resp_sim.text

    # Queue a high-severity intent so it needs approval
    resp_intent = _post_rollback_intent(
        client=client,
        endpoint_id=endpoint_id,
        headers=headers,
        simulation_id=sim_id,
        candidate_set_hash=candidate_hash,
        severity_hint="high",
    )
    assert resp_intent.status_code == 202, resp_intent.text
    action_id = resp_intent.json()["id"]

    # Manually expire the simulation in the DB
    with connection() as conn, conn.cursor() as cur:
        cur.execute(
            "update rollback_simulations set valid_until = %s where simulation_id = %s",
            (datetime.now(UTC) - timedelta(hours=1), sim_id),
        )

    # Approval should now be blocked because the simulation is expired
    resp_approve = client.post(
        f"/endpoints/{endpoint_id}/rollback-intent/{action_id}/approve",
        json={"reason": "Approve after sim expired"},
        headers=headers_second,
    )
    assert resp_approve.status_code == 409, resp_approve.text
    assert "expired" in resp_approve.json().get("detail", "").lower()

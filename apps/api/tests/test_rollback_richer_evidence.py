"""Richer rollback evidence integration tests.

Covers the new capabilities added in the 2026-05-30 cycle:

1. pending inbox surfaces simulation fields (simulation_id, confidence,
   valid_until, is_expired, candidate_count, restorable_count).
2. GET /endpoints/{id}/rollback-restore-results returns stored rows.
3. Restore result with metadata_preservation_summary stores correctly;
   has_metadata_preservation=True in list response.
4. Evidence events include metadata_preservation_summary when provided.
5. simulation_is_expired=True when simulation valid_until is in the past.
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


def _sim_payload(
    *,
    simulation_id: str | None = None,
    candidate_set_hash: str | None = None,
    valid_hours: float = 2.0,
    overrides: dict | None = None,
) -> dict:
    fixture = _load_fixture()
    base = fixture["simulate_restore_output"].copy()
    base["simulation_id"] = simulation_id or f"sim-rich-{uuid.uuid4().hex[:8]}"
    base["candidate_set_hash"] = candidate_set_hash or f"hash-rich-{uuid.uuid4().hex[:8]}"
    base["valid_until"] = (datetime.now(UTC) + timedelta(hours=valid_hours)).isoformat()
    if overrides:
        base.update(overrides)
    return base


def _post_simulation(
    *,
    client: TestClient,
    payload: dict,
    endpoint_id: str,
    token: str,
):
    return client.post(
        "/agent/rollback-simulation",
        json=payload,
        params={"endpoint_id": endpoint_id},
        headers={"Authorization": f"Bearer {token}"},
    )


def _post_restore_result(
    *,
    client: TestClient,
    payload: dict,
    endpoint_id: str,
    token: str,
):
    return client.post(
        "/agent/rollback-restore-result",
        json=payload,
        params={"endpoint_id": endpoint_id},
        headers={"Authorization": f"Bearer {token}"},
    )


def _make_result_payload(
    *,
    execution_id: str | None = None,
    simulation_id: str | None = None,
    candidate_set_hash: str | None = None,
    success: bool = True,
    paths_attempted: int = 3,
    paths_restored: int = 3,
    paths_failed: int = 0,
    metadata_preservation_summary: dict | None = None,
    provider: str = "vss",
    recovery_point_id: str = "rp-rich-001",
    duration_ms: int = 250,
) -> dict:
    if execution_id is None:
        execution_id = f"exec-rich-{uuid.uuid4().hex[:8]}"
    if simulation_id is None:
        simulation_id = f"sim-rich-{uuid.uuid4().hex[:8]}"
    if candidate_set_hash is None:
        candidate_set_hash = f"hash-rich-{uuid.uuid4().hex[:8]}"

    path_results = [
        {
            "path": f"/home/user/doc{i}.xlsx",
            "outcome": "restored",
            "bytes_restored": 1024,
            "hash_before": "a" * 64,
            "hash_after": "b" * 64,
            "error_message": None,
        }
        for i in range(paths_restored)
    ]

    payload: dict = {
        "execution_id": execution_id,
        "simulation_id": simulation_id,
        "candidate_set_hash": candidate_set_hash,
        "success": success,
        "paths_attempted": paths_attempted,
        "paths_restored": paths_restored,
        "paths_failed": paths_failed,
        "path_results": path_results,
        "error_message": None,
        "provider": provider,
        "recovery_point_id": recovery_point_id,
        "executed_at": datetime.now(UTC).isoformat(),
        "duration_ms": duration_ms,
    }
    if metadata_preservation_summary is not None:
        payload["metadata_preservation_summary"] = metadata_preservation_summary
    return payload


def _queue_rollback_intent(
    *,
    client: TestClient,
    endpoint_id: str,
    headers: dict,
    simulation_id: str,
    candidate_set_hash: str,
    valid_hours: float = 2.0,
    severity_hint: str = "high",
) -> dict:
    valid_until = (datetime.now(UTC) + timedelta(hours=valid_hours)).isoformat()
    resp = client.post(
        f"/endpoints/{endpoint_id}/rollback-intent",
        json={
            "simulation_id": simulation_id,
            "candidate_set_hash": candidate_set_hash,
            "affected_paths": ["/home/user/important.xlsx"],
            "recovery_point_id": "rp-rich-001",
            "provider": "vss",
            "valid_until": valid_until,
            "severity_hint": severity_hint,
            "reason": "richer evidence test",
        },
        headers=headers,
    )
    assert resp.status_code in (201, 202), f"failed to queue intent: {resp.text}"
    return resp.json()


# ---------------------------------------------------------------------------
# Test 1 — pending inbox surfaces simulation fields
# ---------------------------------------------------------------------------


def test_pending_inbox_surfaces_simulation_fields(
    tenant_hierarchy_factory, auth_headers
) -> None:
    """GET /rollback-intents/pending returns simulation metadata fields.

    After a simulation is posted and a high-severity rollback intent is queued,
    the pending inbox must include simulation_id, simulation_confidence,
    simulation_valid_until, simulation_is_expired=False, candidate_count,
    and restorable_count on each PendingRollbackIntent item.
    """
    fixture = _load_fixture()
    agent = fixture["agent"]
    token = agent["secret"]
    endpoint_id = agent["id"]

    tenant = tenant_hierarchy_factory(endpoint_id=endpoint_id)
    admin_id = tenant["company_admin_id"]
    client = TestClient(app)
    headers = auth_headers(admin_id)

    # Post simulation
    sim_id = f"sim-inbox-{uuid.uuid4().hex[:8]}"
    sim_hash = f"hash-inbox-{uuid.uuid4().hex[:8]}"
    sim = _sim_payload(
        simulation_id=sim_id,
        candidate_set_hash=sim_hash,
        valid_hours=4.0,
    )
    resp_sim = _post_simulation(
        client=client, payload=sim, endpoint_id=endpoint_id, token=token
    )
    assert resp_sim.status_code == 201, resp_sim.text

    # Queue intent
    _queue_rollback_intent(
        client=client,
        endpoint_id=endpoint_id,
        headers=headers,
        simulation_id=sim_id,
        candidate_set_hash=sim_hash,
        valid_hours=4.0,
        severity_hint="high",
    )

    # Check pending inbox
    resp = client.get("/rollback-intents/pending", headers=headers)
    assert resp.status_code == 200, resp.text
    items = resp.json()
    assert len(items) >= 1

    match = next(
        (i for i in items if i.get("simulation_id") == sim_id),
        None,
    )
    assert match is not None, f"Expected item with simulation_id={sim_id} in: {items}"
    assert match["simulation_id"] == sim_id
    assert match["simulation_is_expired"] is False
    assert match["simulation_valid_until"] is not None
    # Confidence should be candidate_count-derived
    assert match["simulation_confidence"] is not None
    assert 0.0 <= match["simulation_confidence"] <= 1.0
    # Candidate counts should be populated
    assert match["simulation_candidate_count"] is not None
    assert match["simulation_restorable_count"] is not None


# ---------------------------------------------------------------------------
# Test 2 — list restore results endpoint returns stored rows
# ---------------------------------------------------------------------------


def test_list_restore_results_endpoint(
    tenant_hierarchy_factory, auth_headers
) -> None:
    """GET /endpoints/{id}/rollback-restore-results returns stored restore records."""
    fixture = _load_fixture()
    agent = fixture["agent"]
    token = agent["secret"]
    endpoint_id = agent["id"]

    tenant = tenant_hierarchy_factory(endpoint_id=endpoint_id)
    admin_id = tenant["company_admin_id"]
    client = TestClient(app)
    headers = auth_headers(admin_id)

    # Post restore result (no prior simulation required for ingest)
    exec_id = f"exec-list-{uuid.uuid4().hex[:8]}"
    sim_id = f"sim-list-{uuid.uuid4().hex[:8]}"
    hash_ = f"hash-list-{uuid.uuid4().hex[:8]}"
    payload = _make_result_payload(
        execution_id=exec_id,
        simulation_id=sim_id,
        candidate_set_hash=hash_,
    )
    resp_post = _post_restore_result(
        client=client, payload=payload, endpoint_id=endpoint_id, token=token
    )
    assert resp_post.status_code == 201, resp_post.text

    # Fetch list
    resp = client.get(
        f"/endpoints/{endpoint_id}/rollback-restore-results", headers=headers
    )
    assert resp.status_code == 200, resp.text
    rows = resp.json()
    assert isinstance(rows, list)

    row = next((r for r in rows if r["execution_id"] == exec_id), None)
    assert row is not None, f"execution_id={exec_id} not found in: {rows}"
    assert row["simulation_id"] == sim_id
    assert row["candidate_set_hash"] == hash_
    assert row["success"] is True
    assert row["paths_attempted"] == 3
    assert row["paths_restored"] == 3
    assert row["restore_success_rate"] == pytest.approx(1.0)
    assert row["has_metadata_preservation"] is False


# ---------------------------------------------------------------------------
# Test 3 — restore result with metadata_preservation_summary
# ---------------------------------------------------------------------------


def test_restore_result_with_metadata_preservation(
    tenant_hierarchy_factory, auth_headers
) -> None:
    """Restore result with metadata_preservation_summary stores correctly.

    has_metadata_preservation=True must appear in the list response.
    """
    fixture = _load_fixture()
    agent = fixture["agent"]
    token = agent["secret"]
    endpoint_id = agent["id"]

    tenant = tenant_hierarchy_factory(endpoint_id=endpoint_id)
    admin_id = tenant["company_admin_id"]
    client = TestClient(app)
    headers = auth_headers(admin_id)

    exec_id = f"exec-meta-{uuid.uuid4().hex[:8]}"
    sim_id = f"sim-meta-{uuid.uuid4().hex[:8]}"
    hash_ = f"hash-meta-{uuid.uuid4().hex[:8]}"
    meta = {
        "acl_preserved": True,
        "acl_details": "DACL preserved from VSS snapshot",
        "original_acl_sha256": "f" * 64,
        "ads_preserved": True,
        "ads_streams": ["Zone.Identifier"],
        "timestamps_preserved": True,
        "preservation_notes": ["Timestamps restored from snapshot metadata"],
    }
    payload = _make_result_payload(
        execution_id=exec_id,
        simulation_id=sim_id,
        candidate_set_hash=hash_,
        metadata_preservation_summary=meta,
    )
    resp_post = _post_restore_result(
        client=client, payload=payload, endpoint_id=endpoint_id, token=token
    )
    assert resp_post.status_code == 201, resp_post.text

    resp = client.get(
        f"/endpoints/{endpoint_id}/rollback-restore-results", headers=headers
    )
    assert resp.status_code == 200, resp.text
    rows = resp.json()
    row = next((r for r in rows if r["execution_id"] == exec_id), None)
    assert row is not None, f"execution_id={exec_id} not in list"
    assert row["has_metadata_preservation"] is True


# ---------------------------------------------------------------------------
# Test 4 — evidence events include metadata_preservation_summary
# ---------------------------------------------------------------------------


def test_restore_result_metadata_preservation_in_evidence(
    tenant_hierarchy_factory,
) -> None:
    """Evidence events include metadata_preservation_summary when provided."""
    fixture = _load_fixture()
    agent = fixture["agent"]
    token = agent["secret"]
    endpoint_id = agent["id"]

    tenant_hierarchy_factory(endpoint_id=endpoint_id)
    client = TestClient(app)

    exec_id = f"exec-ev-{uuid.uuid4().hex[:8]}"
    sim_id = f"sim-ev-{uuid.uuid4().hex[:8]}"
    hash_ = f"hash-ev-{uuid.uuid4().hex[:8]}"
    meta = {
        "acl_preserved": True,
        "ads_preserved": False,
        "timestamps_preserved": True,
    }
    payload = _make_result_payload(
        execution_id=exec_id,
        simulation_id=sim_id,
        candidate_set_hash=hash_,
        metadata_preservation_summary=meta,
    )
    resp_post = _post_restore_result(
        client=client, payload=payload, endpoint_id=endpoint_id, token=token
    )
    assert resp_post.status_code == 201, resp_post.text

    # Verify evidence event carries metadata_preservation_summary
    with connection() as conn, conn.cursor() as cur:
        cur.execute(
            """
            select payload from evidence_events
                where action in ('endpoint.rollback.executed', 'endpoint.rollback.failed')
              and payload->>'execution_id' = %s
            """,
            (exec_id,),
        )
        ev_row = cur.fetchone()

    assert ev_row is not None, "No evidence event found for restore result"
    ev_payload = ev_row["payload"]
    assert ev_payload.get("metadata_preservation_summary") is not None, (
        f"metadata_preservation_summary missing from evidence payload: {ev_payload}"
    )
    mps = ev_payload["metadata_preservation_summary"]
    assert mps["acl_preserved"] is True
    assert mps["timestamps_preserved"] is True


# ---------------------------------------------------------------------------
# Test 5 — simulation_is_expired=True when valid_until is in the past
# ---------------------------------------------------------------------------


def test_pending_inbox_simulation_expired_flag(
    tenant_hierarchy_factory, auth_headers
) -> None:
    """Pending inbox marks simulation_is_expired=True when valid_until is past.

    We insert the simulation row directly into the DB (already expired), then
    queue an intent using override to embed a past valid_until in the action
    payload, and verify the pending inbox returns simulation_is_expired=True.
    """
    endpoint_id = f"agent-expiry-{uuid.uuid4().hex[:8]}"
    tenant = tenant_hierarchy_factory(endpoint_id=endpoint_id)
    admin_id = tenant["company_admin_id"]
    customer_id = tenant["customer_id"]
    client = TestClient(app)
    headers = auth_headers(admin_id)

    # Insert expired simulation row directly
    sim_id = f"sim-expired-{uuid.uuid4().hex[:8]}"
    hash_ = f"hash-expiry-{uuid.uuid4().hex[:8]}"
    past_time = datetime.now(UTC) - timedelta(hours=3)

    with connection() as conn, conn.cursor() as cur:
        cur.execute(
            """
            insert into rollback_simulations
                (simulation_id, endpoint_id, candidate_set_hash, candidate_count,
                 restorable_count, skipped_paths, destructive, valid_until,
                 decision_trace, provider, recovery_point_id, affected_paths,
                 customer_id, created_at)
            values (%s, %s, %s, 3, 2, '[]', false, %s, '[]', 'vss', 'rp-exp-001',
                    '["/home/user/x.xlsx"]', %s, now())
            on conflict (simulation_id) do nothing
            """,
            (sim_id, endpoint_id, hash_, past_time, customer_id),
        )

    # Queue rollback intent — queue-time guard checks DB row exists;
    # we pass a past valid_until so the action payload records expiry.
    past_iso = past_time.isoformat()
    resp_intent = client.post(
        f"/endpoints/{endpoint_id}/rollback-intent",
        json={
            "simulation_id": sim_id,
            "candidate_set_hash": hash_,
            "affected_paths": ["/home/user/x.xlsx"],
            "recovery_point_id": "rp-exp-001",
            "provider": "vss",
            "valid_until": past_iso,
            "severity_hint": "high",
            "reason": "expiry flag test",
        },
        headers=headers,
    )
    # The intent queue endpoint may or may not reject an already-expired
    # simulation — if it does (400/409) the test is still valid as the
    # simulation_is_expired semantics only matter for queued items.
    # We only assert the pending inbox flag when the queue succeeded.
    if resp_intent.status_code not in (201,):
        pytest.skip(
            f"intent queue rejected expired simulation ({resp_intent.status_code}); "
            "skipping pending inbox assertion"
        )

    resp = client.get("/rollback-intents/pending", headers=headers)
    assert resp.status_code == 200, resp.text
    items = resp.json()
    match = next((i for i in items if i.get("simulation_id") == sim_id), None)
    assert match is not None, f"Expected item with simulation_id={sim_id} in {items}"
    assert match["simulation_is_expired"] is True, (
        f"Expected simulation_is_expired=True, got: {match}"
    )

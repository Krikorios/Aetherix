"""VSS restore-result ingest smoke tests — POST /agent/rollback-restore-result.

Covers the full ingest → storage → evidence-emission path for
``AgentRollbackRestoreResult`` payloads produced by the agent after
executing a real restore.

Test cases
----------
1. Successful restore: 201, row in rollback_restore_results, evidence emitted.
2. Failed restore: emits endpoint.rollback.failed evidence.
3. Idempotent upsert on duplicate execution_id → still 201, row updated.
4. Bad token → 401.
5. Unregistered agent → 401.
6. Zero paths → restore_success_rate = 0.0, no crash.
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


def _make_result_payload(
    *,
    execution_id: str | None = None,
    simulation_id: str | None = None,
    candidate_set_hash: str | None = None,
    success: bool = True,
    paths_attempted: int = 3,
    paths_restored: int = 3,
    paths_failed: int = 0,
    path_results: list[dict] | None = None,
    error_message: str | None = None,
    provider: str = "vss",
    recovery_point_id: str = "rp-smoke-001",
    executed_at: str | None = None,
    duration_ms: int = 250,
) -> dict:
    if execution_id is None:
        execution_id = f"exec-smoke-{uuid.uuid4().hex[:8]}"
    if simulation_id is None:
        simulation_id = f"sim-smoke-{uuid.uuid4().hex[:8]}"
    if candidate_set_hash is None:
        candidate_set_hash = "hash-smoke-001"
    if executed_at is None:
        executed_at = datetime.now(UTC).isoformat()
    if path_results is None:
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
    return {
        "execution_id": execution_id,
        "simulation_id": simulation_id,
        "candidate_set_hash": candidate_set_hash,
        "success": success,
        "paths_attempted": paths_attempted,
        "paths_restored": paths_restored,
        "paths_failed": paths_failed,
        "path_results": path_results,
        "error_message": error_message,
        "recovery_point_id": recovery_point_id,
        "provider": provider,
        "executed_at": executed_at,
        "duration_ms": duration_ms,
    }


def _post_restore_result(
    *,
    payload: dict,
    endpoint_id: str,
    token: str,
    client: TestClient | None = None,
):
    c = client or TestClient(app)
    return c.post(
        "/agent/rollback-restore-result",
        json=payload,
        params={"endpoint_id": endpoint_id},
        headers={"Authorization": f"Bearer {token}"},
    )


def _fetch_restore_row(execution_id: str) -> dict | None:
    with connection() as conn, conn.cursor() as cur:
        cur.execute(
            "select * from rollback_restore_results where execution_id = %s",
            (execution_id,),
        )
        return cur.fetchone()


def _fetch_evidence_by_action(action: str, resource_prefix: str) -> list[dict]:
    with connection() as conn, conn.cursor() as cur:
        cur.execute(
            """
            select * from evidence_events
             where action = %s and resource like %s
             order by created_at desc
            """,
            (action, f"{resource_prefix}%"),
        )
        return cur.fetchall()


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


def test_restore_result_success_ingest(tenant_hierarchy_factory) -> None:
    """Happy path: 201, DB row stored, endpoint.rollback.executed evidence emitted."""
    fixture = _load_fixture()
    agent = fixture["agent"]
    token = agent["secret"]
    endpoint_id = agent["id"]

    tenant_hierarchy_factory(endpoint_id=endpoint_id)
    client = TestClient(app)

    execution_id = f"exec-success-{uuid.uuid4().hex[:8]}"
    payload = _make_result_payload(
        execution_id=execution_id,
        simulation_id="sim-success-001",
        candidate_set_hash="hash-success-001",
        success=True,
        paths_attempted=2,
        paths_restored=2,
        paths_failed=0,
    )

    resp = _post_restore_result(payload=payload, endpoint_id=endpoint_id, token=token, client=client)
    assert resp.status_code == 201, resp.text
    body = resp.json()
    assert body["execution_id"] == execution_id
    assert body["accepted"] is True
    assert body["restore_success_rate"] == 1.0
    assert body["evidence_event_id"] is not None

    row = _fetch_restore_row(execution_id)
    assert row is not None
    assert row["endpoint_id"] == endpoint_id
    assert row["success"] is True
    assert row["paths_restored"] == 2

    events = _fetch_evidence_by_action("endpoint.rollback.executed", f"endpoint:{endpoint_id}")
    assert len(events) >= 1


def test_restore_result_failure_emits_failed_event(tenant_hierarchy_factory) -> None:
    """Failed restore emits endpoint.rollback.failed evidence."""
    fixture = _load_fixture()
    agent = fixture["agent"]
    token = agent["secret"]
    endpoint_id = agent["id"]

    tenant_hierarchy_factory(endpoint_id=endpoint_id)
    client = TestClient(app)

    execution_id = f"exec-fail-{uuid.uuid4().hex[:8]}"
    payload = _make_result_payload(
        execution_id=execution_id,
        simulation_id="sim-fail-smoke-001",
        candidate_set_hash="hash-fail-smoke-001",
        success=False,
        paths_attempted=3,
        paths_restored=0,
        paths_failed=3,
        path_results=[
            {
                "path": f"/home/user/doc{i}.xlsx",
                "outcome": "failed_integrity",
                "bytes_restored": 0,
                "hash_before": "a" * 64,
                "hash_after": None,
                "error_message": "VSS snapshot unavailable",
            }
            for i in range(3)
        ],
        error_message="VSS snapshot store is corrupted",
    )

    resp = _post_restore_result(payload=payload, endpoint_id=endpoint_id, token=token, client=client)
    assert resp.status_code == 201, resp.text
    body = resp.json()
    assert body["accepted"] is True
    assert body["restore_success_rate"] == 0.0

    events = _fetch_evidence_by_action("endpoint.rollback.failed", f"endpoint:{endpoint_id}")
    assert len(events) >= 1


def test_restore_result_idempotent_upsert(tenant_hierarchy_factory) -> None:
    """Duplicate execution_id → idempotent upsert, still 201."""
    fixture = _load_fixture()
    agent = fixture["agent"]
    token = agent["secret"]
    endpoint_id = agent["id"]

    tenant_hierarchy_factory(endpoint_id=endpoint_id)
    client = TestClient(app)

    execution_id = f"exec-idem-{uuid.uuid4().hex[:8]}"
    payload = _make_result_payload(
        execution_id=execution_id,
        paths_attempted=1,
        paths_restored=1,
    )

    resp1 = _post_restore_result(payload=payload, endpoint_id=endpoint_id, token=token, client=client)
    assert resp1.status_code == 201, resp1.text

    resp2 = _post_restore_result(payload=payload, endpoint_id=endpoint_id, token=token, client=client)
    assert resp2.status_code == 201, resp2.text

    # Row should exist exactly once
    with connection() as conn, conn.cursor() as cur:
        cur.execute(
            "select count(*) as n from rollback_restore_results where execution_id = %s",
            (execution_id,),
        )
        row = cur.fetchone()
    assert row["n"] == 1


def test_restore_result_bad_token(tenant_hierarchy_factory) -> None:
    """Bad token → 401."""
    fixture = _load_fixture()
    agent = fixture["agent"]
    endpoint_id = agent["id"]

    tenant_hierarchy_factory(endpoint_id=endpoint_id)
    client = TestClient(app)

    payload = _make_result_payload()
    resp = _post_restore_result(payload=payload, endpoint_id=endpoint_id, token="bad-token", client=client)
    assert resp.status_code == 401, resp.text


def test_restore_result_unregistered_agent() -> None:
    """Unregistered agent → 401."""
    client = TestClient(app)
    payload = _make_result_payload()
    resp = _post_restore_result(
        payload=payload,
        endpoint_id="agent-not-enrolled-at-all",
        token="any-token",
        client=client,
    )
    assert resp.status_code == 401, resp.text


def test_restore_result_zero_paths(tenant_hierarchy_factory) -> None:
    """Zero paths attempted → restore_success_rate = 0.0, no crash."""
    fixture = _load_fixture()
    agent = fixture["agent"]
    token = agent["secret"]
    endpoint_id = agent["id"]

    tenant_hierarchy_factory(endpoint_id=endpoint_id)
    client = TestClient(app)

    execution_id = f"exec-zero-{uuid.uuid4().hex[:8]}"
    payload = _make_result_payload(
        execution_id=execution_id,
        success=False,
        paths_attempted=0,
        paths_restored=0,
        paths_failed=0,
        path_results=[],
        error_message="Nothing to restore",
    )

    resp = _post_restore_result(payload=payload, endpoint_id=endpoint_id, token=token, client=client)
    assert resp.status_code == 201, resp.text
    body = resp.json()
    assert body["restore_success_rate"] == 0.0

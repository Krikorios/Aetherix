"""Tests for DLP ↔ EDR cross-module correlation via sha256_hash.

Covers both execution orderings:

* DLP event observed before the EDR detection (forward path) — verified
  through ``correlate_new_edr_alert`` which now queries the ``dlp_events``
  table by ``sha256_hash`` when the incoming EDR alert carries a
  ``file_sha256``.
* EDR detection observed before the DLP event (reverse path) — verified
  through ``correlate_new_dlp_event`` which is called inside
  ``persist_dlp_event`` when a ``sha256_hash`` is supplied.

Each happy path asserts:
  (a) the ``security_alerts`` row's severity is uplifted one rung and
      ``severity_uplifted_from`` is set,
  (b) a ``correlation_links`` row is recorded with ``related_kind = 'dlp_event'``
      and ``correlation_type = 'sha256_match'``,
  (c) a ``correlation.severity_uplift`` evidence event is written.

The negative cases guard against accidental cross-hash, cross-endpoint,
outside-window, and missing-hash joins.
"""

from __future__ import annotations

import hashlib
import hmac
import json
from datetime import UTC, datetime, timedelta

from fastapi.testclient import TestClient

from app.db import connection
from app.main import app
from app.schemas import EdrEvent, FimEvent


def _sign(secret: str, agent_id: str, hostname: str, os_name: str, collected_at: str, policy_version: str, nonce: int) -> str:
    msg = f"{agent_id}|{hostname}|{os_name}|{collected_at}|{policy_version}|{nonce}"
    return hmac.new(secret.encode(), msg.encode(), hashlib.sha256).hexdigest()


def _post_heartbeat(
    *,
    agent_id: str,
    nonce: int,
    collected_at: datetime,
    fim_events: list[FimEvent] | None = None,
    edr_events: list[EdrEvent] | None = None,
    secret: str = "e2e-endpoint-secret",
) -> dict:
    collected_at_str = collected_at.isoformat()
    payload = {
        "agent_id": agent_id,
        "hostname": "e2e-host",
        "os": "linux",
        "collected_at": collected_at_str,
        "policy_version": "policy-v1",
        "agent_version": "0.1.0",
        "nonce": nonce,
        "signals": {
            "blocked_events": 0,
            "dlp_events": 0,
            "pending_updates": 0,
            "cpu_percent": 5.0,
            "memory_percent": 12.0,
        },
        "fim_events": [e.model_dump(mode="json") for e in (fim_events or [])],
        "edr_events": [e.model_dump(mode="json") for e in (edr_events or [])],
    }
    payload["signature"] = _sign(secret, agent_id, "e2e-host", "linux", collected_at_str, "policy-v1", nonce)
    client = TestClient(app)
    resp = client.post("/agent/heartbeat", json=payload)
    assert resp.status_code == 200, resp.text
    return resp.json()


def _persist_dlp_event(
    *,
    customer_id: str,
    endpoint_id: str,
    sha256_hash: str | None,
    source: str = "e2e-dlp-scan",
) -> str:
    """Call persist_dlp_event directly and return the event id."""
    from app.services.state import persist_dlp_event

    event_id = persist_dlp_event(
        customer_id=customer_id,
        endpoint_id=endpoint_id,
        source=source,
        action="block",
        entity_types=["CREDIT_CARD"],
        risk_band="high",
        sha256_hash=sha256_hash,
    )
    assert event_id is not None
    return str(event_id)


def _fetch_alert(agent_id: str) -> dict:
    with connection() as conn, conn.cursor() as cur:
        cur.execute(
            "select * from security_alerts where agent_id = %s and category = 'malware'",
            (agent_id,),
        )
        rows = cur.fetchall()
    assert len(rows) == 1, f"expected exactly 1 malware alert, got {len(rows)}"
    return rows[0]


def _fetch_links(alert_id) -> list[dict]:
    with connection() as conn, conn.cursor() as cur:
        cur.execute(
            "select * from correlation_links where security_alert_id = %s",
            (alert_id,),
        )
        return list(cur.fetchall())


def _fetch_uplift_events() -> list[dict]:
    with connection() as conn, conn.cursor() as cur:
        cur.execute(
            "select * from evidence_events where action = 'correlation.severity_uplift'",
        )
        return list(cur.fetchall())


def _fetch_dlp_event(event_id: str) -> dict | None:
    with connection() as conn, conn.cursor() as cur:
        cur.execute(
            "select * from dlp_events where id = %s",
            (event_id,),
        )
        return cur.fetchone()


def test_dlp_then_edr_same_sha256_uplifts_severity(tenant_hierarchy_factory) -> None:
    """Forward path: DLP event exists before EDR detection; EDR alert is uplifted."""
    agent_id = "agent-corr-dlp-fwd-001"
    tenant = tenant_hierarchy_factory(endpoint_id=agent_id)
    shared_hash = "d" * 64
    customer_id = tenant["customer_id"]

    _persist_dlp_event(
        customer_id=customer_id,
        endpoint_id=agent_id,
        sha256_hash=shared_hash,
    )

    edr_time = datetime.now(UTC).replace(microsecond=0) + timedelta(seconds=2)
    edr_event = EdrEvent(
        kind="yara_match",
        rule_id="SensitiveFileDLP",
        action="monitor",
        file_path="/data/secrets.txt",
        file_sha256=shared_hash,
        matched_indicator="DLP_CORR_MATCH",
        policy_version="policy-v1",
        collected_at=edr_time.isoformat(),
    )
    _post_heartbeat(agent_id=agent_id, nonce=1, collected_at=edr_time, edr_events=[edr_event])

    alert = _fetch_alert(agent_id)
    assert alert["severity"] == "critical", "high yara_match should uplift to critical when DLP joins via sha256"
    assert alert["severity_uplifted_from"] == "high"
    payload_json = alert["payload"]
    assert payload_json.get("correlation", {}).get("uplifted_from") == "high"

    links = _fetch_links(alert["id"])
    assert len(links) >= 1
    dlp_links = [l for l in links if l["related_kind"] == "dlp_event"]
    assert len(dlp_links) == 1, "expected exactly one DLP correlation link"
    assert dlp_links[0]["correlation_type"] == "sha256_match"
    assert dlp_links[0]["evidence"]["sha256_hash"] == shared_hash

    uplift_events = _fetch_uplift_events()
    assert len(uplift_events) == 1
    payload = uplift_events[0]["payload"]
    related = payload.get("related", [])
    assert any(r["kind"] == "dlp_event" for r in related)


def test_edr_then_dlp_same_sha256_uplifts_existing_alert(tenant_hierarchy_factory) -> None:
    """Reverse path: EDR alert exists before DLP event; DLP event triggers uplift."""
    agent_id = "agent-corr-dlp-rev-001"
    tenant = tenant_hierarchy_factory(endpoint_id=agent_id)
    shared_hash = "e" * 64
    customer_id = tenant["customer_id"]

    edr_time = datetime.now(UTC).replace(microsecond=0)
    edr_event = EdrEvent(
        kind="yara_match",
        rule_id="ExistingAlert",
        action="monitor",
        file_path="/tmp/sensitive.doc",
        file_sha256=shared_hash,
        matched_indicator="EXISTING",
        policy_version="policy-v1",
        collected_at=edr_time.isoformat(),
    )
    _post_heartbeat(agent_id=agent_id, nonce=1, collected_at=edr_time, edr_events=[edr_event])

    alert_before = _fetch_alert(agent_id)
    assert alert_before["severity"] == "high"
    assert alert_before["severity_uplifted_from"] is None

    dlp_time = edr_time + timedelta(seconds=45)
    _persist_dlp_event(
        customer_id=customer_id,
        endpoint_id=agent_id,
        sha256_hash=shared_hash,
        source="e2e-reverse-scan",
    )

    alert_after = _fetch_alert(agent_id)
    assert alert_after["severity"] == "critical", "existing EDR alert should uplift when DLP matches via sha256"
    assert alert_after["severity_uplifted_from"] == "high"
    payload = alert_after["payload"]
    assert payload["correlation"]["uplifted_from"] == "high"

    links = _fetch_links(alert_after["id"])
    dlp_links = [l for l in links if l["related_kind"] == "dlp_event"]
    assert len(dlp_links) >= 1, "expected at least one DLP correlation link in reverse direction"
    assert dlp_links[0]["correlation_type"] == "sha256_match"

    uplift_events = _fetch_uplift_events()
    assert len(uplift_events) == 1


def test_different_sha256_does_not_sha256_correlate(tenant_hierarchy_factory) -> None:
    """Negative: different SHA-256 on DLP vs EDR should NOT produce a sha256_match link,
    though endpoint_proximity may still apply."""
    agent_id = "agent-corr-dlp-neg-001"
    tenant = tenant_hierarchy_factory(endpoint_id=agent_id)

    _persist_dlp_event(
        customer_id=tenant["customer_id"],
        endpoint_id=agent_id,
        sha256_hash="a" * 64,
        source="e2e-neg-scan",
    )

    edr_time = datetime.now(UTC).replace(microsecond=0)
    edr_event = EdrEvent(
        kind="yara_match",
        rule_id="NoMatch",
        action="monitor",
        file_path="/tmp/unrelated.exe",
        file_sha256="b" * 64,
        matched_indicator="NO_MATCH",
        policy_version="policy-v1",
        collected_at=edr_time.isoformat(),
    )
    _post_heartbeat(agent_id=agent_id, nonce=1, collected_at=edr_time, edr_events=[edr_event])

    alert = _fetch_alert(agent_id)
    links = _fetch_links(alert["id"])
    sha256_links = [l for l in links if l["correlation_type"] == "sha256_match"]
    prox_links = [l for l in links if l["correlation_type"] == "endpoint_proximity"]
    assert sha256_links == [], "different sha256 should NOT produce sha256_match links"
    assert len(prox_links) >= 1, "same endpoint should still have endpoint_proximity link"


def test_different_endpoint_does_not_correlate(tenant_hierarchy_factory) -> None:
    """Negative: DLP on one endpoint should not correlate with EDR on another."""
    agent_id_edr = "agent-corr-dlp-x-endpoint-edr"
    agent_id_dlp = "agent-corr-dlp-x-endpoint-dlp"
    shared_hash = "f" * 64

    tenant_edr = tenant_hierarchy_factory(endpoint_id=agent_id_edr)
    tenant_hierarchy_factory(endpoint_id=agent_id_dlp)

    _persist_dlp_event(
        customer_id=tenant_edr["customer_id"],
        endpoint_id=agent_id_dlp,
        sha256_hash=shared_hash,
        source="e2e-x-endpoint-scan",
    )

    edr_time = datetime.now(UTC).replace(microsecond=0)
    edr_event = EdrEvent(
        kind="yara_match",
        rule_id="CrossEndpoint",
        action="monitor",
        file_path="/tmp/cross.exe",
        file_sha256=shared_hash,
        matched_indicator="CROSS_ENDPOINT",
        policy_version="policy-v1",
        collected_at=edr_time.isoformat(),
    )
    _post_heartbeat(agent_id=agent_id_edr, nonce=1, collected_at=edr_time, edr_events=[edr_event])

    alert = _fetch_alert(agent_id_edr)
    assert alert["severity"] == "high", "cross-endpoint DLP should NOT uplift EDR"
    assert alert["severity_uplifted_from"] is None
    assert _fetch_uplift_events() == []


def test_outside_window_does_not_uplift(tenant_hierarchy_factory, monkeypatch) -> None:
    """Negative: EDR alert created far in the past, DLP at now, outside window."""
    monkeypatch.setenv("AETHERIX_CORRELATION_WINDOW_SECONDS", "60")
    agent_id = "agent-corr-dlp-window-001"
    tenant = tenant_hierarchy_factory(endpoint_id=agent_id)
    shared_hash = "g" * 64

    edr_time = datetime.now(UTC).replace(microsecond=0) - timedelta(seconds=600)
    edr_event = EdrEvent(
        kind="yara_match",
        rule_id="LateWindow",
        action="monitor",
        file_path="/tmp/late.exe",
        file_sha256=shared_hash,
        matched_indicator="LATE_WINDOW",
        policy_version="policy-v1",
        collected_at=edr_time.isoformat(),
    )
    _post_heartbeat(agent_id=agent_id, nonce=1, collected_at=edr_time, edr_events=[edr_event])

    alert_before = _fetch_alert(agent_id)
    assert alert_before["severity"] == "high"

    _persist_dlp_event(
        customer_id=tenant["customer_id"],
        endpoint_id=agent_id,
        sha256_hash=shared_hash,
        source="e2e-window-scan",
    )

    alert_after = _fetch_alert(agent_id)
    assert alert_after["severity"] == "high", "EDR outside window should NOT uplift"
    assert alert_after["severity_uplifted_from"] is None
    assert _fetch_links(alert_after["id"]) == []
    assert _fetch_uplift_events() == []


def test_dlp_no_sha256_still_proximity_correlates(tenant_hierarchy_factory) -> None:
    """DLP event without sha256_hash should still create endpoint_proximity link."""
    agent_id = "agent-corr-dlp-nohash-001"
    tenant = tenant_hierarchy_factory(endpoint_id=agent_id)

    _persist_dlp_event(
        customer_id=tenant["customer_id"],
        endpoint_id=agent_id,
        sha256_hash=None,  # type: ignore[arg-type]
        source="e2e-nohash-scan",
    )

    edr_time = datetime.now(UTC).replace(microsecond=0)
    edr_event = EdrEvent(
        kind="yara_match",
        rule_id="NoHashDLP",
        action="monitor",
        file_path="/tmp/nohash.exe",
        file_sha256="h" * 64,
        matched_indicator="NO_HASH_DLP",
        policy_version="policy-v1",
        collected_at=edr_time.isoformat(),
    )
    _post_heartbeat(agent_id=agent_id, nonce=1, collected_at=edr_time, edr_events=[edr_event])

    alert = _fetch_alert(agent_id)
    links = _fetch_links(alert["id"])
    sha256_links = [l for l in links if l["correlation_type"] == "sha256_match"]
    prox_links = [l for l in links if l["correlation_type"] == "endpoint_proximity"]
    assert sha256_links == [], "DLP without sha256 should NOT produce sha256_match"
    assert len(prox_links) >= 1, "same endpoint should still have endpoint_proximity link"


def test_dlp_correlations_endpoint_returns_links(tenant_hierarchy_factory, auth_headers) -> None:
    """API: GET /dlp-events/{dlp_event_id}/correlations returns linked security alerts."""
    agent_id = "agent-corr-dlp-api-001"
    tenant = tenant_hierarchy_factory(endpoint_id=agent_id)
    shared_hash = "i" * 64
    customer_id = tenant["customer_id"]

    edr_time = datetime.now(UTC).replace(microsecond=0)
    edr_event = EdrEvent(
        kind="yara_match",
        rule_id="ApiTestRule",
        action="monitor",
        file_path="/tmp/api-test.exe",
        file_sha256=shared_hash,
        matched_indicator="API_TEST",
        policy_version="policy-v1",
        collected_at=edr_time.isoformat(),
    )
    _post_heartbeat(agent_id=agent_id, nonce=1, collected_at=edr_time, edr_events=[edr_event])

    alert = _fetch_alert(agent_id)
    assert alert["severity"] == "high"

    dlp_event_id = _persist_dlp_event(
        customer_id=customer_id,
        endpoint_id=agent_id,
        sha256_hash=shared_hash,
        source="e2e-api-scan",
    )

    alert_after = _fetch_alert(agent_id)
    assert alert_after["severity"] == "critical"

    client = TestClient(app)
    admin_id = tenant["company_admin_id"]
    headers = auth_headers(admin_id)
    resp = client.get(f"/dlp-events/{dlp_event_id}/correlations", headers=headers)
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["dlp_event_id"] == dlp_event_id
    assert body["total_correlations"] >= 1
    link = body["correlations"][0]
    assert link["security_alert_id"] == str(alert["id"])
    assert link["correlation_type"] == "sha256_match"
    assert link["alert_severity"] == "critical"


def test_dlp_endpoint_proximity_without_sha256_match(tenant_hierarchy_factory) -> None:
    """Temporal proximity: DLP on same endpoint creates endpoint_proximity link even when sha256 differs."""
    agent_id = "agent-corr-dlp-prox-001"
    tenant = tenant_hierarchy_factory(endpoint_id=agent_id)
    customer_id = tenant["customer_id"]

    _persist_dlp_event(
        customer_id=customer_id,
        endpoint_id=agent_id,
        sha256_hash="a" * 64,  # Different from EDR
    )

    edr_time = datetime.now(UTC).replace(microsecond=0)
    edr_event = EdrEvent(
        kind="yara_match",
        rule_id="ProxMatch",
        action="monitor",
        file_path="/tmp/prox-test.exe",
        file_sha256="b" * 64,  # Different from DLP
        matched_indicator="PROX_TEST",
        policy_version="policy-v1",
        collected_at=edr_time.isoformat(),
    )
    _post_heartbeat(agent_id=agent_id, nonce=1, collected_at=edr_time, edr_events=[edr_event])

    alert = _fetch_alert(agent_id)
    links = _fetch_links(alert["id"])
    prox_links = [l for l in links if l["correlation_type"] == "endpoint_proximity"]
    assert len(prox_links) >= 1, "expected at least one endpoint_proximity link"
    assert prox_links[0]["related_kind"] == "dlp_event"

    uplift_events = _fetch_uplift_events()
    assert len(uplift_events) == 1


def test_dlp_endpoint_proximity_not_cross_endpoint(tenant_hierarchy_factory) -> None:
    """Negative: DLP on one endpoint should NOT create endpoint_proximity link for EDR on another."""
    agent_id_edr = "agent-corr-dlp-prox-x-edr"
    agent_id_dlp = "agent-corr-dlp-prox-x-dlp"

    tenant_edr = tenant_hierarchy_factory(endpoint_id=agent_id_edr)
    tenant_hierarchy_factory(endpoint_id=agent_id_dlp)

    _persist_dlp_event(
        customer_id=tenant_edr["customer_id"],
        endpoint_id=agent_id_dlp,
        sha256_hash="c" * 64,
    )

    edr_time = datetime.now(UTC).replace(microsecond=0)
    edr_event = EdrEvent(
        kind="yara_match",
        rule_id="CrossEndpointProx",
        action="monitor",
        file_path="/tmp/prox-cross.exe",
        file_sha256="d" * 64,
        matched_indicator="PROX_CROSS",
        policy_version="policy-v1",
        collected_at=edr_time.isoformat(),
    )
    _post_heartbeat(agent_id=agent_id_edr, nonce=1, collected_at=edr_time, edr_events=[edr_event])

    alert = _fetch_alert(agent_id_edr)
    prox_links = [l for l in _fetch_links(alert["id"]) if l["correlation_type"] == "endpoint_proximity"]
    assert prox_links == [], "cross-endpoint DLP should NOT produce endpoint_proximity link"
    assert _fetch_uplift_events() == []


def test_dlp_edr_full_multimodal_pipeline(tenant_hierarchy_factory) -> None:
    """Comprehensive: DLP + FIM + EDR with sha256, file_path, and process_path all linking together."""
    agent_id = "agent-corr-full-001"
    tenant = tenant_hierarchy_factory(endpoint_id=agent_id)
    customer_id = tenant["customer_id"]
    shared_hash = "full-pipeline-hash-" + "0" * 46
    file_path = "/tmp/multimodal.exe"
    proc_path = "/usr/bin/loader"

    # 1. DLP event captures a sha256
    _persist_dlp_event(
        customer_id=customer_id,
        endpoint_id=agent_id,
        sha256_hash=shared_hash,
    )

    # 2. FIM event on the process_path
    fim_time = datetime.now(UTC).replace(microsecond=0)
    fim_event = FimEvent(
        event_type="modified",
        file_path=proc_path,
        sha256_hash="proc-" + shared_hash[4:],
        timestamp=fim_time.isoformat(),
    )
    _post_heartbeat(agent_id=agent_id, nonce=1, collected_at=fim_time, fim_events=[fim_event])

    # 3. EDR detection on the file_path with the shared sha256 + separate process_path
    edr_time = fim_time + timedelta(seconds=30)
    edr_event = EdrEvent(
        kind="yara_match",
        rule_id="FullPipeline",
        action="monitor",
        file_path=file_path,
        file_sha256=shared_hash,
        process_path=proc_path,
        matched_indicator="FULL_PIPELINE",
        policy_version="policy-v1",
        collected_at=edr_time.isoformat(),
    )
    _post_heartbeat(agent_id=agent_id, nonce=2, collected_at=edr_time, edr_events=[edr_event])

    alert = _fetch_alert(agent_id)
    assert alert["severity"] == "critical"
    assert alert["severity_uplifted_from"] == "high"

    links = _fetch_links(alert["id"])
    # We should have: sha256_match (DLP), process_path_match (FIM), and maybe endpoint_proximity (DLP) or file_path_match
    ctypes = {l["correlation_type"] for l in links}
    assert "sha256_match" in ctypes, "sha256_match needed from DLP sha256 join"
    assert "process_path_match" in ctypes, "process_path_match needed from FIM process-path join"

    # The DLP link should be sha256_match (not endpoint_proximity) since the hash matched
    dlp_links = [l for l in links if l["related_kind"] == "dlp_event"]
    assert all(l["correlation_type"] == "sha256_match" for l in dlp_links), \
        "dlp_event links should be sha256_match when hash matches"

    uplift_events = _fetch_uplift_events()
    assert len(uplift_events) == 1
    direction = uplift_events[0]["payload"]["direction"]
    assert "edr" in direction
    assert "dlp" in direction

"""Tests for cross-module correlation (FIM ↔ EDR, file_path joins).

Covers the two execution orderings the agent can produce:

* FIM event observed before the EDR detection — verified through
  `correlate_new_edr_alert` (forward path) inside `state.upsert_heartbeat`.
* FIM event observed after the EDR detection — verified through
  `correlate_new_fim_event` (reverse path).

Each happy path asserts (a) the security_alerts row's severity is
uplifted one rung and `severity_uplifted_from` is set, (b) a
`correlation_links` row is recorded, (c) a `correlation.severity_uplift`
evidence event is written for the compliance trail. The negative cases
guard against accidental cross-agent/cross-path joins.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import uuid
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


def test_fim_then_edr_same_path_uplifts_severity(tenant_hierarchy_factory) -> None:
    agent_id = "agent-corr-fwd-001"
    tenant_hierarchy_factory(endpoint_id=agent_id)
    file_path = "/tmp/malicious.exe"

    fim_time = datetime.now(UTC).replace(microsecond=0)
    fim_event = FimEvent(event_type="modified", file_path=file_path, sha256_hash="a" * 64, timestamp=fim_time.isoformat())
    _post_heartbeat(agent_id=agent_id, nonce=1, collected_at=fim_time, fim_events=[fim_event])

    edr_time = fim_time + timedelta(seconds=30)
    edr_event = EdrEvent(
        kind="yara_match",
        rule_id="SuspiciousString",
        action="monitor",
        file_path=file_path,
        file_sha256="b" * 64,
        matched_indicator="AETHERIX_TEST_EICAR",
        policy_version="policy-v1",
        collected_at=edr_time.isoformat(),
    )
    _post_heartbeat(agent_id=agent_id, nonce=2, collected_at=edr_time, edr_events=[edr_event])

    alert = _fetch_alert(agent_id)
    assert alert["severity"] == "critical", "high yara_match should uplift to critical when FIM joins"
    assert alert["severity_uplifted_from"] == "high"
    payload = alert["payload"]
    assert payload.get("correlation", {}).get("uplifted_from") == "high"
    related = payload["correlation"]["related"]
    assert any(r["related_kind"] == "fim_event" for r in related)

    links = _fetch_links(alert["id"])
    assert len(links) == 1
    assert links[0]["correlation_type"] == "file_path_match"

    uplift_events = _fetch_uplift_events()
    assert len(uplift_events) == 1
    assert uplift_events[0]["resource"] == f"security_alert:{alert['id']}"


def test_edr_then_fim_same_path_uplifts_existing_alert(tenant_hierarchy_factory) -> None:
    agent_id = "agent-corr-rev-001"
    tenant_hierarchy_factory(endpoint_id=agent_id)
    file_path = "/var/www/app/wp-config.php"

    edr_time = datetime.now(UTC).replace(microsecond=0)
    edr_event = EdrEvent(
        kind="yara_match",
        rule_id="WPShellMarker",
        action="monitor",
        file_path=file_path,
        file_sha256="c" * 64,
        matched_indicator="AETHERIX_TEST_WPSHELL",
        policy_version="policy-v1",
        collected_at=edr_time.isoformat(),
    )
    _post_heartbeat(agent_id=agent_id, nonce=1, collected_at=edr_time, edr_events=[edr_event])

    alert_before = _fetch_alert(agent_id)
    assert alert_before["severity"] == "high"
    assert alert_before["severity_uplifted_from"] is None

    fim_time = edr_time + timedelta(seconds=45)
    fim_event = FimEvent(event_type="modified", file_path=file_path, sha256_hash="d" * 64, timestamp=fim_time.isoformat())
    _post_heartbeat(agent_id=agent_id, nonce=2, collected_at=fim_time, fim_events=[fim_event])

    alert_after = _fetch_alert(agent_id)
    assert alert_after["severity"] == "critical"
    assert alert_after["severity_uplifted_from"] == "high"
    payload = alert_after["payload"]
    assert payload["correlation"]["uplifted_from"] == "high"

    links = _fetch_links(alert_after["id"])
    assert len(links) == 1
    assert links[0]["related_kind"] == "fim_event"

    uplift_events = _fetch_uplift_events()
    assert len(uplift_events) == 1


def test_different_paths_do_not_correlate(tenant_hierarchy_factory) -> None:
    agent_id = "agent-corr-neg-001"
    tenant_hierarchy_factory(endpoint_id=agent_id)

    fim_time = datetime.now(UTC).replace(microsecond=0)
    fim_event = FimEvent(event_type="modified", file_path="/etc/passwd", sha256_hash=None, timestamp=fim_time.isoformat())
    _post_heartbeat(agent_id=agent_id, nonce=1, collected_at=fim_time, fim_events=[fim_event])

    edr_time = fim_time + timedelta(seconds=10)
    edr_event = EdrEvent(
        kind="yara_match",
        rule_id="UnrelatedRule",
        action="monitor",
        file_path="/tmp/unrelated.bin",
        file_sha256="e" * 64,
        matched_indicator="UNRELATED",
        policy_version="policy-v1",
        collected_at=edr_time.isoformat(),
    )
    _post_heartbeat(agent_id=agent_id, nonce=2, collected_at=edr_time, edr_events=[edr_event])

    alert = _fetch_alert(agent_id)
    assert alert["severity"] == "high"
    assert alert["severity_uplifted_from"] is None
    assert _fetch_links(alert["id"]) == []
    assert _fetch_uplift_events() == []


def test_outside_window_does_not_uplift(tenant_hierarchy_factory, monkeypatch) -> None:
    monkeypatch.setenv("AETHERIX_CORRELATION_WINDOW_SECONDS", "60")
    agent_id = "agent-corr-window-001"
    tenant_hierarchy_factory(endpoint_id=agent_id)
    file_path = "/tmp/window-test.exe"

    fim_time = datetime.now(UTC).replace(microsecond=0) - timedelta(seconds=600)
    fim_event = FimEvent(event_type="modified", file_path=file_path, sha256_hash=None, timestamp=fim_time.isoformat())
    _post_heartbeat(agent_id=agent_id, nonce=1, collected_at=fim_time, fim_events=[fim_event])

    edr_time = datetime.now(UTC).replace(microsecond=0)
    edr_event = EdrEvent(
        kind="yara_match",
        rule_id="LateRule",
        action="monitor",
        file_path=file_path,
        file_sha256="f" * 64,
        matched_indicator="LATE",
        policy_version="policy-v1",
        collected_at=edr_time.isoformat(),
    )
    _post_heartbeat(agent_id=agent_id, nonce=2, collected_at=edr_time, edr_events=[edr_event])

    alert = _fetch_alert(agent_id)
    assert alert["severity"] == "high"
    assert alert["severity_uplifted_from"] is None
    assert _fetch_links(alert["id"]) == []


def test_sha256_match_uplifts_with_different_path(tenant_hierarchy_factory) -> None:
    agent_id = "agent-corr-sha256-001"
    tenant_hierarchy_factory(endpoint_id=agent_id)
    shared_hash = "a" * 64

    fim_time = datetime.now(UTC).replace(microsecond=0)
    fim_path = "/tmp/renamed.exe"
    fim_event = FimEvent(
        event_type="modified",
        file_path=fim_path,
        sha256_hash=shared_hash,
        timestamp=fim_time.isoformat(),
    )
    _post_heartbeat(agent_id=agent_id, nonce=1, collected_at=fim_time, fim_events=[fim_event])

    edr_time = fim_time + timedelta(seconds=30)
    edr_event = EdrEvent(
        kind="yara_match",
        rule_id="ShaMatchRule",
        action="monitor",
        file_path="/different/path/renamed-copy.exe",
        file_sha256=shared_hash,
        matched_indicator="SHA256_MATCH",
        policy_version="policy-v1",
        collected_at=edr_time.isoformat(),
    )
    _post_heartbeat(agent_id=agent_id, nonce=2, collected_at=edr_time, edr_events=[edr_event])

    alert = _fetch_alert(agent_id)
    assert alert["severity"] == "critical", "sha256 match should uplift to critical"
    assert alert["severity_uplifted_from"] == "high"

    links = _fetch_links(alert["id"])
    assert len(links) == 1
    assert links[0]["correlation_type"] == "sha256_match"
    assert links[0]["evidence"]["sha256_hash"] == shared_hash

    uplift_events = _fetch_uplift_events()
    assert len(uplift_events) == 1


def test_sha256_match_reverse_uplifts_existing_alert(tenant_hierarchy_factory) -> None:
    agent_id = "agent-corr-sha256-rev-001"
    tenant_hierarchy_factory(endpoint_id=agent_id)
    shared_hash = "b" * 64

    edr_time = datetime.now(UTC).replace(microsecond=0)
    edr_event = EdrEvent(
        kind="yara_match",
        rule_id="ShaRevRule",
        action="monitor",
        file_path="/initial/alert-path.exe",
        file_sha256=shared_hash,
        matched_indicator="SHA256_REV",
        policy_version="policy-v1",
        collected_at=edr_time.isoformat(),
    )
    _post_heartbeat(agent_id=agent_id, nonce=1, collected_at=edr_time, edr_events=[edr_event])

    alert_before = _fetch_alert(agent_id)
    assert alert_before["severity"] == "high"

    fim_time = edr_time + timedelta(seconds=30)
    fim_path = "/later/seen-by-fim.exe"
    fim_event = FimEvent(
        event_type="added",
        file_path=fim_path,
        sha256_hash=shared_hash,
        timestamp=fim_time.isoformat(),
    )
    _post_heartbeat(agent_id=agent_id, nonce=2, collected_at=fim_time, fim_events=[fim_event])

    alert_after = _fetch_alert(agent_id)
    assert alert_after["severity"] == "critical"
    assert alert_after["severity_uplifted_from"] == "high"

    links = _fetch_links(alert_after["id"])
    assert len(links) >= 1
    sha_links = [l for l in links if l["correlation_type"] == "sha256_match"]
    assert len(sha_links) >= 1, "expected at least one sha256_match link in reverse direction"
    assert sha_links[0]["evidence"]["sha256_hash"] == shared_hash


def test_correlations_endpoint_returns_links(tenant_hierarchy_factory, auth_headers) -> None:
    agent_id = "agent-corr-api-001"
    tenant = tenant_hierarchy_factory(endpoint_id=agent_id)
    admin_id = tenant["company_admin_id"]
    file_path = "/srv/data/secrets.env"

    fim_time = datetime.now(UTC).replace(microsecond=0)
    fim_event = FimEvent(event_type="added", file_path=file_path, sha256_hash="1" * 64, timestamp=fim_time.isoformat())
    _post_heartbeat(agent_id=agent_id, nonce=1, collected_at=fim_time, fim_events=[fim_event])

    edr_time = fim_time + timedelta(seconds=15)
    edr_event = EdrEvent(
        kind="yara_match",
        rule_id="SecretsScan",
        action="monitor",
        file_path=file_path,
        file_sha256="2" * 64,
        matched_indicator="SECRETS",
        policy_version="policy-v1",
        collected_at=edr_time.isoformat(),
    )
    _post_heartbeat(agent_id=agent_id, nonce=2, collected_at=edr_time, edr_events=[edr_event])

    alert = _fetch_alert(agent_id)
    client = TestClient(app)
    headers = auth_headers(admin_id)
    resp = client.get(f"/security-alerts/{alert['id']}/correlations", headers=headers)
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["alert_id"] == str(alert["id"])
    assert body["severity"] == "critical"
    assert body["severity_uplifted_from"] == "high"
    assert len(body["correlations"]) == 1
    link = body["correlations"][0]
    assert link["related_kind"] == "fim_event"
    assert link["correlation_type"] == "file_path_match"
    assert link["evidence"]["file_path"] == file_path

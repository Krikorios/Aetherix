"""OpenSearch Data Streams + ILM integration for high-volume security events and logs.

This module manages tenant-scoped **Data Streams** (not regular indices) for
security telemetry (security_alerts, fim_events, dlp_events, future raw SIEM logs).

Key features:
- Automatic rollover via ILM
- Configurable retention through multiple ILM policies (30d / 90d / 365d / 7y)
- Proper @timestamp handling required by data streams
- Every document carries postgres_ref for verification against the authoritative chain

Design principles (see architecture.md §3.3.1):
- Postgres = source of truth + hash-chained compliance record
- OpenSearch Data Streams = scalable search + retention tier
- Graceful degradation: OpenSearch unavailability never affects primary flows

Environment:
    AETHERIX_OPENSEARCH_URL   e.g. http://localhost:9200 (dev) or https://...
"""

from __future__ import annotations

import json
import logging
import os
import threading
import time
from datetime import UTC, datetime
from typing import Any

from opensearchpy import OpenSearch, helpers
from opensearchpy.exceptions import OpenSearchException

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------
# Circuit Breaker & Resilient Error Handling
# ---------------------------------------------------------------------

class CircuitBreaker:
    def __init__(self, failure_threshold=3, recovery_timeout=60):
        self.failure_threshold = failure_threshold
        self.recovery_timeout = recovery_timeout
        self.failure_count = 0
        self.state = "CLOSED"  # CLOSED, OPEN, HALF-OPEN
        self.last_state_change = time.time()
        self.lock = threading.Lock()

    def record_success(self):
        with self.lock:
            self.failure_count = 0
            self.state = "CLOSED"

    def record_failure(self):
        with self.lock:
            self.failure_count += 1
            if self.failure_count >= self.failure_threshold:
                self.state = "OPEN"
                self.last_state_change = time.time()
                logger.warning("OpenSearch Circuit Breaker tripped to OPEN state")

    def allow_request(self) -> bool:
        with self.lock:
            if self.state == "CLOSED":
                return True
            elif self.state == "OPEN":
                if time.time() - self.last_state_change > self.recovery_timeout:
                    self.state = "HALF-OPEN"
                    self.last_state_change = time.time()
                    logger.info("OpenSearch Circuit Breaker entered HALF-OPEN state, probing...")
                    return True
                return False
            elif self.state == "HALF-OPEN":
                # Only allow one probe request at a time
                return False

_CIRCUIT_BREAKER = CircuitBreaker()

# ---------------------------------------------------------------------
# Client & configuration
# ---------------------------------------------------------------------

_CLIENT: OpenSearch | None = None
_ENABLED = False

# Data stream naming for tenant-isolated security events.
# Format: aetherix-events-{partner_id}-{customer_id}
# This becomes a Data Stream (not a regular index). Backing indices are managed automatically
# with names like .ds-aetherix-events-...-YYYY.MM.DD-000001
EVENTS_DATA_STREAM_PATTERN = "aetherix-events-{partner_id}-{customer_id}"

# Template and ILM names
EVENTS_INDEX_TEMPLATE_NAME = "aetherix-security-events"
ILM_POLICY_PREFIX = "aetherix-security-"


def is_enabled() -> bool:
    return _ENABLED and _CLIENT is not None


def get_client() -> OpenSearch | None:
    """Return the OpenSearch client if configured and reachable, else None."""
    global _CLIENT, _ENABLED

    if not _CIRCUIT_BREAKER.allow_request():
        return None

    if _CLIENT is not None:
        return _CLIENT

    url = os.getenv("AETHERIX_OPENSEARCH_URL")
    if not url:
        logger.debug("AETHERIX_OPENSEARCH_URL not set — OpenSearch integration disabled")
        _ENABLED = False
        return None

    try:
        client = OpenSearch(
            hosts=[url],
            use_ssl=url.startswith("https"),
            verify_certs=not url.startswith("http://localhost"),
            ssl_show_warn=False,
            timeout=3,  # Short timeout to avoid blocking primary writes!
        )
        # Quick health probe (non-fatal)
        client.cluster.health(request_timeout=2)
        _CLIENT = client
        _ENABLED = True
        _CIRCUIT_BREAKER.record_success()
        logger.info("OpenSearch client initialized successfully at %s", url)
        return _CLIENT
    except Exception as exc:  # noqa: BLE001
        logger.warning("Failed to initialize OpenSearch client at %s: %s", url, exc)
        _CLIENT = None
        _ENABLED = False
        _CIRCUIT_BREAKER.record_failure()
        return None


# ---------------------------------------------------------------------
# ILM Policies + Data Stream Index Template (modern best practice)
# ---------------------------------------------------------------------

def _create_ilm_policy(client: OpenSearch, policy_name: str, delete_after_days: int) -> None:
    """Create or update a simple ILM policy for security events."""
    policy = {
        "policy": {
            "description": f"Aetherix security events retention policy ({delete_after_days} days)",
            "phases": {
                "hot": {
                    "min_age": "0ms",
                    "actions": {
                        "rollover": {
                            "max_primary_shard_size": "25gb",
                            "max_age": "1d",
                            "max_docs": 10000000,
                        },
                        "set_priority": {"priority": 100},
                    },
                },
                "warm": {
                    "min_age": "0d",  # Move to warm immediately after rollover
                    "actions": {
                        "readonly": {},
                        "set_priority": {"priority": 50},
                    },
                },
                "delete": {
                    "min_age": f"{delete_after_days}d",
                    "actions": {"delete": {}},
                },
            },
        }
    }

    try:
        client.ilm.put_lifecycle(policy=policy_name, body=policy)
        logger.debug("ILM policy %s ensured (delete after %sd)", policy_name, delete_after_days)
    except OpenSearchException as exc:
        logger.warning("Failed to create ILM policy %s: %s", policy_name, exc)


def ensure_ilm_policies() -> None:
    """Create the standard set of ILM policies used by Aetherix event data streams."""
    client = get_client()
    if not client:
        return

    # Common retention tiers (can be selected per customer in the future)
    policies = [
        ("aetherix-security-30d", 30),
        ("aetherix-security-90d", 90),
        ("aetherix-security-365d", 365),
        ("aetherix-security-7y", 2555),  # ~7 years
    ]

    for name, days in policies:
        _create_ilm_policy(client, name, days)


def ensure_templates() -> None:
    """
    Ensure ILM policies + the modern index template for security event data streams.

    We use the new composable-style index template API + explicit data_stream: {}.
    All customer data streams matching aetherix-events-* will use this template.
    """
    client = get_client()
    if not client:
        return

    # 1. Make sure our ILM policies exist first
    ensure_ilm_policies()

    # Default policy for new data streams (can be overridden later per customer)
    default_ilm_policy = "aetherix-security-90d"

    template_body = {
        "index_patterns": ["aetherix-events-*"],
        "data_stream": {},   # This makes matching indices into Data Streams
        "template": {
            "settings": {
                "number_of_shards": 1,
                "number_of_replicas": 0,           # Dev default
                "index.refresh_interval": "5s",
                "index.lifecycle.name": default_ilm_policy,
                "index.lifecycle.rollover_alias": None,  # Not needed with data streams
            },
            "mappings": {
                "dynamic": "strict",
                "_source": {"enabled": True},
                "properties": {
                    # Primary time field required/recommended for Data Streams
                    "@timestamp": {"type": "date", "format": "strict_date_optional_time||epoch_millis"},

                    # Tenant & scope (mandatory for isolation + routing)
                    "partner_id": {"type": "keyword"},
                    "customer_id": {"type": "keyword"},
                    "group_id": {"type": "keyword"},
                    "endpoint_id": {"type": "keyword"},

                    # Core event metadata
                    "event_type": {"type": "keyword"},
                    "module": {"type": "keyword"},
                    "detector_id": {"type": "keyword"},
                    "policy_version": {"type": "keyword"},
                    "severity": {"type": "keyword"},
                    "category": {"type": "keyword"},
                    "timestamp": {"type": "date"},   # keep for compatibility

                    # Compliance & correlation
                    "evidence_controls": {"type": "keyword"},
                    "mitre_tactics": {"type": "keyword"},
                    "mitre_techniques": {"type": "keyword"},

                    # Back-reference to authoritative Postgres record
                    "postgres_ref": {
                        "properties": {
                            "table": {"type": "keyword"},
                            "id": {"type": "keyword"},
                            "seq": {"type": "long"},
                            "chain_hash": {"type": "keyword"},
                        }
                    },

                    "payload": {"type": "object", "enabled": True},
                    "raw": {"type": "object", "enabled": False},
                },
            },
        },
        "priority": 200,
        "version": 2,
        "_meta": {
            "description": "Aetherix security events data stream template with ILM",
            "managed_by": "aetherix-platform",
        },
    }

    try:
        client.indices.put_index_template(
            name=EVENTS_INDEX_TEMPLATE_NAME,
            body=template_body
        )
        logger.info("OpenSearch data stream index template %s ensured (ILM: %s)",
                    EVENTS_INDEX_TEMPLATE_NAME, default_ilm_policy)
    except OpenSearchException as exc:
        logger.warning("Failed to put data stream index template %s: %s",
                       EVENTS_INDEX_TEMPLATE_NAME, exc)


# ---------------------------------------------------------------------
# Core indexing API
# ---------------------------------------------------------------------

def _build_data_stream_name(partner_id: str | None, customer_id: str | None) -> str:
    """Return the tenant-scoped data stream name for security events."""
    pid = (partner_id or "unknown").replace("-", "_")
    cid = (customer_id or "unknown").replace("-", "_")
    return f"aetherix-events-{pid}-{cid}"


# ---------------------------------------------------------------------
# Dynamic ILM policy selection per customer (retention settings)
# ---------------------------------------------------------------------

RETENTION_TO_POLICY: dict[int, str] = {
    30: "aetherix-security-30d",
    90: "aetherix-security-90d",
    365: "aetherix-security-365d",
    2555: "aetherix-security-7y",   # ~7 years
}

DEFAULT_RETENTION_DAYS = 90
DEFAULT_ILM_POLICY = "aetherix-security-90d"


def retention_days_to_ilm_policy(days: int | None) -> str:
    """Map a retention period in days to the closest standard ILM policy."""
    if not days or days <= 0:
        return DEFAULT_ILM_POLICY

    # Find the smallest policy that is >= requested retention
    sorted_days = sorted(RETENTION_TO_POLICY.keys())
    for d in sorted_days:
        if days <= d:
            return RETENTION_TO_POLICY[d]

    return RETENTION_TO_POLICY[sorted_days[-1]]


def get_customer_event_retention_days(customer_id: str | UUID | None) -> int | None:
    """
    Look up the configured event retention (in days) for a customer.
    Returns None if not set (will use default).
    """
    if not customer_id:
        return None

    try:
        from app.db import connection
        from uuid import UUID as _UUID

        cid = _UUID(str(customer_id))
        with connection() as conn, conn.cursor() as cur:
            cur.execute(
                "SELECT event_retention_days FROM customers WHERE id = %s",
                (cid,),
            )
            row = cur.fetchone()
            if row and row.get("event_retention_days") is not None:
                return int(row["event_retention_days"])
    except Exception as exc:  # noqa: BLE001
        logger.debug("Could not load event_retention_days for customer %s: %s", customer_id, exc)

    return None


def resolve_ilm_policy_for_customer(customer_id: str | UUID | None) -> str:
    """Resolve the correct ILM policy name for a given customer's retention settings."""
    days = get_customer_event_retention_days(customer_id)
    return retention_days_to_ilm_policy(days)


def ensure_data_stream_ilm_policy(data_stream_name: str, policy_name: str) -> None:
    """
    Ensure the given data stream's current write index is using the desired ILM policy.
    This allows per-customer dynamic retention without changing the global template.
    """
    client = get_client()
    if not client:
        return

    try:
        # Make sure the data stream exists (safe if it already does)
        try:
            client.indices.create_data_stream(name=data_stream_name)
        except Exception:
            pass  # Already exists or will be created on first index

        # Get the current write index for this data stream
        ds_info = client.indices.get_data_stream(name=data_stream_name)
        streams = ds_info.get("data_streams", [])
        if not streams:
            return

        write_index = streams[0].get("write_index")
        if not write_index:
            return

        # Update the write index to use the correct ILM policy
        client.indices.put_settings(
            index=write_index,
            body={
                "index": {
                    "lifecycle.name": policy_name,
                }
            },
        )
        logger.debug("Set ILM policy %s on data stream %s (write_index=%s)",
                     policy_name, data_stream_name, write_index)

    except OpenSearchException as exc:
        logger.warning("Failed to ensure ILM policy %s on %s: %s",
                       policy_name, data_stream_name, exc)


def index_event(
    *,
    partner_id: str | None,
    customer_id: str | None,
    endpoint_id: str | None = None,
    event_type: str,
    module: str | None = None,
    detector_id: str | None = None,
    policy_version: str | None = None,
    severity: str | None = None,
    category: str | None = None,
    timestamp: datetime | None = None,
    evidence_controls: list[str] | None = None,
    mitre_tactics: list[str] | None = None,
    mitre_techniques: list[str] | None = None,
    payload: dict[str, Any] | None = None,
    postgres_ref: dict[str, Any] | None = None,
    raw: dict[str, Any] | None = None,
) -> bool:
    """
    Index one security-related event into the tenant-scoped OpenSearch index.

    Returns True if the document was accepted by OpenSearch (or if OpenSearch
    is disabled / unreachable — we degrade gracefully).
    """
    client = get_client()
    if not client:
        return False

    ts = timestamp or datetime.now(UTC)
    ts_iso = ts.isoformat()

    doc = {
        "@timestamp": ts_iso,                    # Required for Data Streams time-series behavior
        "timestamp": ts_iso,                     # Kept for compatibility with existing queries
        "partner_id": partner_id,
        "customer_id": customer_id,
        "group_id": None,
        "endpoint_id": endpoint_id,
        "event_type": event_type,
        "module": module,
        "detector_id": detector_id,
        "policy_version": policy_version,
        "severity": severity,
        "category": category,
        "evidence_controls": evidence_controls or [],
        "mitre_tactics": mitre_tactics or [],
        "mitre_techniques": mitre_techniques or [],
        "payload": payload or {},
        "postgres_ref": postgres_ref or {},
        "raw": raw,
    }

    data_stream = _build_data_stream_name(partner_id, customer_id)

    # Dynamic per-customer ILM (based on event_retention_days)
    try:
        ilm_policy = resolve_ilm_policy_for_customer(customer_id)
        ensure_data_stream_ilm_policy(data_stream, ilm_policy)
    except Exception:  # noqa: BLE001 - never break indexing because of ILM management
        pass

    retries = 2
    for attempt in range(retries):
        try:
            # When the matching index template has "data_stream": {}, this call creates/uses
            # a Data Stream instead of a regular index.
            client.index(
                index=data_stream,
                id=None,
                body=doc,
                refresh=False,
                request_timeout=2,  # Short timeout to avoid blocking primary writes
            )
            _CIRCUIT_BREAKER.record_success()
            return True
        except OpenSearchException as exc:
            if attempt == retries - 1:
                logger.warning(
                    "OpenSearch index failed after %d attempts for event_type=%s customer=%s: %s",
                    retries,
                    event_type,
                    customer_id,
                    exc,
                )
                _CIRCUIT_BREAKER.record_failure()
                global _CLIENT
                _CLIENT = None
                return False
            time.sleep(0.05)  # Quick backoff

    return False


def bulk_index_events(events: list[dict[str, Any]]) -> int:
    """
    Bulk index a list of pre-built documents.
    Each document must contain at minimum: partner_id, customer_id, and the rest of the shape.
    Returns number of successfully indexed documents.
    """
    client = get_client()
    if not client or not events:
        return 0

    actions = []
    for ev in events:
        partner_id = ev.get("partner_id")
        customer_id = ev.get("customer_id")
        if not partner_id or not customer_id:
            continue
        ds_name = _build_data_stream_name(partner_id, customer_id)
        actions.append({
            "_index": ds_name,
            "_source": ev,
        })

    if not actions:
        return 0

    try:
        success, _ = helpers.bulk(client, actions, raise_on_error=False, request_timeout=5)
        _CIRCUIT_BREAKER.record_success()
        return success
    except Exception as exc:  # noqa: BLE001
        logger.warning("OpenSearch bulk index failed: %s", exc)
        _CIRCUIT_BREAKER.record_failure()
        global _CLIENT
        _CLIENT = None
        return 0


# ---------------------------------------------------------------------
# Convenience helpers for common Aetherix event types
# ---------------------------------------------------------------------

def index_security_alert(
    *,
    partner_id: str | None,
    customer_id: str | None,
    agent_id: str,
    alert_id: str,
    severity: str,
    category: str,
    payload: dict[str, Any],
    evidence_controls: list[str],
    created_at: datetime,
    postgres_seq: int | None = None,
    chain_hash: str | None = None,
) -> bool:
    """Convenience wrapper for security_alerts rows."""
    return index_event(
        partner_id=partner_id,
        customer_id=customer_id,
        endpoint_id=agent_id,
        event_type="security_alert",
        module="edr",
        severity=severity,
        category=category,
        timestamp=created_at,
        evidence_controls=evidence_controls,
        payload=payload,
        postgres_ref={
            "table": "security_alerts",
            "id": str(alert_id),
            "seq": postgres_seq,
            "chain_hash": chain_hash,
        },
    )


def index_fim_event(
    *,
    partner_id: str | None,
    customer_id: str | None,
    agent_id: str,
    fim_event_id: str,
    event_type: str,
    file_path: str,
    sha256_hash: str | None,
    observed_at: datetime,
    evidence_controls: list[str] | None = None,
) -> bool:
    """Convenience wrapper for fim_events rows (from agent heartbeats)."""
    payload = {
        "file_path": file_path,
        "sha256_hash": sha256_hash,
        "event_type": event_type,
    }
    return index_event(
        partner_id=partner_id,
        customer_id=customer_id,
        endpoint_id=agent_id,
        event_type="fim_event",
        module="fim",
        severity="info",   # FIM is usually informational unless correlated
        category="file_integrity",
        timestamp=observed_at,
        evidence_controls=evidence_controls or [],
        payload=payload,
        postgres_ref={
            "table": "fim_events",
            "id": str(fim_event_id),
        },
    )


def index_dlp_event(
    *,
    partner_id: str | None,
    customer_id: str | None,
    endpoint_id: str | None,
    dlp_event_id: str,
    source: str,
    action: str,
    entity_types: list[str] | None,
    risk_band: str | None,
    sha256_hash: str | None,
    observed_at: datetime,
    evidence_controls: list[str] | None = None,
) -> bool:
    """Convenience wrapper for dlp_events (from /dlp/scan and future agent DLP)."""
    payload = {
        "source": source,
        "action": action,
        "entity_types": entity_types or [],
        "risk_band": risk_band,
        "sha256_hash": sha256_hash,
    }
    return index_event(
        partner_id=partner_id,
        customer_id=customer_id,
        endpoint_id=endpoint_id,
        event_type="dlp_event",
        module="dlp",
        severity=risk_band or "medium",
        category="data_loss_prevention",
        timestamp=observed_at,
        evidence_controls=evidence_controls or [],
        payload=payload,
        postgres_ref={
            "table": "dlp_events",
            "id": str(dlp_event_id),
        },
    )


# ---------------------------------------------------------------------
# Search helpers (read path)
# ---------------------------------------------------------------------

def search_events(
    *,
    customer_id: str,
    query: dict[str, Any] | None = None,
    size: int = 50,
    from_: int = 0,
) -> dict[str, Any]:
    """
    Simple tenant-scoped search against the customer's security events **data stream**.
    `query` is a raw OpenSearch query body.
    Searching a data stream name works the same as a regular index/alias.
    """
    client = get_client()
    if not client:
        return {"error": "opensearch_not_available"}

    # Searching the data stream (or wildcard over multiple customer streams) works directly
    index_pattern = f"aetherix-events-*-{customer_id.replace('-', '_')}"

    body: dict[str, Any] = {
        "query": query or {"match_all": {}},
        "size": min(size, 200),
        "from": from_,
        "sort": [{"timestamp": {"order": "desc"}}],
    }

    try:
        return client.search(index=index_pattern, body=body)
    except OpenSearchException as exc:
        logger.warning("OpenSearch search failed for customer=%s: %s", customer_id, exc)
        return {"error": str(exc)}


# Future: index_fim_event, index_dlp_event, index_evidence_event, etc. can be added here.


def warmup() -> None:
    """Call once at application startup to initialize client, ILM policies, and data stream templates."""
    client = get_client()
    if client:
        ensure_templates()   # This now also ensures ILM policies
        logger.info("OpenSearch data stream + ILM integration warmed up")
    else:
        logger.info("OpenSearch integration not configured (AETHERIX_OPENSEARCH_URL missing)")
"""Ecosystem connector state.

The catalog of available connectors (id, name, category, description, icon,
required config field names) is a code constant. Per-connector runtime state
— status, encrypted config payload, last sync timestamp, last error — is
persisted in the ``integrations`` table.

Credentials are encrypted at rest with Fernet via the same key infrastructure
used by ``app.services.ai_settings`` so we don't need to manage a second
secret. Config payloads are stored as canonical JSON ciphertext; only a SHA-256
fingerprint of the field-name set is stored in plaintext (for diagnostics).
"""

from __future__ import annotations

import hashlib
import json
import logging
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Mapping
from uuid import UUID

from app.db import connection
from app.schemas import Connector
from app.services.ai_settings import _fernet  # reuse Fernet bootstrap

LOGGER = logging.getLogger(__name__)


class IntegrationError(Exception):
    """Domain error for connector configure/disconnect failures."""


@dataclass(frozen=True)
class ConnectorTemplate:
    id: str
    name: str
    category: str
    description: str
    icon_emoji: str
    config_fields: tuple[str, ...]


CATALOG: tuple[ConnectorTemplate, ...] = (
    ConnectorTemplate(
        id="connectwise",
        name="ConnectWise Manage",
        category="psa",
        description="Sync tickets, companies, and contacts from Aetherix incidents.",
        icon_emoji="CW",
        config_fields=("api_url", "company_id", "public_key", "private_key"),
    ),
    ConnectorTemplate(
        id="datto",
        name="Datto RMM",
        category="rmm",
        description="Pull endpoint inventory and push remediation scripts.",
        icon_emoji="DR",
        config_fields=("api_url", "api_key", "secret_key"),
    ),
    ConnectorTemplate(
        id="splunk",
        name="Splunk",
        category="siem",
        description="Forward Aetherix events to Splunk HEC.",
        icon_emoji="SI",
        config_fields=("hec_url", "hec_token", "index"),
    ),
    ConnectorTemplate(
        id="sentinel",
        name="Microsoft Sentinel",
        category="siem",
        description="Stream events and alerts to Microsoft Sentinel.",
        icon_emoji="MS",
        config_fields=(
            "workspace_id",
            "dce_endpoint",
            "dcr_id",
            "tenant_id",
            "client_id",
            "client_secret",
        ),
    ),
    ConnectorTemplate(
        id="entra",
        name="Microsoft Entra ID",
        category="identity",
        description="Resolve user identities and risk signals.",
        icon_emoji="ID",
        config_fields=("tenant_id", "client_id", "client_secret"),
    ),
    ConnectorTemplate(
        id="stripe",
        name="Stripe",
        category="billing",
        description="Sync usage metering for automated MSP billing.",
        icon_emoji="ST",
        config_fields=("secret_key", "meter_event_name", "customer_id_mapping"),
    ),
)


_CATALOG_BY_ID: dict[str, ConnectorTemplate] = {c.id: c for c in CATALOG}


def _template(connector_id: str) -> ConnectorTemplate:
    template = _CATALOG_BY_ID.get(connector_id)
    if template is None:
        raise IntegrationError(f"connector '{connector_id}' is not registered")
    return template


def _encrypt(payload: Mapping[str, str]) -> tuple[bytes, str]:
    canonical = json.dumps(dict(payload), sort_keys=True, separators=(",", ":"))
    ciphertext = _fernet().encrypt(canonical.encode("utf-8"))
    fingerprint = hashlib.sha256(
        ",".join(sorted(payload.keys())).encode("utf-8")
    ).hexdigest()[:16]
    return ciphertext, fingerprint


def _decrypt(ciphertext: bytes) -> dict[str, str]:
    raw = _fernet().decrypt(bytes(ciphertext)).decode("utf-8")
    return json.loads(raw)


def _row_to_connector(
    template: ConnectorTemplate,
    row: dict | None,
) -> Connector:
    status = row["status"] if row else "disconnected"
    last_sync = row.get("last_sync") if row else None
    error_message = row.get("last_error") if row else None
    return Connector(
        id=template.id,
        name=template.name,
        category=template.category,  # type: ignore[arg-type]
        description=template.description,
        status=status,  # type: ignore[arg-type]
        icon_emoji=template.icon_emoji,
        last_sync=last_sync,
        error_message=error_message,
        config_fields=list(template.config_fields),
    )


def list_connectors() -> list[Connector]:
    """Return the full connector catalog merged with persisted state."""

    with connection() as conn, conn.cursor() as cur:
        cur.execute(
            "select connector_id, status, last_sync, last_error from integrations"
        )
        rows = {r["connector_id"]: r for r in cur.fetchall()}
    return [_row_to_connector(t, rows.get(t.id)) for t in CATALOG]


def configure(
    connector_id: str,
    config: Mapping[str, str],
    actor_id: UUID,
) -> Connector:
    template = _template(connector_id)
    missing = [f for f in template.config_fields if not config.get(f)]
    if missing:
        raise IntegrationError(
            f"missing required configuration fields: {', '.join(missing)}"
        )
    ciphertext, fingerprint = _encrypt(
        {k: v for k, v in config.items() if k in template.config_fields}
    )
    now = datetime.now(UTC)
    with connection() as conn, conn.cursor() as cur:
        cur.execute(
            """
            insert into integrations (
                connector_id, status, config_ciphertext, config_fingerprint,
                last_sync, last_error, updated_at, updated_by
            ) values (%s, %s, %s, %s, %s, null, %s, %s)
            on conflict (connector_id) do update set
                status = excluded.status,
                config_ciphertext = excluded.config_ciphertext,
                config_fingerprint = excluded.config_fingerprint,
                last_sync = excluded.last_sync,
                last_error = null,
                updated_at = excluded.updated_at,
                updated_by = excluded.updated_by
            returning connector_id, status, last_sync, last_error
            """,
            (
                connector_id,
                "connected",
                ciphertext,
                fingerprint,
                now,
                now,
                actor_id,
            ),
        )
        row = cur.fetchone()
    return _row_to_connector(template, row)


def disconnect(connector_id: str, actor_id: UUID) -> Connector:
    template = _template(connector_id)
    now = datetime.now(UTC)
    with connection() as conn, conn.cursor() as cur:
        cur.execute(
            """
            insert into integrations (
                connector_id, status, config_ciphertext, config_fingerprint,
                last_sync, last_error, updated_at, updated_by
            ) values (%s, %s, null, null, null, null, %s, %s)
            on conflict (connector_id) do update set
                status = excluded.status,
                config_ciphertext = null,
                config_fingerprint = null,
                last_sync = null,
                last_error = null,
                updated_at = excluded.updated_at,
                updated_by = excluded.updated_by
            returning connector_id, status, last_sync, last_error
            """,
            (connector_id, "disconnected", now, actor_id),
        )
        row = cur.fetchone()
    return _row_to_connector(template, row)


def get_decrypted_config(connector_id: str) -> dict[str, str] | None:
    """Return the decrypted config for downstream sync workers."""

    _template(connector_id)
    with connection() as conn, conn.cursor() as cur:
        cur.execute(
            "select config_ciphertext from integrations where connector_id = %s",
            (connector_id,),
        )
        row = cur.fetchone()
    if row is None or row["config_ciphertext"] is None:
        return None
    return _decrypt(row["config_ciphertext"])

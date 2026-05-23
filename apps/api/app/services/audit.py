"""Append-only, hash-chained audit log stored in Postgres.

Every mutating action in the control plane writes one record here. Records
are never updated or deleted. Each record's ``chain_hash`` is computed
over the previous record's ``chain_hash`` plus the canonical JSON of the
new record, so any tampering with history is detectable by
:func:`verify_chain`.
"""

from __future__ import annotations

import hashlib
import json
from datetime import UTC, datetime
from typing import Any, Iterable

from pydantic import BaseModel

from app.db import connection
from app.services.compliance import controls_for_event


GENESIS_HASH = "0" * 64


class AuditRecord(BaseModel):
    seq: int
    ts: datetime
    actor: str
    action: str
    resource: str
    before_hash: str | None = None
    after_hash: str | None = None
    request_id: str | None = None
    chain_hash: str
    evidence_controls: list[str] = []


def record(
    action: str,
    resource: str,
    *,
    actor: str = "system",
    before: Any = None,
    after: Any = None,
    request_id: str | None = None,
    evidence_controls: list[str] | None = None,
) -> AuditRecord:
    """Append one audit record. ``before``/``after`` are hashed, not stored."""

    before_hash = _hash_payload(before) if before is not None else None
    after_hash = _hash_payload(after) if after is not None else None
    controls = evidence_controls if evidence_controls is not None else controls_for_event(action)
    ts = datetime.now(UTC)

    with connection() as conn, conn.cursor() as cur:
        cur.execute(
            "select chain_hash from audit_log order by seq desc limit 1 for update"
        )
        prev_row = cur.fetchone()
        prev_hash = prev_row["chain_hash"] if prev_row else GENESIS_HASH

        body = {
            "ts": ts.isoformat(),
            "actor": actor,
            "action": action,
            "resource": resource,
            "before_hash": before_hash,
            "after_hash": after_hash,
            "request_id": request_id,
            "evidence_controls": controls,
        }
        chain_hash = _chain_hash(prev_hash, body)
        cur.execute(
            """
            insert into audit_log(
                ts, actor, action, resource,
                before_hash, after_hash, request_id,
                prev_chain_hash, chain_hash, evidence_controls
            ) values (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s::jsonb)
            returning seq
            """,
            (
                ts,
                actor,
                action,
                resource,
                before_hash,
                after_hash,
                request_id,
                prev_hash,
                chain_hash,
                json.dumps(controls),
            ),
        )
        seq = int(cur.fetchone()["seq"])

    return AuditRecord(
        seq=seq,
        ts=ts,
        actor=actor,
        action=action,
        resource=resource,
        before_hash=before_hash,
        after_hash=after_hash,
        request_id=request_id,
        chain_hash=chain_hash,
        evidence_controls=controls,
    )


def list_records(
    *,
    limit: int = 100,
    action: str | None = None,
    actor: str | None = None,
    resource: str | None = None,
) -> list[AuditRecord]:
    limit = max(1, min(limit, 1000))
    clauses: list[str] = []
    params: list[Any] = []
    if action:
        clauses.append("action = %s")
        params.append(action)
    if actor:
        clauses.append("actor = %s")
        params.append(actor)
    if resource:
        clauses.append("resource = %s")
        params.append(resource)

    where = f"where {' and '.join(clauses)}" if clauses else ""
    params.append(limit)

    with connection() as conn, conn.cursor() as cur:
        cur.execute(
            f"select * from audit_log {where} order by seq desc limit %s",
            params,
        )
        rows = cur.fetchall()

    return [_row_to_record(row) for row in rows]


def verify_chain() -> tuple[bool, int | None]:
    """Recompute the hash chain. Returns ``(ok, first_bad_seq)``."""

    with connection() as conn, conn.cursor() as cur:
        cur.execute("select * from audit_log order by seq asc")
        rows = cur.fetchall()

    prev_hash = GENESIS_HASH
    for row in rows:
        if row["prev_chain_hash"] != prev_hash:
            return False, int(row["seq"])
        ts = row["ts"]
        if isinstance(ts, datetime):
            ts_iso = ts.isoformat()
        else:
            ts_iso = str(ts)
        body = {
            "ts": ts_iso,
            "actor": row["actor"],
            "action": row["action"],
            "resource": row["resource"],
            "before_hash": row["before_hash"],
            "after_hash": row["after_hash"],
            "request_id": row["request_id"],
            "evidence_controls": list(row["evidence_controls"]),
        }
        expected = _chain_hash(prev_hash, body)
        if expected != row["chain_hash"]:
            legacy_body = dict(body)
            legacy_body.pop("evidence_controls")
            expected = _chain_hash(prev_hash, legacy_body)
        if expected != row["chain_hash"]:
            return False, int(row["seq"])
        prev_hash = row["chain_hash"]

    return True, None


def _chain_hash(prev_hash: str, body: dict[str, Any]) -> str:
    canonical = json.dumps(body, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(f"{prev_hash}|{canonical}".encode()).hexdigest()


def _hash_payload(payload: Any) -> str:
    if isinstance(payload, BaseModel):
        data: Any = payload.model_dump(mode="json")
    else:
        data = payload
    canonical = json.dumps(data, sort_keys=True, separators=(",", ":"), default=str)
    return hashlib.sha256(canonical.encode()).hexdigest()


def _row_to_record(row: dict[str, Any]) -> AuditRecord:
    return AuditRecord(
        seq=int(row["seq"]),
        ts=row["ts"],
        actor=row["actor"],
        action=row["action"],
        resource=row["resource"],
        before_hash=row["before_hash"],
        after_hash=row["after_hash"],
        request_id=row["request_id"],
        chain_hash=row["chain_hash"],
        evidence_controls=list(row["evidence_controls"]),
    )


def all_records() -> Iterable[AuditRecord]:
    return list_records(limit=1000)

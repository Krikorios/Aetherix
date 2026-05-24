"""Versioned, signed policy documents stored in Postgres.

A policy is stored as an append-only sequence of versions. The single row
with ``is_active = true`` is the live document. Promotion increments the
version and atomically swaps ``is_active``. Signatures are HMAC-SHA256
over the canonical JSON body using ``AETHERIX_POLICY_SIGNING_KEY``.

There are no env-based fallbacks: if no document has been promoted,
:func:`active_policy_document` returns ``None`` and callers that need a
runtime :class:`Policy` (e.g. :func:`app.services.state.active_policy`)
raise :class:`~app.services.state.PolicyNotConfigured`.
"""

from __future__ import annotations

import hashlib
import hmac
import json
from datetime import UTC, datetime

from app.db import connection
from app.services.compliance import controls_for_event
from app.services.crypto import _signing_key, signing_key_id
from app.schemas import (
    DlpScanRequest,
    Policy,
    PolicyDocument,
    PolicyDocumentDraft,
    PolicySimulationOutcome,
    PolicySimulationOutcomeSide,
    PolicySimulationResponse,
    PolicySimulationSummary,
)


def sign_document_body(body: dict) -> str:
    canonical = json.dumps(body, sort_keys=True, separators=(",", ":"), default=str)
    return hmac.new(_signing_key(), canonical.encode(), hashlib.sha256).hexdigest()


def verify_document(document: PolicyDocument) -> bool:
    body = _signable_body(document)
    expected = sign_document_body(body)
    return hmac.compare_digest(expected, document.signature)


def active_policy_document() -> PolicyDocument | None:
    with connection() as conn, conn.cursor() as cur:
        cur.execute("select payload from policy_documents where is_active limit 1")
        row = cur.fetchone()

    if row is None:
        return None
    return PolicyDocument.model_validate(row["payload"])


def list_policy_documents(limit: int = 50) -> list[PolicyDocument]:
    limit = max(1, min(limit, 500))
    with connection() as conn, conn.cursor() as cur:
        cur.execute(
            "select payload from policy_documents order by version desc limit %s",
            (limit,),
        )
        rows = cur.fetchall()
    return [PolicyDocument.model_validate(row["payload"]) for row in rows]


def promote_policy_document(draft: PolicyDocumentDraft, *, actor: str = "operator") -> PolicyDocument:
    """Create the next version of the policy and make it the active row."""

    now = datetime.now(UTC)

    with connection() as conn, conn.cursor() as cur:
        cur.execute("select coalesce(max(version), 0) as v from policy_documents")
        next_version = int(cur.fetchone()["v"]) + 1
        document_id = f"policy-{now.strftime('%Y%m%d')}-v{next_version:04d}"

        body = {
            "id": document_id,
            "version": next_version,
            "signed_by": signing_key_id(),
            "name": draft.name,
            "mode_default": draft.mode_default,
            "escalate_at": draft.escalate_at,
            "genai_guardrail": draft.genai_guardrail,
            "rules": [rule.model_dump(mode="json") for rule in draft.rules],
            "created_at": now.isoformat(),
            "created_by": actor,
        }
        signature = sign_document_body(body)

        document = PolicyDocument(
            id=document_id,
            version=next_version,
            signed_by=body["signed_by"],
            signature=signature,
            name=draft.name,
            mode_default=draft.mode_default,
            escalate_at=draft.escalate_at,
            genai_guardrail=draft.genai_guardrail,
            rules=draft.rules,
            created_at=now,
            created_by=actor,
        )

        cur.execute("update policy_documents set is_active = false where is_active")
        cur.execute(
            """
            insert into policy_documents(version, payload, is_active, created_at, evidence_controls)
            values (%s, %s::jsonb, true, %s, %s::jsonb)
            """,
            (
                next_version,
                json.dumps(document.model_dump(mode="json"), default=str),
                now,
                json.dumps(controls_for_event("policy.promote")),
            ),
        )

    return document


def policy_summary_from(document: PolicyDocument) -> Policy:
    entities = sorted(
        {rule.entity_type for rule in document.rules if rule.kind == "entity" and rule.entity_type}
    )
    return Policy(
        id=document.id,
        name=document.name,
        mode=document.mode_default,
        protected_entities=entities,
        genai_guardrail=document.genai_guardrail,
        escalate_at=document.escalate_at,
    )


def _draft_summary(draft: PolicyDocumentDraft) -> Policy:
    """Derive a runtime Policy from an unsigned draft for simulation purposes."""

    entities = sorted(
        {rule.entity_type for rule in draft.rules if rule.kind == "entity" and rule.entity_type}
    )
    return Policy(
        id="policy-draft",
        name=draft.name,
        mode=draft.mode_default,
        protected_entities=entities,
        genai_guardrail=draft.genai_guardrail,
        escalate_at=draft.escalate_at,
    )


def simulate(draft: PolicyDocumentDraft, samples: list[DlpScanRequest]) -> PolicySimulationResponse:
    """Evaluate samples under the active policy and the draft, return the diff.

    Requires an active policy document to exist so the "before" side is
    derived from real persisted state. Raises
    :class:`~app.services.state.PolicyNotConfigured` otherwise.
    """

    from app.services.dlp import apply_policy, scan_text
    from app.services.state import active_policy as _load_active_policy

    before_policy = _load_active_policy()
    after_policy = _draft_summary(draft)

    results: list[PolicySimulationOutcome] = []
    counts = {"allow": 0, "review": 0, "block": 0}
    changed_count = 0

    for sample in samples:
        scan = scan_text(sample)
        before = apply_policy(scan, before_policy)
        after = apply_policy(scan, after_policy)

        before_side = PolicySimulationOutcomeSide(
            action=before.action,
            risk_band=before.risk_band,
            entity_types=sorted({f.entity_type for f in before.findings}),
        )
        after_side = PolicySimulationOutcomeSide(
            action=after.action,
            risk_band=after.risk_band,
            entity_types=sorted({f.entity_type for f in after.findings}),
        )
        changed = before_side.action != after_side.action
        if changed:
            changed_count += 1
        counts[after_side.action] += 1

        results.append(
            PolicySimulationOutcome(
                source=sample.source,
                endpoint_id=sample.endpoint_id,
                before=before_side,
                after=after_side,
                changed=changed,
            )
        )

    summary = PolicySimulationSummary(
        total=len(results),
        changed=changed_count,
        would_block=counts["block"],
        would_review=counts["review"],
        would_allow=counts["allow"],
    )
    return PolicySimulationResponse(summary=summary, results=results)


def _signable_body(document: PolicyDocument) -> dict:
    return {
        "id": document.id,
        "version": document.version,
        "signed_by": document.signed_by,
        "name": document.name,
        "mode_default": document.mode_default,
        "escalate_at": document.escalate_at,
        "genai_guardrail": document.genai_guardrail,
        "rules": [rule.model_dump(mode="json") for rule in document.rules],
        "created_at": document.created_at.isoformat(),
        "created_by": document.created_by,
    }

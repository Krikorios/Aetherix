"""Impersonation session lifecycle.

A platform owner (or any account with ``impersonate=manage`` against a
target's tenancy scope) can temporarily mint a JWT that represents
another operator account so they can investigate an issue exactly as
that operator sees it. Every start/end is:

* Persisted in ``impersonation_sessions`` with a non-null ``reason``.
* Recorded in the hash-chained ``audit_log``.
* Emitted as an ``evidence_events`` row so it shows up in compliance
  reports against the ISO/SOC mappings declared in
  :mod:`app.services.compliance`.

The minted impersonation token carries an ``impersonation_session_id``
claim so any downstream action can be traced to the session that
authorised it.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any
from uuid import UUID

from app.db import connection
from app.services import audit, jwt_tokens, tenancy
from app.services.policy_v2_runtime import EvidenceEmitter

# Default lifetime for an impersonation token. Short on purpose: the
# operator can re-issue if a long investigation is needed, and the
# audit trail will reflect every re-issuance.
DEFAULT_TTL_SECONDS = 30 * 60


class ImpersonationError(ValueError):
    """Raised when an impersonation request is invalid or unauthorised."""


@dataclass
class ImpersonationSession:
    id: UUID
    actor_account_id: UUID
    target_account_id: UUID
    reason: str
    started_at: datetime
    ended_at: datetime | None

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": str(self.id),
            "actor_account_id": str(self.actor_account_id),
            "target_account_id": str(self.target_account_id),
            "reason": self.reason,
            "started_at": self.started_at.isoformat(),
            "ended_at": self.ended_at.isoformat() if self.ended_at else None,
        }


def _row_to_session(row: dict[str, Any]) -> ImpersonationSession:
    return ImpersonationSession(
        id=row["id"],
        actor_account_id=row["actor_account_id"],
        target_account_id=row["target_account_id"],
        reason=row["reason"],
        started_at=row["started_at"],
        ended_at=row["ended_at"],
    )


def _evidence_scope(actor_id: UUID, target_id: UUID) -> dict[str, Any]:
    return {
        "actor_account_id": str(actor_id),
        "target_account_id": str(target_id),
    }


def start_session(
    *,
    actor: tenancy.Account,
    target_account_id: UUID,
    reason: str,
    request_id: str | None = None,
    ttl_seconds: int = DEFAULT_TTL_SECONDS,
) -> tuple[ImpersonationSession, str, int]:
    """Start an impersonation session and mint a scoped JWT.

    Returns ``(session, token, exp_epoch_seconds)``.
    """

    if not reason or len(reason.strip()) < 4:
        raise ImpersonationError(
            "reason is required and must describe why impersonation is needed"
        )
    if actor.id == target_account_id:
        raise ImpersonationError("cannot impersonate yourself")

    target = tenancy.get_account(target_account_id)
    if target is None:
        raise ImpersonationError("target account not found")
    if target.status in ("locked", "suspended"):
        raise ImpersonationError(
            f"cannot impersonate an account that is {target.status}"
        )
    if not tenancy.account_visible_to(actor, target):
        raise ImpersonationError("target account not found")

    # Authorisation: the actor must hold ``impersonate=manage`` over a
    # scope that includes the target. Platform owners always qualify
    # through :func:`tenancy.has_permission`.
    target_partner = next(
        (role.partner_id for role in target.roles if role.partner_id is not None),
        None,
    )
    target_customer = next(
        (role.customer_id for role in target.roles if role.customer_id is not None),
        None,
    )
    if not tenancy.has_permission(
        actor,
        "impersonate",
        "manage",
        partner_id=target_partner,
        customer_id=target_customer,
    ):
        raise ImpersonationError(
            "requires manage on impersonate for the target account's scope"
        )

    session_id = uuid.uuid4()
    now = datetime.now(UTC)
    with connection() as conn, conn.cursor() as cur:
        cur.execute(
            """
            insert into impersonation_sessions(
                id, actor_account_id, target_account_id, reason, started_at
            ) values (%s, %s, %s, %s, %s)
            """,
            (session_id, actor.id, target_account_id, reason.strip(), now),
        )
    session = ImpersonationSession(
        id=session_id,
        actor_account_id=actor.id,
        target_account_id=target_account_id,
        reason=reason.strip(),
        started_at=now,
        ended_at=None,
    )

    token, exp = jwt_tokens.issue(
        str(target_account_id),
        ttl_seconds=ttl_seconds,
        extra={
            "impersonation_session_id": str(session_id),
            "impersonator_account_id": str(actor.id),
        },
    )

    audit.record(
        action="impersonation.start",
        resource=f"account:{target_account_id}",
        actor=str(actor.id),
        after={
            "session_id": str(session_id),
            "target_account_id": str(target_account_id),
            "reason_hash": True,  # body is hashed by audit.record
            "reason": reason.strip(),
        },
        request_id=request_id,
    )
    EvidenceEmitter.emit(
        action="impersonation.start",
        resource=f"impersonation:{session_id}",
        actor=str(actor.id),
        scope=_evidence_scope(actor.id, target_account_id),
        payload={
            "session_id": str(session_id),
            "started_at": now.isoformat(),
            "ttl_seconds": ttl_seconds,
        },
    )

    return session, token, exp


def end_session(
    *,
    session_id: UUID,
    actor: tenancy.Account,
    request_id: str | None = None,
) -> ImpersonationSession:
    """End an impersonation session. Idempotent on already-ended rows."""

    with connection() as conn, conn.cursor() as cur:
        cur.execute(
            "select * from impersonation_sessions where id = %s",
            (session_id,),
        )
        row = cur.fetchone()
        if row is None:
            raise ImpersonationError("impersonation session not found")
        session = _row_to_session(row)

        # Only the original actor or a platform owner can end a
        # session. (Platform owners can end any session for cleanup.)
        is_owner = any(role.role_code == "platform_owner" for role in actor.roles)
        if session.actor_account_id != actor.id and not is_owner:
            raise ImpersonationError(
                "only the originating actor or a platform owner can end this session"
            )

        if session.ended_at is not None:
            return session

        ended_at = datetime.now(UTC)
        cur.execute(
            "update impersonation_sessions set ended_at = %s where id = %s",
            (ended_at, session_id),
        )

    session.ended_at = ended_at
    audit.record(
        action="impersonation.end",
        resource=f"account:{session.target_account_id}",
        actor=str(actor.id),
        after={
            "session_id": str(session.id),
            "ended_at": ended_at.isoformat(),
        },
        request_id=request_id,
    )
    EvidenceEmitter.emit(
        action="impersonation.end",
        resource=f"impersonation:{session.id}",
        actor=str(actor.id),
        scope=_evidence_scope(session.actor_account_id, session.target_account_id),
        payload={
            "session_id": str(session.id),
            "started_at": session.started_at.isoformat(),
            "ended_at": ended_at.isoformat(),
            "duration_seconds": int((ended_at - session.started_at).total_seconds()),
        },
    )
    return session


def list_sessions(
    *,
    actor: tenancy.Account,
    actor_account_id: UUID | None = None,
    target_account_id: UUID | None = None,
    active_only: bool = False,
    limit: int = 100,
) -> list[ImpersonationSession]:
    """List impersonation sessions visible to ``actor``.

    Platform owners see everything. Other accounts see sessions they
    originated and sessions where they were the target (so an operator
    can audit who has impersonated them).
    """

    is_owner = any(role.role_code == "platform_owner" for role in actor.roles)
    clauses: list[str] = []
    params: list[Any] = []

    if not is_owner:
        clauses.append("(actor_account_id = %s or target_account_id = %s)")
        params.extend([actor.id, actor.id])
    if actor_account_id is not None:
        clauses.append("actor_account_id = %s")
        params.append(actor_account_id)
    if target_account_id is not None:
        clauses.append("target_account_id = %s")
        params.append(target_account_id)
    if active_only:
        clauses.append("ended_at is null")

    where = ("where " + " and ".join(clauses)) if clauses else ""
    sql = f"""
        select * from impersonation_sessions
        {where}
        order by started_at desc
        limit %s
    """
    params.append(max(1, min(int(limit), 500)))

    with connection() as conn, conn.cursor() as cur:
        cur.execute(sql, tuple(params))
        rows = cur.fetchall()
    return [_row_to_session(row) for row in rows]

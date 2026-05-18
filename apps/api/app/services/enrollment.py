"""Agent enrollment + per-agent HMAC heartbeat verification (Postgres-backed)."""

from __future__ import annotations

import hashlib
import hmac
import secrets
from datetime import UTC, datetime, timedelta

from app.db import connection
from app.schemas import (
    AgentHeartbeat,
    EnrolledAgent,
    EnrollmentResult,
    EnrollmentTokenIssued,
    EnrollmentTokenRequest,
)


class EnrollmentError(Exception):
    """Raised when an enrollment token cannot be honoured."""


class HeartbeatAuthError(Exception):
    """Raised when an enrolled-agent heartbeat fails verification."""


def issue_enrollment_token(request: EnrollmentTokenRequest) -> EnrollmentTokenIssued:
    token = secrets.token_urlsafe(32)
    now = datetime.now(UTC)
    expires_at = now + timedelta(seconds=request.ttl_seconds)

    with connection() as conn, conn.cursor() as cur:
        cur.execute(
            """
            insert into enrollment_tokens(
                token_hash, note, created_at, expires_at, consumed_at,
                partner_id, customer_id, group_id, policy_package_id,
                purpose, max_uses, use_count, created_by
            ) values (%s, %s, %s, %s, null, %s, %s, %s, %s, %s, %s, 0, %s)
            """,
            (
                _token_hash(token),
                request.note,
                now,
                expires_at,
                request.partner_id,
                request.customer_id,
                request.group_id,
                request.policy_package_id,
                request.purpose,
                request.max_uses,
                request.created_by,
            ),
        )

    return EnrollmentTokenIssued(token=token, expires_at=expires_at, note=request.note)


def consume_enrollment_token(
    token: str,
    *,
    hostname: str,
    os_name: str,
) -> EnrollmentResult:
    now = datetime.now(UTC)
    token_hash = _token_hash(token)

    with connection() as conn, conn.cursor() as cur:
        cur.execute(
            """
            select
                id, expires_at, consumed_at, partner_id, customer_id,
                group_id, policy_package_id, max_uses, use_count
            from enrollment_tokens
            where token_hash = %s
            for update
            """,
            (token_hash,),
        )
        row = cur.fetchone()

        if row is None:
            raise EnrollmentError("Enrollment token is unknown")
        if row["consumed_at"] is not None or int(row["use_count"]) >= int(row["max_uses"]):
            raise EnrollmentError("Enrollment token has already been used")
        expires_at = row["expires_at"]
        if expires_at.tzinfo is None:
            expires_at = expires_at.replace(tzinfo=UTC)
        if expires_at < now:
            raise EnrollmentError("Enrollment token has expired")

        agent_id = f"agent-{secrets.token_hex(8)}"
        agent_secret = secrets.token_urlsafe(32)

        cur.execute(
            """
            update enrollment_tokens
            set use_count = use_count + 1,
                consumed_at = case when use_count + 1 >= max_uses then %s else consumed_at end
            where id = %s
            """,
            (now, row["id"]),
        )
        cur.execute(
            """
            insert into enrolled_agents(
                agent_id, hostname, os, secret, enrolled_at, last_nonce, revoked,
                partner_id, customer_id, group_id, policy_package_id
            )
            values (%s, %s, %s, %s, %s, 0, false, %s, %s, %s, %s)
            """,
            (
                agent_id,
                hostname,
                os_name,
                agent_secret,
                now,
                row["partner_id"],
                row["customer_id"],
                row["group_id"],
                row["policy_package_id"],
            ),
        )

    return EnrollmentResult(
        agent_id=agent_id,
        agent_secret=agent_secret,
        enrolled_at=now,
        customer_id=row["customer_id"],
        group_id=row["group_id"],
        policy_package_id=row["policy_package_id"],
    )


def get_enrolled_agent(agent_id: str) -> EnrolledAgent | None:
    with connection() as conn, conn.cursor() as cur:
        cur.execute(
            """
            select agent_id, hostname, os, enrolled_at, last_nonce, revoked
            from enrolled_agents
            where agent_id = %s
            """,
            (agent_id,),
        )
        row = cur.fetchone()

    if row is None:
        return None
    return EnrolledAgent(
        agent_id=row["agent_id"],
        hostname=row["hostname"],
        os=row["os"],
        enrolled_at=row["enrolled_at"],
        last_nonce=int(row["last_nonce"]),
        revoked=bool(row["revoked"]),
    )


def verify_enrolled_heartbeat(heartbeat: AgentHeartbeat) -> bool:
    """Return True if the agent is enrolled and the heartbeat verified.

    Returns False if the agent is not enrolled (caller may fall back to
    legacy shared-secret verification). Raises ``HeartbeatAuthError`` if
    the agent IS enrolled but the heartbeat fails authentication or
    replay checks — never silently accept those.
    """

    with connection() as conn, conn.cursor() as cur:
        cur.execute(
            """
            select secret, last_nonce, revoked
            from enrolled_agents
            where agent_id = %s
            for update
            """,
            (heartbeat.agent_id,),
        )
        row = cur.fetchone()

        if row is None:
            return False
        if row["revoked"]:
            raise HeartbeatAuthError("Agent has been revoked")
        if heartbeat.nonce is None:
            raise HeartbeatAuthError("Heartbeat is missing nonce")
        if heartbeat.signature is None:
            raise HeartbeatAuthError("Heartbeat is missing signature")
        if heartbeat.nonce <= int(row["last_nonce"]):
            raise HeartbeatAuthError("Heartbeat nonce is not strictly increasing")

        expected = enrolled_heartbeat_signature(heartbeat, row["secret"])
        if not hmac.compare_digest(expected, heartbeat.signature):
            raise HeartbeatAuthError("Heartbeat signature is invalid")

        cur.execute(
            "update enrolled_agents set last_nonce = %s where agent_id = %s",
            (heartbeat.nonce, heartbeat.agent_id),
        )

    return True


def enrolled_heartbeat_signature(heartbeat: AgentHeartbeat, secret: str) -> str:
    message = "|".join(
        [
            heartbeat.agent_id,
            heartbeat.hostname,
            heartbeat.os,
            heartbeat.collected_at.isoformat(),
            heartbeat.policy_version,
            str(heartbeat.nonce),
        ]
    )
    return hmac.new(secret.encode(), message.encode(), hashlib.sha256).hexdigest()


def _token_hash(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()

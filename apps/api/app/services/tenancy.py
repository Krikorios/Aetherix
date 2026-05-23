"""Accounts, role assignments, and RBAC scope resolution.

This is the authority for "who can see / do what" across the three-tier
hierarchy (Platform Owner ▸ MSP Partner ▸ Company). The API layer never
queries ``accounts``/``account_roles`` directly; it goes through the
functions defined here.

Authentication itself is intentionally out of scope for this module —
the API uses ``resolve_current_account`` which reads ``X-Aetherix-Account``
(account id) until real session auth lands. Permission evaluation,
however, is final here and shared by every endpoint.
"""

from __future__ import annotations

import uuid
import hashlib
import secrets
from datetime import UTC, datetime, timedelta
from typing import Iterable
from uuid import UUID

from app.db import PERMISSION_LEVELS, connection
from app.schemas import (
    Account,
    AccountCreate,
    Branding,
    DEFAULT_BRANDING,
    MeResponse,
    PermissionLevel,
    Role,
    RoleAssignment,
    RoleAssignmentRequest,
    RoleCode,
    TenantScope,
)
from app.services.passwords import hash_password, verify_password


class TenancyError(Exception):
    """Domain error raised for tenancy/RBAC failures (mapped to 4xx)."""


# Default lifetime for account-setup invite tokens.
INVITE_TOKEN_TTL = timedelta(days=7)


def _hash_invite_token(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


# ---------------------------------------------------------------------------
# Permission helpers
# ---------------------------------------------------------------------------


def _level_rank(level: PermissionLevel) -> int:
    try:
        return PERMISSION_LEVELS.index(level)
    except ValueError:
        return 0


def merge_permissions(roles: Iterable[Role]) -> dict[str, PermissionLevel]:
    """Return the highest permission level held across the given roles."""

    merged: dict[str, PermissionLevel] = {}
    for role in roles:
        for resource, level in role.permissions.items():
            if _level_rank(level) > _level_rank(merged.get(resource, "none")):
                merged[resource] = level
    return merged


# ---------------------------------------------------------------------------
# Role catalog
# ---------------------------------------------------------------------------


def list_roles() -> list[Role]:
    with connection() as conn, conn.cursor() as cur:
        cur.execute("select code, display_name, permissions from roles order by code")
        return [
            Role(
                code=row["code"],
                display_name=row["display_name"],
                permissions=row["permissions"],
            )
            for row in cur.fetchall()
        ]


def get_role(code: RoleCode) -> Role | None:
    with connection() as conn, conn.cursor() as cur:
        cur.execute(
            "select code, display_name, permissions from roles where code = %s",
            (code,),
        )
        row = cur.fetchone()
    if row is None:
        return None
    return Role(code=row["code"], display_name=row["display_name"], permissions=row["permissions"])


# ---------------------------------------------------------------------------
# Accounts
# ---------------------------------------------------------------------------


def _row_to_account(row: dict, assignments: list[RoleAssignment]) -> Account:
    return Account(
        id=row["id"],
        email=row["email"],
        full_name=row["full_name"],
        status=row["status"],
        two_factor=row["two_factor"],
        password_expires_at=row["password_expires_at"],
        locked_until=row["locked_until"],
        last_login_at=row["last_login_at"],
        created_at=row["created_at"],
        roles=assignments,
    )


def _load_assignments(cur, account_id: UUID) -> list[RoleAssignment]:
    cur.execute(
        """
        select id, role_code, partner_id, customer_id, granted_by, granted_at
        from account_roles
        where account_id = %s
        order by granted_at
        """,
        (account_id,),
    )
    return [
        RoleAssignment(
            id=row["id"],
            role_code=row["role_code"],
            partner_id=row["partner_id"],
            customer_id=row["customer_id"],
            granted_by=row["granted_by"],
            granted_at=row["granted_at"],
        )
        for row in cur.fetchall()
    ]


def create_account(payload: AccountCreate) -> Account:
    email = payload.email.strip().lower()
    if "@" not in email:
        raise TenancyError("email must contain '@'")

    account_id = uuid.uuid4()
    now = datetime.now(UTC)
    password_hash_value = hash_password(payload.password) if payload.password else None
    initial_status = "active" if password_hash_value else "invited"

    with connection() as conn, conn.cursor() as cur:
        cur.execute("select 1 from accounts where email = %s", (email,))
        if cur.fetchone() is not None:
            raise TenancyError(f"account with email {email!r} already exists")

        cur.execute(
            """
            insert into accounts (id, email, full_name, password_hash, status, two_factor, created_by, created_at)
            values (%s, %s, %s, %s, %s, 'missing', %s, %s)
            returning id, email, full_name, status, two_factor,
                      password_expires_at, locked_until, last_login_at, created_at
            """,
            (
                account_id,
                email,
                payload.full_name,
                password_hash_value,
                initial_status,
                payload.created_by,
                now,
            ),
        )
        row = cur.fetchone()

        assignments: list[RoleAssignment] = []
        if payload.initial_role is not None:
            assignment = _insert_role_assignment(
                cur,
                account_id=account_id,
                request=payload.initial_role,
                granted_by=payload.created_by,
                now=now,
            )
            assignments.append(assignment)

    return _row_to_account(row, assignments)


def set_password(account_id: UUID, password: str) -> None:
    """Hash and store a new password, activating the account."""

    hashed = hash_password(password)
    with connection() as conn, conn.cursor() as cur:
        cur.execute(
            """
            update accounts
               set password_hash = %s,
                   status = case when status = 'invited' then 'active' else status end
             where id = %s
            """,
            (hashed, account_id),
        )
        if cur.rowcount == 0:
            raise TenancyError("account not found")


def issue_invite_token(account_id: UUID, *, ttl: timedelta = INVITE_TOKEN_TTL) -> tuple[str, datetime]:
    """Generate and persist a one-time setup token for an invited account.

    Returns ``(plaintext_token, expires_at)``. Only the SHA-256 hash of the
    token is stored, so this is the only chance the caller has to learn the
    plaintext value. Calling this again for the same account rotates the
    token and invalidates any previously issued link.
    """

    token = secrets.token_urlsafe(32)
    expires_at = datetime.now(UTC) + ttl
    token_hash = _hash_invite_token(token)
    with connection() as conn, conn.cursor() as cur:
        cur.execute(
            """
            update accounts
               set invite_token_hash = %s,
                   invite_expires_at = %s
             where id = %s
            """,
            (token_hash, expires_at, account_id),
        )
        if cur.rowcount == 0:
            raise TenancyError("account not found")
    return token, expires_at


def accept_invite(token: str, password: str, *, full_name: str | None = None) -> Account:
    """Redeem an invite token: set the password and activate the account.

    Raises ``TenancyError`` if the token is unknown, expired, or already
    consumed.
    """

    token_hash = _hash_invite_token(token)
    now = datetime.now(UTC)
    password_hash_value = hash_password(password)
    with connection() as conn, conn.cursor() as cur:
        cur.execute(
            """
            select id, status, invite_expires_at
              from accounts
             where invite_token_hash = %s
            """,
            (token_hash,),
        )
        row = cur.fetchone()
        if row is None:
            raise TenancyError("invite token is invalid or has already been used")
        if row["invite_expires_at"] is None or row["invite_expires_at"] < now:
            raise TenancyError("invite token has expired")
        if row["status"] in ("locked", "suspended"):
            raise TenancyError(f"account is {row['status']}")
        account_id = row["id"]
        cur.execute(
            """
            update accounts
               set password_hash = %s,
                   status = 'active',
                   invite_token_hash = null,
                   invite_expires_at = null,
                   full_name = case
                       when %s::text is not null and length(%s::text) > 0
                           then %s::text
                       else full_name
                   end
             where id = %s
            """,
            (password_hash_value, full_name, full_name, full_name, account_id),
        )

    refreshed = get_account(account_id)
    if refreshed is None:
        raise TenancyError("account not found after invite acceptance")
    return refreshed


def authenticate(email: str, password: str) -> dict:
    """Verify password only. Returns the account snapshot needed to drive
    the second-factor step. Does **not** update ``last_login_at`` — that
    happens once the full login (including 2FA) completes.
    """

    email = email.strip().lower()
    with connection() as conn, conn.cursor() as cur:
        cur.execute(
            """
            select id, email, full_name, password_hash, status, locked_until,
                   two_factor, totp_secret
            from accounts where email = %s
            """,
            (email,),
        )
        row = cur.fetchone()
        if row is None:
            raise TenancyError("invalid email or password")
        if row["status"] in ("locked", "suspended"):
            raise TenancyError(f"account is {row['status']}")
        if row["locked_until"] is not None and row["locked_until"] > datetime.now(UTC):
            raise TenancyError("account is temporarily locked")
        if not verify_password(password, row["password_hash"]):
            raise TenancyError("invalid email or password")

    return {
        "account_id": row["id"],
        "email": row["email"],
        "full_name": row["full_name"],
        "two_factor": row["two_factor"],
        "totp_secret": row["totp_secret"],
    }


def store_totp_secret(account_id: UUID, secret: str) -> None:
    with connection() as conn, conn.cursor() as cur:
        cur.execute(
            "update accounts set totp_secret = %s where id = %s",
            (secret, account_id),
        )
        if cur.rowcount == 0:
            raise TenancyError("account not found")


def mark_totp_enrolled(account_id: UUID) -> None:
    with connection() as conn, conn.cursor() as cur:
        cur.execute(
            "update accounts set two_factor = 'enabled' where id = %s",
            (account_id,),
        )


def touch_last_login(account_id: UUID) -> None:
    with connection() as conn, conn.cursor() as cur:
        cur.execute(
            "update accounts set last_login_at = %s where id = %s",
            (datetime.now(UTC), account_id),
        )


def create_login_challenge(account_id: UUID, purpose: str, ttl_seconds: int) -> UUID:
    if purpose not in ("totp_setup", "totp_verify"):
        raise TenancyError("invalid challenge purpose")
    challenge_id = uuid.uuid4()
    now = datetime.now(UTC)
    expires_at = now + timedelta(seconds=ttl_seconds)
    with connection() as conn, conn.cursor() as cur:
        # Garbage-collect any expired challenges for this account so the
        # table stays small without a separate cron job.
        cur.execute(
            "delete from login_challenges where account_id = %s and expires_at < %s",
            (account_id, now),
        )
        cur.execute(
            """
            insert into login_challenges (id, account_id, purpose, expires_at, created_at)
            values (%s, %s, %s, %s, %s)
            """,
            (challenge_id, account_id, purpose, expires_at, now),
        )
    return challenge_id


def consume_login_challenge(challenge_id: UUID) -> dict:
    """Fetch + delete a challenge atomically; return account context.

    Raises ``TenancyError`` if the challenge is unknown or expired.
    """

    now = datetime.now(UTC)
    with connection() as conn, conn.cursor() as cur:
        cur.execute(
            """
            delete from login_challenges
             where id = %s
            returning account_id, purpose, expires_at
            """,
            (challenge_id,),
        )
        row = cur.fetchone()
        if row is None:
            raise TenancyError("challenge not found or already used")
        if row["expires_at"] < now:
            raise TenancyError("challenge expired")
        cur.execute(
            "select id, totp_secret, two_factor from accounts where id = %s",
            (row["account_id"],),
        )
        account_row = cur.fetchone()
        if account_row is None:
            raise TenancyError("account not found")
    return {
        "account_id": account_row["id"],
        "totp_secret": account_row["totp_secret"],
        "two_factor": account_row["two_factor"],
        "purpose": row["purpose"],
    }


def get_account(account_id: UUID) -> Account | None:
    with connection() as conn, conn.cursor() as cur:
        cur.execute(
            """
            select id, email, full_name, status, two_factor,
                   password_expires_at, locked_until, last_login_at, created_at
            from accounts where id = %s
            """,
            (account_id,),
        )
        row = cur.fetchone()
        if row is None:
            return None
        assignments = _load_assignments(cur, account_id)
    return _row_to_account(row, assignments)


def list_accounts() -> list[Account]:
    with connection() as conn, conn.cursor() as cur:
        cur.execute(
            """
            select id, email, full_name, status, two_factor,
                   password_expires_at, locked_until, last_login_at, created_at
            from accounts order by created_at
            """
        )
        rows = cur.fetchall()
        results: list[Account] = []
        for row in rows:
            assignments = _load_assignments(cur, row["id"])
            results.append(_row_to_account(row, assignments))
    return results


# ---------------------------------------------------------------------------
# Role assignments
# ---------------------------------------------------------------------------


def _insert_role_assignment(
    cur,
    *,
    account_id: UUID,
    request: RoleAssignmentRequest,
    granted_by: str,
    now: datetime,
) -> RoleAssignment:
    cur.execute("select 1 from roles where code = %s", (request.role_code,))
    if cur.fetchone() is None:
        raise TenancyError(f"unknown role: {request.role_code}")

    # Scope validation: enforce that platform roles have no scope, MSP
    # roles have a partner_id, and company roles have a customer_id.
    role_code = request.role_code
    if role_code == "platform_owner":
        if request.partner_id or request.customer_id:
            raise TenancyError("platform_owner role must not be scoped")
    elif role_code == "msp_partner":
        if not request.partner_id or request.customer_id:
            raise TenancyError("msp_partner role requires partner_id and no customer_id")
    else:  # company_*
        if not request.customer_id:
            raise TenancyError(f"{role_code} role requires customer_id")

    assignment_id = uuid.uuid4()
    cur.execute(
        """
        select id from account_roles
        where account_id = %s
          and role_code = %s
          and coalesce(partner_id, '00000000-0000-0000-0000-000000000000'::uuid)
              = coalesce(%s::uuid, '00000000-0000-0000-0000-000000000000'::uuid)
          and coalesce(customer_id, '00000000-0000-0000-0000-000000000000'::uuid)
              = coalesce(%s::uuid, '00000000-0000-0000-0000-000000000000'::uuid)
        """,
        (account_id, request.role_code, request.partner_id, request.customer_id),
    )
    if cur.fetchone() is not None:
        raise TenancyError("role assignment already exists for this scope")

    cur.execute(
        """
        insert into account_roles
            (id, account_id, role_code, partner_id, customer_id, granted_by, granted_at)
        values (%s, %s, %s, %s, %s, %s, %s)
        returning id, role_code, partner_id, customer_id, granted_by, granted_at
        """,
        (
            assignment_id,
            account_id,
            request.role_code,
            request.partner_id,
            request.customer_id,
            granted_by,
            now,
        ),
    )
    row = cur.fetchone()
    if row is None:
        raise TenancyError("failed to create role assignment")
    return RoleAssignment(
        id=row["id"],
        role_code=row["role_code"],
        partner_id=row["partner_id"],
        customer_id=row["customer_id"],
        granted_by=row["granted_by"],
        granted_at=row["granted_at"],
    )


def assign_role(
    account_id: UUID,
    request: RoleAssignmentRequest,
    *,
    granted_by: str,
) -> RoleAssignment:
    now = datetime.now(UTC)
    with connection() as conn, conn.cursor() as cur:
        cur.execute("select 1 from accounts where id = %s", (account_id,))
        if cur.fetchone() is None:
            raise TenancyError("account not found")
        return _insert_role_assignment(
            cur,
            account_id=account_id,
            request=request,
            granted_by=granted_by,
            now=now,
        )


def revoke_role(account_id: UUID, assignment_id: UUID) -> bool:
    with connection() as conn, conn.cursor() as cur:
        cur.execute(
            "delete from account_roles where id = %s and account_id = %s",
            (assignment_id, account_id),
        )
        return cur.rowcount > 0


def delete_account(account_id: UUID) -> bool:
    """Hard-delete an account and every record that references it.

    Role assignments and login challenges cascade via FK. Impersonation
    sessions do not cascade, so we clear them explicitly to avoid
    leaving orphan rows or violating the FK on subsequent inserts.
    """

    with connection() as conn, conn.cursor() as cur:
        cur.execute(
            "delete from impersonation_sessions where actor_account_id = %s or target_account_id = %s",
            (account_id, account_id),
        )
        cur.execute("delete from accounts where id = %s", (account_id,))
        return cur.rowcount > 0


# ---------------------------------------------------------------------------
# Scope resolution + permission checks
# ---------------------------------------------------------------------------


def _roles_for(account: Account) -> list[Role]:
    codes = {a.role_code for a in account.roles}
    return [role for role in list_roles() if role.code in codes]


def compute_scope(account: Account) -> TenantScope:
    """Return the partner/customer ids the account can see.

    - platform_owner ➜ ``is_platform=True``; partner/customer lists are empty
      (callers should treat ``is_platform`` as "all").
    - msp_partner ➜ partner_ids from their assignments; customers are derived
      at query time by joining ``customers.partner_id``.
    - company_* ➜ customer_ids from their assignments.
    """

    is_platform = False
    partner_ids: set[UUID] = set()
    customer_ids: set[UUID] = set()
    for assignment in account.roles:
        if assignment.role_code == "platform_owner":
            is_platform = True
        elif assignment.role_code == "msp_partner":
            if assignment.partner_id:
                partner_ids.add(assignment.partner_id)
        else:
            if assignment.customer_id:
                customer_ids.add(assignment.customer_id)
    return TenantScope(
        is_platform=is_platform,
        partner_ids=sorted(partner_ids, key=str),
        customer_ids=sorted(customer_ids, key=str),
    )


def merged_permissions_for(account: Account) -> dict[str, PermissionLevel]:
    return merge_permissions(_roles_for(account))


def me(account: Account) -> MeResponse:
    return MeResponse(
        account=account,
        permissions=merged_permissions_for(account),
        scope=compute_scope(account),
        branding=resolve_branding(account),
    )


_BRANDING_FIELDS = {
    "product_name",
    "tagline",
    "primary_color",
    "accent_color",
    "logo_url",
    "support_email",
    "support_url",
    "footer_note",
}


def _merge_branding_layer(base: dict, layer: dict | None) -> dict:
    if not layer:
        return base
    for key, value in layer.items():
        if key in _BRANDING_FIELDS and value is not None and value != "":
            base[key] = value
    return base


def resolve_branding(account: Account) -> Branding:
    """Pick the most specific branding layer visible to ``account``.

    Order of precedence (most specific wins): customer > partner > platform default.
    Falls back to defaults when the account has no scoped assignments.
    """

    scope = compute_scope(account)
    # Pick the first customer/partner the account is bound to. The console can
    # later add a tenant switcher to let an MSP user preview other branding.
    customer_id = scope.customer_ids[0] if scope.customer_ids else None
    partner_id = scope.partner_ids[0] if scope.partner_ids else None

    customer_branding: dict | None = None
    partner_branding: dict | None = None
    source = "platform"

    with connection() as conn, conn.cursor() as cur:
        if customer_id is not None:
            cur.execute(
                "select branding, partner_id from customers where id = %s",
                (str(customer_id),),
            )
            row = cur.fetchone()
            if row is not None:
                customer_branding = row["branding"] or {}
                partner_id = row["partner_id"]
                source = "customer"
        if partner_id is not None:
            cur.execute(
                "select branding from partners where id = %s",
                (str(partner_id),),
            )
            row = cur.fetchone()
            if row is not None:
                partner_branding = row["branding"] or {}
                if source == "platform":
                    source = "partner"

    merged: dict = DEFAULT_BRANDING.model_dump()
    _merge_branding_layer(merged, partner_branding)
    _merge_branding_layer(merged, customer_branding)
    merged["source"] = source
    return Branding(**merged)


def has_permission(
    account: Account,
    resource: str,
    required: PermissionLevel,
    *,
    partner_id: UUID | None = None,
    customer_id: UUID | None = None,
) -> bool:
    """Evaluate whether ``account`` has ``required`` on ``resource``.

    Only role assignments whose scope covers the requested
    ``(partner_id, customer_id)`` contribute to the decision. A
    platform_owner assignment matches everything; an msp_partner
    assignment matches when its ``partner_id`` equals the requested
    partner; a company_* assignment matches when its ``customer_id``
    equals the requested customer.
    """

    scope_roles: list[Role] = []
    role_catalog = {role.code: role for role in list_roles()}
    for assignment in account.roles:
        role = role_catalog.get(assignment.role_code)
        if role is None:
            continue
        if assignment.role_code == "platform_owner":
            scope_roles.append(role)
            continue
        if assignment.role_code == "msp_partner":
            if partner_id is not None and assignment.partner_id == partner_id:
                scope_roles.append(role)
            elif partner_id is None and customer_id is None:
                scope_roles.append(role)
            continue
        # company_* roles
        if customer_id is not None and assignment.customer_id == customer_id:
            scope_roles.append(role)
        elif partner_id is None and customer_id is None:
            scope_roles.append(role)

    merged = merge_permissions(scope_roles)
    return _level_rank(merged.get(resource, "none")) >= _level_rank(required)


# ---------------------------------------------------------------------------
# Bootstrap helper
# ---------------------------------------------------------------------------


def ensure_platform_owner(email: str, full_name: str, password: str | None = None) -> Account:
    """Idempotently create (or return) the bootstrap Platform Owner account.

    If ``password`` is provided, it is set on the account (whether new or
    existing) so the bootstrap script can rotate credentials.
    """

    email = email.strip().lower()
    existing = _find_by_email(email)
    if existing is not None:
        if not any(a.role_code == "platform_owner" for a in existing.roles):
            assign_role(
                existing.id,
                RoleAssignmentRequest(role_code="platform_owner"),
                granted_by="system",
            )
        if password:
            set_password(existing.id, password)
        refreshed = get_account(existing.id)
        return refreshed if refreshed is not None else existing

    account = create_account(
        AccountCreate(
            email=email,
            full_name=full_name,
            initial_role=RoleAssignmentRequest(role_code="platform_owner"),
            password=password,
            created_by="system",
        )
    )
    return account


def _find_by_email(email: str) -> Account | None:
    with connection() as conn, conn.cursor() as cur:
        cur.execute("select id from accounts where email = %s", (email,))
        row = cur.fetchone()
    if row is None:
        return None
    return get_account(row["id"])

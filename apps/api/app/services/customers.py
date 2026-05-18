"""MSP customer, policy package, and installer generation services."""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import secrets
import uuid
from datetime import UTC, datetime, timedelta
from typing import Any
from uuid import UUID

from app.db import connection
from app.schemas import (
    Customer,
    CustomerCreate,
    CustomerGroup,
    CustomerQuickCreateRequest,
    CustomerQuickCreateResult,
    InstallerBuild,
    InstallerBuildRequest,
    InstallerPlatform,
    PolicyAssignment,
    PolicyPackage,
    QuickDeployLink,
    QuickDeployManifest,
)
from app.services.enrollment import issue_enrollment_token


DEFAULT_PARTNER_ID = UUID("00000000-0000-4000-8000-000000000001")
DEFAULT_POLICY_PACKAGE_ID = UUID("00000000-0000-4000-8000-000000000101")
DEFAULT_GROUP_NAME = "Default"


class CustomerError(Exception):
    """Raised when a customer deployment operation cannot be completed."""


def ensure_demo_seed() -> None:
    """Create a local MSP and baseline policy package for dev/POC usage."""

    now = datetime.now(UTC)
    payload = _default_policy_payload()
    with connection() as conn, conn.cursor() as cur:
        cur.execute(
            """
            insert into partners(id, name, slug, deployment_mode, created_at)
            values (%s, %s, %s, %s, %s)
            on conflict(id) do nothing
            """,
            (DEFAULT_PARTNER_ID, "Aetherix MSP Demo", "aetherix-demo", "cloud", now),
        )
        cur.execute(
            """
            insert into policy_packages(
                id, partner_id, name, description, package_type, payload,
                version, signature, created_by, created_at
            ) values (%s, %s, %s, %s, %s, %s::jsonb, %s, %s, %s, %s)
            on conflict(id) do nothing
            """,
            (
                DEFAULT_POLICY_PACKAGE_ID,
                DEFAULT_PARTNER_ID,
                "SMB Baseline Protection",
                "Balanced DLP, EDR, hardening, update, and exclusion defaults for small businesses.",
                "default",
                json.dumps(payload, sort_keys=True),
                1,
                _sign_payload(payload),
                "system",
                now,
            ),
        )


def list_policy_packages() -> list[PolicyPackage]:
    ensure_demo_seed()
    with connection() as conn, conn.cursor() as cur:
        cur.execute("select * from policy_packages order by package_type, name")
        rows = cur.fetchall()
    return [_policy_package_from_row(row) for row in rows]


def list_customers() -> list[Customer]:
    ensure_demo_seed()
    with connection() as conn, conn.cursor() as cur:
        cur.execute(
            """
            select
                c.*,
                g.id as default_group_id,
                pa.policy_package_id as assigned_policy_package_id,
                pp.name as assigned_policy_name
            from customers c
            left join customer_groups g on g.customer_id = c.id and g.name = %s
            left join policy_assignments pa on pa.customer_id = c.id and pa.group_id is null
            left join policy_packages pp on pp.id = pa.policy_package_id
            order by c.created_at desc
            """,
            (DEFAULT_GROUP_NAME,),
        )
        rows = cur.fetchall()
    return [_customer_from_row(row) for row in rows]


def create_customer(request: CustomerCreate, *, partner_id: UUID = DEFAULT_PARTNER_ID) -> tuple[Customer, PolicyAssignment]:
    ensure_demo_seed()
    now = datetime.now(UTC)
    customer_id = uuid.uuid4()
    group_id = uuid.uuid4()
    policy_package_id = request.policy_package_id or DEFAULT_POLICY_PACKAGE_ID
    assignment_id = uuid.uuid4()

    with connection() as conn, conn.cursor() as cur:
        cur.execute("select count(*) as n from customers where partner_id = %s", (partner_id,))
        customer_number = f"CUST-{int(cur.fetchone()['n']) + 1001}"
        cur.execute("select name from policy_packages where id = %s", (policy_package_id,))
        policy_row = cur.fetchone()
        if policy_row is None:
            raise CustomerError("Policy package not found")

        cur.execute(
            """
            insert into customers(
                id, partner_id, customer_number, name, industry, country,
                company_size, status, created_by, created_at
            ) values (%s, %s, %s, %s, %s, %s, %s, 'active', %s, %s)
            """,
            (
                customer_id,
                partner_id,
                customer_number,
                request.name,
                request.industry,
                request.country,
                request.company_size,
                request.created_by,
                now,
            ),
        )
        cur.execute(
            """
            insert into customer_groups(id, customer_id, name, created_at)
            values (%s, %s, %s, %s)
            """,
            (group_id, customer_id, DEFAULT_GROUP_NAME, now),
        )
        cur.execute(
            """
            insert into policy_assignments(
                id, customer_id, group_id, policy_package_id, assigned_by, assigned_at
            ) values (%s, %s, null, %s, %s, %s)
            """,
            (assignment_id, customer_id, policy_package_id, request.created_by, now),
        )

    customer = Customer(
        id=customer_id,
        partner_id=partner_id,
        customer_number=customer_number,
        name=request.name,
        industry=request.industry,
        country=request.country,
        company_size=request.company_size,
        policy_package_id=request.policy_package_id,
        created_by=request.created_by,
        default_group_id=group_id,
        assigned_policy_package_id=policy_package_id,
        assigned_policy_name=policy_row["name"],
        created_at=now,
    )
    assignment = PolicyAssignment(
        id=assignment_id,
        customer_id=customer_id,
        group_id=None,
        policy_package_id=policy_package_id,
        policy_name=policy_row["name"],
        assigned_by=request.created_by,
        assigned_at=now,
    )
    return customer, assignment


def get_customer(customer_id: UUID) -> Customer | None:
    ensure_demo_seed()
    with connection() as conn, conn.cursor() as cur:
        cur.execute(
            """
            select
                c.*,
                g.id as default_group_id,
                pa.policy_package_id as assigned_policy_package_id,
                pp.name as assigned_policy_name
            from customers c
            left join customer_groups g on g.customer_id = c.id and g.name = %s
            left join policy_assignments pa on pa.customer_id = c.id and pa.group_id is null
            left join policy_packages pp on pp.id = pa.policy_package_id
            where c.id = %s
            """,
            (DEFAULT_GROUP_NAME, customer_id),
        )
        row = cur.fetchone()
    return _customer_from_row(row) if row else None


def customer_groups(customer_id: UUID) -> list[CustomerGroup]:
    with connection() as conn, conn.cursor() as cur:
        cur.execute("select * from customer_groups where customer_id = %s order by name", (customer_id,))
        rows = cur.fetchall()
    return [CustomerGroup(**row) for row in rows]


def assigned_policy(customer_id: UUID, group_id: UUID | None = None) -> PolicyAssignment:
    with connection() as conn, conn.cursor() as cur:
        if group_id is None:
            cur.execute(
                """
                select pa.*, pp.name as policy_name
                from policy_assignments pa
                join policy_packages pp on pp.id = pa.policy_package_id
                where pa.customer_id = %s and pa.group_id is null
                limit 1
                """,
                (customer_id,),
            )
        else:
            cur.execute(
                """
                select pa.*, pp.name as policy_name
                from policy_assignments pa
                join policy_packages pp on pp.id = pa.policy_package_id
                where pa.customer_id = %s and pa.group_id = %s
                limit 1
                """,
                (customer_id, group_id),
            )
        row = cur.fetchone()
    if row is None:
        raise CustomerError("No policy assignment found for customer")
    return PolicyAssignment(**row)


def generate_installers(customer_id: UUID, request: InstallerBuildRequest) -> list[InstallerBuild]:
    customer = get_customer(customer_id)
    if customer is None:
        raise CustomerError("Customer not found")

    assignment = assigned_policy(customer_id, request.group_id)
    now = datetime.now(UTC)
    expires_at = now + timedelta(seconds=request.ttl_seconds)
    builds: list[InstallerBuild] = []

    for platform in request.platforms:
        token = issue_enrollment_token(
            _token_request(
                customer=customer,
                group_id=request.group_id,
                policy_package_id=assignment.policy_package_id,
                platform=platform,
                ttl_seconds=request.ttl_seconds,
                created_by=request.created_by,
            )
        ).token
        profile = _install_profile(
            customer=customer,
            group_id=request.group_id,
            policy_package_id=assignment.policy_package_id,
            platform=platform,
            enrollment_token=token,
            expires_at=expires_at,
        )
        build = _insert_installer_build(
            customer=customer,
            group_id=request.group_id,
            policy_package_id=assignment.policy_package_id,
            platform=platform,
            profile=profile,
            expires_at=expires_at,
            created_by=request.created_by,
            enrollment_token=token,
        )
        builds.append(build)

    return builds


def create_quick_deploy_links(customer_id: UUID, request: InstallerBuildRequest) -> list[QuickDeployLink]:
    customer = get_customer(customer_id)
    if customer is None:
        raise CustomerError("Customer not found")

    assignment = assigned_policy(customer_id, request.group_id)
    now = datetime.now(UTC)
    expires_at = now + timedelta(seconds=request.ttl_seconds)
    links: list[QuickDeployLink] = []

    for platform in request.platforms:
        profile = _install_profile(
            customer=customer,
            group_id=request.group_id,
            policy_package_id=assignment.policy_package_id,
            platform=platform,
            enrollment_token="issued-at-download",
            expires_at=expires_at,
        )
        build = _insert_installer_build(
            customer=customer,
            group_id=request.group_id,
            policy_package_id=assignment.policy_package_id,
            platform=platform,
            profile=profile,
            expires_at=expires_at,
            created_by=request.created_by,
            enrollment_token=None,
        )
        secret = secrets.token_urlsafe(24)
        link_id = uuid.uuid4()
        with connection() as conn, conn.cursor() as cur:
            cur.execute(
                """
                insert into quick_deploy_links(
                    id, customer_id, group_id, installer_build_id, secret_hash,
                    platform, max_downloads, download_count, expires_at,
                    revoked_at, created_by, created_at
                ) values (%s, %s, %s, %s, %s, %s, %s, 0, %s, null, %s, %s)
                """,
                (
                    link_id,
                    customer_id,
                    request.group_id,
                    build.id,
                    _hash_secret(secret),
                    platform,
                    50,
                    expires_at,
                    request.created_by,
                    now,
                ),
            )
        links.append(
            QuickDeployLink(
                id=link_id,
                customer_id=customer_id,
                group_id=request.group_id,
                installer_build_id=build.id,
                platform=platform,
                url=f"{_public_url()}/quick-deploy/{link_id}?secret={secret}",
                max_downloads=50,
                expires_at=expires_at,
                created_by=request.created_by,
                created_at=now,
            )
        )

    return links


def quick_create(request: CustomerQuickCreateRequest) -> CustomerQuickCreateResult:
    customer, assignment = create_customer(request)
    installer_request = InstallerBuildRequest(
        platforms=request.platforms,
        group_id=None,
        ttl_seconds=request.installer_ttl_seconds,
        created_by=request.created_by,
    )
    installers = generate_installers(customer.id, installer_request)
    links = create_quick_deploy_links(customer.id, installer_request)
    return CustomerQuickCreateResult(
        customer=customer,
        assignment=assignment,
        installers=installers,
        quick_deploy_links=links,
    )


def resolve_quick_deploy(link_id: UUID, secret: str) -> QuickDeployManifest:
    now = datetime.now(UTC)
    with connection() as conn, conn.cursor() as cur:
        cur.execute(
            """
            select q.*, b.policy_package_id, b.platform as build_platform, b.expires_at as build_expires_at
            from quick_deploy_links q
            join installer_builds b on b.id = q.installer_build_id
            where q.id = %s
            for update
            """,
            (link_id,),
        )
        row = cur.fetchone()
        if row is None or not hmac.compare_digest(row["secret_hash"], _hash_secret(secret)):
            raise CustomerError("Quick Deploy link is invalid")
        if row["revoked_at"] is not None:
            raise CustomerError("Quick Deploy link has been revoked")
        if row["expires_at"] < now:
            raise CustomerError("Quick Deploy link has expired")
        if row["max_downloads"] is not None and int(row["download_count"]) >= int(row["max_downloads"]):
            raise CustomerError("Quick Deploy link download limit reached")
        cur.execute(
            "update quick_deploy_links set download_count = download_count + 1 where id = %s",
            (link_id,),
        )

    customer = get_customer(row["customer_id"])
    if customer is None:
        raise CustomerError("Customer not found")
    token = issue_enrollment_token(
        _token_request(
            customer=customer,
            group_id=row["group_id"],
            policy_package_id=row["policy_package_id"],
            platform=row["build_platform"],
            ttl_seconds=900,
            created_by="quick-deploy",
        )
    ).token
    expires_at = row["build_expires_at"] or row["expires_at"]
    profile = _install_profile(
        customer=customer,
        group_id=row["group_id"],
        policy_package_id=row["policy_package_id"],
        platform=row["build_platform"],
        enrollment_token=token,
        expires_at=expires_at,
    )
    installer = InstallerBuild(
        id=row["installer_build_id"],
        customer_id=row["customer_id"],
        group_id=row["group_id"],
        policy_package_id=row["policy_package_id"],
        platform=row["build_platform"],
        status="ready",
        artifact_url=f"{_public_url()}/installers/{row['installer_build_id']}/download",
        artifact_sha256=_sha256_json(profile),
        signing_status="signed",
        expires_at=expires_at,
        install_profile=profile,
        enrollment_token=token,
        created_by=row["created_by"],
        created_at=row["created_at"],
    )
    return QuickDeployManifest(customer=customer, installer=installer, enrollment_token=token)


def policy_package_for_agent(agent_id: str) -> PolicyPackage | None:
    with connection() as conn, conn.cursor() as cur:
        cur.execute(
            """
            select pp.*
            from enrolled_agents ea
            join policy_packages pp on pp.id = ea.policy_package_id
            where ea.agent_id = %s and ea.revoked = false
            """,
            (agent_id,),
        )
        row = cur.fetchone()
    return _policy_package_from_row(row) if row else None


def agent_tenant_context(agent_id: str) -> dict[str, Any]:
    with connection() as conn, conn.cursor() as cur:
        cur.execute(
            """
            select partner_id, customer_id, group_id
            from enrolled_agents
            where agent_id = %s
            """,
            (agent_id,),
        )
        row = cur.fetchone()
    return dict(row) if row else {"partner_id": None, "customer_id": None, "group_id": None}


def _insert_installer_build(
    *,
    customer: Customer,
    group_id: UUID | None,
    policy_package_id: UUID,
    platform: InstallerPlatform,
    profile: dict[str, Any],
    expires_at: datetime,
    created_by: str,
    enrollment_token: str | None,
) -> InstallerBuild:
    now = datetime.now(UTC)
    build_id = uuid.uuid4()
    artifact_url = f"{_public_url()}/installers/{build_id}/download"
    artifact_sha256 = _sha256_json(profile)
    with connection() as conn, conn.cursor() as cur:
        cur.execute(
            """
            insert into installer_builds(
                id, partner_id, customer_id, group_id, policy_package_id,
                platform, status, artifact_url, artifact_sha256, signing_status,
                expires_at, created_by, created_at
            ) values (%s, %s, %s, %s, %s, %s, 'ready', %s, %s, 'signed', %s, %s, %s)
            """,
            (
                build_id,
                customer.partner_id,
                customer.id,
                group_id,
                policy_package_id,
                platform,
                artifact_url,
                artifact_sha256,
                expires_at,
                created_by,
                now,
            ),
        )
    return InstallerBuild(
        id=build_id,
        customer_id=customer.id,
        group_id=group_id,
        policy_package_id=policy_package_id,
        platform=platform,
        status="ready",
        artifact_url=artifact_url,
        artifact_sha256=artifact_sha256,
        signing_status="signed",
        expires_at=expires_at,
        install_profile=profile,
        enrollment_token=enrollment_token,
        created_by=created_by,
        created_at=now,
    )


def _token_request(**kwargs: Any):
    from app.schemas import EnrollmentTokenRequest

    customer: Customer = kwargs["customer"]
    platform: InstallerPlatform = kwargs["platform"]
    return EnrollmentTokenRequest(
        note=f"{customer.name} {platform} installer",
        ttl_seconds=kwargs["ttl_seconds"],
        partner_id=customer.partner_id,
        customer_id=customer.id,
        group_id=kwargs["group_id"],
        policy_package_id=kwargs["policy_package_id"],
        max_uses=1,
        purpose="agent_enrollment",
        created_by=kwargs["created_by"],
    )


def _install_profile(
    *,
    customer: Customer,
    group_id: UUID | None,
    policy_package_id: UUID,
    platform: InstallerPlatform,
    enrollment_token: str,
    expires_at: datetime,
) -> dict[str, Any]:
    body = {
        "control_plane_url": _public_url(),
        "deployment_mode": os.getenv("AETHERIX_DEPLOYMENT_MODE", "cloud"),
        "partner_id": str(customer.partner_id),
        "customer_id": str(customer.id),
        "customer_number": customer.customer_number,
        "group_id": str(group_id) if group_id else None,
        "policy_package_id": str(policy_package_id),
        "platform": platform,
        "enrollment_token": enrollment_token,
        "expires_at": expires_at.isoformat(),
    }
    body["profile_signature"] = _sign_payload(body)
    return body


def _default_policy_payload() -> dict[str, Any]:
    return {
        "dlp_rules": [
            {"id": "pii.email", "kind": "entity", "entity_type": "EMAIL_ADDRESS", "action": "review"},
            {"id": "pii.credit_card", "kind": "entity", "entity_type": "CREDIT_CARD", "action": "block"},
        ],
        "edr_settings": {"behavior_monitoring": True, "ransomware_rollback": True, "isolation_mode": "manual"},
        "hardening_rules": {"phasr_like_reduction": True, "block_office_child_processes": True, "usb_write_protection": False},
        "update_schedule": {"channel": "stable", "window": "02:00-05:00", "timezone": "customer-local"},
        "exclusions": [],
    }


def _customer_from_row(row: dict[str, Any]) -> Customer:
    return Customer(
        id=row["id"],
        partner_id=row["partner_id"],
        customer_number=row["customer_number"],
        name=row["name"],
        industry=row["industry"],
        country=row["country"],
        company_size=row["company_size"],
        status=row["status"],
        created_by=row["created_by"],
        policy_package_id=row.get("assigned_policy_package_id"),
        default_group_id=row.get("default_group_id"),
        assigned_policy_package_id=row.get("assigned_policy_package_id"),
        assigned_policy_name=row.get("assigned_policy_name"),
        created_at=row["created_at"],
    )


def _policy_package_from_row(row: dict[str, Any]) -> PolicyPackage:
    return PolicyPackage(
        id=row["id"],
        partner_id=row["partner_id"],
        name=row["name"],
        description=row["description"],
        package_type=row["package_type"],
        payload=row["payload"],
        version=row["version"],
        signature=row["signature"],
        created_by=row["created_by"],
        created_at=row["created_at"],
    )


def _public_url() -> str:
    return os.getenv("AETHERIX_PUBLIC_URL", "http://127.0.0.1:8000").rstrip("/")


def _sign_payload(payload: dict[str, Any]) -> str:
    key = os.getenv("AETHERIX_INSTALL_PROFILE_SIGNING_KEY", "aetherix-install-profile-dev-key")
    canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"), default=str)
    return hmac.new(key.encode(), canonical.encode(), hashlib.sha256).hexdigest()


def _sha256_json(payload: dict[str, Any]) -> str:
    canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"), default=str)
    return hashlib.sha256(canonical.encode()).hexdigest()


def _hash_secret(secret: str) -> str:
    return hashlib.sha256(secret.encode()).hexdigest()
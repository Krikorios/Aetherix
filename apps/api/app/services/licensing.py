"""Subscription catalog + per-company license management.

The Companies+Licensing module separates the *catalog* (what we sell) from
the *entitlement* (what a specific company has). The catalog lives in
``subscriptions``; per-company entitlement in ``company_licenses`` with one
``license_products`` row per product line and a daily rollup in
``license_usage_daily``.

Service functions never enforce RBAC themselves — the API layer composes
``has_permission`` with these calls.
"""

from __future__ import annotations

import hashlib
import json
import secrets
import uuid
from datetime import UTC, date, datetime
from uuid import UUID

from app.db import connection
from app.schemas import (
    CompanyLicense,
    CompanyLicenseAssign,
    LicenseProduct,
    LicenseUsageDay,
    Subscription,
    SubscriptionCreate,
)


class LicensingError(Exception):
    """Domain error for subscription/license operations (maps to 4xx)."""


# ---------------------------------------------------------------------------
# Subscriptions (catalog)
# ---------------------------------------------------------------------------


def _row_to_subscription(row: dict) -> Subscription:
    return Subscription(
        id=row["id"],
        sku=row["sku"],
        display_name=row["display_name"],
        tier=row["tier"],
        core_features=row["core_features"] or [],
        available_addons=row["available_addons"] or [],
        billing_model=row["billing_model"],
        list_price_per_seat=float(row["list_price_per_seat"]),
        created_at=row["created_at"],
    )


def list_subscriptions() -> list[Subscription]:
    with connection() as conn, conn.cursor() as cur:
        cur.execute("select * from subscriptions order by tier, sku")
        return [_row_to_subscription(row) for row in cur.fetchall()]


def get_subscription_by_sku(sku: str) -> Subscription | None:
    with connection() as conn, conn.cursor() as cur:
        cur.execute("select * from subscriptions where sku = %s", (sku,))
        row = cur.fetchone()
    return _row_to_subscription(row) if row else None


def create_subscription(payload: SubscriptionCreate) -> Subscription:
    sub_id = uuid.uuid4()
    now = datetime.now(UTC)
    with connection() as conn, conn.cursor() as cur:
        cur.execute("select 1 from subscriptions where sku = %s", (payload.sku,))
        if cur.fetchone() is not None:
            raise LicensingError(f"subscription sku {payload.sku!r} already exists")
        cur.execute(
            """
            insert into subscriptions (
                id, sku, display_name, tier, core_features, available_addons,
                billing_model, list_price_per_seat, created_at
            )
            values (%s, %s, %s, %s, %s::jsonb, %s::jsonb, %s, %s, %s)
            returning *
            """,
            (
                sub_id,
                payload.sku,
                payload.display_name,
                payload.tier,
                json.dumps(payload.core_features),
                json.dumps(payload.available_addons),
                payload.billing_model,
                payload.list_price_per_seat,
                now,
            ),
        )
        return _row_to_subscription(cur.fetchone())


def ensure_default_catalog() -> None:
    """Seed a minimal Core + add-on catalog for dev/POC usage. Idempotent."""

    if list_subscriptions():
        return
    create_subscription(
        SubscriptionCreate(
            sku="core",
            display_name="Aetherix Core",
            tier="core",
            core_features=[
                "antimalware",
                "web_protection",
                "device_control",
                "behavior_monitoring",
                "firewall",
            ],
            available_addons=[
                "semantic_dlp",
                "agentic_ir",
                "xdr",
                "patch_management",
                "sandbox_analyzer",
                "email_security",
                "mobile_security",
                "full_disk_encryption",
            ],
            billing_model="monthly",
            list_price_per_seat=4.50,
        )
    )
    create_subscription(
        SubscriptionCreate(
            sku="core-plus-xdr",
            display_name="Aetherix Core + XDR",
            tier="advanced",
            core_features=[
                "antimalware",
                "web_protection",
                "device_control",
                "behavior_monitoring",
                "firewall",
            ],
            available_addons=[
                "semantic_dlp",
                "agentic_ir",
                "xdr",
                "patch_management",
                "sandbox_analyzer",
                "email_security",
                "mobile_security",
                "full_disk_encryption",
            ],
            billing_model="monthly",
            list_price_per_seat=7.95,
        )
    )
    create_subscription(
        SubscriptionCreate(
            sku="enterprise",
            display_name="Aetherix Enterprise",
            tier="enterprise",
            core_features=[
                "antimalware",
                "web_protection",
                "device_control",
                "behavior_monitoring",
                "firewall",
                "edr",
            ],
            available_addons=[
                "semantic_dlp",
                "agentic_ir",
                "xdr",
                "patch_management",
                "sandbox_analyzer",
                "email_security",
                "mobile_security",
                "full_disk_encryption",
            ],
            billing_model="annual",
            list_price_per_seat=12.50,
        )
    )


# ---------------------------------------------------------------------------
# Per-company license
# ---------------------------------------------------------------------------


def _generate_license_key() -> str:
    # 4 groups of 5 uppercase alphanumerics: AETHX-XXXXX-XXXXX-XXXXX
    raw = secrets.token_hex(10).upper()
    return f"AETHX-{raw[0:5]}-{raw[5:10]}-{raw[10:15]}"


def _company_hash(customer_id: UUID) -> str:
    digest = hashlib.sha256(f"aetherix:{customer_id}".encode()).hexdigest()
    return digest[:32]


def _row_to_license(row: dict, products: list[LicenseProduct]) -> CompanyLicense:
    return CompanyLicense(
        id=row["id"],
        customer_id=row["customer_id"],
        subscription_id=row["subscription_id"],
        subscription_sku=row["subscription_sku"],
        license_key=row["license_key"],
        company_hash=row["company_hash"],
        payment_plan=row["payment_plan"],
        status=row["status"],
        issued_at=row["issued_at"],
        expires_at=row["expires_at"],
        total_seats=row["total_seats"],
        reserved_seats=row["reserved_seats"],
        auto_renewal=row["auto_renewal"],
        minimum_usage=row["minimum_usage"],
        addons=row["addons"] or [],
        products=products,
        created_at=row["created_at"],
    )


def _load_products(cur, license_id: UUID) -> list[LicenseProduct]:
    cur.execute(
        """
        select id, license_id, product_code, product_name, product_type,
               protection_model, status, total_seats, used_seats, reserved_seats
        from license_products
        where license_id = %s
        order by product_code
        """,
        (license_id,),
    )
    return [LicenseProduct(**row) for row in cur.fetchall()]


def _fetch_license_row(cur, customer_id: UUID) -> dict | None:
    cur.execute(
        """
        select cl.*, s.sku as subscription_sku
        from company_licenses cl
        join subscriptions s on s.id = cl.subscription_id
        where cl.customer_id = %s
        """,
        (customer_id,),
    )
    return cur.fetchone()


def get_license(customer_id: UUID) -> CompanyLicense | None:
    with connection() as conn, conn.cursor() as cur:
        row = _fetch_license_row(cur, customer_id)
        if row is None:
            return None
        products = _load_products(cur, row["id"])
    return _row_to_license(row, products)


def list_licenses(customer_ids: list[UUID]) -> dict[UUID, CompanyLicense]:
    if not customer_ids:
        return {}
    with connection() as conn, conn.cursor() as cur:
        cur.execute(
            """
            select cl.*, s.sku as subscription_sku
            from company_licenses cl
            join subscriptions s on s.id = cl.subscription_id
            where cl.customer_id = any(%s)
            """,
            (customer_ids,),
        )
        rows = cur.fetchall()
        if not rows:
            return {}
        license_ids = [row["id"] for row in rows]
        cur.execute(
            """
            select id, license_id, product_code, product_name, product_type,
                   protection_model, status, total_seats, used_seats, reserved_seats
            from license_products
            where license_id = any(%s)
            order by product_code
            """,
            (license_ids,),
        )
        products_by_license: dict[UUID, list[LicenseProduct]] = {}
        for product_row in cur.fetchall():
            products_by_license.setdefault(product_row["license_id"], []).append(
                LicenseProduct(**product_row)
            )
    return {
        row["customer_id"]: _row_to_license(row, products_by_license.get(row["id"], []))
        for row in rows
    }


def assign_license(
    customer_id: UUID,
    payload: CompanyLicenseAssign,
    *,
    actor: str,
) -> CompanyLicense:
    """Create or replace the active license for a company.

    A company has at most one license row at a time (per the schema). To
    keep history we *update in place* when one exists and *insert* otherwise.
    """

    subscription = get_subscription_by_sku(payload.subscription_sku)
    if subscription is None:
        raise LicensingError(f"unknown subscription sku: {payload.subscription_sku}")

    if payload.reserved_seats > payload.total_seats:
        raise LicensingError("reserved_seats cannot exceed total_seats")

    unknown_addons = [a for a in payload.addons if a not in subscription.available_addons]
    if unknown_addons:
        raise LicensingError(
            f"addons not available on {subscription.sku}: {', '.join(unknown_addons)}"
        )

    now = datetime.now(UTC)
    company_hash = _company_hash(customer_id)

    with connection() as conn, conn.cursor() as cur:
        cur.execute("select 1 from customers where id = %s", (customer_id,))
        if cur.fetchone() is None:
            raise LicensingError("company not found")

        existing = _fetch_license_row(cur, customer_id)
        if existing is None:
            license_id = uuid.uuid4()
            license_key = _generate_license_key()
            cur.execute(
                """
                insert into company_licenses (
                    id, customer_id, subscription_id, license_key, company_hash,
                    payment_plan, status, issued_at, expires_at,
                    total_seats, reserved_seats, auto_renewal, minimum_usage,
                    addons, created_by, created_at
                )
                values (
                    %s, %s, %s, %s, %s,
                    %s, 'active', %s, %s,
                    %s, %s, %s, %s,
                    %s::jsonb, %s, %s
                )
                """,
                (
                    license_id,
                    customer_id,
                    subscription.id,
                    license_key,
                    company_hash,
                    payload.payment_plan,
                    now,
                    payload.expires_at,
                    payload.total_seats,
                    payload.reserved_seats,
                    payload.auto_renewal,
                    payload.minimum_usage,
                    json.dumps(payload.addons),
                    actor,
                    now,
                ),
            )
        else:
            license_id = existing["id"]
            cur.execute(
                """
                update company_licenses
                set subscription_id = %s,
                    payment_plan = %s,
                    expires_at = %s,
                    total_seats = %s,
                    reserved_seats = %s,
                    auto_renewal = %s,
                    minimum_usage = %s,
                    addons = %s::jsonb,
                    status = 'active'
                where id = %s
                """,
                (
                    subscription.id,
                    payload.payment_plan,
                    payload.expires_at,
                    payload.total_seats,
                    payload.reserved_seats,
                    payload.auto_renewal,
                    payload.minimum_usage,
                    json.dumps(payload.addons),
                    license_id,
                ),
            )

        # Materialize product rows. If the caller supplied explicit products
        # use them; otherwise derive a single Endpoint Security row from the
        # totals and one row per enabled addon.
        cur.execute("delete from license_products where license_id = %s", (license_id,))
        product_rows = _build_product_rows(
            license_id=license_id,
            payload=payload,
            subscription_sku=subscription.sku,
        )
        for prod in product_rows:
            cur.execute(
                """
                insert into license_products (
                    id, license_id, product_code, product_name, product_type,
                    protection_model, status, total_seats, used_seats, reserved_seats
                ) values (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                """,
                (
                    prod.id,
                    prod.license_id,
                    prod.product_code,
                    prod.product_name,
                    prod.product_type,
                    prod.protection_model,
                    prod.status,
                    prod.total_seats,
                    prod.used_seats,
                    prod.reserved_seats,
                ),
            )

        # Mirror license totals onto the customer for table rendering.
        cur.execute(
            """
            update customers
            set auto_renewal = %s, minimum_usage = %s
            where id = %s
            """,
            (payload.auto_renewal, payload.minimum_usage, customer_id),
        )

        row = _fetch_license_row(cur, customer_id)
        products = _load_products(cur, license_id)

    assert row is not None
    return _row_to_license(row, products)


def _build_product_rows(
    *,
    license_id: UUID,
    payload: CompanyLicenseAssign,
    subscription_sku: str,
) -> list[LicenseProduct]:
    if payload.products is not None:
        return [
            LicenseProduct(
                id=p.id or uuid.uuid4(),
                license_id=license_id,
                product_code=p.product_code,
                product_name=p.product_name,
                product_type=p.product_type,
                protection_model=p.protection_model,
                status=p.status,
                total_seats=p.total_seats,
                used_seats=p.used_seats,
                reserved_seats=p.reserved_seats,
            )
            for p in payload.products
        ]

    rows = [
        LicenseProduct(
            id=uuid.uuid4(),
            license_id=license_id,
            product_code="endpoint_security",
            product_name="Endpoint Security",
            product_type="endpoint",
            protection_model="bundled",
            status="active",
            total_seats=payload.total_seats,
            used_seats=0,
            reserved_seats=payload.reserved_seats,
        )
    ]
    addon_catalog = {
        "semantic_dlp": ("Semantic DLP", "endpoint"),
        "agentic_ir": ("Agentic IR", "endpoint"),
        "xdr": ("XDR", "endpoint"),
        "patch_management": ("Patch Management", "endpoint"),
        "sandbox_analyzer": ("Sandbox Analyzer", "endpoint"),
        "email_security": ("Email Security", "email"),
        "mobile_security": ("Mobile Security", "mobile"),
        "full_disk_encryption": ("Full Disk Encryption", "endpoint"),
    }
    for addon in payload.addons:
        name, ptype = addon_catalog.get(addon, (addon.replace("_", " ").title(), "endpoint"))
        rows.append(
            LicenseProduct(
                id=uuid.uuid4(),
                license_id=license_id,
                product_code=addon,
                product_name=name,
                product_type=ptype,
                protection_model="a_la_carte",
                status="active",
                total_seats=payload.total_seats,
                used_seats=0,
                reserved_seats=0,
            )
        )
    return rows


# ---------------------------------------------------------------------------
# Usage rollups
# ---------------------------------------------------------------------------


def record_daily_usage(
    customer_id: UUID,
    product_code: str,
    *,
    day: date | None = None,
    active_seats: int,
) -> None:
    """Upsert today's usage row, tracking peak_seats as the max observed."""

    day = day or datetime.now(UTC).date()
    with connection() as conn, conn.cursor() as cur:
        cur.execute(
            "select id from company_licenses where customer_id = %s",
            (customer_id,),
        )
        row = cur.fetchone()
        if row is None:
            raise LicensingError("company has no license")
        license_id = row["id"]
        cur.execute(
            """
            insert into license_usage_daily
                (license_id, product_code, day, active_seats, peak_seats)
            values (%s, %s, %s, %s, %s)
            on conflict (license_id, product_code, day) do update
                set active_seats = excluded.active_seats,
                    peak_seats = greatest(license_usage_daily.peak_seats, excluded.peak_seats)
            """,
            (license_id, product_code, day, active_seats, active_seats),
        )


def list_usage(
    customer_id: UUID,
    *,
    since: date | None = None,
    until: date | None = None,
) -> list[LicenseUsageDay]:
    with connection() as conn, conn.cursor() as cur:
        cur.execute(
            "select id from company_licenses where customer_id = %s",
            (customer_id,),
        )
        row = cur.fetchone()
        if row is None:
            return []
        license_id = row["id"]
        clauses = ["license_id = %s"]
        params: list = [license_id]
        if since is not None:
            clauses.append("day >= %s")
            params.append(since)
        if until is not None:
            clauses.append("day <= %s")
            params.append(until)
        cur.execute(
            f"""
            select product_code, day, active_seats, peak_seats
            from license_usage_daily
            where {' and '.join(clauses)}
            order by day, product_code
            """,
            params,
        )
        results = []
        for r in cur.fetchall():
            day_value = r["day"]
            ts = datetime(day_value.year, day_value.month, day_value.day, tzinfo=UTC)
            results.append(
                LicenseUsageDay(
                    product_code=r["product_code"],
                    day=ts,
                    active_seats=r["active_seats"],
                    peak_seats=r["peak_seats"],
                )
            )
    return results


# ---------------------------------------------------------------------------
# Lookups used by RBAC at the API layer
# ---------------------------------------------------------------------------


def partner_id_for_customer(customer_id: UUID) -> UUID | None:
    with connection() as conn, conn.cursor() as cur:
        cur.execute("select partner_id from customers where id = %s", (customer_id,))
        row = cur.fetchone()
    return row["partner_id"] if row else None

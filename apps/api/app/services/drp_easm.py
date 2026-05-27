"""Concrete CRUD service for Digital Risk Protection (DRP) and EASM findings/exposures."""

from __future__ import annotations

import json
import uuid
from datetime import UTC, datetime
from uuid import UUID

from app.db import connection
from app.schemas import (
    Account,
    DRPFinding,
    DRPFindingCreate,
    EASMExposure,
    EASMExposureCreate,
    PermissionLevel,
)
from app.services import tenancy


class ExternalRiskError(ValueError):
    """Domain-level validation or authorization error for DRP/EASM operations."""


# --- helpers ----------------------------------------------------------------

def _now() -> datetime:
    return datetime.now(UTC)


def _row_to_drp_finding(row: dict) -> DRPFinding:
    return DRPFinding(
        id=row["id"],
        customer_id=row["customer_id"],
        asset_id=row["asset_id"],
        asset_display_name=row["asset_display_name"] or "",
        asset_type=row["asset_type"] or None,
        finding_type=row["finding_type"],
        title=row["title"],
        summary=row["summary"],
        source=row["source"],
        severity=row["severity"],
        status=row["status"],
        risk_score=row["risk_score"],
        confidence_score=row["confidence_score"],
        llm_validation=row["llm_validation"],
        screenshot_url=row["screenshot_url"],
        evidence_links=list(row["evidence_links"] or []),
        related_easm_asset_id=row["related_easm_asset_id"],
        detected_at=row["detected_at"],
        created_at=row["created_at"],
    )


def _row_to_easm_exposure(row: dict) -> EASMExposure:
    return EASMExposure(
        id=row["id"],
        customer_id=row["customer_id"],
        asset_id=row["asset_id"],
        asset_display_name=row["asset_display_name"],
        asset_type=row["asset_type"],
        exposure_type=row["exposure_type"],
        title=row["title"],
        summary=row["summary"],
        severity=row["severity"],
        status=row["status"],
        risk_score=row["risk_score"],
        confidence_score=row["confidence_score"],
        ip_address=row["ip_address"],
        fqdn=row["fqdn"],
        cloud_provider=row["cloud_provider"],
        open_ports=list(row["open_ports"] or []),
        tags=list(row["tags"] or []),
        metadata=dict(row["metadata"] or {}),
        first_seen=row["first_seen"],
        last_seen=row["last_seen"],
        created_at=row["created_at"],
        updated_at=row["updated_at"],
    )


def _visible_scope_filter(account: Account) -> tuple[str, list[object]]:
    scope = tenancy.compute_scope(account)
    if scope.is_platform:
        return "true", []

    clauses: list[str] = []
    params: list[object] = []
    if scope.partner_ids:
        clauses.append(f"partner_id = ANY(%s)")
        params.append(list(scope.partner_ids))
    if scope.customer_ids:
        clauses.append(f"customer_id = ANY(%s)")
        params.append(list(scope.customer_ids))

    if not clauses:
        return "false", []
    return " OR ".join(f"({c})" for c in clauses), params


def _require_scope(
    account: Account,
    level: PermissionLevel,
    *,
    partner_id: UUID | None,
    customer_id: UUID | None,
) -> None:
    if not tenancy.has_permission(
        account,
        "policies",
        level,
        partner_id=partner_id,
        customer_id=customer_id,
    ):
        raise ExternalRiskError(f"requires {level} on policies for this scope")


# --- DRP Findings -----------------------------------------------------------

def list_findings(
    account: Account,
    *,
    customer_id: UUID | None = None,
    partner_id: UUID | None = None,
    status: str | None = None,
) -> list[DRPFinding]:
    scope_clause, scope_params = _visible_scope_filter(account)
    filters = [scope_clause]
    params: list[object] = list(scope_params)

    if customer_id is not None:
        filters.append("customer_id = %s")
        params.append(customer_id)
    if partner_id is not None:
        filters.append("partner_id = %s")
        params.append(partner_id)
    if status is not None:
        filters.append("status = %s")
        params.append(status)

    where = " AND ".join(f"({f})" for f in filters)
    with connection() as conn, conn.cursor() as cur:
        cur.execute(
            f"SELECT * FROM drp_findings WHERE {where} ORDER BY created_at DESC LIMIT 200",
            params,
        )
        return [_row_to_drp_finding(r) for r in cur.fetchall()]


def create_finding(
    payload: DRPFindingCreate,
    account: Account,
    *,
    customer_id: UUID,
) -> DRPFinding:
    # Resolve partner_id from customer
    with connection() as conn, conn.cursor() as cur:
        cur.execute("SELECT partner_id FROM customers WHERE id = %s", (customer_id,))
        row = cur.fetchone()
    if row is None:
        raise ExternalRiskError("customer not found")
    partner_id: UUID = row["partner_id"]

    _require_scope(account, "edit", partner_id=partner_id, customer_id=customer_id)

    now = _now()
    finding_id = uuid.uuid4()
    detected_at = payload.detected_at or now

    with connection() as conn, conn.cursor() as cur:
        cur.execute(
            """
            INSERT INTO drp_findings (
                id, customer_id, partner_id, asset_display_name, asset_type,
                finding_type, title, summary, source, severity, status,
                risk_score, confidence_score, llm_validation, screenshot_url,
                evidence_links, detected_at, created_at
            ) VALUES (
                %s, %s, %s, %s, %s,
                %s, %s, %s, %s, %s, %s,
                %s, %s, %s, %s,
                %s::jsonb, %s, %s
            ) RETURNING *
            """,
            (
                finding_id, customer_id, partner_id,
                payload.asset_display_name, payload.asset_type,
                payload.finding_type, payload.title, payload.summary,
                payload.source, payload.severity, "new",
                payload.risk_score, payload.confidence_score,
                payload.llm_validation, payload.screenshot_url,
                json.dumps(payload.evidence_links),
                detected_at, now,
            ),
        )
        return _row_to_drp_finding(cur.fetchone())


def _transition_finding(
    finding_id: UUID,
    account: Account,
    new_status: str,
) -> DRPFinding:
    with connection() as conn, conn.cursor() as cur:
        cur.execute(
            "SELECT * FROM drp_findings WHERE id = %s",
            (finding_id,),
        )
        row = cur.fetchone()
    if row is None:
        raise ExternalRiskError("finding not found")

    _require_scope(
        account, "edit",
        partner_id=row["partner_id"],
        customer_id=row["customer_id"],
    )

    with connection() as conn, conn.cursor() as cur:
        cur.execute(
            "UPDATE drp_findings SET status = %s WHERE id = %s RETURNING *",
            (new_status, finding_id),
        )
        return _row_to_drp_finding(cur.fetchone())


def validate_finding(finding_id: UUID, account: Account) -> DRPFinding:
    """Transition a finding to 'reviewing' (AI/analyst validation step)."""
    return _transition_finding(finding_id, account, "reviewing")


def confirm_takedown(finding_id: UUID, account: Account) -> DRPFinding:
    """Transition a finding to 'confirmed' (takedown initiated)."""
    return _transition_finding(finding_id, account, "confirmed")


# --- EASM Exposures ---------------------------------------------------------

def list_exposures(
    account: Account,
    *,
    customer_id: UUID | None = None,
    partner_id: UUID | None = None,
    status: str | None = None,
) -> list[EASMExposure]:
    scope_clause, scope_params = _visible_scope_filter(account)
    filters = [scope_clause]
    params: list[object] = list(scope_params)

    if customer_id is not None:
        filters.append("customer_id = %s")
        params.append(customer_id)
    if partner_id is not None:
        filters.append("partner_id = %s")
        params.append(partner_id)
    if status is not None:
        filters.append("status = %s")
        params.append(status)

    where = " AND ".join(f"({f})" for f in filters)
    with connection() as conn, conn.cursor() as cur:
        cur.execute(
            f"SELECT * FROM easm_exposures WHERE {where} ORDER BY created_at DESC LIMIT 200",
            params,
        )
        return [_row_to_easm_exposure(r) for r in cur.fetchall()]


def create_exposure(
    payload: EASMExposureCreate,
    account: Account,
    *,
    customer_id: UUID,
) -> EASMExposure:
    with connection() as conn, conn.cursor() as cur:
        cur.execute("SELECT partner_id FROM customers WHERE id = %s", (customer_id,))
        row = cur.fetchone()
    if row is None:
        raise ExternalRiskError("customer not found")
    partner_id: UUID = row["partner_id"]

    _require_scope(account, "edit", partner_id=partner_id, customer_id=customer_id)

    now = _now()
    exposure_id = uuid.uuid4()

    with connection() as conn, conn.cursor() as cur:
        cur.execute(
            """
            INSERT INTO easm_exposures (
                id, customer_id, partner_id, asset_display_name, asset_type,
                exposure_type, title, summary, severity, status,
                risk_score, confidence_score, ip_address, fqdn,
                cloud_provider, open_ports, tags,
                first_seen, last_seen, created_at, updated_at
            ) VALUES (
                %s, %s, %s, %s, %s,
                %s, %s, %s, %s, %s,
                %s, %s, %s, %s,
                %s, %s::jsonb, %s::jsonb,
                %s, %s, %s, %s
            ) RETURNING *
            """,
            (
                exposure_id, customer_id, partner_id,
                payload.asset_display_name, payload.asset_type,
                payload.exposure_type, payload.title, payload.summary,
                payload.severity, "new",
                payload.risk_score, payload.confidence_score,
                payload.ip_address, payload.fqdn,
                payload.cloud_provider,
                json.dumps(payload.open_ports),
                json.dumps(payload.tags),
                now, now, now, now,
            ),
        )
        return _row_to_easm_exposure(cur.fetchone())


def _transition_exposure(
    exposure_id: UUID,
    account: Account,
    new_status: str,
) -> EASMExposure:
    with connection() as conn, conn.cursor() as cur:
        cur.execute(
            "SELECT * FROM easm_exposures WHERE id = %s",
            (exposure_id,),
        )
        row = cur.fetchone()
    if row is None:
        raise ExternalRiskError("exposure not found")

    _require_scope(
        account, "edit",
        partner_id=row["partner_id"],
        customer_id=row["customer_id"],
    )

    now = _now()
    with connection() as conn, conn.cursor() as cur:
        cur.execute(
            "UPDATE easm_exposures SET status = %s, updated_at = %s WHERE id = %s RETURNING *",
            (new_status, now, exposure_id),
        )
        return _row_to_easm_exposure(cur.fetchone())


def investigate_exposure(exposure_id: UUID, account: Account) -> EASMExposure:
    """Transition an exposure to 'investigating'."""
    return _transition_exposure(exposure_id, account, "investigating")


def remediate_exposure(exposure_id: UUID, account: Account) -> EASMExposure:
    """Transition an exposure to 'remediated'."""
    return _transition_exposure(exposure_id, account, "remediated")


# --- Policy view + simulate (Phase 2) --------------------------------------

_DRP_DEFAULT_CONTROLS: dict[str, bool] = {
    "brand_misuse_detection": True,
    "executive_impersonation": True,
    "dark_web_credential_monitoring": True,
    "leaked_secret_detection": True,
}

_EASM_DEFAULT_CONTROLS: dict[str, bool] = {
    "continuous_port_scanning": True,
    "certificate_lifecycle_monitoring": True,
    "cloud_storage_exposure": True,
    "subdomain_takeover_prevention": True,
}

_DRP_EVIDENCE = ["nist-csf-2.0:ID.RA", "iso27001-2022:A.5.7"]
_EASM_EVIDENCE = ["nist-csf-2.0:PR.AC", "iso27001-2022:A.8.20"]

# Actions that mutate the upstream asset / require approval.
_DRP_DESTRUCTIVE = {"takedown", "remediate"}
_EASM_DESTRUCTIVE = {"remediate"}


def _module_policy_view(
    account: Account,
    customer_id: UUID | None,
    module: str,
    defaults: dict[str, bool],
):
    """Resolve effective policy for an external-risk module.

    Falls back to a deterministic protected baseline when no policy is
    assigned (matching the legacy hardcoded UI defaults but sourced
    server-side).
    """

    from app.schemas import ExternalRiskPolicyView
    from app.services import policy_v2 as policy_v2_service

    now = _now()
    policy_version = "v0-default"
    approval_required = True
    controls = dict(defaults)

    if customer_id is not None:
        try:
            effective = policy_v2_service.effective_policy(
                account,
                customer_id=customer_id,
            )
            policy_version = effective.policy_version_hash[:12] or policy_version
            modules = effective.resolved_policy.modules or {}
            module_payload = modules.get(module)
            if isinstance(module_payload, dict):
                approval_required = bool(
                    module_payload.get("approval_required", approval_required)
                )
                module_controls = module_payload.get("controls")
                if isinstance(module_controls, dict):
                    controls = {
                        name: bool(value)
                        for name, value in module_controls.items()
                    }
                elif module_payload.get("enabled", True) is False:
                    controls = {name: False for name in controls}
        except Exception:
            # If policy resolution fails (no assignment, transient db error),
            # fall back to defaults — UI still gets a coherent shape.
            pass

    status = "protected" if any(controls.values()) else "off"
    return ExternalRiskPolicyView(
        policy_version=policy_version,
        last_updated=now,
        status=status,
        approval_required=approval_required,
        controls=controls,
    )


def drp_policy_view(account: Account, customer_id: UUID | None):
    return _module_policy_view(account, customer_id, "drp", _DRP_DEFAULT_CONTROLS)


def easm_policy_view(account: Account, customer_id: UUID | None):
    return _module_policy_view(account, customer_id, "easm", _EASM_DEFAULT_CONTROLS)


def _simulation_preview(
    *,
    detection_id: str,
    action: str,
    destructive: bool,
    approval_required: bool,
    target_label: str,
    evidence: list[str],
):
    from app.schemas import ExternalRiskSimulationPreview

    impact: list[str] = [
        f"Action: {action.replace('_', ' ')} will be applied to {target_label}.",
    ]
    if destructive:
        impact.append(
            "Marks the upstream entity as remediated and emits an evidence event."
        )
    elif action == "investigate":
        impact.append("Moves the entity into the active investigation queue.")
    else:
        impact.append("Records analyst review; no state change to upstream entity.")

    return ExternalRiskSimulationPreview(
        id=f"sim-{uuid.uuid4()}",
        detection_id=detection_id,
        action=action,
        destructive=destructive,
        approval_required=approval_required or destructive,
        affected_systems=1,
        evidence_controls=evidence,
        estimated_impact=impact,
        created_at=_now(),
    )


def simulate_finding(finding_id: UUID, action: str, account: Account):
    with connection() as conn, conn.cursor() as cur:
        cur.execute("SELECT * FROM drp_findings WHERE id = %s", (finding_id,))
        row = cur.fetchone()
    if row is None:
        raise ExternalRiskError("finding not found")
    _require_scope(
        account, "view",
        partner_id=row["partner_id"],
        customer_id=row["customer_id"],
    )
    policy = drp_policy_view(account, row["customer_id"])
    destructive = action in _DRP_DESTRUCTIVE
    return _simulation_preview(
        detection_id=str(finding_id),
        action=action,
        destructive=destructive,
        approval_required=policy.approval_required,
        target_label=row.get("asset_display_name") or "DRP finding",
        evidence=_DRP_EVIDENCE,
    )


def simulate_exposure(exposure_id: UUID, action: str, account: Account):
    with connection() as conn, conn.cursor() as cur:
        cur.execute("SELECT * FROM easm_exposures WHERE id = %s", (exposure_id,))
        row = cur.fetchone()
    if row is None:
        raise ExternalRiskError("exposure not found")
    _require_scope(
        account, "view",
        partner_id=row["partner_id"],
        customer_id=row["customer_id"],
    )
    policy = easm_policy_view(account, row["customer_id"])
    destructive = action in _EASM_DESTRUCTIVE
    return _simulation_preview(
        detection_id=str(exposure_id),
        action=action,
        destructive=destructive,
        approval_required=policy.approval_required,
        target_label=row.get("asset_display_name") or "External exposure",
        evidence=_EASM_EVIDENCE,
    )

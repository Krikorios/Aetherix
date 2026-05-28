"""Policy Engine v2 service layer.

Implements versioned policy documents, simulation gates, assignment resolution,
and entitlement-aware effective policy rendering for agents.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import uuid
from datetime import UTC, datetime
from typing import Any
from uuid import UUID

from app.db import connection
from app.schemas import (
    AgentDlpEvidenceIngest,
    AgentPolicyAck,
    AgentPolicyAckRequest,
    AgentPolicyResponse,
    Account,
    EvidenceEvent,
    EffectivePolicyResponse,
    PolicyPromotion,
    PolicyAssignRequest,
    PolicyAssignmentListItem,
    PolicyAssignmentV2,
    PolicyCreateResponse,
    PolicyDocumentV2,
    PolicyDocumentV2Input,
    PolicyGetResponse,
    PolicyLineageV2,
    PolicyListItemV2,
    PolicyListResponse,
    PolicyPromoteRequest,
    PolicyRollbackRequest,
    PolicyScopeV2,
    PolicySimulationModuleOutcome,
    PolicySimulationRecord,
    PolicySimulationSummaryV2,
    PolicyUpdateInput,
    PolicyVersion,
    PolicyVersionSummary,
)
from app.services import correlation as correlation_service, licensing, tenancy
from app.services.compliance import controls_for_event
from app.services.crypto import canonical_json, _signing_key, signing_key_id
from app.services.policy_v2_runtime import (
    DESTRUCTIVE_ACTIONS,
    EffectivePolicyResolver,
    EvidenceEmitter,
    PolicySimulationService,
    PolicyValidationService,
    policy_payload_hash,
)


class PolicyV2Error(ValueError):
    """Domain-level validation failure for Policy Engine v2."""


REQUIRED_MODULE_KEYS: tuple[str, ...] = (
    "general",
    "tenant_scope",
    "entitlements",
    "deployment_profile",
    "antimalware",
    "behavior_monitoring",
    "anti_exploit",
    "ransomware_mitigation",
    "firewall",
    "network_protection",
    "web_protection",
    "device_control",
    "compliance_evidence",
    "integrations",
    "platform_observability",
    "white_label",
)

CORE_MODULE_KEYS: set[str] = set(REQUIRED_MODULE_KEYS)

ADDON_MODULE_KEYS: set[str] = {
    "classification_labeling",
    "semantic_dlp",
    "genai_guardrails",
    "siem_hids",
    "integrity_monitoring",
    "vulnerability_inventory",
    "digital_risk_protection",
    "external_attack_surface_management",
    "threat_intelligence",
    "takedown_workflows",
    "incident_correlation",
    "agentic_response",
    "ai_settings",
    "ai_reports",
}

ADDON_TO_MODULES: dict[str, set[str]] = {
    "semantic_dlp": {"semantic_dlp", "classification_labeling", "genai_guardrails"},
    "xdr": {
        "siem_hids",
        "integrity_monitoring",
        "vulnerability_inventory",
        "incident_correlation",
        "agentic_response",
        "ai_reports",
    },
    "agentic_ir": {"agentic_response", "incident_correlation", "ai_reports"},
    "threat_intelligence": {"threat_intelligence", "takedown_workflows"},
    "digital_risk_protection": {"digital_risk_protection"},
    "external_attack_surface_management": {"external_attack_surface_management"},
}


def _signature(payload: dict[str, Any]) -> str:
    return hmac.new(_signing_key(), canonical_json(payload).encode(), hashlib.sha256).hexdigest()


def _row_to_policy(row: dict[str, Any]) -> PolicyDocumentV2:
    return PolicyDocumentV2(
        id=row["id"],
        schema_version=row["schema_version"],
        name=row["name"],
        scope=PolicyScopeV2(
            partner_id=row["partner_id"],
            customer_id=row["customer_id"],
            group_id=row["group_id"],
            endpoint_id=row["endpoint_id"],
        ),
        lineage=PolicyLineageV2(),
        modules={},
        white_label_names={},
        status=row["status"],
        latest_version=row["latest_version"],
        active_version=row["active_version"],
        created_at=row["created_at"],
        created_by=row["created_by"],
        updated_at=row["updated_at"],
        updated_by=row["updated_by"],
    )


def _row_to_version(row: dict[str, Any]) -> PolicyVersion:
    return PolicyVersion(
        id=row["id"],
        policy_id=row["policy_id"],
        version=row["version"],
        status=row["status"],
        payload=PolicyDocumentV2Input.model_validate(row["payload"]),
        payload_hash=row["payload_hash"],
        signed_by=row["signed_by"],
        signature=row["signature"],
        signed_payload=row["payload"],
        promoted_from_simulation_id=row["promoted_from_simulation_id"],
        created_at=row["created_at"],
        created_by=row["created_by"],
    )


def _row_to_assignment(row: dict[str, Any]) -> PolicyAssignmentV2:
    return PolicyAssignmentV2(
        id=row["id"],
        policy_id=row["policy_id"],
        policy_version_id=row["policy_version_id"],
        partner_id=row["partner_id"],
        customer_id=row["customer_id"],
        group_id=row["group_id"],
        endpoint_id=row["endpoint_id"],
        assigned_by=row["assigned_by"],
        assigned_at=row["assigned_at"],
    )


def _row_to_simulation(row: dict[str, Any]) -> PolicySimulationRecord:
    return PolicySimulationRecord(
        id=row["id"],
        policy_id=row["policy_id"],
        policy_version_id=row["policy_version_id"],
        status=row["status"],
        summary=PolicySimulationSummaryV2.model_validate(row["summary"]),
        outcomes=[PolicySimulationModuleOutcome.model_validate(item) for item in row["outcomes"]],
        approval_required=row["approval_required"],
        approved=row["approved"],
        approved_by=row["approved_by"],
        approval_reason=row["approval_reason"],
        evidence_event_id=row.get("evidence_event_id"),
        approved_at=row["approved_at"],
        created_at=row["created_at"],
        created_by=row["created_by"],
        evidence_controls=list(row["evidence_controls"]),
    )


def _row_to_promotion(row: dict[str, Any]) -> PolicyPromotion:
    return PolicyPromotion(
        id=row["id"],
        policy_id=row["policy_id"],
        policy_version_id=row["policy_version_id"],
        simulation_id=row["simulation_id"],
        status=row["status"],
        operator_approved=row["operator_approved"],
        approval_reason=row["approval_reason"],
        approver=row["approver"],
        approved_at=row["approved_at"],
        evidence_event_id=row["evidence_event_id"],
        evidence_controls=list(row["evidence_controls"]),
    )


def _module_enabled(module_payload: dict[str, Any]) -> bool:
    if not module_payload:
        return False
    if "enabled" in module_payload:
        return bool(module_payload["enabled"])
    return True


def _scope_dict(scope: PolicyScopeV2) -> dict[str, Any]:
    return {
        "partner_id": str(scope.partner_id) if scope.partner_id else None,
        "customer_id": str(scope.customer_id) if scope.customer_id else None,
        "group_id": str(scope.group_id) if scope.group_id else None,
        "endpoint_id": scope.endpoint_id,
    }


def _default_modules(modules: dict[str, dict[str, Any]]) -> dict[str, dict[str, Any]]:
    full: dict[str, dict[str, Any]] = {}
    for key in REQUIRED_MODULE_KEYS:
        full[key] = dict(modules.get(key) or {})
    for key, value in modules.items():
        if key not in full:
            full[key] = dict(value)
    return full


def _resolve_customer_scope_partners(customer_id: UUID) -> UUID:
    with connection() as conn, conn.cursor() as cur:
        cur.execute("select partner_id from customers where id = %s", (customer_id,))
        row = cur.fetchone()
    if row is None:
        raise PolicyV2Error("customer not found")
    return row["partner_id"]


def _resolve_endpoint_scope(endpoint_id: str) -> tuple[UUID | None, UUID | None, UUID | None]:
    with connection() as conn, conn.cursor() as cur:
        cur.execute(
            """
            select partner_id, customer_id, group_id
            from enrolled_agents
            where agent_id = %s and revoked = false
            """,
            (endpoint_id,),
        )
        row = cur.fetchone()
    if row is None:
        raise PolicyV2Error("endpoint not found")
    return row["partner_id"], row["customer_id"], row["group_id"]


def _assert_scope_access(actor: Account, scope: PolicyScopeV2, *, level: str = "edit") -> None:
    resolved_partner_id = scope.partner_id
    resolved_customer_id = scope.customer_id
    if scope.endpoint_id and (resolved_partner_id is None or resolved_customer_id is None):
        endpoint_partner, endpoint_customer, _ = _resolve_endpoint_scope(scope.endpoint_id)
        resolved_partner_id = resolved_partner_id or endpoint_partner
        resolved_customer_id = resolved_customer_id or endpoint_customer
    if resolved_customer_id and resolved_partner_id is None:
        resolved_partner_id = _resolve_customer_scope_partners(resolved_customer_id)

    if not tenancy.has_permission(
        actor,
        "policies",
        level,
        partner_id=resolved_partner_id,
        customer_id=resolved_customer_id,
    ):
        raise PolicyV2Error("insufficient scope to manage policy for target tenant")


def _licensed_modules(customer_id: UUID | None) -> set[str]:
    if customer_id is None:
        return set(CORE_MODULE_KEYS) | set(ADDON_MODULE_KEYS)

    # If the customer has a subscription_instance whose status is not
    # active/trialing/past_due, treat them as core-only regardless of any
    # legacy company_license row. This is the runtime gate for cancellations
    # and operator-driven suspensions.
    try:
        from app.services import subscriptions as _subs  # local import to avoid cycle

        instance = _subs.get_subscription_for(customer_id)
    except Exception:  # pragma: no cover - defensive; subs table absent in tests w/o init
        instance = None
    if instance is not None and instance.status in {"canceled", "paused"}:
        return set(CORE_MODULE_KEYS)

    licensing.ensure_default_catalog()
    lic = licensing.get_license(customer_id)
    if lic is None:
        core = licensing.get_subscription_by_sku("core")
        if core is None:
            return set(CORE_MODULE_KEYS)
        modules = set(CORE_MODULE_KEYS)
        modules.update(core.core_features)
        return modules

    subscription = licensing.get_subscription_by_sku(lic.subscription_sku)
    modules = set(CORE_MODULE_KEYS)
    if subscription is not None:
        modules.update(subscription.core_features)
    for addon in lic.addons:
        modules.update(ADDON_TO_MODULES.get(addon, {addon}))
    return modules


def _locked_modules(payload: PolicyDocumentV2Input, customer_id: UUID | None) -> list[str]:
    entitled = _licensed_modules(customer_id)
    locked: list[str] = []
    for key, module_payload in payload.modules.items():
        if not _module_enabled(module_payload):
            continue
        if key in entitled or key in CORE_MODULE_KEYS:
            continue
        locked.append(key)
    return sorted(set(locked))


def _validate_payload(payload: PolicyDocumentV2Input) -> None:
    try:
        PolicyValidationService.validate_required_modules(payload, REQUIRED_MODULE_KEYS)
    except ValueError as error:
        raise PolicyV2Error(str(error)) from error


def _ensure_entitlements(payload: PolicyDocumentV2Input) -> list[str]:
    entitled = _licensed_modules(payload.scope.customer_id)
    locked = PolicyValidationService.validate_entitlements(
        payload,
        entitled_modules=entitled,
        core_modules=CORE_MODULE_KEYS,
    )
    if locked:
        raise PolicyV2Error(
            "policy enables modules not entitled for the target company: "
            + ", ".join(locked)
        )
    return locked


def create_policy(payload: PolicyDocumentV2Input, *, actor: Account) -> PolicyCreateResponse:
    _assert_scope_access(actor, payload.scope, level="edit")
    payload = PolicyDocumentV2Input(
        schema_version=payload.schema_version,
        name=payload.name,
        scope=payload.scope,
        lineage=payload.lineage,
        modules=_default_modules(payload.modules),
        white_label_names=payload.white_label_names,
    )
    payload = PolicyDocumentV2Input(
        schema_version=payload.schema_version,
        name=payload.name,
        scope=payload.scope,
        lineage=payload.lineage,
        modules=PolicyValidationService.normalize_semantic_modules(dict(payload.modules)),
        white_label_names=payload.white_label_names,
    )
    _validate_payload(payload)
    try:
        PolicyValidationService.validate_semantic_modules(payload)
    except ValueError as error:
        raise PolicyV2Error(str(error)) from error
    _ensure_entitlements(payload)

    now = datetime.now(UTC)
    policy_id = uuid.uuid4()
    version_id = uuid.uuid4()
    payload_json = payload.model_dump(mode="json")
    payload_hash = policy_payload_hash(payload_json)
    signature = _signature(payload_json)
    controls = controls_for_event("policy_v2.create")

    with connection() as conn, conn.cursor() as cur:
        cur.execute(
            """
            insert into policy_documents_v2 (
                id, name, schema_version, status,
                partner_id, customer_id, group_id, endpoint_id,
                latest_version, active_version,
                created_at, created_by, updated_at, updated_by,
                evidence_controls
            ) values (
                %s, %s, '2.0', 'draft',
                %s, %s, %s, %s,
                1, null,
                %s, %s, %s, %s,
                %s::jsonb
            )
            """,
            (
                policy_id,
                payload.name,
                payload.scope.partner_id,
                payload.scope.customer_id,
                payload.scope.group_id,
                payload.scope.endpoint_id,
                now,
                str(actor.id),
                now,
                str(actor.id),
                json.dumps(controls),
            ),
        )
        cur.execute(
            """
            insert into policy_versions (
                id, policy_id, version, status, payload, payload_hash,
                signed_by, signature, promoted_from_simulation_id,
                created_at, created_by, evidence_controls
            ) values (
                %s, %s, 1, 'draft', %s::jsonb, %s,
                %s, %s, null,
                %s, %s, %s::jsonb
            )
            """,
            (
                version_id,
                policy_id,
                json.dumps(payload_json),
                payload_hash,
                signing_key_id(),
                signature,
                now,
                str(actor.id),
                json.dumps(controls),
            ),
        )

    policy = PolicyDocumentV2(
        id=policy_id,
        schema_version="2.0",
        name=payload.name,
        scope=payload.scope,
        lineage=payload.lineage,
        modules=payload.modules,
        white_label_names=payload.white_label_names,
        status="draft",
        latest_version=1,
        active_version=None,
        created_at=now,
        created_by=str(actor.id),
        updated_at=now,
        updated_by=str(actor.id),
    )
    version = PolicyVersion(
        id=version_id,
        policy_id=policy_id,
        version=1,
        status="draft",
        payload=payload,
        payload_hash=payload_hash,
        signed_by=signing_key_id(),
        signature=signature,
        signed_payload=payload_json,
        promoted_from_simulation_id=None,
        created_at=now,
        created_by=str(actor.id),
    )
    EvidenceEmitter.emit(
        action="policy_v2.create",
        resource=f"policy:{policy_id}",
        actor=str(actor.id),
        scope=_scope_dict(payload.scope),
        payload={
            "policy_id": str(policy_id),
            "version": 1,
            "payload_hash": payload_hash,
        },
    )
    return PolicyCreateResponse(policy=policy, version=version)


def delete_policy(policy_id: UUID, *, hard: bool = False, actor: Account) -> None:
    row = _policy_row(policy_id)
    scope = PolicyScopeV2(
        partner_id=row["partner_id"],
        customer_id=row["customer_id"],
        group_id=row["group_id"],
        endpoint_id=row["endpoint_id"],
    )
    _assert_scope_access(actor, scope, level="edit")

    if hard:
        with connection() as conn, conn.cursor() as cur:
            cur.execute(
                "select count(*) as n from policy_assignments_v2 where policy_id = %s",
                (policy_id,),
            )
            if int(cur.fetchone()["n"]) > 0:
                raise PolicyV2Error("cannot hard-delete policy with active assignments; archive it first")

            cur.execute("delete from policy_documents_v2 where id = %s", (policy_id,))
        EvidenceEmitter.emit(
            action="policy_v2.delete",
            resource=f"policy:{policy_id}",
            actor=str(actor.id),
            scope=_scope_dict(scope),
        )
        return

    now = datetime.now(UTC)
    with connection() as conn, conn.cursor() as cur:
        cur.execute(
            "update policy_documents_v2 set status = 'archived', updated_at = %s, updated_by = %s where id = %s",
            (now, str(actor.id), policy_id),
        )
        cur.execute(
            "update policy_versions set status = 'archived' where policy_id = %s",
            (policy_id,),
        )

    EvidenceEmitter.emit(
        action="policy_v2.archive",
        resource=f"policy:{policy_id}",
        actor=str(actor.id),
        scope=_scope_dict(scope),
    )


def update_policy(policy_id: UUID, payload: PolicyUpdateInput, *, actor: Account) -> PolicyCreateResponse:
    row = _policy_row(policy_id)
    current_scope = PolicyScopeV2(
        partner_id=row["partner_id"],
        customer_id=row["customer_id"],
        group_id=row["group_id"],
        endpoint_id=row["endpoint_id"],
    )
    _assert_scope_access(actor, current_scope, level="edit")
    if row["status"] != "draft":
        raise PolicyV2Error("only draft policies can be updated")

    latest = _latest_version(policy_id)
    existing_payload = latest.payload

    updated_modules = existing_payload.modules.copy()
    if payload.modules is not None:
        merged = dict(updated_modules)
        merged.update(payload.modules)
        updated_modules = _default_modules(merged)
        updated_modules = PolicyValidationService.normalize_semantic_modules(updated_modules)

    new_payload = PolicyDocumentV2Input(
        schema_version="2.0",
        name=payload.name if payload.name is not None else existing_payload.name,
        scope=existing_payload.scope,
        lineage=payload.lineage if payload.lineage is not None else existing_payload.lineage,
        modules=updated_modules,
        white_label_names=(
            dict(payload.white_label_names) if payload.white_label_names is not None
            else existing_payload.white_label_names.copy()
        ),
    )

    _validate_payload(new_payload)
    try:
        PolicyValidationService.validate_semantic_modules(new_payload)
    except ValueError as error:
        raise PolicyV2Error(str(error)) from error
    _ensure_entitlements(new_payload)

    now = datetime.now(UTC)
    new_version = latest.version + 1
    version_id = uuid.uuid4()
    payload_json = new_payload.model_dump(mode="json")
    payload_hash = policy_payload_hash(payload_json)
    signature = _signature(payload_json)
    controls = controls_for_event("policy_v2.update")

    with connection() as conn, conn.cursor() as cur:
        cur.execute(
            "update policy_documents_v2 set name = %s, latest_version = %s, updated_at = %s, updated_by = %s, evidence_controls = %s::jsonb where id = %s",
            (new_payload.name, new_version, now, str(actor.id), json.dumps(controls), policy_id),
        )
        cur.execute(
            """
            insert into policy_versions (
                id, policy_id, version, status, payload, payload_hash,
                signed_by, signature, promoted_from_simulation_id,
                created_at, created_by, evidence_controls
            ) values (
                %s, %s, %s, 'draft', %s::jsonb, %s,
                %s, %s, null,
                %s, %s, %s::jsonb
            )
            """,
            (
                version_id,
                policy_id,
                new_version,
                json.dumps(payload_json),
                payload_hash,
                signing_key_id(),
                signature,
                now,
                str(actor.id),
                json.dumps(controls),
            ),
        )

    policy = _row_to_policy(row)
    policy.name = new_payload.name
    policy.latest_version = new_version
    policy.updated_at = now
    policy.updated_by = str(actor.id)
    policy.modules = new_payload.modules
    policy.lineage = new_payload.lineage
    policy.white_label_names = new_payload.white_label_names

    version = PolicyVersion(
        id=version_id,
        policy_id=policy_id,
        version=new_version,
        status="draft",
        payload=new_payload,
        payload_hash=payload_hash,
        signed_by=signing_key_id(),
        signature=signature,
        signed_payload=payload_json,
        promoted_from_simulation_id=None,
        created_at=now,
        created_by=str(actor.id),
    )

    EvidenceEmitter.emit(
        action="policy_v2.update",
        resource=f"policy:{policy_id}",
        actor=str(actor.id),
        scope=_scope_dict(current_scope),
        payload={
            "policy_id": str(policy_id),
            "previous_version": latest.version,
            "new_version": new_version,
            "payload_hash": payload_hash,
        },
        evidence_controls=controls,
    )
    return PolicyCreateResponse(policy=policy, version=version)


def _latest_version(policy_id: UUID) -> PolicyVersion:
    with connection() as conn, conn.cursor() as cur:
        cur.execute(
            """
            select * from policy_versions
            where policy_id = %s
            order by version desc
            limit 1
            """,
            (policy_id,),
        )
        row = cur.fetchone()
    if row is None:
        raise PolicyV2Error("policy version not found")
    return _row_to_version(row)


def _active_or_latest_version(policy_id: UUID) -> PolicyVersion:
    with connection() as conn, conn.cursor() as cur:
        cur.execute(
            """
            select * from policy_versions
            where policy_id = %s and status = 'active'
            order by version desc
            limit 1
            """,
            (policy_id,),
        )
        row = cur.fetchone()
    if row is not None:
        return _row_to_version(row)
    return _latest_version(policy_id)


def _policy_row(policy_id: UUID) -> dict[str, Any]:
    with connection() as conn, conn.cursor() as cur:
        cur.execute("select * from policy_documents_v2 where id = %s", (policy_id,))
        row = cur.fetchone()
    if row is None:
        raise PolicyV2Error("policy not found")
    return row


def list_policies(
    actor: Account,
    *,
    status: str | None = None,
    customer_id: UUID | None = None,
    module: str | None = None,
    limit: int = 50,
    offset: int = 0,
) -> PolicyListResponse:
    if not tenancy.has_permission(actor, "policies", "view"):
        raise PolicyV2Error("requires view on policies")
    scope = tenancy.compute_scope(actor)
    clauses: list[str] = []
    params: list[Any] = []
    if status:
        clauses.append("pd.status = %s")
        params.append(status)
    if customer_id is not None:
        clauses.append("pd.customer_id = %s")
        params.append(customer_id)
    if module:
        clauses.append(
            "exists (select 1 from policy_versions pv where pv.policy_id = pd.id and pv.version = pd.latest_version and pv.payload ? 'modules' and pv.payload->'modules' ? %s)"
        )
        params.append(module)

    if not scope.is_platform:
        if scope.partner_ids:
            clauses.append("(pd.partner_id = any(%s) or pd.customer_id = any(%s))")
            params.append(scope.partner_ids)
            params.append(scope.customer_ids)
        elif scope.customer_ids:
            clauses.append("pd.customer_id = any(%s)")
            params.append(scope.customer_ids)
        else:
            return PolicyListResponse(items=[], total=0, limit=limit, offset=offset)

    where = f"where {' and '.join(clauses)}" if clauses else ""
    with connection() as conn, conn.cursor() as cur:
        cur.execute(
            f"select count(*) as n from policy_documents_v2 pd {where}",
            params,
        )
        total = int(cur.fetchone()["n"])
        cur.execute(
            f"""
            select pd.*
            from policy_documents_v2 pd
            {where}
            order by pd.updated_at desc
            limit %s offset %s
            """,
            [*params, limit, offset],
        )
        rows = cur.fetchall()

    items = [
        PolicyListItemV2(
            id=row["id"],
            name=row["name"],
            status=row["status"],
            latest_version=row["latest_version"],
            active_version=row["active_version"],
            scope=PolicyScopeV2(
                partner_id=row["partner_id"],
                customer_id=row["customer_id"],
                group_id=row["group_id"],
                endpoint_id=row["endpoint_id"],
            ),
            created_at=row["created_at"],
            updated_at=row["updated_at"],
        )
        for row in rows
    ]
    return PolicyListResponse(items=items, total=total, limit=limit, offset=offset)


def _deep_merge(base: Any, override: Any) -> Any:
    return EffectivePolicyResolver.deep_merge(base, override)


def _resolve_lineage_payload(payload: PolicyDocumentV2Input, _seen: set[UUID] | None = None) -> PolicyDocumentV2Input:
    try:
        resolved = EffectivePolicyResolver.resolve_lineage(
            payload,
            parent_loader=lambda parent_id: _active_or_latest_version(parent_id).payload,
            seen=_seen,
        )
        return PolicyDocumentV2Input(
            schema_version=resolved.schema_version,
            name=resolved.name,
            scope=resolved.scope,
            lineage=resolved.lineage,
            modules=PolicyValidationService.normalize_semantic_modules(dict(resolved.modules)),
            white_label_names=resolved.white_label_names,
        )
    except ValueError as error:
        raise PolicyV2Error(str(error)) from error


def list_policy_versions(policy_id: UUID, actor: Account, *, limit: int = 50, offset: int = 0) -> list[PolicyVersionSummary]:
    row = _policy_row(policy_id)
    scope = PolicyScopeV2(
        partner_id=row["partner_id"],
        customer_id=row["customer_id"],
        group_id=row["group_id"],
        endpoint_id=row["endpoint_id"],
    )
    _assert_scope_access(actor, scope, level="view")

    with connection() as conn, conn.cursor() as cur:
        cur.execute(
            """
            select id, version, status, payload_hash, signed_by, created_at, created_by, promoted_from_simulation_id
            from policy_versions
            where policy_id = %s
            order by version desc
            limit %s offset %s
            """,
            (policy_id, limit, offset),
        )
        rows = cur.fetchall()

    return [
        PolicyVersionSummary(
            id=row["id"],
            version=row["version"],
            status=row["status"],
            payload_hash=row["payload_hash"],
            signed_by=row["signed_by"],
            created_at=row["created_at"],
            created_by=row["created_by"],
            promoted_from_simulation_id=row["promoted_from_simulation_id"],
        )
        for row in rows
    ]


def get_policy_version(policy_id: UUID, version: int, actor: Account) -> PolicyVersion:
    row = _policy_row(policy_id)
    scope = PolicyScopeV2(
        partner_id=row["partner_id"],
        customer_id=row["customer_id"],
        group_id=row["group_id"],
        endpoint_id=row["endpoint_id"],
    )
    _assert_scope_access(actor, scope, level="view")
    return _version_by_number(policy_id, version)


def _entitlement_filtered_payload(payload: PolicyDocumentV2Input, customer_id: UUID | None) -> PolicyDocumentV2Input:
    entitled = _licensed_modules(customer_id)
    all_addon_keys = ADDON_MODULE_KEYS - CORE_MODULE_KEYS
    filtered_modules: dict[str, dict[str, Any]] = {}
    for key, module_payload in payload.modules.items():
        if key in CORE_MODULE_KEYS or key in entitled:
            filtered_modules[key] = module_payload
        else:
            filtered_modules[key] = {"enabled": False, "locked": True, "reason": "requires_addon"}
    for key in all_addon_keys:
        if key not in filtered_modules:
            filtered_modules[key] = {"enabled": False, "locked": True, "reason": "requires_addon"}
    return PolicyDocumentV2Input(
        schema_version=payload.schema_version,
        name=payload.name,
        scope=payload.scope,
        lineage=payload.lineage,
        modules=filtered_modules,
        white_label_names=payload.white_label_names,
    )


def get_policy(policy_id: UUID, actor: Account) -> PolicyGetResponse:
    row = _policy_row(policy_id)
    policy_scope = PolicyScopeV2(
        partner_id=row["partner_id"],
        customer_id=row["customer_id"],
        group_id=row["group_id"],
        endpoint_id=row["endpoint_id"],
    )
    _assert_scope_access(actor, policy_scope, level="view")

    latest = _latest_version(policy_id)
    resolved = _resolve_lineage_payload(latest.payload)
    locked = _locked_modules(resolved, resolved.scope.customer_id)
    filtered = _entitlement_filtered_payload(resolved, resolved.scope.customer_id)

    policy = _row_to_policy(row)
    policy.lineage = latest.payload.lineage
    policy.modules = latest.payload.modules
    policy.white_label_names = latest.payload.white_label_names
    return PolicyGetResponse(
        policy=policy,
        latest_version=latest,
        resolved_preview=filtered,
        locked_modules=locked,
    )


def simulate_policy(policy_id: UUID, actor: Account) -> PolicySimulationRecord:
    row = _policy_row(policy_id)
    scope = PolicyScopeV2(
        partner_id=row["partner_id"],
        customer_id=row["customer_id"],
        group_id=row["group_id"],
        endpoint_id=row["endpoint_id"],
    )
    _assert_scope_access(actor, scope, level="edit")

    latest = _latest_version(policy_id)
    payload = _resolve_lineage_payload(latest.payload)
    summary, outcomes = PolicySimulationService.simulate(payload)

    now = datetime.now(UTC)
    simulation_id = uuid.uuid4()
    controls = controls_for_event("policy_v2.simulate")
    evidence_event = EvidenceEmitter.emit(
        action="policy_v2.simulate",
        resource=f"policy:{policy_id}",
        actor=str(actor.id),
        scope=_scope_dict(scope),
        payload={
            "policy_id": str(policy_id),
            "policy_version_id": str(latest.id),
            "simulation_id": str(simulation_id),
            "summary": summary.model_dump(mode="json"),
        },
        evidence_controls=controls,
    )
    if "ransomware_mitigation" in payload.modules:
        rb_controls = controls_for_event("endpoint.rollback.simulated")
        EvidenceEmitter.emit(
            action="endpoint.rollback.simulated",
            resource=f"policy:{policy_id}",
            actor=str(actor.id),
            scope=_scope_dict(scope),
            payload={
                "policy_id": str(policy_id),
                "policy_version_id": str(latest.id),
                "simulation_id": str(simulation_id),
            },
            evidence_controls=rb_controls,
        )
    with connection() as conn, conn.cursor() as cur:
        cur.execute(
            """
            insert into policy_simulations (
                id, policy_id, policy_version_id, status, summary, outcomes,
                approval_required, approved, approved_by, approval_reason,
                approved_at, created_at, created_by, evidence_event_id, evidence_controls
            ) values (
                %s, %s, %s, 'completed', %s::jsonb, %s::jsonb,
                %s, false, null, null,
                null, %s, %s, %s, %s::jsonb
            )
            """,
            (
                simulation_id,
                policy_id,
                latest.id,
                json.dumps(summary.model_dump(mode="json")),
                json.dumps([item.model_dump(mode="json") for item in outcomes]),
                summary.approval_required,
                now,
                str(actor.id),
                evidence_event.id,
                json.dumps(controls),
            ),
        )
        cur.execute("select * from policy_simulations where id = %s", (simulation_id,))
        row = cur.fetchone()
    return _row_to_simulation(row)


def _simulation_for_policy(policy_id: UUID, simulation_id: UUID) -> PolicySimulationRecord:
    with connection() as conn, conn.cursor() as cur:
        cur.execute(
            """
            select * from policy_simulations
            where id = %s and policy_id = %s
            """,
            (simulation_id, policy_id),
        )
        row = cur.fetchone()
    if row is None:
        raise PolicyV2Error("simulation not found for policy")
    return _row_to_simulation(row)


def promote_policy(policy_id: UUID, request: PolicyPromoteRequest, actor: Account) -> PolicyVersion:
    policy_row = _policy_row(policy_id)
    scope = PolicyScopeV2(
        partner_id=policy_row["partner_id"],
        customer_id=policy_row["customer_id"],
        group_id=policy_row["group_id"],
        endpoint_id=policy_row["endpoint_id"],
    )
    _assert_scope_access(actor, scope, level="manage")

    simulation = _simulation_for_policy(policy_id, request.simulation_id)
    if simulation.status != "completed":
        raise PolicyV2Error("simulation is not in a promotable state")

    latest = _latest_version(policy_id)
    if simulation.policy_version_id != latest.id:
        raise PolicyV2Error("simulation must target the latest policy version")

    if simulation.approval_required:
        if not request.operator_approved:
            raise PolicyV2Error("operator approval is required for destructive actions")
        if not request.approval_reason:
            raise PolicyV2Error("approval_reason is required for destructive promotions")

    next_version = latest.version + 1
    now = datetime.now(UTC)
    payload_json = latest.payload.model_dump(mode="json")
    payload_hash = policy_payload_hash(payload_json)
    signature = _signature(payload_json)
    version_id = uuid.uuid4()
    promotion_id = uuid.uuid4()
    controls = controls_for_event("policy_v2.promote")
    evidence_event = EvidenceEmitter.emit(
        action="policy_v2.promote",
        resource=f"policy:{policy_id}",
        actor=str(actor.id),
        scope=_scope_dict(scope),
        payload={
            "policy_id": str(policy_id),
            "from_version": latest.version,
            "to_version": next_version,
            "simulation_id": str(request.simulation_id),
            "operator_approved": request.operator_approved,
            "approval_reason": request.approval_reason,
        },
        evidence_controls=controls,
    )

    with connection() as conn, conn.cursor() as cur:
        cur.execute(
            "update policy_versions set status = 'archived' where policy_id = %s and status = 'active'",
            (policy_id,),
        )
        cur.execute(
            """
            insert into policy_versions (
                id, policy_id, version, status, payload, payload_hash,
                signed_by, signature, promoted_from_simulation_id,
                created_at, created_by, evidence_controls
            ) values (
                %s, %s, %s, 'active', %s::jsonb, %s,
                %s, %s, %s,
                %s, %s, %s::jsonb
            )
            """,
            (
                version_id,
                policy_id,
                next_version,
                json.dumps(payload_json),
                payload_hash,
                signing_key_id(),
                signature,
                request.simulation_id,
                now,
                str(actor.id),
                json.dumps(controls),
            ),
        )
        cur.execute(
            """
            update policy_documents_v2
            set status = 'active', latest_version = %s, active_version = %s,
                updated_at = %s, updated_by = %s
            where id = %s
            """,
            (next_version, next_version, now, str(actor.id), policy_id),
        )
        cur.execute(
            """
            update policy_simulations
            set status = %s,
                approved = %s,
                approved_by = %s,
                approval_reason = %s,
                approved_at = %s
            where id = %s
            """,
            (
                "approved" if request.operator_approved else "completed",
                request.operator_approved,
                str(actor.id) if request.operator_approved else None,
                request.approval_reason,
                now if request.operator_approved else None,
                request.simulation_id,
            ),
        )
        cur.execute(
            """
            insert into policy_promotions (
                id, policy_id, policy_version_id, simulation_id,
                status, operator_approved, approval_reason,
                approver, approved_at, evidence_event_id, evidence_controls
            ) values (
                %s, %s, %s, %s,
                %s, %s, %s,
                %s, %s, %s, %s::jsonb
            )
            """,
            (
                promotion_id,
                policy_id,
                version_id,
                request.simulation_id,
                "approved",
                request.operator_approved,
                request.approval_reason,
                str(actor.id),
                now,
                evidence_event.id,
                json.dumps(controls),
            ),
        )
        cur.execute("select * from policy_versions where id = %s", (version_id,))
        version_row = cur.fetchone()

    return _row_to_version(version_row)


def _version_by_number(policy_id: UUID, version: int) -> PolicyVersion:
    with connection() as conn, conn.cursor() as cur:
        cur.execute(
            "select * from policy_versions where policy_id = %s and version = %s",
            (policy_id, version),
        )
        row = cur.fetchone()
    if row is None:
        raise PolicyV2Error(f"version {version} not found for policy {policy_id}")
    return _row_to_version(row)


def rollback_policy(policy_id: UUID, request: PolicyRollbackRequest, actor: Account) -> PolicyVersion:
    row = _policy_row(policy_id)
    scope = PolicyScopeV2(
        partner_id=row["partner_id"],
        customer_id=row["customer_id"],
        group_id=row["group_id"],
        endpoint_id=row["endpoint_id"],
    )
    _assert_scope_access(actor, scope, level="manage")

    target = _version_by_number(policy_id, request.target_version)
    latest = _latest_version(policy_id)

    if target.version >= latest.version:
        raise PolicyV2Error(f"target version {target.version} is not older than the latest version {latest.version}")

    payload = _resolve_lineage_payload(target.payload)
    summary, _ = PolicySimulationService.simulate(payload)

    if summary.approval_required:
        if not request.operator_approved:
            raise PolicyV2Error("operator approval is required for rollback with destructive actions")
        if not request.approval_reason:
            raise PolicyV2Error("approval_reason is required for destructive rollback")

    next_version = latest.version + 1
    now = datetime.now(UTC)
    payload_json = target.payload.model_dump(mode="json")
    payload_hash = policy_payload_hash(payload_json)
    signature = _signature(payload_json)
    version_id = uuid.uuid4()
    controls = controls_for_event("policy_v2.rollback")
    evidence_event = EvidenceEmitter.emit(
        action="policy_v2.rollback",
        resource=f"policy:{policy_id}",
        actor=str(actor.id),
        scope=_scope_dict(scope),
        payload={
            "policy_id": str(policy_id),
            "from_version": latest.version,
            "to_version": next_version,
            "target_version": target.version,
            "approval_reason": request.approval_reason,
        },
        evidence_controls=controls,
    )

    with connection() as conn, conn.cursor() as cur:
        cur.execute(
            "update policy_versions set status = 'archived' where policy_id = %s and status = 'active'",
            (policy_id,),
        )
        cur.execute(
            """
            insert into policy_versions (
                id, policy_id, version, status, payload, payload_hash,
                signed_by, signature, promoted_from_simulation_id,
                created_at, created_by, evidence_controls
            ) values (
                %s, %s, %s, 'active', %s::jsonb, %s,
                %s, %s, null,
                %s, %s, %s::jsonb
            )
            """,
            (
                version_id,
                policy_id,
                next_version,
                json.dumps(payload_json),
                payload_hash,
                signing_key_id(),
                signature,
                now,
                str(actor.id),
                json.dumps(controls),
            ),
        )
        cur.execute(
            "update policy_documents_v2 set latest_version = %s, active_version = %s, updated_at = %s, updated_by = %s where id = %s",
            (next_version, next_version, now, str(actor.id), policy_id),
        )
        cur.execute("select * from policy_versions where id = %s", (version_id,))
        version_row = cur.fetchone()

    return _row_to_version(version_row)


def assign_policy(request: PolicyAssignRequest, actor: Account) -> PolicyAssignmentV2:
    policy_row = _policy_row(request.policy_id)
    scope = PolicyScopeV2(
        partner_id=request.partner_id or policy_row["partner_id"],
        customer_id=request.customer_id or policy_row["customer_id"],
        group_id=request.group_id,
        endpoint_id=request.endpoint_id,
    )
    _assert_scope_access(actor, scope, level="edit")

    if request.policy_version is None:
        version = _active_or_latest_version(request.policy_id)
    else:
        with connection() as conn, conn.cursor() as cur:
            cur.execute(
                """
                select * from policy_versions
                where policy_id = %s and version = %s
                """,
                (request.policy_id, request.policy_version),
            )
            row = cur.fetchone()
        if row is None:
            raise PolicyV2Error("requested policy version does not exist")
        version = _row_to_version(row)

    resolved_assignment_customer_id = request.customer_id
    if request.endpoint_id and resolved_assignment_customer_id is None:
        _, endpoint_customer_id, _ = _resolve_endpoint_scope(request.endpoint_id)
        resolved_assignment_customer_id = endpoint_customer_id

    resolved_payload = _resolve_lineage_payload(version.payload)
    locked_for_scope = _locked_modules(resolved_payload, resolved_assignment_customer_id)
    if locked_for_scope:
        raise PolicyV2Error(
            "cannot assign policy to scope without required add-on entitlements: "
            + ", ".join(locked_for_scope)
        )

    now = datetime.now(UTC)
    assignment_id = uuid.uuid4()
    controls = controls_for_event("policy_v2.assign")
    with connection() as conn, conn.cursor() as cur:
        cur.execute(
            """
            delete from policy_assignments_v2
            where coalesce(partner_id, '00000000-0000-0000-0000-000000000000'::uuid) = coalesce(%s, '00000000-0000-0000-0000-000000000000'::uuid)
              and coalesce(customer_id, '00000000-0000-0000-0000-000000000000'::uuid) = coalesce(%s, '00000000-0000-0000-0000-000000000000'::uuid)
              and coalesce(group_id, '00000000-0000-0000-0000-000000000000'::uuid) = coalesce(%s, '00000000-0000-0000-0000-000000000000'::uuid)
              and coalesce(endpoint_id, '') = coalesce(%s, '')
            """,
            (
                request.partner_id,
                request.customer_id,
                request.group_id,
                request.endpoint_id,
            ),
        )
        cur.execute(
            """
            insert into policy_assignments_v2 (
                id, policy_id, policy_version_id,
                partner_id, customer_id, group_id, endpoint_id,
                assigned_by, assigned_at, evidence_controls
            ) values (
                %s, %s, %s,
                %s, %s, %s, %s,
                %s, %s, %s::jsonb
            )
            returning *
            """,
            (
                assignment_id,
                request.policy_id,
                version.id,
                request.partner_id,
                request.customer_id,
                request.group_id,
                request.endpoint_id,
                str(actor.id),
                now,
                json.dumps(controls),
            ),
        )
        row = cur.fetchone()
    assignment = _row_to_assignment(row)
    EvidenceEmitter.emit(
        action="policy_v2.assign",
        resource=f"policy:{request.policy_id}",
        actor=str(actor.id),
        scope={
            "partner_id": str(request.partner_id) if request.partner_id else None,
            "customer_id": str(resolved_assignment_customer_id)
            if resolved_assignment_customer_id
            else None,
            "group_id": str(request.group_id) if request.group_id else None,
            "endpoint_id": request.endpoint_id,
        },
        payload={
            "assignment_id": str(assignment.id),
            "policy_version_id": str(version.id),
            "locked_modules": locked_for_scope,
        },
        evidence_controls=controls,
    )
    return assignment


def _assignments_for_scope(scope: PolicyScopeV2) -> list[PolicyAssignmentV2]:
    clauses: list[str] = ["(partner_id is null and customer_id is null and group_id is null and endpoint_id is null)"]
    params: list[Any] = []
    if scope.partner_id is not None:
        clauses.append(
            "(partner_id = %s and customer_id is null and group_id is null and endpoint_id is null)"
        )
        params.append(scope.partner_id)
    if scope.customer_id is not None:
        clauses.append(
            "(customer_id = %s and group_id is null and endpoint_id is null)"
        )
        params.append(scope.customer_id)
    if scope.group_id is not None:
        clauses.append("(group_id = %s and endpoint_id is null)")
        params.append(scope.group_id)
    if scope.endpoint_id is not None:
        clauses.append("(endpoint_id = %s)")
        params.append(scope.endpoint_id)

    with connection() as conn, conn.cursor() as cur:
        cur.execute(
            f"""
            select * from policy_assignments_v2
            where {' or '.join(clauses)}
            order by
                case
                    when endpoint_id is not null then 5
                    when group_id is not null then 4
                    when customer_id is not null then 3
                    when partner_id is not null then 2
                    else 0
                end asc,
                assigned_at asc
            """,
            params,
        )
        rows = cur.fetchall()
    return [_row_to_assignment(row) for row in rows]


def _version_by_id(version_id: UUID) -> PolicyVersion:
    with connection() as conn, conn.cursor() as cur:
        cur.execute("select * from policy_versions where id = %s", (version_id,))
        row = cur.fetchone()
    if row is None:
        raise PolicyV2Error("policy version not found")
    return _row_to_version(row)


def system_effective_modules_for_customer(
    customer_id: UUID,
    *,
    endpoint_id: str | None = None,
) -> dict[str, dict[str, Any]]:
    """Return the merged, entitlement-filtered ``modules`` dict for a
    customer (and optionally a specific endpoint), without running any
    actor-level access check.

    This is intended for trusted system-internal code paths (heartbeat
    ingest, evidence emission) that need to consult the effective
    policy. Routes that serve operator traffic should keep using
    :func:`effective_policy`, which performs scope checks and emits an
    audit event.
    """
    partner_id: UUID | None = None
    group_id: UUID | None = None
    if endpoint_id:
        ep_partner_id, ep_customer_id, ep_group_id = _resolve_endpoint_scope(endpoint_id)
        partner_id = ep_partner_id
        if customer_id is None and ep_customer_id is not None:
            customer_id = ep_customer_id
        group_id = ep_group_id
    if partner_id is None and customer_id is not None:
        try:
            partner_id = _resolve_customer_scope_partners(customer_id)
        except PolicyV2Error:
            partner_id = None

    scope = PolicyScopeV2(
        partner_id=partner_id,
        customer_id=customer_id,
        group_id=group_id,
        endpoint_id=endpoint_id,
    )
    assignments = _assignments_for_scope(scope)
    if not assignments:
        return {}

    payloads: list[PolicyDocumentV2Input] = []
    for assignment in assignments:
        version = _version_by_id(assignment.policy_version_id)
        payloads.append(_resolve_lineage_payload(version.payload))

    merged_payload = EffectivePolicyResolver.merge_payloads(payloads)
    if merged_payload is None:
        return {}
    filtered = _entitlement_filtered_payload(merged_payload, customer_id)
    return filtered.modules or {}


def effective_policy(
    actor: Account,
    *,
    endpoint_id: str | None = None,
    partner_id: UUID | None = None,
    customer_id: UUID | None = None,
    group_id: UUID | None = None,
) -> EffectivePolicyResponse:
    if endpoint_id:
        ep_partner_id, ep_customer_id, ep_group_id = _resolve_endpoint_scope(endpoint_id)
        partner_id = partner_id or ep_partner_id
        customer_id = customer_id or ep_customer_id
        group_id = group_id or ep_group_id

    scope = PolicyScopeV2(
        partner_id=partner_id,
        customer_id=customer_id,
        group_id=group_id,
        endpoint_id=endpoint_id,
    )
    _assert_scope_access(actor, scope, level="view")

    assignments = _assignments_for_scope(scope)
    if not assignments:
        empty_payload = PolicyDocumentV2Input(
            schema_version="2.0",
            name="Empty effective policy",
            scope=scope,
            lineage=PolicyLineageV2(),
            modules=_default_modules({}),
            white_label_names={},
        )
        filtered = _entitlement_filtered_payload(empty_payload, customer_id)
        version_hash = policy_payload_hash(filtered.model_dump(mode="json"))
        return EffectivePolicyResponse(
            endpoint_id=endpoint_id,
            scope=scope,
            assignments_applied=[],
            resolved_policy=filtered,
            policy_ids_applied=[],
            policy_version_hash=version_hash,
            evidence_controls=controls_for_event("policy_v2.effective"),
        )

    payloads: list[PolicyDocumentV2Input] = []
    applied_ids: list[UUID] = []
    applied_version_ids: list[UUID] = []
    for assignment in assignments:
        version = _version_by_id(assignment.policy_version_id)
        payload = _resolve_lineage_payload(version.payload)
        payloads.append(payload)
        applied_ids.append(assignment.policy_id)
        applied_version_ids.append(version.id)

    merged_payload = EffectivePolicyResolver.merge_payloads(payloads)
    if merged_payload is None:
        raise PolicyV2Error("unable to resolve effective policy")

    filtered = _entitlement_filtered_payload(merged_payload, customer_id)
    version_hash = policy_payload_hash(filtered.model_dump(mode="json"))
    EvidenceEmitter.emit(
        action="policy_v2.effective",
        resource=f"policy:effective:{endpoint_id or customer_id or partner_id or 'global'}",
        actor=str(actor.id),
        scope=_scope_dict(scope),
        payload={
            "assignments_applied": [str(item.id) for item in assignments],
            "policy_ids_applied": [str(policy_id) for policy_id in applied_ids],
            "policy_version_ids_applied": [str(version_id) for version_id in applied_version_ids],
            "policy_version_hash": version_hash,
        },
    )
    return EffectivePolicyResponse(
        endpoint_id=endpoint_id,
        scope=scope,
        assignments_applied=assignments,
        resolved_policy=filtered,
        policy_ids_applied=applied_ids,
        policy_version_hash=version_hash,
        evidence_controls=controls_for_event("policy_v2.effective"),
    )


def effective_policy_for_agent(endpoint_id: str, token: str) -> AgentPolicyResponse:
    with connection() as conn, conn.cursor() as cur:
        cur.execute(
            """
            select partner_id, customer_id, group_id, secret, revoked
            from enrolled_agents
            where agent_id = %s
            """,
            (endpoint_id,),
        )
        enrolled = cur.fetchone()

    if enrolled is None or enrolled["revoked"]:
        raise PolicyV2Error("agent is not enrolled")
    if not hmac.compare_digest(enrolled["secret"], token):
        raise PolicyV2Error("invalid agent token")

    scope = PolicyScopeV2(
        partner_id=enrolled["partner_id"],
        customer_id=enrolled["customer_id"],
        group_id=enrolled["group_id"],
        endpoint_id=endpoint_id,
    )
    assignments = _assignments_for_scope(scope)
    payloads: list[PolicyDocumentV2Input] = []
    for assignment in assignments:
        version = _version_by_id(assignment.policy_version_id)
        payloads.append(_resolve_lineage_payload(version.payload))

    merged_payload = EffectivePolicyResolver.merge_payloads(payloads)
    if merged_payload is None:
        merged_payload = PolicyDocumentV2Input(
            schema_version="2.0",
            name="Empty effective policy",
            scope=scope,
            lineage=PolicyLineageV2(),
            modules=_default_modules({}),
            white_label_names={},
        )

    filtered = _entitlement_filtered_payload(merged_payload, scope.customer_id)
    version_hash = policy_payload_hash(filtered.model_dump(mode="json"))

    EvidenceEmitter.emit(
        action="policy_v2.agent_fetch",
        resource=f"policy:agent:{endpoint_id}",
        actor=f"agent:{endpoint_id}",
        scope=_scope_dict(scope),
        payload={
            "policy_version_hash": version_hash,
            "assignments_applied": [str(item.id) for item in assignments],
        },
    )
    return AgentPolicyResponse(
        endpoint_id=endpoint_id,
        policy_version_hash=version_hash,
        resolved_policy=filtered,
        evidence_controls=controls_for_event("policy_v2.agent_fetch"),
    )


def ingest_agent_dlp_evidence(endpoint_id: str, token: str, payload: AgentDlpEvidenceIngest) -> EvidenceEvent:
    with connection() as conn, conn.cursor() as cur:
        cur.execute(
            """
            select partner_id, customer_id, group_id, secret, revoked
            from enrolled_agents
            where agent_id = %s
            """,
            (endpoint_id,),
        )
        enrolled = cur.fetchone()

    if enrolled is None or enrolled["revoked"]:
        raise PolicyV2Error("agent is not enrolled")
    if not hmac.compare_digest(enrolled["secret"], token):
        raise PolicyV2Error("invalid agent token")
    if payload.endpoint_id != endpoint_id:
        raise PolicyV2Error("endpoint_id mismatch")

    scope = {
        "partner_id": str(enrolled["partner_id"]) if enrolled["partner_id"] else None,
        "customer_id": str(enrolled["customer_id"]) if enrolled["customer_id"] else None,
        "group_id": str(enrolled["group_id"]) if enrolled["group_id"] else None,
        "endpoint_id": endpoint_id,
        "policy_version": payload.policy_version,
    }

    event = EvidenceEmitter.emit(
        action=f"dlp.{payload.action_type}",
        resource=f"endpoint:{endpoint_id}",
        actor=f"agent:{endpoint_id}",
        scope=scope,
        payload={
            "decision": payload.decision,
            "event_type": payload.event_type,
            "destination": payload.destination,
            "label_detected": payload.label_detected,
            "content_hash": payload.content_hash,
            "sha256_hash": payload.sha256_hash,
            "policy_action_field": payload.policy_action_field,
            "process_name": payload.process_name,
            "endpoint_id": payload.endpoint_id,
        },
    )

    # Persist DLP event in dlp_events table for correlation pipeline
    # when the agent provides a file sha256_hash alongside the DLP evidence.
    try:
        customer_id = enrolled["customer_id"]
        if payload.sha256_hash and customer_id:
            now = datetime.now(UTC)
            dlp_event_id = uuid.uuid4()
            with connection() as conn, conn.cursor() as cur:
                cur.execute(
                    """
                    insert into dlp_events (
                        id, customer_id, endpoint_id, source, action,
                        entity_types, risk_band, sha256_hash,
                        request_preview_hash, observed_at, created_at
                    ) values (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                    """,
                    (
                        dlp_event_id,
                        customer_id,
                        endpoint_id,
                        f"agent:{payload.event_type}",
                        payload.decision,
                        json.dumps([payload.label_detected] if payload.label_detected else []),
                        None,
                        payload.sha256_hash,
                        payload.content_hash[:16],
                        now,
                        now,
                    ),
                )
                correlation_service.correlate_new_dlp_event(
                    cur,
                    dlp_event_id=dlp_event_id,
                    customer_id=customer_id,
                    agent_id=endpoint_id,
                    sha256_hash=payload.sha256_hash,
                    observed_at=now,
                )
    except Exception:
        pass

    return event


def _authenticate_agent(endpoint_id: str, token: str) -> dict[str, Any]:
    with connection() as conn, conn.cursor() as cur:
        cur.execute(
            "select partner_id, customer_id, group_id, secret, revoked from enrolled_agents where agent_id = %s",
            (endpoint_id,),
        )
        enrolled = cur.fetchone()
    if enrolled is None or enrolled["revoked"]:
        raise PolicyV2Error("agent is not enrolled")
    if not hmac.compare_digest(enrolled["secret"], token):
        raise PolicyV2Error("invalid agent token")
    return enrolled


def _assignment_scope_dict(row: dict[str, Any]) -> dict[str, Any]:
    return {
        "partner_id": str(row["partner_id"]) if row["partner_id"] else None,
        "customer_id": str(row["customer_id"]) if row["customer_id"] else None,
        "group_id": str(row["group_id"]) if row["group_id"] else None,
        "endpoint_id": row["endpoint_id"],
    }


def _assignment_scope_type(row: dict[str, Any]) -> tuple[str, str, str]:
    partner_id_val = row["partner_id"]
    customer_id_val = row["customer_id"]
    group_id_val = row["group_id"]
    endpoint_id_val = row["endpoint_id"]

    if partner_id_val and customer_id_val is None and group_id_val is None and endpoint_id_val is None:
        return "partner", f"Partner {partner_id_val}", str(partner_id_val)
    if customer_id_val and group_id_val is None and endpoint_id_val is None:
        return "company", f"Customer {customer_id_val}", str(customer_id_val)
    if group_id_val and endpoint_id_val is None:
        return "group", f"Group {group_id_val}", str(group_id_val)
    if endpoint_id_val:
        return "endpoint", endpoint_id_val, str(endpoint_id_val)
    return "platform", "Aetherix Platform", "platform"


def _assignment_payload_for_row(row: dict[str, Any]) -> PolicyDocumentV2Input:
    version = _version_by_id(row["policy_version_id"])
    return _resolve_lineage_payload(version.payload)


def _effective_for_assignment_target(row: dict[str, Any]) -> PolicyDocumentV2Input:
    endpoint_id = row["endpoint_id"]
    partner_id = row["partner_id"]
    customer_id = row["customer_id"]
    group_id = row["group_id"]
    if endpoint_id:
        ep_partner_id, ep_customer_id, ep_group_id = _resolve_endpoint_scope(endpoint_id)
        partner_id = partner_id or ep_partner_id
        customer_id = customer_id or ep_customer_id
        group_id = group_id or ep_group_id

    scope = PolicyScopeV2(
        partner_id=partner_id,
        customer_id=customer_id,
        group_id=group_id,
        endpoint_id=endpoint_id,
    )

    assignments = _assignments_for_scope(scope)
    payloads: list[PolicyDocumentV2Input] = []
    for assignment in assignments:
        payloads.append(_assignment_payload_for_row({"policy_version_id": assignment.policy_version_id}))

    merged = EffectivePolicyResolver.merge_payloads(payloads)
    if merged is None:
        merged = PolicyDocumentV2Input(
            schema_version="2.0",
            name="Empty effective policy",
            scope=scope,
            lineage=PolicyLineageV2(),
            modules=_default_modules({}),
            white_label_names={},
        )
    return _entitlement_filtered_payload(merged, customer_id)


def _count_endpoints_for_assignment(row: dict[str, Any]) -> int:
    with connection() as conn, conn.cursor() as cur:
        if row["endpoint_id"]:
            cur.execute(
                """
                select count(*) as n
                from enrolled_agents ea
                where ea.revoked = false
                  and ea.agent_id = %s
                """,
                (row["endpoint_id"],),
            )
        elif row["group_id"]:
            cur.execute(
                """
                select count(*) as n
                from enrolled_agents ea
                where ea.revoked = false
                  and ea.group_id = %s
                """,
                (row["group_id"],),
            )
        elif row["customer_id"]:
            cur.execute(
                """
                select count(*) as n
                from enrolled_agents ea
                where ea.revoked = false
                  and ea.customer_id = %s
                """,
                (row["customer_id"],),
            )
        elif row["partner_id"]:
            cur.execute(
                """
                select count(*) as n
                from enrolled_agents ea
                where ea.revoked = false
                  and ea.partner_id = %s
                """,
                (row["partner_id"],),
            )
        else:
            cur.execute(
                """
                select count(*) as n
                from enrolled_agents ea
                where ea.revoked = false
                """
            )
        row_count = cur.fetchone()
    return int(row_count["n"]) if row_count else 0


def _drift_count_for_assignment(row: dict[str, Any]) -> int:
    target_policy = _effective_for_assignment_target(row)
    target_hash = policy_payload_hash(target_policy.model_dump(mode="json"))

    where_sql = ""
    params: list[Any] = []
    if row["endpoint_id"]:
        where_sql = "ea.agent_id = %s"
        params.append(row["endpoint_id"])
    elif row["group_id"]:
        where_sql = "ea.group_id = %s"
        params.append(row["group_id"])
    elif row["customer_id"]:
        where_sql = "ea.customer_id = %s"
        params.append(row["customer_id"])
    elif row["partner_id"]:
        where_sql = "ea.partner_id = %s"
        params.append(row["partner_id"])
    else:
        where_sql = "true"

    with connection() as conn, conn.cursor() as cur:
        cur.execute(
            f"""
            select
                ea.agent_id,
                (
                    select pa.policy_version_hash
                    from policy_acks pa
                    where pa.endpoint_id = ea.agent_id
                    order by pa.acknowledged_at desc
                    limit 1
                ) as ack_hash
            from enrolled_agents ea
            where ea.revoked = false
              and {where_sql}
            """,
            params,
        )
        rows = cur.fetchall()

    drift = 0
    for endpoint in rows:
        if endpoint["ack_hash"] != target_hash:
            drift += 1
    return drift


def _build_assignment_list_item(row: dict[str, Any]) -> PolicyAssignmentListItem:
    scope_type, scope_label, scope_id = _assignment_scope_type(row)
    endpoint_count = _count_endpoints_for_assignment(row)
    drift_count = _drift_count_for_assignment(row)

    with connection() as conn, conn.cursor() as cur:
        cur.execute(
            """
            select created_at, payload
            from evidence_events
            where action = 'policy_v2.apply_diff'
              and payload->>'assignment_id' = %s
            order by created_at desc
            limit 1
            """,
            (str(row["id"]),),
        )
        apply_event = cur.fetchone()

    last_diff = apply_event["created_at"].isoformat() if apply_event else None
    pending_diff: str | None = None
    if drift_count > 0:
        pending_diff = (
            f"{drift_count} endpoint(s) have not acknowledged the current effective policy"
        )

    return PolicyAssignmentListItem(
        id=row["id"],
        scope=scope_type,
        scope_id=scope_id,
        scope_name=scope_label,
        policy_id=row["policy_id"],
        policy_name=row["policy_name"],
        policy_version=f"v{row['policy_version']}",
        inherited=False,
        override=(scope_type != "platform"),
        effective_since=row["assigned_at"],
        last_diff=last_diff,
        pending_diff=pending_diff,
        endpoint_count=endpoint_count,
        drift_count=drift_count,
    )


def agent_acknowledge_policy(endpoint_id: str, token: str, ack: AgentPolicyAckRequest) -> AgentPolicyAck:
    _authenticate_agent(endpoint_id, token)
    now = datetime.now(UTC)
    ack_id = uuid.uuid4()
    with connection() as conn, conn.cursor() as cur:
        cur.execute(
            """
            insert into policy_acks (id, endpoint_id, policy_version_hash, agent_version, acknowledged_at)
            values (%s, %s, %s, %s, %s)
            returning *
            """,
            (ack_id, endpoint_id, ack.policy_version_hash, ack.agent_version, now),
        )
        row = cur.fetchone()
    return AgentPolicyAck(
        id=row["id"],
        endpoint_id=row["endpoint_id"],
        policy_version_hash=row["policy_version_hash"],
        agent_version=row["agent_version"],
        acknowledged_at=row["acknowledged_at"],
    )


def list_assignments_v2(
    actor: Account,
    *,
    partner_id: UUID | None = None,
    customer_id: UUID | None = None,
) -> list[PolicyAssignmentListItem]:
    """Return all v2 policy assignments visible to the actor, enriched for the console."""
    scope = tenancy.compute_scope(actor)
    clauses: list[str] = []
    params: list[Any] = []

    if partner_id is not None:
        clauses.append("pa.partner_id = %s")
        params.append(partner_id)
    if customer_id is not None:
        clauses.append("pa.customer_id = %s")
        params.append(customer_id)

    if not scope.is_platform:
        if scope.partner_ids:
            clauses.append("(pa.partner_id = any(%s) or pa.customer_id = any(%s))")
            params.append(scope.partner_ids)
            params.append(scope.customer_ids)
        elif scope.customer_ids:
            clauses.append("pa.customer_id = any(%s)")
            params.append(scope.customer_ids)
        else:
            return []

    where = f"where {' and '.join(clauses)}" if clauses else ""
    with connection() as conn, conn.cursor() as cur:
        cur.execute(
            f"""
            select
                pa.id,
                pa.partner_id,
                pa.customer_id,
                pa.group_id,
                pa.endpoint_id,
                pa.policy_id,
                pa.assigned_at,
                pd.name as policy_name,
                pv.version as policy_version
            from policy_assignments_v2 pa
            join policy_documents_v2 pd on pd.id = pa.policy_id
            join policy_versions pv on pv.id = pa.policy_version_id
            {where}
            order by pa.assigned_at desc
            """,
            params,
        )
        rows = cur.fetchall()

    return [_build_assignment_list_item(row) for row in rows]


def apply_assignment_diff(assignment_id: UUID, actor: Account) -> None:
    """Apply pending diff for an assignment by recording endpoint acknowledgements."""
    with connection() as conn, conn.cursor() as cur:
        cur.execute(
            "select pa.* from policy_assignments_v2 pa where pa.id = %s",
            (assignment_id,),
        )
        row = cur.fetchone()
    if row is None:
        raise PolicyV2Error("assignment not found")

    scope = PolicyScopeV2(
        partner_id=row["partner_id"],
        customer_id=row["customer_id"],
        group_id=row["group_id"],
        endpoint_id=row["endpoint_id"],
    )
    _assert_scope_access(actor, scope, level="edit")

    effective = _effective_for_assignment_target(row)
    target_hash = policy_payload_hash(effective.model_dump(mode="json"))

    where_sql = ""
    params: list[Any] = []
    if row["endpoint_id"]:
        where_sql = "ea.agent_id = %s"
        params.append(row["endpoint_id"])
    elif row["group_id"]:
        where_sql = "ea.group_id = %s"
        params.append(row["group_id"])
    elif row["customer_id"]:
        where_sql = "ea.customer_id = %s"
        params.append(row["customer_id"])
    elif row["partner_id"]:
        where_sql = "ea.partner_id = %s"
        params.append(row["partner_id"])
    else:
        where_sql = "true"

    now = datetime.now(UTC)
    applied_count = 0
    with connection() as conn, conn.cursor() as cur:
        cur.execute(
            f"""
            select ea.agent_id
            from enrolled_agents ea
            where ea.revoked = false
              and {where_sql}
            """,
            params,
        )
        endpoints = [record["agent_id"] for record in cur.fetchall()]

        for endpoint_id in endpoints:
            ack_id = uuid.uuid4()
            cur.execute(
                """
                insert into policy_acks (id, endpoint_id, policy_version_hash, agent_version, acknowledged_at)
                values (%s, %s, %s, %s, %s)
                """,
                (
                    ack_id,
                    endpoint_id,
                    target_hash,
                    "operator-apply-diff",
                    now,
                ),
            )
            applied_count += 1

    EvidenceEmitter.emit(
        action="policy_v2.apply_diff",
        resource=f"assignment:{assignment_id}",
        actor=str(actor.id),
        scope=_assignment_scope_dict(row),
        payload={
            "assignment_id": str(assignment_id),
            "applied_endpoint_count": applied_count,
            "policy_version_hash": target_hash,
        },
    )

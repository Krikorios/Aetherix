import hashlib
import json
import secrets
import uuid
import logging
import os
import psycopg
from contextlib import asynccontextmanager
from datetime import UTC, date, datetime
from uuid import UUID
from typing import Any

from fastapi import Depends, FastAPI, Header, HTTPException, Query, Request
from fastapi.responses import RedirectResponse, Response
from fastapi.middleware.cors import CORSMiddleware

from app.db import init_schema
from app import db
from app.schemas import AgentDlpEvidenceIngest, AgentHeartbeat, AgentPolicyAck, AgentPolicyAckRequest, AgentPolicyResponse, Alert, AiProbeResult, AiProvider, BulkActionFailure, BulkActionResult, BulkIdsRequest, CompanyBulkStatusRequest, Customer, CustomerAiSettings, CustomerAiSettingsUpdate, CustomerCreate, CustomerGroup, CustomerQuickCreateRequest, CustomerQuickCreateResult, CustomerRiskSummary, CustomerStatusUpdate, CustomerUpdate, DetectionRule, DetectionRuleCreate, DetectionRulePromotion, DetectionRuleSimulation, DeviceEvent, DlpScanRequest, DlpScanResponse, EffectivePolicyResponse, Endpoint, EndpointHealthRecord, EnrollmentRequest, EnrollmentResult, EnrollmentTokenIssued, EnrollmentTokenRequest, EvidenceEvent, InstallerBuild, InstallerBuildRequest, LoginRequest, LoginResult, ModuleActionRequest, ModuleActionResult, ModuleSimulationResult, PasswordSetRequest, PatchItem, PlatformUsage, PolicyAssignRequest, PolicyAssignmentV2, PolicyCreateResponse, PolicyDocumentV2Input, PolicyGetResponse, PolicyListResponse, PolicyListItemV2, PolicyPromoteRequest, PolicyRollbackRequest, PolicySimulationRecord, PolicyUpdateInput, PolicyVersion, PolicyVersionSummary, QuarantineItem, ReportGenerateRequest, ReportRecord, TotpChallenge, TotpVerifyRequest, Partner, Policy, PolicyDocument, PolicyDocumentDraft, PolicyPackage, PolicySimulationRequest, PolicySimulationResponse, QuickDeployLink, SimulationRequest, TelemetryEvent, SecurityAlert, IncidentCase, Account, AccountCreate, AccountCreated, InviteAcceptRequest, MeResponse, PermissionLevel, Role, RoleAssignment, RoleAssignmentRequest, CompanyLicense, CompanyLicenseAssign, CompanySummary, CompanySummaryPage, LicenseUsageDay, Subscription, SubscriptionCreate, BlocklistEntry, BlocklistEntryCreate, BlocklistSimulationResult, BlocklistActivateResult, AgentCase, AgentCaseActionResult, SystemBanner, SystemBannerCreate, Connector, RecoveryCodeList, RecoveryCodeVerifyRequest, OAuth2Provider, OAuth2ProviderCreate, OAuth2ProviderUpdate
from app.services import audit
from app.services import compliance
from app.schemas import ComplianceAttestationCreate, ComplianceAttestation, ComplianceReviewCreate, ComplianceReview, ComplianceReviewQueueItem, ComplianceSourceTable
from app.schemas import (
    DRPFinding,
    DRPFindingCreate,
    EASMExposure,
    EASMExposureCreate,
    ExternalRiskPolicyView,
    ExternalRiskSimulateRequest,
    ExternalRiskSimulationPreview,
)
from app.services import tenancy
from app.services import licensing
from app.schemas import PolicyAssignmentListItem as PolicyAssignmentListItemSchema
from app.services import policy_v2 as policy_v2_service
from app.services import detection_rules as detection_rules_service
from app.services import blocklist as blocklist_service
from app.services import drp_easm as drp_easm_service
from app.services import totp as totp_service
from app.services import ai_settings as ai_settings_service
from app.services import subscriptions as subscriptions_service
from app.services import integrations as integrations_service
from app.services import reports as reports_service
from app.schemas import (
    SubscriptionInstance,
    SubscriptionEvent,
    StartTrialRequest,
    SubscribeRequest,
    CancelSubscriptionRequest,
)
from app.services.ai_settings import AiSettingsError
from app.services.tenancy import TenancyError
from app.services.licensing import LicensingError
from app.services.subscriptions import SubscriptionError
from app.services.customers import CustomerError, assigned_policy, build_installer_download, create_customer, create_quick_deploy_links, customer_groups, delete_customer, generate_installers, get_customer, list_customers, list_customers_page, list_partners, list_policy_packages, policy_package_for_agent, quick_create, resolve_quick_deploy, update_customer, update_customer_status
from app.services.dlp import apply_policy, scan_text
from app.services.enrollment import EnrollmentError, consume_enrollment_token, issue_enrollment_token
from app.services.policy import active_policy_document, list_policy_documents, promote_policy_document, simulate as simulate_policy
from app.services.state import PolicyNotConfigured, acknowledge_alert, active_policy as load_active_policy, create_dlp_alert, list_alerts, list_endpoints, upsert_heartbeat


@asynccontextmanager
async def lifespan(_: FastAPI):
    # Postgres is the single source of truth. Ensure the schema exists
    # before serving the first request; do not seed any sample data.
    init_schema()
    try:
        yield
    finally:
        db.reset_pool()


app = FastAPI(title="Aetherix DLP API", version="0.1.0", lifespan=lifespan)

app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://127.0.0.1:4173",
        "http://localhost:4173",
        "http://127.0.0.1:5173",
        "http://localhost:5173",
        "http://127.0.0.1:5174",
        "http://localhost:5174",
        "http://127.0.0.1:5175",
        "http://localhost:5175",
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.middleware("http")
async def request_id_middleware(request: Request, call_next):
    request_id = request.headers.get("x-request-id") or uuid.uuid4().hex
    request.state.request_id = request_id
    response = await call_next(request)
    response.headers["x-request-id"] = request_id
    return response


@app.middleware("http")
async def tenant_context_middleware(request: Request, call_next):
    """Set the RLS tenant context from the JWT (if present).

    Every database connection opened during this request will inherit the
    ``app.partner_ids`` / ``app.customer_ids`` custom options, allowing
    PostgreSQL Row-Level Security policies to filter rows transparently.
    """
    auth = request.headers.get("Authorization")
    if auth and auth.startswith("Bearer "):
        token = auth[len("Bearer "):]
        try:
            from app.services import jwt_tokens
            claims = jwt_tokens.verify(token.strip())
            account_id = UUID(claims["sub"])
            account = tenancy.get_account(account_id)
            if account is not None:
                scope = tenancy.compute_scope(account)
                if not scope.is_platform:
                    with db.connection() as conn, conn.cursor() as cur:
                        cur.execute(
                            "select app.set_tenant_context(%s::uuid[], %s::uuid[])",
                            (
                                scope.partner_ids if scope.partner_ids else None,
                                scope.customer_ids if scope.customer_ids else None,
                            ),
                        )
        except Exception:
            pass
    response = await call_next(request)
    return response


def _request_id(request: Request) -> str | None:
    return getattr(request.state, "request_id", None)


_logger = logging.getLogger("aetherix.api")


def _build_invite_url(request: Request, token: str) -> str:
    """Build the URL the invitee follows to set their password.

    Priority order:
      1. ``AETHERIX_CONSOLE_URL`` env var (preferred for prod / when the
         console runs on a different origin than the API).
      2. The request's ``Origin`` header (covers most browser-driven cases).
      3. The request base URL as a last resort (will point at the API,
         which is wrong in split-deploy setups but fine for tests).
    """

    base = os.environ.get("AETHERIX_CONSOLE_URL") or request.headers.get("origin")
    if not base:
        base = str(request.base_url).rstrip("/")
    base = base.rstrip("/")
    return f"{base}/#/invite/{token}"


def _resolve_agent_token(
    authorization: str | None = None,
    token_query: str | None = None,
) -> str:
    """Resolve the agent bearer token from either the Authorization header
    (preferred) or the ``token`` query parameter (deprecated fallback).

    The query-parameter form is maintained for a transition period so that
    older agents do not break immediately. Only agents newer than the auth
    header migration use ``Bearer``.
    """
    if authorization and authorization.startswith("Bearer "):
        token = authorization[len("Bearer "):]
        if token and len(token) >= 8:
            return token
        raise HTTPException(status_code=401, detail="invalid bearer token")
    if token_query and len(token_query) >= 8:
        return token_query
    raise HTTPException(status_code=401, detail="missing or malformed Authorization header")


def current_account(
    authorization: str | None = Header(default=None, alias="Authorization"),
) -> Account:
    from app.services import jwt_tokens

    if not authorization:
        raise HTTPException(status_code=401, detail="missing bearer token")

    scheme, _, token = authorization.partition(" ")
    if scheme.lower() != "bearer" or not token:
        raise HTTPException(status_code=401, detail="invalid authorization scheme")
    try:
        claims = jwt_tokens.verify(token.strip())
    except jwt_tokens.JwtError as error:
        raise HTTPException(status_code=401, detail=str(error)) from error
    try:
        account_id = UUID(claims["sub"])
    except (KeyError, ValueError) as error:
        raise HTTPException(status_code=401, detail="invalid token subject") from error

    account = tenancy.get_account(account_id)
    if account is None:
        raise HTTPException(status_code=401, detail="unknown account")
    if account.status in ("locked", "suspended"):
        raise HTTPException(status_code=403, detail=f"account is {account.status}")
    return account


def _scope_filter(account: Account, table_alias: str = "") -> tuple[list[str], list[object]]:
    prefix = f"{table_alias}." if table_alias else ""
    scope = tenancy.compute_scope(account)
    if scope.is_platform:
        return [], []
    clauses: list[str] = []
    params: list[object] = []
    if scope.partner_ids:
        clauses.append(f"{prefix}partner_id = any(%s)")
        params.append(scope.partner_ids)
    if scope.customer_ids:
        clauses.append(f"{prefix}customer_id = any(%s)")
        params.append(scope.customer_ids)
    if not clauses:
        return ["false"], []
    return ["(" + " or ".join(clauses) + ")"], params


def _customer_partner(customer_id: UUID) -> UUID:
    customer = get_customer(customer_id)
    if customer is None:
        raise HTTPException(status_code=404, detail="Customer not found")
    return customer.partner_id


def _require_customer_access(
    customer_id: UUID,
    account: Account,
    resource: str = "incidents",
    level: PermissionLevel = "view",
) -> None:
    partner_id = _customer_partner(customer_id)
    if not tenancy.has_permission(account, resource, level, partner_id=partner_id, customer_id=customer_id):
        raise HTTPException(status_code=403, detail=f"requires {level} on {resource} for this company")


def require(
    resource: str,
    level: PermissionLevel,
    *,
    partner_id: UUID | None = None,
    customer_id: UUID | None = None,
):
    """Build a FastAPI dependency that checks one permission."""

    def _checker(account: Account = Depends(current_account)) -> Account:
        if not tenancy.has_permission(
            account,
            resource,
            level,
            partner_id=partner_id,
            customer_id=customer_id,
        ):
            raise HTTPException(
                status_code=403,
                detail=f"requires {level} on {resource}",
            )
        return account

    return _checker


def require_platform_owner(account: Account = Depends(current_account)) -> Account:
    if not any(role.role_code == "platform_owner" for role in account.roles):
        raise HTTPException(status_code=403, detail="requires platform owner")
    return account


@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok"}


@app.post("/dlp/scan", response_model=DlpScanResponse)
def scan_dlp(request: DlpScanRequest, http_request: Request) -> DlpScanResponse:
    try:
        policy = load_active_policy()
    except PolicyNotConfigured as error:
        raise HTTPException(status_code=409, detail=str(error)) from error
    response = apply_policy(scan_text(request), policy)
    alert = create_dlp_alert(request, response, policy)
    # Audit the scan decision. The raw scan text is hashed, never stored.
    audit.record(
        action="dlp.scan",
        resource=f"endpoint:{request.endpoint_id or 'unknown'}",
        actor="operator",
        before={"source": request.source, "endpoint_id": request.endpoint_id, "text": request.text},
        after={"action": response.action, "risk_band": response.risk_band, "alert_id": alert.id if alert else None},
        request_id=_request_id(http_request),
    )
    return response


@app.post("/enrollment/tokens", response_model=EnrollmentTokenIssued, status_code=201)
def create_enrollment_token(
    payload: EnrollmentTokenRequest,
    http_request: Request,
    account: Account = Depends(require("companies", "edit")),
) -> EnrollmentTokenIssued:
    issued = issue_enrollment_token(payload)
    audit.record(
        action="enrollment.token.issued",
        resource="enrollment:token",
        actor=str(account.id),
        after={"expires_at": issued.expires_at.isoformat(), "note": issued.note},
        request_id=_request_id(http_request),
    )
    return issued


@app.post("/agent/enroll", response_model=EnrollmentResult, status_code=201)
def enroll_agent(payload: EnrollmentRequest, http_request: Request) -> EnrollmentResult:
    try:
        result = consume_enrollment_token(
            payload.enrollment_token,
            hostname=payload.hostname,
            os_name=payload.os,
        )
    except EnrollmentError as error:
        audit.record(
            action="agent.enroll.rejected",
            resource="enrollment:token",
            actor="agent:unenrolled",
            after={"reason": str(error), "hostname": payload.hostname},
            request_id=_request_id(http_request),
        )
        raise HTTPException(status_code=400, detail=str(error)) from error

    audit.record(
        action="agent.enroll",
        resource=f"agent:{result.agent_id}",
        actor=f"agent:{result.agent_id}",
        after={"hostname": payload.hostname, "os": payload.os, "agent_version": payload.agent_version},
        request_id=_request_id(http_request),
    )
    return result


@app.post("/agent/heartbeat", response_model=Endpoint)
def agent_heartbeat(heartbeat: AgentHeartbeat, http_request: Request) -> Endpoint:
    try:
        endpoint = upsert_heartbeat(heartbeat)
    except ValueError as error:
        audit.record(
            action="agent.heartbeat.rejected",
            resource=f"agent:{heartbeat.agent_id}",
            actor=f"agent:{heartbeat.agent_id}",
            after={"reason": str(error)},
            request_id=_request_id(http_request),
        )
        raise HTTPException(status_code=401, detail=str(error)) from error

    audit.record(
        action="agent.heartbeat",
        resource=f"agent:{heartbeat.agent_id}",
        actor=f"agent:{heartbeat.agent_id}",
        after={"policy_version": heartbeat.policy_version, "agent_version": heartbeat.agent_version},
        request_id=_request_id(http_request),
    )
    return endpoint


@app.get("/endpoints", response_model=list[Endpoint])
def endpoints(
    account: Account = Depends(require("incidents", "view")),
) -> list[Endpoint]:
    filters, params = _scope_filter(account, "h")
    where = f"where {' and '.join(filters)}" if filters else ""
    with db.connection() as conn, conn.cursor() as cur:
        cur.execute(
            f"select agent_id from heartbeats h {where} order by updated_at desc",
            params,
        )
        visible_ids = {row["agent_id"] for row in cur.fetchall()}
    return [endpoint for endpoint in list_endpoints() if endpoint.id in visible_ids]

@app.get("/policies/active", response_model=Policy)
def active_policy(
    _: Account = Depends(require("policies", "view")),
) -> Policy:
    try:
        return load_active_policy()
    except PolicyNotConfigured as error:
        raise HTTPException(status_code=409, detail=str(error)) from error


@app.get("/policy-packages", response_model=list[PolicyPackage])
def policy_packages(
    _: Account = Depends(require("policies", "view")),
) -> list[PolicyPackage]:
    return list_policy_packages()


@app.get("/customers", response_model=list[Customer])
def customers(
    account: Account = Depends(require("companies", "view")),
) -> list[Customer]:
    scope = tenancy.compute_scope(account)
    items, _total = list_customers_page(
        partner_ids=None if scope.is_platform else scope.partner_ids,
        customer_ids=None if scope.is_platform else scope.customer_ids,
    )
    return items


@app.post("/customers", response_model=Customer, status_code=201)
def create_customer_route(
    payload: CustomerCreate,
    http_request: Request,
    account: Account = Depends(require("companies", "manage")),
) -> Customer:
    try:
        customer, assignment = create_customer(payload)
    except CustomerError as error:
        raise HTTPException(status_code=400, detail=str(error)) from error
    audit.record(
        action="customer.create",
        resource=f"customer:{customer.id}",
        actor=str(account.id),
        after={"customer": customer.model_dump(mode="json"), "assignment": assignment.model_dump(mode="json")},
        request_id=_request_id(http_request),
    )
    return customer


@app.post("/customers/quick-create", response_model=CustomerQuickCreateResult, status_code=201)
def quick_create_customer_route(
    payload: CustomerQuickCreateRequest,
    http_request: Request,
    account: Account = Depends(require("companies", "manage")),
) -> CustomerQuickCreateResult:
    try:
        result = quick_create(payload)
    except CustomerError as error:
        raise HTTPException(status_code=400, detail=str(error)) from error
    audit.record(
        action="customer.quick_create",
        resource=f"customer:{result.customer.id}",
        actor=str(account.id),
        after={
            "customer": result.customer.model_dump(mode="json"),
            "policy_package_id": str(result.assignment.policy_package_id),
            "platforms": [installer.platform for installer in result.installers],
            "quick_deploy_link_ids": [str(link.id) for link in result.quick_deploy_links],
        },
        request_id=_request_id(http_request),
    )
    return result


@app.get("/customers/{customer_id}", response_model=Customer)
def customer_detail(
    customer_id: UUID,
    account: Account = Depends(require("companies", "view")),
) -> Customer:
    return _require_company_access(customer_id, "companies", "view", account)


@app.put("/customers/{customer_id}", response_model=Customer)
def update_customer_route(
    customer_id: UUID,
    payload: CustomerUpdate,
    http_request: Request,
    account: Account = Depends(require("companies", "manage")),
) -> Customer:
    _require_company_access(customer_id, "companies", "manage", account)
    try:
        customer = update_customer(customer_id, payload)
    except CustomerError as error:
        raise HTTPException(status_code=400, detail=str(error)) from error
    if customer is None:
        raise HTTPException(status_code=404, detail="Customer not found")
    audit.record(
        action="customer.update",
        resource=f"customer:{customer_id}",
        actor=str(account.id),
        after={"customer": customer.model_dump(mode="json")},
        request_id=_request_id(http_request),
    )
    return customer


@app.get("/customers/{customer_id}/groups", response_model=list[CustomerGroup])
def customer_group_list(
    customer_id: UUID,
    account: Account = Depends(require("companies", "view")),
) -> list[CustomerGroup]:
    _require_company_access(customer_id, "companies", "view", account)
    return customer_groups(customer_id)


@app.post("/customers/{customer_id}/installers", response_model=list[InstallerBuild], status_code=201)
def generate_customer_installers(
    customer_id: UUID,
    payload: InstallerBuildRequest,
    http_request: Request,
    account: Account = Depends(require("companies", "manage")),
) -> list[InstallerBuild]:
    _require_company_access(customer_id, "companies", "manage", account)
    try:
        installers = generate_installers(customer_id, payload)
    except CustomerError as error:
        raise HTTPException(status_code=400, detail=str(error)) from error
    audit.record(
        action="installer.generate",
        resource=f"customer:{customer_id}",
        actor=str(account.id),
        after={"installer_ids": [str(installer.id) for installer in installers], "platforms": payload.platforms},
        request_id=_request_id(http_request),
    )
    return installers


@app.post("/customers/{customer_id}/quick-deploy", response_model=list[QuickDeployLink], status_code=201)
def create_quick_deploy(
    customer_id: UUID,
    payload: InstallerBuildRequest,
    http_request: Request,
    account: Account = Depends(require("companies", "manage")),
) -> list[QuickDeployLink]:
    _require_company_access(customer_id, "companies", "manage", account)
    try:
        links = create_quick_deploy_links(customer_id, payload)
    except CustomerError as error:
        raise HTTPException(status_code=400, detail=str(error)) from error
    audit.record(
        action="quick_deploy.create",
        resource=f"customer:{customer_id}",
        actor=str(account.id),
        after={"link_ids": [str(link.id) for link in links], "platforms": payload.platforms},
        request_id=_request_id(http_request),
    )
    return links


@app.get("/quick-deploy/{link_id}")
def quick_deploy_redirect(link_id: UUID, secret: str, http_request: Request):
    try:
        build_id = resolve_quick_deploy(link_id, secret)
    except CustomerError as error:
        audit.record(
            action="quick_deploy.rejected",
            resource=f"quick_deploy:{link_id}",
            actor="download",
            after={"reason": str(error)},
            request_id=_request_id(http_request),
        )
        raise HTTPException(status_code=400, detail=str(error)) from error
    audit.record(
        action="quick_deploy.download",
        resource=f"quick_deploy:{link_id}",
        actor="download",
        after={"build_id": str(build_id)},
        request_id=_request_id(http_request),
    )
    return RedirectResponse(url=f"/installers/{build_id}/download", status_code=302)


@app.get("/installers/{build_id}/download")
def download_installer(build_id: UUID, http_request: Request):
    try:
        package_bytes, filename, sha256, _ = build_installer_download(build_id)
    except CustomerError as error:
        raise HTTPException(status_code=400, detail=str(error)) from error
    audit.record(
        action="installer.download",
        resource=f"installer_build:{build_id}",
        actor="download",
        after={"sha256": sha256, "filename": filename},
        request_id=_request_id(http_request),
    )
    return Response(
        content=package_bytes,
        media_type="application/octet-stream",
        headers={
            "Content-Disposition": f'attachment; filename="{filename}"',
            "X-Installer-SHA256": sha256,
        },
    )


@app.get("/agent/{agent_id}/policy", response_model=PolicyPackage)
def agent_policy(agent_id: str) -> PolicyPackage:
    package = policy_package_for_agent(agent_id)
    if package is None:
        raise HTTPException(status_code=404, detail="Assigned policy package not found")
    return package


@app.get("/policies/document", response_model=PolicyDocument | None)
def active_policy_document_route(
    _: Account = Depends(require("policies", "view")),
) -> PolicyDocument | None:
    return active_policy_document()


@app.get("/policies/documents", response_model=list[PolicyDocument])
def policy_document_history(
    limit: int = Query(default=50, ge=1, le=500),
    _: Account = Depends(require("policies", "view")),
) -> list[PolicyDocument]:
    return list_policy_documents(limit=limit)


@app.post("/policies/document", response_model=PolicyDocument, status_code=201)
def promote_policy(
    draft: PolicyDocumentDraft,
    http_request: Request,
    account: Account = Depends(require("policies", "edit")),
) -> PolicyDocument:
    previous = active_policy_document()
    document = promote_policy_document(draft, actor=str(account.id))
    audit.record(
        action="policy.promote",
        resource=f"policy:{document.id}",
        actor=str(account.id),
        before=previous.model_dump(mode="json") if previous else None,
        after=document.model_dump(mode="json"),
        request_id=_request_id(http_request),
    )
    return document


@app.post("/policies/document/simulate", response_model=PolicySimulationResponse)
def simulate_policy_route(
    payload: PolicySimulationRequest,
    http_request: Request,
    account: Account = Depends(require("policies", "edit")),
) -> PolicySimulationResponse:
    try:
        result = simulate_policy(payload.draft, payload.samples)
    except PolicyNotConfigured as error:
        raise HTTPException(status_code=409, detail=str(error)) from error
    # Simulation does not mutate state, but we still audit the operator
    # action so reviewers can see what was simulated and the outcome counts.
    # Raw sample text is hashed via ``before``; only the summary is stored.
    audit.record(
        action="policy.simulate",
        resource="policy:draft",
        actor=str(account.id),
        before={"draft": payload.draft.model_dump(mode="json"), "samples": [s.model_dump(mode="json") for s in payload.samples]},
        after=result.summary.model_dump(mode="json"),
        request_id=_request_id(http_request),
    )
    return result


@app.get("/alerts", response_model=list[Alert])
def alerts(
    account: Account = Depends(require("incidents", "view")),
) -> list[Alert]:
    filters, params = _scope_filter(account, "a")
    where = f"where {' and '.join(filters)}" if filters else ""
    with db.connection() as conn, conn.cursor() as cur:
        cur.execute(
            f"select payload from alerts a {where} order by created_at desc",
            params,
        )
        rows = cur.fetchall()
    return [Alert.model_validate(row["payload"]) for row in rows]


@app.patch("/alerts/{alert_id}/acknowledge", response_model=Alert)
def acknowledge(
    alert_id: str,
    http_request: Request,
    account: Account = Depends(require("incidents", "edit")),
) -> Alert:
    with db.connection() as conn, conn.cursor() as cur:
        cur.execute("select customer_id from alerts where id = %s", (alert_id,))
        row = cur.fetchone()
    if row is None:
        raise HTTPException(status_code=404, detail="Alert not found")
    customer_id = row["customer_id"]
    if customer_id is not None:
        _require_customer_access(customer_id, account, "incidents", "edit")
    alert = acknowledge_alert(alert_id)
    if alert is None:
        raise HTTPException(status_code=404, detail="Alert not found")

    audit.record(
        action="alert.ack",
        resource=f"alert:{alert.id}",
        actor=str(account.id),
        after={"status": alert.status},
        request_id=_request_id(http_request),
    )
    return alert


@app.get("/audit", response_model=list[audit.AuditRecord])
def audit_records(
    limit: int = Query(default=100, ge=1, le=1000),
    action: str | None = Query(default=None),
    actor: str | None = Query(default=None),
    resource: str | None = Query(default=None),
    _: Account = Depends(require_platform_owner),
) -> list[audit.AuditRecord]:
    return audit.list_records(limit=limit, action=action, actor=actor, resource=resource)


@app.get("/audit/verify")
def audit_verify(_: Account = Depends(require_platform_owner)) -> dict[str, object]:
    ok, first_bad = audit.verify_chain()
    return {"ok": ok, "first_bad_seq": first_bad}


@app.get("/compliance/export")
def compliance_export(
    customer_id: UUID = Query(...),
    framework: str = Query(...),
    account: Account = Depends(current_account),
) -> dict[str, object]:
    if get_customer(customer_id) is None:
        raise HTTPException(status_code=404, detail="Customer not found")
    _require_customer_access(customer_id, account, "companies", "view")
    try:
        return compliance.export_bundle(customer_id, framework)
    except compliance.ComplianceExportError as error:
        raise HTTPException(status_code=400, detail=str(error)) from error


@app.post("/simulate/scenario")
def simulate_scenario(
    req: SimulationRequest,
    account: Account = Depends(require("incidents", "edit")),
):
    """Simulate security events for testing and demo purposes."""
    import json
    import uuid
    import psycopg
    from datetime import datetime, timezone
    
    with db.connection() as conn:
        with conn.cursor() as cur:
            # find customer for agent
            cur.execute("select customer_id from enrolled_agents where agent_id = %s", (req.agent_id,))
            row = cur.fetchone()
            if not row:
                raise HTTPException(status_code=404, detail="Agent not found")
            
            customer_id = row["customer_id"]
            if not customer_id:
                raise HTTPException(status_code=400, detail="Agent has no associated customer")
            _require_customer_access(customer_id, account, "incidents", "edit")
                
            event_id = uuid.uuid4()
            alert_id = uuid.uuid4()
            incident_id = uuid.uuid4()
            ts = datetime.now(timezone.utc)
            
            # Simple simulation of different scenarios
            if req.scenario == "dlp_paste":
                event_type = "dlp.violation"
                payload = {"text": "Pasted source code to ChatGPT", "matched_rules": ["Source Code"]}
                category = "Data Exfiltration"
                severity = "high"
                action = "Block and Alert"
            else:
                event_type = "system.anomaly"
                payload = {"details": f"Simulated {req.scenario}"}
                category = "Anomaly"
                severity = "medium"
                action = "Monitor"

            cur.execute(
                "insert into telemetry_events (id, customer_id, agent_id, event_type, payload, timestamp) values (%s, %s, %s, %s, %s, %s)",
                (event_id, customer_id, req.agent_id, event_type, psycopg.types.json.Jsonb(payload), ts)
            )
            
            cur.execute(
                "insert into security_alerts (id, customer_id, agent_id, category, severity, confidence, recommended_action, payload, status, created_at, evidence_controls) values (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)",
                (alert_id, customer_id, req.agent_id, category, severity, 85, action, psycopg.types.json.Jsonb(payload), "new", ts, psycopg.types.json.Jsonb(compliance.controls_for_event("security.alert")))
            )

            try:
                ai_summary = ai_settings_service.summarize_alert(
                    customer_id,
                    {
                        "category": category,
                        "severity": severity,
                        "confidence": 85,
                        "recommended_action": action,
                        "payload": payload,
                    },
                )
            except Exception as e:  # noqa: BLE001 - alert ingest must not depend on AI
                # Log the error but don't fail the simulation if AI is unavailable
                _logger.warning(f"AI summarization failed: {e}")
                ai_summary = None
            if ai_summary:
                cur.execute(
                    "update security_alerts set ai_summary = %s where id = %s",
                    (ai_summary, alert_id),
                )

            cur.execute(
                "insert into incident_cases (id, customer_id, title, description, severity, status, recommended_response, created_at, updated_at) values (%s, %s, %s, %s, %s, %s, %s, %s, %s)",
                (incident_id, customer_id, f"Simulated {req.scenario}", "Generated by simulation", severity, "open", "Investigate", ts, ts)
            )

            agentic_case_id = uuid.uuid4()
            steps = [
                {"id": "s1", "description": "Ingested telemetry from agent", "completed": True, "timestamp": ts.isoformat(), "evidence": None},
                {"id": "s2", "description": "Correlated events with threat intel", "completed": True, "timestamp": ts.isoformat(), "evidence": "3 IoCs matched"},
                {"id": "s3", "description": "Generated response recommendation", "completed": True, "timestamp": ts.isoformat(), "evidence": None},
                {"id": "s4", "description": "Awaiting operator approval", "completed": False, "timestamp": None, "evidence": None},
            ]
            cur.execute(
                """
                insert into agentic_cases (
                    id, customer_id, title, summary, status, confidence, confidence_pct,
                    severity, affected_endpoints, related_events, mitre_tactics,
                    recommended_response, steps, created_at, updated_at
                ) values (%s, %s, %s, %s, 'awaiting_approval', 'high', 85, %s,
                    %s::jsonb, %s, %s::jsonb, %s, %s::jsonb, %s, %s)
                """,
                (
                    agentic_case_id, customer_id,
                    f"Investigation: {req.scenario} on {req.agent_id}",
                    f"AI-correlated investigation generated from {req.scenario} scenario simulation with {severity} severity.",
                    severity,
                    json.dumps([req.agent_id]),
                    3 if severity == "high" else 1,
                    json.dumps(["Anomaly", "Execution"]),
                    action,
                    json.dumps(steps),
                    ts, ts,
                ),
            )

            return {"status": "ok", "alert_id": alert_id, "incident_id": incident_id, "agentic_case_id": agentic_case_id}

@app.get("/customers/{customer_id}/telemetry", response_model=list[TelemetryEvent])
def get_customer_telemetry(
    customer_id: UUID,
    account: Account = Depends(require("incidents", "view")),
):
    _require_customer_access(customer_id, account, "incidents", "view")
    with db.connection() as conn:
        with conn.cursor() as cur:
            cur.execute("select * from telemetry_events where customer_id = %s order by timestamp desc", (customer_id,))
            return cur.fetchall()

@app.get("/customers/{customer_id}/security-alerts", response_model=list[SecurityAlert])
def get_customer_security_alerts(
    customer_id: UUID,
    account: Account = Depends(require("incidents", "view")),
):
    _require_customer_access(customer_id, account, "incidents", "view")
    with db.connection() as conn:
        with conn.cursor() as cur:
            cur.execute("select * from security_alerts where customer_id = %s order by created_at desc", (customer_id,))
            return cur.fetchall()

@app.get("/customers/{customer_id}/incidents", response_model=list[IncidentCase])
def get_customer_incidents(
    customer_id: UUID,
    account: Account = Depends(require("incidents", "view")),
):
    _require_customer_access(customer_id, account, "incidents", "view")
    with db.connection() as conn:
        with conn.cursor() as cur:
            cur.execute("select * from incident_cases where customer_id = %s order by updated_at desc", (customer_id,))
            return cur.fetchall()


def _module_simulation(
    target_id: str,
    action: str,
    *,
    destructive: bool,
    approval_required: bool,
    impact: list[str],
    controls: list[str],
) -> ModuleSimulationResult:
    now = datetime.now(UTC)
    return ModuleSimulationResult(
        id=f"sim-{target_id}-{int(now.timestamp())}",
        detection_id=target_id,
        action=action,
        destructive=destructive,
        approval_required=approval_required,
        affected_systems=1,
        estimated_impact=impact,
        evidence_controls=controls,
        created_at=now,
    )


def _module_action(
    target_id: str,
    action: str,
    payload: dict[str, Any] | None = None,
    *,
    approval_required: bool,
    controls: list[str],
    created_by: str = "operator",
) -> ModuleActionResult:
    # Persist a queued module action so agents can poll and consume it.
    action_id = uuid.uuid4()
    status = "awaiting_approval" if approval_required else "queued"
    now = datetime.now(UTC)
    payload_json = json.dumps(payload) if payload is not None else None

    # Insert into DB
    with db.connection() as conn, conn.cursor() as cur:
        cur.execute(
            """
            insert into module_actions(id, endpoint_id, action, payload, status, approval_required, created_by, created_at, evidence_controls)
            values (%s, %s, %s, %s::jsonb, %s, %s, %s, %s, %s)
            returning *
            """,
            (
                action_id,
                target_id,
                action,
                payload_json,
                status,
                approval_required,
                created_by,
                now,
                json.dumps(controls),
            ),
        )
        row = cur.fetchone()

    return ModuleActionResult(
        id=str(row["id"]),
        target_id=row["endpoint_id"],
        action=row["action"],
        status=row["status"],
        approval_required=bool(row["approval_required"]),
        payload=row["payload"] or None,
        evidence_controls=row["evidence_controls"] or [],
        created_at=row["created_at"],
    )


@app.get("/me", response_model=MeResponse)
def me(account: Account = Depends(current_account)) -> MeResponse:
    return tenancy.me(account)


@app.get("/endpoints/health", response_model=list[EndpointHealthRecord])
def endpoint_health(
    customer_id: UUID | None = Query(default=None),
    account: Account = Depends(current_account),
) -> list[EndpointHealthRecord]:
    filters, params = _scope_filter(account, "h")
    if customer_id is not None:
        _require_customer_access(customer_id, account)
        filters.append("h.customer_id = %s")
        params.append(customer_id)
    where = f"where {' and '.join(filters)}" if filters else ""
    with db.connection() as conn, conn.cursor() as cur:
        cur.execute(
            f"""
            select h.agent_id, h.customer_id, h.payload, h.updated_at,
                   coalesce(open_alerts.n, 0) as open_alerts
            from heartbeats h
            left join lateral (
                select count(*) as n
                from alerts a
                where a.status = 'open' and a.payload->>'endpoint_id' = h.agent_id
            ) open_alerts on true
            {where}
            order by h.updated_at desc
            """,
            params,
        )
        rows = cur.fetchall()
    endpoints_by_id = {endpoint.id: endpoint for endpoint in list_endpoints()}
    records: list[EndpointHealthRecord] = []
    for row in rows:
        payload = row["payload"] or {}
        endpoint = endpoints_by_id.get(row["agent_id"])
        if endpoint is None:
            continue
        pending_actions = int(((payload.get("signals") or {}).get("pending_updates") or 0))
        latest_agent_version = payload.get("agent_version") or endpoint.agent_version
        active_policy_version = payload.get("policy_version") or endpoint.policy_version
        status = "drifted" if endpoint.policy_version != active_policy_version else endpoint.status
        records.append(
            EndpointHealthRecord(
                id=endpoint.id,
                customer_id=row["customer_id"],
                endpoint_name=endpoint.hostname,
                hostname=endpoint.hostname,
                os=endpoint.os,
                agent_version=endpoint.agent_version,
                latest_agent_version=latest_agent_version,
                policy_version=endpoint.policy_version,
                active_policy_version=active_policy_version,
                status=status,
                last_heartbeat=endpoint.last_seen,
                risk_score=endpoint.risk_score,
                open_alerts=int(row["open_alerts"]),
                pending_actions=pending_actions,
                tags=[],
            )
        )
    return records


@app.post("/endpoints/{endpoint_id}/simulate-remediation", response_model=ModuleSimulationResult)
def simulate_endpoint_remediation(endpoint_id: str, _: Account = Depends(current_account)) -> ModuleSimulationResult:
    endpoint = next((item for item in list_endpoints() if item.id == endpoint_id), None)
    if endpoint is None:
        raise HTTPException(status_code=404, detail="endpoint not found")
    return _module_simulation(
        endpoint_id,
        "push_policy_update",
        destructive=False,
        approval_required=False,
        impact=[f"Queue policy refresh for {endpoint.hostname}.", "Agent applies on the next heartbeat cycle."],
        controls=["iso27001-2022:A.8.9", "nist-csf-2.0:PR.PS"],
    )


@app.post("/endpoints/{endpoint_id}/remediate", response_model=ModuleActionResult)
def remediate_endpoint(endpoint_id: str, payload: ModuleActionRequest, http_request: Request, account: Account = Depends(current_account)) -> ModuleActionResult:
    if not any(item.id == endpoint_id for item in list_endpoints()):
        raise HTTPException(status_code=404, detail="endpoint not found")
    result = _module_action(endpoint_id, payload.action, payload=payload.payload, approval_required=False, controls=["iso27001-2022:A.8.9", "nist-csf-2.0:PR.PS"])
    audit.record(action="endpoint.remediate", resource=f"endpoint:{endpoint_id}", actor=str(account.id), after=result.model_dump(mode="json"), request_id=_request_id(http_request))
    return result


@app.patch("/branding", response_model=MeResponse)
def update_scoped_branding(payload: dict[str, object], http_request: Request, account: Account = Depends(current_account)) -> MeResponse:
    allowed = {"product_name", "tagline", "primary_color", "accent_color", "logo_url", "support_email", "support_url", "footer_note"}
    branding = {key: value for key, value in payload.items() if key in allowed and (value is None or isinstance(value, str))}
    scope = tenancy.compute_scope(account)
    if scope.customer_ids:
        customer_id = scope.customer_ids[0]
        _require_customer_access(customer_id, account, resource="companies", level="manage")
        with db.connection() as conn, conn.cursor() as cur:
            cur.execute("update customers set branding = %s::jsonb where id = %s", (json.dumps(branding), customer_id))
        audit.record(action="branding.update", resource=f"customer:{customer_id}", actor=str(account.id), after=branding, request_id=_request_id(http_request))
        return tenancy.me(account)
    if scope.partner_ids:
        partner_id = scope.partner_ids[0]
        if not tenancy.has_permission(account, "companies", "manage", partner_id=partner_id):
            raise HTTPException(status_code=403, detail="requires manage on companies for this partner")
        with db.connection() as conn, conn.cursor() as cur:
            cur.execute("update partners set branding = %s::jsonb where id = %s", (json.dumps(branding), partner_id))
        audit.record(action="branding.update", resource=f"partner:{partner_id}", actor=str(account.id), after=branding, request_id=_request_id(http_request))
        return tenancy.me(account)
    raise HTTPException(status_code=400, detail="branding update requires a scoped partner or customer account")


def _security_alert_scope(customer_id: UUID | None, account: Account) -> tuple[str, list[object]]:
    filters, params = _scope_filter(account, "sa")
    if customer_id is not None:
        _require_customer_access(customer_id, account)
        filters.append("sa.customer_id = %s")
        params.append(customer_id)
    where = f"where {' and '.join(filters)}" if filters else ""
    return where, params


def _severity_from_text(value: str | None) -> str:
    value = (value or "medium").lower()
    return value if value in {"low", "medium", "high", "critical"} else "medium"


def _risk_band_from_score(score: int) -> str:
    if score >= 75:
        return "critical"
    if score >= 55:
        return "high"
    if score >= 35:
        return "medium"
    return "low"


@app.get("/behavior/detections", response_model=list[SecurityAlert])
def behavior_detections(
    customer_id: UUID | None = Query(default=None),
    partner_id: UUID | None = Query(default=None),
    limit: int = Query(default=25, ge=1, le=100),
    account: Account = Depends(current_account),
) -> list[SecurityAlert]:
    filters, params = _scope_filter(account, "sa")
    if customer_id is not None:
        _require_customer_access(customer_id, account)
        filters.append("sa.customer_id = %s")
        params.append(customer_id)
    if partner_id is not None:
        if not tenancy.has_permission(account, "incidents", "view", partner_id=partner_id):
            raise HTTPException(status_code=403, detail="requires view on incidents for this partner")
        filters.append("sa.customer_id in (select id from customers where partner_id = %s)")
        params.append(partner_id)
    filters.append("lower(sa.category) in ('anomaly', 'malware', 'behavior', 'data exfiltration')")
    where = f"where {' and '.join(filters)}" if filters else ""
    with db.connection() as conn, conn.cursor() as cur:
        cur.execute(f"select * from security_alerts sa {where} order by created_at desc limit %s", [*params, limit])
        return cur.fetchall()


@app.post("/behavior/simulate", response_model=ModuleSimulationResult)
def simulate_behavior(payload: dict, _: Account = Depends(current_account)) -> ModuleSimulationResult:
    detection_id = str(payload.get("detection_id") or "behavior")
    action = str(payload.get("action") or "quarantine")
    destructive = action in {"kill_process", "isolate_endpoint", "rollback"}
    return _module_simulation(
        detection_id,
        action,
        destructive=destructive,
        approval_required=destructive,
        impact=[f"Response action {action.replace('_', ' ')} targets alert {detection_id}.", "Control-plane audit evidence will be recorded before dispatch."],
        controls=["nist-csf-2.0:RS.MI", "iso27001-2022:A.8.7"],
    )


@app.post("/behavior/action", response_model=ModuleActionResult)
def stage_behavior_action(payload: dict, http_request: Request, account: Account = Depends(current_account)) -> ModuleActionResult:
    detection_id = str(payload.get("detection_id") or payload.get("alert_id") or "behavior")
    endpoint_id = str(payload.get("endpoint_id") or payload.get("agent_id") or detection_id)
    action = str(payload.get("action") or "quarantine")

    # Resolve correct agent_id and extract telemetry targets from alert record
    agent_id = endpoint_id
    target_pid = None
    target_path = None

    try:
        detection_uuid = UUID(detection_id)
    except ValueError:
        detection_uuid = None

    if detection_uuid:
        with db.connection() as conn, conn.cursor() as cur:
            cur.execute("select agent_id, payload from security_alerts where id = %s", (detection_uuid,))
            row = cur.fetchone()
            if row:
                agent_id = row["agent_id"]
                alert_payload = row["payload"] or {}
                target_pid = alert_payload.get("process_pid")
                target_path = alert_payload.get("file_path") or alert_payload.get("process_path")
            else:
                cur.execute("select agent_id, payload from telemetry_events where id = %s", (detection_uuid,))
                row = cur.fetchone()
                if row:
                    agent_id = row["agent_id"]
                    alert_payload = row["payload"] or {}
                    target_pid = alert_payload.get("process_pid")
                    target_path = alert_payload.get("file_path") or alert_payload.get("process_path")

    action_payload = dict(payload)
    action_payload["detection_id"] = detection_id
    if target_pid is not None:
        action_payload["target_pid"] = target_pid
    if target_path is not None:
        action_payload["target_path"] = target_path
        action_payload["file_path"] = target_path

    result = _module_action(
        agent_id,
        action,
        payload=action_payload,
        approval_required=False,
        controls=["nist-csf-2.0:RS.MI", "iso27001-2022:A.8.7"],
    )
    audit.record(action="behavior.action.stage", resource=f"alert:{detection_id}", actor=str(account.id), after=result.model_dump(mode="json"), request_id=_request_id(http_request))
    return result


@app.post("/web-protection/simulate", response_model=ModuleSimulationResult)
def simulate_web_protection(payload: dict, _: Account = Depends(current_account)) -> ModuleSimulationResult:
    detection_id = str(payload.get("detection_id") or "web_protection")
    action = str(payload.get("action") or "block_paste_action")
    destructive = action in {"isolate_endpoint_browser", "force_extension_reload"}
    return _module_simulation(
        detection_id,
        action,
        destructive=destructive,
        approval_required=destructive,
        impact=[
            f"Action: {action.replace('_', ' ')} targets alert {detection_id}.",
            "Will restrict endpoint browser capabilities or isolate web connections until administrative release." if destructive else "Recorded as analyst decision against the underlying alert."
        ],
        controls=["nist-csf-2.0:PR.DS", "iso27001-2022:A.8.23"],
    )


@app.post("/web-protection/action", response_model=ModuleActionResult)
def stage_web_protection_action(payload: dict, http_request: Request, account: Account = Depends(current_account)) -> ModuleActionResult:
    detection_id = str(payload.get("detection_id") or "web_protection")
    action = str(payload.get("action") or "block_paste_action")
    result = _module_action(
        detection_id,
        action,
        payload=payload,
        approval_required=action in {"isolate_endpoint_browser", "force_extension_reload"},
        controls=["nist-csf-2.0:PR.DS", "iso27001-2022:A.8.23"]
    )
    audit.record(
        action="web_protection.action.stage",
        resource=f"alert:{detection_id}",
        actor=str(account.id),
        after=result.model_dump(mode="json"),
        request_id=_request_id(http_request)
    )
    return result



@app.get("/device-control/events", response_model=list[DeviceEvent])
def device_control_events(
    customer_id: UUID | None = Query(default=None),
    account: Account = Depends(current_account),
) -> list[DeviceEvent]:
    where, params = _security_alert_scope(customer_id, account)
    with db.connection() as conn, conn.cursor() as cur:
        cur.execute(f"select * from security_alerts sa {where} order by created_at desc limit 200", params)
        rows = cur.fetchall()
    events: list[DeviceEvent] = []
    keywords = ("device", "usb", "clipboard", "printer", "bluetooth", "paste")
    for row in rows:
        payload = row["payload"] or {}
        haystack = " ".join(str(payload.get(k, "")) for k in ("source", "detector", "module", "device_type", "destination")) + " " + row["category"]
        if not any(word in haystack.lower() for word in keywords):
            continue
        action = str(payload.get("action") or ("paste_attempted" if "paste" in haystack.lower() else "connected"))
        if action not in {"connected", "blocked", "allowed_once", "read_attempted", "write_attempted", "paste_attempted", "print_job"}:
            action = "connected"
        device_type = str(payload.get("device_type") or ("clipboard" if action == "paste_attempted" else "usb_storage"))
        if device_type not in {"usb_storage", "usb_other", "printer", "bluetooth", "optical", "thunderbolt", "clipboard"}:
            device_type = "usb_other"
        status = "blocked" if action in {"blocked", "write_attempted", "paste_attempted"} else "review"
        events.append(DeviceEvent(
            id=str(row["id"]), customer_id=row["customer_id"], hostname=payload.get("hostname") or row["agent_id"], user=payload.get("user") or "unknown",
            device_type=device_type, device_name=payload.get("device_name") or payload.get("title") or row["category"], vendor_id=payload.get("vendor_id") or "n/a",
            product_id=payload.get("product_id") or "n/a", serial=payload.get("serial"), action=action, severity=_severity_from_text(row["severity"]),
            status=status, timestamp=row["created_at"], bytes_written=payload.get("bytes_written"), destination=payload.get("destination"),
            policy_rule=payload.get("policy_rule"), approval_required=status != "allowed",
        ))
    return events


@app.post("/device-control/events/{event_id}/simulate", response_model=ModuleSimulationResult)
def simulate_device_event(event_id: str, payload: ModuleActionRequest, _: Account = Depends(current_account)) -> ModuleSimulationResult:
    return _module_simulation(event_id, payload.action, destructive=False, approval_required=payload.action in {"approve_device", "add_to_allowlist"}, impact=[f"Evaluate device-control action {payload.action} for event {event_id}."], controls=["iso27001-2022:A.8.12", "nist-csf-2.0:PR.DS"])


@app.post("/device-control/events/{event_id}/action", response_model=ModuleActionResult)
def stage_device_event(event_id: str, payload: ModuleActionRequest, http_request: Request, account: Account = Depends(current_account)) -> ModuleActionResult:
    result = _module_action(event_id, payload.action, payload=payload.payload, approval_required=payload.action in {"approve_device", "add_to_allowlist"}, controls=["iso27001-2022:A.8.12", "nist-csf-2.0:PR.DS"])
    audit.record(action="device_control.action.stage", resource=f"device-event:{event_id}", actor=str(account.id), after=result.model_dump(mode="json"), request_id=_request_id(http_request))
    return result


@app.get("/quarantine", response_model=list[QuarantineItem])
def quarantine_items(customer_id: UUID | None = Query(default=None), account: Account = Depends(current_account)) -> list[QuarantineItem]:
    where, params = _security_alert_scope(customer_id, account)
    with db.connection() as conn, conn.cursor() as cur:
        cur.execute(f"select * from security_alerts sa {where} order by created_at desc limit 200", params)
        rows = cur.fetchall()
    items: list[QuarantineItem] = []
    for row in rows:
        payload = row["payload"] or {}
        haystack = f"{row['recommended_action']} {row['category']} {payload}".lower()
        if "quarantine" not in haystack and "isolate" not in haystack:
            continue
        kind = payload.get("kind") or ("email" if "email" in haystack else "file")
        if kind not in {"file", "email", "process", "network_connection"}:
            kind = "file"
        items.append(QuarantineItem(
            id=str(row["id"]), customer_id=row["customer_id"], hostname=payload.get("hostname") or row["agent_id"], kind=kind,
            name=payload.get("file_name") or payload.get("process") or payload.get("title") or row["category"], path=payload.get("path"), hash=payload.get("sha256") or payload.get("hash"),
            quarantine_reason=row["ai_summary"] or row["recommended_action"], severity=_severity_from_text(row["severity"]), status="quarantined",
            quarantined_at=row["created_at"], quarantined_by="Aetherix control plane", detection_id=str(row["id"]),
        ))
    return items


@app.post("/quarantine/{item_id}/simulate", response_model=ModuleSimulationResult)
def simulate_quarantine(item_id: str, payload: ModuleActionRequest, _: Account = Depends(current_account)) -> ModuleSimulationResult:
    return _module_simulation(item_id, payload.action, destructive=payload.action in {"delete_permanently", "release_from_quarantine"}, approval_required=True, impact=[f"Evaluate quarantine action {payload.action} for item {item_id}."], controls=["iso27001-2022:A.8.7", "nist-csf-2.0:RS.MI"])


@app.post("/quarantine/{item_id}/action", response_model=ModuleActionResult)
def stage_quarantine(item_id: str, payload: ModuleActionRequest, http_request: Request, account: Account = Depends(current_account)) -> ModuleActionResult:
    # Resolve correct agent_id and extract telemetry targets from alert record
    agent_id = item_id
    target_pid = None
    target_path = None

    try:
        item_uuid = UUID(item_id)
    except ValueError:
        item_uuid = None

    if item_uuid:
        with db.connection() as conn, conn.cursor() as cur:
            cur.execute("select agent_id, payload from security_alerts where id = %s", (item_uuid,))
            row = cur.fetchone()
            if row:
                agent_id = row["agent_id"]
                alert_payload = row["payload"] or {}
                target_pid = alert_payload.get("process_pid")
                target_path = alert_payload.get("file_path") or alert_payload.get("process_path")

    action_payload = dict(payload.payload) if payload.payload is not None else {}
    action_payload["detection_id"] = item_id
    if target_pid is not None:
        action_payload["target_pid"] = target_pid
    if target_path is not None:
        action_payload["target_path"] = target_path
        action_payload["file_path"] = target_path

    result = _module_action(
        agent_id,
        payload.action,
        payload=action_payload,
        approval_required=False,
        controls=["iso27001-2022:A.8.7", "nist-csf-2.0:RS.MI"],
    )
    audit.record(action="quarantine.action.stage", resource=f"quarantine:{item_id}", actor=str(account.id), after=result.model_dump(mode="json"), request_id=_request_id(http_request))
    return result


@app.get("/risk/patches", response_model=list[PatchItem])
def risk_patches(customer_id: UUID | None = Query(default=None), account: Account = Depends(current_account)) -> list[PatchItem]:
    filters, params = _scope_filter(account, "h")
    if customer_id is not None:
        _require_customer_access(customer_id, account)
        filters.append("h.customer_id = %s")
        params.append(customer_id)
    where = f"where {' and '.join(filters)}" if filters else ""
    with db.connection() as conn, conn.cursor() as cur:
        cur.execute(f"select h.agent_id, h.customer_id, h.payload from heartbeats h {where} order by updated_at desc", params)
        rows = cur.fetchall()
    patches: list[PatchItem] = []
    for row in rows:
        payload = row["payload"] or {}
        signals = payload.get("signals") or {}
        pending = int(signals.get("pending_updates") or 0)
        if pending <= 0:
            continue
        severity = "high" if pending >= 3 else "medium"
        patches.append(PatchItem(
            id=f"patch-{row['agent_id']}", customer_id=row["customer_id"], hostname=payload.get("hostname") or row["agent_id"], os=payload.get("os") or "unknown",
            cve_id=None, kb_id=None, title=f"{pending} pending endpoint update{'s' if pending != 1 else ''}", description="Agent heartbeat reports pending OS or application updates.",
            severity=severity, status="missing", category="security", vendor="Endpoint agent", release_date=datetime.now(UTC), installed_at=None, tags=["heartbeat"], cvss_score=None,
        ))
    return patches


@app.post("/risk/patches/{patch_id}/simulate", response_model=ModuleSimulationResult)
def simulate_patch(patch_id: str, payload: dict, _: Account = Depends(current_account)) -> ModuleSimulationResult:
    action = str(payload.get("action") or "schedule_patch")
    return _module_simulation(patch_id, action, destructive=True, approval_required=True, impact=[f"Schedule deployment for {patch_id}.", "Endpoint may require a restart depending on vendor update metadata."], controls=["iso27001-2022:A.8.8", "nist-csf-2.0:PR.PS"])


@app.post("/risk/patches/{patch_id}/deploy", response_model=ModuleActionResult)
def deploy_patch(patch_id: str, payload: ModuleActionRequest, http_request: Request, account: Account = Depends(current_account)) -> ModuleActionResult:
    result = _module_action(patch_id, payload.action, payload=payload.payload, approval_required=True, controls=["iso27001-2022:A.8.8", "nist-csf-2.0:PR.PS"])
    audit.record(action="risk.patch.stage", resource=f"patch:{patch_id}", actor=str(account.id), after=result.model_dump(mode="json"), request_id=_request_id(http_request))
    return result


@app.get("/companies/risk-summary", response_model=list[CustomerRiskSummary])
def companies_risk_summary(account: Account = Depends(current_account)) -> list[CustomerRiskSummary]:
    _ = account
    summaries: list[CustomerRiskSummary] = []
    now = datetime.now(UTC)
    for customer in list_customers():
        if not tenancy.has_permission(account, "incidents", "view", partner_id=customer.partner_id, customer_id=customer.id):
            continue
        with db.connection() as conn, conn.cursor() as cur:
            cur.execute("select count(*) as n, max(updated_at) as last_seen from heartbeats where customer_id = %s", (customer.id,))
            heartbeat_row = cur.fetchone()
            cur.execute("select count(*) as n from security_alerts where customer_id = %s and status not in ('resolved', 'closed', 'dismissed')", (customer.id,))
            security_alerts = int(cur.fetchone()["n"])
            cur.execute("select count(*) as n from alerts where customer_id = %s and status = 'open'", (customer.id,))
            dlp_alerts = int(cur.fetchone()["n"])
            cur.execute("select coalesce(max(payload->>'policy_version'), 'No active assignment') as policy_version from heartbeats where customer_id = %s", (customer.id,))
            policy_version = cur.fetchone()["policy_version"] or "No active assignment"
            cur.execute("select status from company_licenses where customer_id = %s", (customer.id,))
            license_row = cur.fetchone()
        enrolled = int(heartbeat_row["n"] or 0)
        open_alerts = security_alerts + dlp_alerts
        risk_score = min(100, open_alerts * 12 + max(0, 5 - enrolled) * 4)
        summaries.append(CustomerRiskSummary(
            customer_id=customer.id,
            company_name=customer.name,
            risk_score=risk_score,
            risk_band=_risk_band_from_score(risk_score),
            open_alerts=open_alerts,
            enrolled_agents=enrolled,
            license_status=(license_row["status"] if license_row else "trial"),
            last_seen=heartbeat_row["last_seen"] or customer.created_at or now,
            policy_version=policy_version,
            ai_efficiency_score=max(0, min(100, 100 - open_alerts * 3)),
        ))
    return sorted(summaries, key=lambda item: item.risk_score, reverse=True)


REPORT_DESCRIPTIONS: dict[str, str] = reports_service.REPORT_DESCRIPTIONS


@app.get("/reports", response_model=list[ReportRecord])
def list_reports(customer_id: UUID | None = Query(default=None), account: Account = Depends(current_account)) -> list[ReportRecord]:
    if customer_id is not None:
        _require_customer_access(customer_id, account)
    clauses, params = _scope_filter(account, "sa")
    scope_clause = " and ".join(clauses)
    return reports_service.list_reports(customer_id, scope_clause, params)


@app.post("/reports/generate", response_model=ReportRecord)
def generate_report(payload: ReportGenerateRequest, http_request: Request, account: Account = Depends(current_account)) -> ReportRecord:
    if payload.customer_id is not None:
        _require_customer_access(payload.customer_id, account)
    clauses, params = _scope_filter(account, "sa")
    scope_clause = " and ".join(clauses)
    partner_id: UUID | None = None
    if payload.customer_id is not None:
        partner_id = _customer_partner(payload.customer_id)
    try:
        report = reports_service.generate(
            payload.type,
            payload.customer_id,
            account.id,
            partner_id,
            scope_clause,
            params,
        )
    except reports_service.ReportError as error:
        raise HTTPException(status_code=400, detail=str(error)) from error
    audit.record(
        action="report.generate",
        resource=f"report:{report.id}",
        actor=str(account.id),
        after=report.model_dump(mode="json"),
        request_id=_request_id(http_request),
    )
    return report


@app.get("/reports/{report_id}/download")
def download_report(report_id: UUID, account: Account = Depends(current_account)) -> dict[str, Any]:
    result = reports_service.get_artifact(report_id)
    if result is None:
        raise HTTPException(status_code=404, detail="report not found")
    record, artifact = result
    if record.customer_id is not None:
        _require_customer_access(record.customer_id, account)
    return {"report": record.model_dump(mode="json"), "artifact": artifact}


@app.get("/usage/summary", response_model=PlatformUsage)
def usage_summary(account: Account = Depends(current_account)) -> PlatformUsage:
    customers = companies_risk_summary(account)
    usage_rows = []
    for customer in customers:
        with db.connection() as conn, conn.cursor() as cur:
            cur.execute(
                "select count(*) as n from telemetry_events "
                "where customer_id = %s and timestamp >= now() - interval '30 days'",
                (customer.customer_id,),
            )
            events_30d = int(cur.fetchone()["n"])
            cur.execute(
                "select count(*) as n from telemetry_events "
                "where customer_id = %s and timestamp >= now() - interval '60 days' "
                "and timestamp < now() - interval '30 days'",
                (customer.customer_id,),
            )
            prior_events_30d = int(cur.fetchone()["n"])
            cur.execute(
                "select count(*) as n from security_alerts "
                "where customer_id = %s and created_at >= now() - interval '30 days'",
                (customer.customer_id,),
            )
            alerts_30d = int(cur.fetchone()["n"])
            cur.execute(
                "select coalesce(sum(calls), 0) as n from customer_ai_usage_daily "
                "where customer_id = %s and day >= current_date - interval '30 days'",
                (customer.customer_id,),
            )
            ai_calls = int(cur.fetchone()["n"] or 0)
            cur.execute(
                "select coalesce(sum(calls), 0) as n from customer_ai_usage_daily "
                "where customer_id = %s and day >= current_date - interval '60 days' "
                "and day < current_date - interval '30 days'",
                (customer.customer_id,),
            )
            prior_ai_calls = int(cur.fetchone()["n"] or 0)
            cur.execute(
                "select coalesce(sum(octet_length(payload::text)), 0) as bytes "
                "from telemetry_events "
                "where customer_id = %s and timestamp >= now() - interval '30 days'",
                (customer.customer_id,),
            )
            telemetry_bytes = int(cur.fetchone()["bytes"] or 0)
            cur.execute(
                "select coalesce(sum(octet_length(payload::text)), 0) as bytes "
                "from security_alerts "
                "where customer_id = %s and created_at >= now() - interval '30 days'",
                (customer.customer_id,),
            )
            alert_bytes = int(cur.fetchone()["bytes"] or 0)

        def _pct(current: int, prior: int) -> int:
            if prior == 0:
                return 100 if current > 0 else 0
            return int(round((current - prior) * 100.0 / prior))

        storage_gb = round((telemetry_bytes + alert_bytes) / (1024 ** 3), 4)
        usage_rows.append({
            "customer_id": customer.customer_id,
            "customer_name": customer.company_name,
            "endpoint_count": customer.enrolled_agents,
            "events_30d": events_30d,
            "ai_calls_30d": ai_calls,
            "ai_efficiency_score": customer.ai_efficiency_score,
            "dlp_events_30d": alerts_30d,
            "alerts_30d": alerts_30d,
            "blocked_30d": customer.open_alerts,
            "storage_gb": storage_gb,
            "trend_events": _pct(events_30d, prior_events_30d),
            "trend_ai": _pct(ai_calls, prior_ai_calls),
        })
    avg_efficiency = int(sum(row["ai_efficiency_score"] for row in usage_rows) / len(usage_rows)) if usage_rows else 0
    return PlatformUsage(
        total_endpoints=sum(row["endpoint_count"] for row in usage_rows),
        total_events_30d=sum(row["events_30d"] for row in usage_rows),
        total_ai_calls_30d=sum(row["ai_calls_30d"] for row in usage_rows),
        avg_ai_efficiency_score=avg_efficiency,
        total_dlp_events_30d=sum(row["dlp_events_30d"] for row in usage_rows),
        total_blocked_30d=sum(row["blocked_30d"] for row in usage_rows),
        total_storage_gb=round(sum(row["storage_gb"] for row in usage_rows), 4),
        customers=usage_rows,
    )


@app.get("/integrations", response_model=list[Connector])
def list_integrations(_: Account = Depends(current_account)) -> list[Connector]:
    return integrations_service.list_connectors()


@app.post("/integrations/{connector_id}/configure", response_model=Connector)
def configure_integration(connector_id: str, payload: dict[str, str], http_request: Request, account: Account = Depends(current_account)) -> Connector:
    try:
        connector = integrations_service.configure(connector_id, payload, account.id)
    except integrations_service.IntegrationError as error:
        message = str(error)
        status = 404 if "not registered" in message else 400
        raise HTTPException(status_code=status, detail=message) from error
    audit.record(
        action="integration.configure",
        resource=f"integration:{connector_id}",
        actor=str(account.id),
        after={"configured_fields": sorted(payload.keys())},
        request_id=_request_id(http_request),
    )
    return connector


@app.post("/integrations/{connector_id}/disconnect", response_model=Connector)
def disconnect_integration(connector_id: str, http_request: Request, account: Account = Depends(current_account)) -> Connector:
    try:
        connector = integrations_service.disconnect(connector_id, account.id)
    except integrations_service.IntegrationError as error:
        raise HTTPException(status_code=404, detail=str(error)) from error
    audit.record(
        action="integration.disconnect",
        resource=f"integration:{connector_id}",
        actor=str(account.id),
        request_id=_request_id(http_request),
    )
    return connector


def _banner_from_row(row: dict) -> SystemBanner:
    return SystemBanner(
        id=row["id"],
        message=row["message"],
        link_label=row["link_label"],
        link_url=row["link_url"],
        severity=row["severity"],
        starts_at=row["starts_at"],
        ends_at=row["ends_at"],
        active=row["active"],
        created_by=row["created_by"],
        created_at=row["created_at"],
    )


@app.get("/system/banners", response_model=list[SystemBanner])
def list_active_banners_route(_: Account = Depends(current_account)) -> list[SystemBanner]:
    now = datetime.now(UTC)
    with db.connection() as conn, conn.cursor() as cur:
        cur.execute(
            """
            select id, message, link_label, link_url, severity, starts_at, ends_at, active, created_by, created_at
            from system_banners
            where active = true
              and starts_at <= %s
              and (ends_at is null or ends_at >= %s)
            order by severity desc, starts_at desc, created_at desc
            """,
            (now, now),
        )
        return [_banner_from_row(row) for row in cur.fetchall()]


@app.get("/system/banners/all", response_model=list[SystemBanner])
def list_all_banners_route(_: Account = Depends(require_platform_owner)) -> list[SystemBanner]:
    with db.connection() as conn, conn.cursor() as cur:
        cur.execute(
            """
            select id, message, link_label, link_url, severity, starts_at, ends_at, active, created_by, created_at
            from system_banners
            order by created_at desc
            limit 50
            """
        )
        return [_banner_from_row(row) for row in cur.fetchall()]


@app.post("/system/banners", response_model=SystemBanner, status_code=201)
def create_banner_route(
    payload: SystemBannerCreate,
    http_request: Request,
    actor: Account = Depends(require_platform_owner),
) -> SystemBanner:
    now = datetime.now(UTC)
    starts_at = payload.starts_at or now
    if payload.ends_at is not None and payload.ends_at <= starts_at:
        raise HTTPException(status_code=400, detail="ends_at must be after starts_at")
    if (payload.link_label and not payload.link_url) or (payload.link_url and not payload.link_label):
        raise HTTPException(status_code=400, detail="link label and url must be provided together")
    banner_id = uuid.uuid4()
    with db.connection() as conn, conn.cursor() as cur:
        cur.execute(
            """
            insert into system_banners (
                id, message, link_label, link_url, severity, starts_at, ends_at, active, created_by, created_at
            ) values (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
            returning id, message, link_label, link_url, severity, starts_at, ends_at, active, created_by, created_at
            """,
            (
                banner_id,
                payload.message.strip(),
                payload.link_label.strip() if payload.link_label else None,
                str(payload.link_url).strip() if payload.link_url else None,
                payload.severity,
                starts_at,
                payload.ends_at,
                payload.active,
                actor.id,
                now,
            ),
        )
        banner = _banner_from_row(cur.fetchone())
    audit.record(
        action="system.banner.create",
        resource=f"system_banner:{banner.id}",
        actor=str(actor.id),
        after={"message": banner.message, "severity": banner.severity, "active": banner.active},
        request_id=_request_id(http_request),
    )
    return banner


@app.delete("/system/banners/{banner_id}", status_code=204)
def delete_banner_route(
    banner_id: UUID,
    http_request: Request,
    actor: Account = Depends(require_platform_owner),
) -> None:
    with db.connection() as conn, conn.cursor() as cur:
        cur.execute(
            """
            update system_banners
            set active = false
            where id = %s and active = true
            returning id, message, severity
            """,
            (banner_id,),
        )
        row = cur.fetchone()
    if row is None:
        raise HTTPException(status_code=404, detail="banner not found")
    audit.record(
        action="system.banner.delete",
        resource=f"system_banner:{banner_id}",
        actor=str(actor.id),
        before={"message": row["message"], "severity": row["severity"]},
        request_id=_request_id(http_request),
    )


_TOTP_ISSUER = "Aetherix"
_TOTP_SETUP_TTL_SECONDS = 600   # 10 min to scan QR + enter first code
_TOTP_VERIFY_TTL_SECONDS = 300  # 5 min for returning users


@app.post("/auth/login", response_model=TotpChallenge)
def auth_login(payload: LoginRequest, http_request: Request) -> TotpChallenge:
    try:
        snapshot = tenancy.authenticate(payload.email, payload.password)
    except TenancyError as error:
        audit.record(
            action="auth.login.failed",
            resource=f"email:{payload.email.strip().lower()}",
            actor="anonymous",
            after={"reason": str(error)},
            request_id=_request_id(http_request),
        )
        raise HTTPException(status_code=401, detail="invalid email or password") from error

    account_id: UUID = snapshot["account_id"]
    needs_enrollment = (
        snapshot["two_factor"] != "enabled" or not snapshot["totp_secret"]
    )

    if needs_enrollment:
        # Generate (or regenerate) the shared secret. We replace any
        # half-finished setup so abandoned QR codes can't be reused.
        secret = totp_service.generate_secret()
        tenancy.store_totp_secret(account_id, secret)
        challenge_id = tenancy.create_login_challenge(
            account_id, "totp_setup", _TOTP_SETUP_TTL_SECONDS
        )
        recovery_codes = tenancy.generate_recovery_codes(account_id)
        otpauth = totp_service.otpauth_url(
            account_name=snapshot["email"], secret=secret, issuer=_TOTP_ISSUER
        )
        audit.record(
            action="auth.totp.setup_started",
            resource=f"account:{account_id}",
            actor=str(account_id),
            request_id=_request_id(http_request),
        )
        return TotpChallenge(
            status="totp_setup_required",
            challenge_id=challenge_id,
            email=snapshot["email"],
            otpauth_url=otpauth,
            secret=secret,
            issuer=_TOTP_ISSUER,
            recovery_codes=recovery_codes,
        )

    challenge_id = tenancy.create_login_challenge(
        account_id, "totp_verify", _TOTP_VERIFY_TTL_SECONDS
    )
    return TotpChallenge(
        status="totp_required",
        challenge_id=challenge_id,
        email=snapshot["email"],
    )


@app.post("/auth/totp/verify", response_model=LoginResult)
def auth_totp_verify(payload: TotpVerifyRequest, http_request: Request) -> LoginResult:
    from app.services import jwt_tokens

    try:
        ctx = tenancy.consume_login_challenge(payload.challenge_id)
    except TenancyError as error:
        raise HTTPException(status_code=401, detail=str(error)) from error

    secret = ctx["totp_secret"]
    if not secret or not totp_service.verify(secret, payload.code):
        audit.record(
            action="auth.totp.failed",
            resource=f"account:{ctx['account_id']}",
            actor=str(ctx["account_id"]),
            after={"purpose": ctx["purpose"]},
            request_id=_request_id(http_request),
        )
        raise HTTPException(status_code=401, detail="invalid verification code")

    if ctx["purpose"] == "totp_setup":
        tenancy.mark_totp_enrolled(ctx["account_id"])
    tenancy.touch_last_login(ctx["account_id"])

    account = tenancy.get_account(ctx["account_id"])
    if account is None:
        raise HTTPException(status_code=404, detail="account not found")
    token, exp_epoch = jwt_tokens.issue(str(account.id))
    audit.record(
        action="auth.login",
        resource=f"account:{account.id}",
        actor=str(account.id),
        after={"email": account.email, "via": ctx["purpose"]},
        request_id=_request_id(http_request),
    )
    return LoginResult(
        access_token=token,
        expires_at=datetime.fromtimestamp(exp_epoch, tz=UTC),
        me=tenancy.me(account),
    )


@app.post("/auth/recovery-code", response_model=LoginResult)
def auth_recovery_code(payload: RecoveryCodeVerifyRequest, http_request: Request) -> LoginResult:
    from app.services import jwt_tokens

    try:
        ctx = tenancy.consume_login_challenge(payload.challenge_id)
    except TenancyError as error:
        raise HTTPException(status_code=401, detail=str(error)) from error

    account_id = ctx["account_id"]
    if not tenancy.verify_recovery_code(account_id, payload.code):
        audit.record(
            action="auth.recovery_code.failed",
            resource=f"account:{account_id}",
            actor=str(account_id),
            request_id=_request_id(http_request),
        )
        raise HTTPException(status_code=401, detail="invalid recovery code")

    tenancy.touch_last_login(account_id)
    account = tenancy.get_account(account_id)
    if account is None:
        raise HTTPException(status_code=404, detail="account not found")
    token, exp_epoch = jwt_tokens.issue(str(account.id))
    audit.record(
        action="auth.login",
        resource=f"account:{account.id}",
        actor=str(account.id),
        after={"email": account.email, "via": "recovery_code"},
        request_id=_request_id(http_request),
    )
    return LoginResult(
        access_token=token,
        expires_at=datetime.fromtimestamp(exp_epoch, tz=UTC),
        me=tenancy.me(account),
    )


@app.get("/auth/recovery-codes", response_model=RecoveryCodeList)
def list_recovery_codes_route(
    account: Account = Depends(current_account),
) -> RecoveryCodeList:
    return tenancy.list_recovery_codes(account.id)


# --- OAuth2 / SSO -------------------------------------------------------------


@app.get("/auth/oauth2/providers")
def list_oauth2_providers_route(
    _: Account = Depends(current_account),
) -> list[dict]:
    return tenancy.list_oauth2_providers()


@app.post("/auth/oauth2/providers", response_model=OAuth2Provider, status_code=201)
def create_oauth2_provider_route(
    payload: OAuth2ProviderCreate,
    http_request: Request,
    account: Account = Depends(require("companies", "manage")),
) -> OAuth2Provider:
    try:
        provider = tenancy.create_oauth2_provider(payload.model_dump())
    except Exception as error:
        raise HTTPException(status_code=400, detail=str(error)) from error
    audit.record(
        action="oauth2.provider.create",
        resource=f"oauth2_provider:{provider['id']}",
        actor=str(account.id),
        after={"name": payload.name, "provider_type": payload.provider_type},
        request_id=_request_id(http_request),
    )
    return OAuth2Provider(**provider)


@app.put("/auth/oauth2/providers/{provider_id}", response_model=OAuth2Provider)
def update_oauth2_provider_route(
    provider_id: UUID,
    payload: OAuth2ProviderUpdate,
    http_request: Request,
    account: Account = Depends(require("companies", "manage")),
) -> OAuth2Provider:
    provider = tenancy.update_oauth2_provider(provider_id, payload.model_dump(exclude_unset=True))
    if provider is None:
        raise HTTPException(status_code=404, detail="provider not found")
    audit.record(
        action="oauth2.provider.update",
        resource=f"oauth2_provider:{provider_id}",
        actor=str(account.id),
        request_id=_request_id(http_request),
    )
    return OAuth2Provider(**provider)


@app.post("/auth/oauth2/authorize")
def auth_oauth2_authorize(
    provider_id: UUID,
    redirect_uri: str | None = Query(default=None),
    account: Account = Depends(current_account),
) -> dict:
    provider = tenancy.get_oauth2_provider(provider_id)
    if provider is None:
        raise HTTPException(status_code=404, detail="OAuth2 provider not found")
    if not provider["enabled"]:
        raise HTTPException(status_code=400, detail="OAuth2 provider is disabled")

    state_token = secrets.token_urlsafe(32)
    tenancy.create_oauth2_state(provider_id, state_token, redirect_uri, ttl_seconds=600)

    auth_url = provider.get("authorization_url") or (provider.get("issuer_url", "").rstrip("/") + "/protocol/openid-connect/auth")
    params = {
        "client_id": provider["client_id"],
        "response_type": "code",
        "scope": provider["scopes"],
        "redirect_uri": redirect_uri or "",
        "state": state_token,
    }
    qs = "&".join(f"{k}={_url_encode(str(v))}" for k, v in params.items() if v)
    full_url = f"{auth_url}?{qs}" if "?" not in auth_url else f"{auth_url}&{qs}"

    return {"authorization_url": full_url, "state_token": state_token}


@app.get("/auth/oauth2/callback")
async def auth_oauth2_callback(
    code: str = Query(...),
    state: str = Query(...),
    http_request: Request = None,
) -> LoginResult:
    import httpx

    state_data = tenancy.consume_oauth2_state(state)
    if state_data is None:
        raise HTTPException(status_code=400, detail="invalid or expired OAuth2 state")

    provider = tenancy.get_oauth2_provider(state_data["provider_id"])
    if provider is None:
        raise HTTPException(status_code=404, detail="OAuth2 provider not found")

    token_url = provider.get("token_url") or (provider.get("issuer_url", "").rstrip("/") + "/protocol/openid-connect/token")
    userinfo_url = provider.get("userinfo_url") or (provider.get("issuer_url", "").rstrip("/") + "/protocol/openid-connect/userinfo")

    # Exchange authorization code for tokens
    async with httpx.AsyncClient() as client:
        token_resp = await client.post(
            token_url,
            data={
                "grant_type": "authorization_code",
                "code": code,
                "redirect_uri": state_data.get("redirect_uri") or "",
                "client_id": provider["client_id"],
                "client_secret": provider["client_secret"],
            },
            headers={"Accept": "application/json"},
        )
        if token_resp.status_code != 200:
            raise HTTPException(status_code=401, detail="failed to exchange authorization code")

        token_data = token_resp.json()
        access_token = token_data.get("access_token")

        # Fetch userinfo
        userinfo_resp = await client.get(
            userinfo_url,
            headers={"Authorization": f"Bearer {access_token}"},
        )
        if userinfo_resp.status_code != 200:
            raise HTTPException(status_code=401, detail="failed to fetch user info")

        userinfo = userinfo_resp.json()

    provider_subject = str(userinfo.get("sub", ""))
    email = userinfo.get("email", "")

    if not provider_subject:
        raise HTTPException(status_code=400, detail="OAuth2 provider did not return a subject claim")

    # Check if identity is already linked to an account
    account_id = tenancy.find_account_by_oauth2_identity(provider["id"], provider_subject)

    if account_id is None:
        # If email matches an existing account, link it
        if email:
            existing = tenancy.find_account_by_email(email)
            if existing is not None:
                account_id = existing.id
                tenancy.upsert_oauth2_identity(account_id, provider["id"], provider_subject, email)

    if account_id is None:
        raise HTTPException(
            status_code=400,
            detail="no matching account found — SSO auto-provisioning not yet supported",
        )

    from app.services import jwt_tokens
    tenancy.touch_last_login(account_id)
    account = tenancy.get_account(account_id)
    if account is None:
        raise HTTPException(status_code=404, detail="account not found")

    token, exp_epoch = jwt_tokens.issue(str(account.id))
    audit.record(
        action="auth.login",
        resource=f"account:{account.id}",
        actor=str(account.id),
        after={"email": account.email, "via": f"oauth2:{provider['provider_type']}"},
        request_id=_request_id(http_request),
    )
    return LoginResult(
        access_token=token,
        expires_at=datetime.fromtimestamp(exp_epoch, tz=UTC),
        me=tenancy.me(account),
    )


def _url_encode(value: str) -> str:
    from urllib.parse import quote
    return quote(value, safe="")


@app.post("/accounts/{account_id}/password", status_code=204)
def set_account_password_route(
    account_id: UUID,
    payload: PasswordSetRequest,
    http_request: Request,
    actor: Account = Depends(current_account),
) -> None:
    # Self-service password change is always allowed; otherwise the actor
    # needs ``accounts:manage`` AND the target must be inside their scope.
    if actor.id != account_id:
        target = tenancy.get_account(account_id)
        if target is None:
            raise HTTPException(status_code=404, detail="account not found")
        if not tenancy.account_visible_to(actor, target):
            raise HTTPException(status_code=404, detail="account not found")
        if not tenancy.has_permission(actor, "accounts", "manage"):
            raise HTTPException(status_code=403, detail="requires manage on accounts")
    try:
        tenancy.set_password(account_id, payload.password)
    except TenancyError as error:
        raise HTTPException(status_code=404, detail=str(error)) from error
    except ValueError as error:
        raise HTTPException(status_code=400, detail=str(error)) from error
    audit.record(
        action="account.password.set",
        resource=f"account:{account_id}",
        actor=str(actor.id),
        request_id=_request_id(http_request),
    )


@app.get("/roles", response_model=list[Role])
def list_roles_route(_: Account = Depends(current_account)) -> list[Role]:
    return tenancy.list_roles()


@app.get("/accounts", response_model=list[Account])
def list_accounts_route(
    actor: Account = Depends(require("accounts", "view")),
) -> list[Account]:
    return tenancy.list_accounts_for(actor)


@app.post("/accounts/bulk-delete", response_model=BulkActionResult)
def bulk_delete_accounts_route(
    payload: BulkIdsRequest,
    http_request: Request,
    actor: Account = Depends(require("accounts", "manage")),
) -> BulkActionResult:
    ok_count = 0
    failures: list[BulkActionFailure] = []
    for account_id in payload.ids:
        if account_id == actor.id:
            failures.append(BulkActionFailure(id=account_id, error="cannot delete your own account"))
            continue
        target = tenancy.get_account(account_id)
        if target is None:
            failures.append(BulkActionFailure(id=account_id, error="account not found"))
            continue
        if not tenancy.account_visible_to(actor, target):
            failures.append(BulkActionFailure(id=account_id, error="account not found"))
            continue
        if not tenancy.delete_account(account_id):
            failures.append(BulkActionFailure(id=account_id, error="account not found"))
            continue
        ok_count += 1
        audit.record(
            action="account.delete",
            resource=f"account:{account_id}",
            actor=str(actor.id),
            before={"email": target.email, "status": target.status},
            request_id=_request_id(http_request),
        )
    return BulkActionResult(ok_count=ok_count, failures=failures)


@app.post("/accounts", response_model=AccountCreated, status_code=201)
def create_account_route(
    payload: AccountCreate,
    http_request: Request,
    actor: Account = Depends(require("accounts", "manage")),
) -> AccountCreated:
    payload.created_by = str(actor.id)
    try:
        account = tenancy.create_account(payload, actor=actor)
    except TenancyError as error:
        raise HTTPException(status_code=400, detail=str(error)) from error

    invite_url: str | None = None
    invite_expires_at = None
    # Only issue an invite token when the account was created without a
    # password (i.e. it is in "invited" status). Pre-set passwords skip the
    # invite flow entirely.
    if payload.password is None:
        token, invite_expires_at = tenancy.issue_invite_token(account.id)
        invite_url = _build_invite_url(http_request, token)
        if payload.delivery == "email":
            # Email delivery is stubbed until an SMTP/transactional provider
            # is wired in. Log the link so dev/ops can hand-deliver if needed,
            # but do not return it to the creator.
            _logger.info(
                "account.invite.email_pending account=%s email=%s url=%s",
                account.id,
                account.email,
                invite_url,
            )

    audit.record(
        action="account.create",
        resource=f"account:{account.id}",
        actor=str(actor.id),
        after={
            "email": account.email,
            "full_name": account.full_name,
            "delivery": payload.delivery,
        },
        request_id=_request_id(http_request),
    )
    return AccountCreated(
        account=account,
        delivery=payload.delivery,
        invite_url=invite_url if payload.delivery == "link" else None,
        invite_expires_at=invite_expires_at if payload.delivery == "link" else None,
    )


@app.post("/auth/accept-invite", response_model=Account)
def accept_invite_route(
    payload: InviteAcceptRequest,
    http_request: Request,
) -> Account:
    try:
        account = tenancy.accept_invite(
            payload.token,
            payload.password,
            full_name=payload.full_name,
        )
    except TenancyError as error:
        raise HTTPException(status_code=400, detail=str(error)) from error
    audit.record(
        action="account.invite.accept",
        resource=f"account:{account.id}",
        actor=str(account.id),
        after={"email": account.email},
        request_id=_request_id(http_request),
    )
    return account


@app.get("/accounts/{account_id}", response_model=Account)
def get_account_route(
    account_id: UUID,
    actor: Account = Depends(require("accounts", "view")),
) -> Account:
    account = tenancy.get_account(account_id)
    if account is None:
        raise HTTPException(status_code=404, detail="account not found")
    if not tenancy.account_visible_to(actor, account):
        raise HTTPException(status_code=404, detail="account not found")
    return account


@app.delete("/accounts/{account_id}", status_code=204)
def delete_account_route(
    account_id: UUID,
    http_request: Request,
    actor: Account = Depends(require("accounts", "manage")),
) -> None:
    """Hard-delete a user account. Refuses to delete the caller themselves."""

    if account_id == actor.id:
        raise HTTPException(status_code=400, detail="cannot delete your own account")
    target = tenancy.get_account(account_id)
    if target is None:
        raise HTTPException(status_code=404, detail="account not found")
    if not tenancy.account_visible_to(actor, target):
        raise HTTPException(status_code=404, detail="account not found")
    removed = tenancy.delete_account(account_id)
    if not removed:
        raise HTTPException(status_code=404, detail="account not found")
    audit.record(
        action="account.delete",
        resource=f"account:{account_id}",
        actor=str(actor.id),
        before={"email": target.email, "status": target.status},
        request_id=_request_id(http_request),
    )


@app.post(
    "/accounts/{account_id}/roles",
    response_model=RoleAssignment,
    status_code=201,
)
def assign_role_route(
    account_id: UUID,
    payload: RoleAssignmentRequest,
    http_request: Request,
    actor: Account = Depends(require("accounts", "manage")),
) -> RoleAssignment:
    target = tenancy.get_account(account_id)
    if target is None:
        raise HTTPException(status_code=404, detail="account not found")
    if not tenancy.account_visible_to(actor, target):
        raise HTTPException(status_code=404, detail="account not found")
    try:
        assignment = tenancy.assign_role(
            account_id, payload, granted_by=str(actor.id), actor=actor
        )
    except TenancyError as error:
        raise HTTPException(status_code=400, detail=str(error)) from error
    audit.record(
        action="account.role.assign",
        resource=f"account:{account_id}",
        actor=str(actor.id),
        after={
            "role_code": assignment.role_code,
            "partner_id": str(assignment.partner_id) if assignment.partner_id else None,
            "customer_id": str(assignment.customer_id) if assignment.customer_id else None,
        },
        request_id=_request_id(http_request),
    )
    return assignment


@app.delete("/accounts/{account_id}/roles/{assignment_id}", status_code=204)
def revoke_role_route(
    account_id: UUID,
    assignment_id: UUID,
    http_request: Request,
    actor: Account = Depends(require("accounts", "manage")),
) -> None:
    target = tenancy.get_account(account_id)
    if target is None:
        raise HTTPException(status_code=404, detail="account not found")
    if not tenancy.account_visible_to(actor, target):
        raise HTTPException(status_code=404, detail="account not found")
    removed = tenancy.revoke_role(account_id, assignment_id)
    if not removed:
        raise HTTPException(status_code=404, detail="role assignment not found")
    audit.record(
        action="account.role.revoke",
        resource=f"account:{account_id}",
        actor=str(actor.id),
        after={"assignment_id": str(assignment_id)},
        request_id=_request_id(http_request),
    )


# --- Impersonation ---------------------------------------------------------


@app.post("/accounts/{account_id}/impersonate", status_code=201)
def start_impersonation_route(
    account_id: UUID,
    payload: dict,
    http_request: Request,
    actor: Account = Depends(current_account),
) -> dict:
    """Start an impersonation session against ``account_id``.

    Request body: ``{"reason": "investigating ticket 1234", "ttl_seconds": 1800}``.

    Authorisation is enforced inside ``impersonation.start_session``
    (requires ``impersonate=manage`` on the target's tenancy scope).
    """

    from app.services import impersonation

    reason = str(payload.get("reason") or "").strip()
    ttl = int(payload.get("ttl_seconds") or impersonation.DEFAULT_TTL_SECONDS)
    ttl = max(60, min(ttl, 8 * 3600))
    try:
        session, token, exp = impersonation.start_session(
            actor=actor,
            target_account_id=account_id,
            reason=reason,
            request_id=_request_id(http_request),
            ttl_seconds=ttl,
        )
    except impersonation.ImpersonationError as error:
        detail = str(error)
        status_code = 404 if "not found" in detail else 400
        if "requires" in detail:
            status_code = 403
        raise HTTPException(status_code=status_code, detail=detail) from error

    return {
        "session": session.to_dict(),
        "token": token,
        "expires_at": exp,
    }


@app.post("/impersonation/{session_id}/end", status_code=200)
def end_impersonation_route(
    session_id: UUID,
    http_request: Request,
    actor: Account = Depends(current_account),
) -> dict:
    from app.services import impersonation

    try:
        session = impersonation.end_session(
            session_id=session_id,
            actor=actor,
            request_id=_request_id(http_request),
        )
    except impersonation.ImpersonationError as error:
        detail = str(error)
        status_code = 404 if "not found" in detail else 403
        raise HTTPException(status_code=status_code, detail=detail) from error
    return {"session": session.to_dict()}


@app.get("/impersonation")
def list_impersonation_route(
    actor_account_id: UUID | None = Query(default=None),
    target_account_id: UUID | None = Query(default=None),
    active_only: bool = Query(default=False),
    limit: int = Query(default=100, ge=1, le=500),
    actor: Account = Depends(current_account),
) -> dict:
    from app.services import impersonation

    sessions = impersonation.list_sessions(
        actor=actor,
        actor_account_id=actor_account_id,
        target_account_id=target_account_id,
        active_only=active_only,
        limit=limit,
    )
    return {"sessions": [s.to_dict() for s in sessions]}


# --- Companies (tenant-scoped) ---------------------------------------------


def _company_or_404(customer_id: UUID) -> Customer:
    company = get_customer(customer_id)
    if company is None:
        raise HTTPException(status_code=404, detail="company not found")
    return company


def _require_company_access(
    customer_id: UUID,
    resource: str,
    level: PermissionLevel,
    account: Account,
) -> Customer:
    """Resolve a company and verify the caller can act on it.

    Translates ``customer_id`` to ``partner_id`` so MSP partner role
    assignments are evaluated against the company's owning partner.
    """

    company = _company_or_404(customer_id)
    if not tenancy.has_permission(
        account,
        resource,
        level,
        partner_id=company.partner_id,
        customer_id=customer_id,
    ):
        raise HTTPException(
            status_code=403,
            detail=f"requires {level} on {resource} for this company",
        )
    return company


def _filter_companies_for_scope(account: Account, all_companies: list[Customer]) -> list[Customer]:
    scope = tenancy.compute_scope(account)
    if scope.is_platform:
        return all_companies
    partner_ids = set(scope.partner_ids)
    customer_ids = set(scope.customer_ids)
    return [
        c for c in all_companies
        if c.partner_id in partner_ids or c.id in customer_ids
    ]


@app.get("/companies", response_model=list[Customer])
def list_companies_route(
    account: Account = Depends(require("companies", "view")),
) -> list[Customer]:
    return _filter_companies_for_scope(account, list_customers())


@app.get("/companies/summary", response_model=CompanySummaryPage)
def list_company_summaries_route(
    q: str | None = Query(default=None, max_length=160),
    status: str | None = Query(default=None, pattern="^(active|suspended|archived)$"),
    limit: int = Query(default=50, ge=1, le=250),
    offset: int = Query(default=0, ge=0),
    account: Account = Depends(require("companies", "view")),
) -> CompanySummaryPage:
    scope = tenancy.compute_scope(account)
    companies, total = list_customers_page(
        partner_ids=None if scope.is_platform else scope.partner_ids,
        customer_ids=None if scope.is_platform else scope.customer_ids,
        search=q,
        status=status,  # type: ignore[arg-type]
        limit=limit,
        offset=offset,
    )
    if not tenancy.has_permission(account, "licensing", "view"):
        return CompanySummaryPage(
            items=[CompanySummary(customer=company, license=None) for company in companies],
            total=total,
            limit=limit,
            offset=offset,
        )
    licenses = licensing.list_licenses([company.id for company in companies])
    return CompanySummaryPage(
        items=[CompanySummary(customer=company, license=licenses.get(company.id)) for company in companies],
        total=total,
        limit=limit,
        offset=offset,
    )


@app.post("/companies/bulk-status", response_model=BulkActionResult)
def bulk_update_company_status_route(
    payload: CompanyBulkStatusRequest,
    http_request: Request,
    account: Account = Depends(current_account),
) -> BulkActionResult:
    ok_count = 0
    failures: list[BulkActionFailure] = []
    for customer_id in payload.ids:
        try:
            company = _require_company_access(customer_id, "companies", "manage", account)
            updated = update_customer_status(customer_id, payload.status)
            if updated is None:
                failures.append(BulkActionFailure(id=customer_id, error="company not found"))
                continue
            ok_count += 1
            audit.record(
                action="company.status.update",
                resource=f"company:{customer_id}",
                actor=str(account.id),
                before={"status": company.status},
                after={"status": updated.status},
                request_id=_request_id(http_request),
            )
        except HTTPException as error:
            failures.append(BulkActionFailure(id=customer_id, error=str(error.detail)))
        except CustomerError as error:
            failures.append(BulkActionFailure(id=customer_id, error=str(error)))
    return BulkActionResult(ok_count=ok_count, failures=failures)


@app.post("/companies/bulk-delete", response_model=BulkActionResult)
def bulk_delete_companies_route(
    payload: BulkIdsRequest,
    http_request: Request,
    account: Account = Depends(current_account),
) -> BulkActionResult:
    ok_count = 0
    failures: list[BulkActionFailure] = []
    for customer_id in payload.ids:
        try:
            company = _require_company_access(customer_id, "companies", "manage", account)
            if not delete_customer(customer_id):
                failures.append(BulkActionFailure(id=customer_id, error="company not found"))
                continue
            ok_count += 1
            audit.record(
                action="company.delete",
                resource=f"company:{customer_id}",
                actor=str(account.id),
                before={"name": company.name, "status": company.status},
                request_id=_request_id(http_request),
            )
        except HTTPException as error:
            failures.append(BulkActionFailure(id=customer_id, error=str(error.detail)))
    return BulkActionResult(ok_count=ok_count, failures=failures)


@app.get("/companies/{customer_id}", response_model=Customer)
def get_company_route(
    customer_id: UUID,
    account: Account = Depends(current_account),
) -> Customer:
    return _require_company_access(customer_id, "companies", "view", account)


@app.patch("/companies/{customer_id}/status", response_model=Customer)
def update_company_status_route(
    customer_id: UUID,
    payload: CustomerStatusUpdate,
    http_request: Request,
    account: Account = Depends(current_account),
) -> Customer:
    """Soft lifecycle change for a company: active / suspended / archived."""

    company = _require_company_access(customer_id, "companies", "manage", account)
    before_status = company.status
    try:
        updated = update_customer_status(customer_id, payload.status)
    except CustomerError as error:
        raise HTTPException(status_code=400, detail=str(error)) from error
    if updated is None:
        raise HTTPException(status_code=404, detail="company not found")
    audit.record(
        action="company.status.update",
        resource=f"company:{customer_id}",
        actor=str(account.id),
        before={"status": before_status},
        after={"status": updated.status},
        request_id=_request_id(http_request),
    )
    return updated


@app.delete("/companies/{customer_id}", status_code=204)
def delete_company_route(
    customer_id: UUID,
    http_request: Request,
    account: Account = Depends(current_account),
) -> None:
    """Hard-delete a company and every record that references it."""

    company = _require_company_access(customer_id, "companies", "manage", account)
    removed = delete_customer(customer_id)
    if not removed:
        raise HTTPException(status_code=404, detail="company not found")
    audit.record(
        action="company.delete",
        resource=f"company:{customer_id}",
        actor=str(account.id),
        before={"name": company.name, "status": company.status},
        request_id=_request_id(http_request),
    )


@app.get("/partners", response_model=list[Partner])
def list_partners_route(
    account: Account = Depends(require("companies", "view")),
) -> list[Partner]:
    scope = tenancy.compute_scope(account)
    partners = list_partners()
    if scope.is_platform:
        return partners
    allowed = set(scope.partner_ids)
    return [p for p in partners if p.id in allowed]


# --- Custom Detection Rules -------------------------------------------------


@app.get("/detection-rules", response_model=list[DetectionRule])
def list_detection_rules_route(
    customer_id: UUID | None = Query(default=None),
    partner_id: UUID | None = Query(default=None),
    account: Account = Depends(current_account),
) -> list[DetectionRule]:
    try:
        return detection_rules_service.list_rules(
            account,
            customer_id=customer_id,
            partner_id=partner_id,
        )
    except detection_rules_service.DetectionRuleError as error:
        raise HTTPException(status_code=403, detail=str(error)) from error


@app.post("/detection-rules", response_model=DetectionRule, status_code=201)
def create_detection_rule_route(
    payload: DetectionRuleCreate,
    http_request: Request,
    account: Account = Depends(current_account),
) -> DetectionRule:
    try:
        rule = detection_rules_service.create_rule(payload, account)
    except detection_rules_service.DetectionRuleError as error:
        raise HTTPException(status_code=400, detail=str(error)) from error
    audit.record(
        action="detection_rule.create",
        resource=f"detection-rule:{rule.id}",
        actor=str(account.id),
        after=rule.model_dump(mode="json"),
        request_id=_request_id(http_request),
    )
    return rule


@app.post("/detection-rules/{rule_id}/simulate", response_model=DetectionRuleSimulation)
def simulate_detection_rule_route(
    rule_id: UUID,
    http_request: Request,
    account: Account = Depends(current_account),
) -> DetectionRuleSimulation:
    try:
        simulation = detection_rules_service.simulate_rule(rule_id, account)
    except detection_rules_service.DetectionRuleError as error:
        raise HTTPException(status_code=400, detail=str(error)) from error
    audit.record(
        action="detection_rule.simulate",
        resource=f"detection-rule:{rule_id}",
        actor=str(account.id),
        after={"matched_events": simulation.matched_events},
        request_id=_request_id(http_request),
    )
    return simulation


@app.post("/detection-rules/{rule_id}/promote", response_model=DetectionRulePromotion)
def promote_detection_rule_route(
    rule_id: UUID,
    http_request: Request,
    account: Account = Depends(current_account),
) -> DetectionRulePromotion:
    try:
        promotion = detection_rules_service.promote_rule(rule_id, account)
    except detection_rules_service.DetectionRuleError as error:
        raise HTTPException(status_code=400, detail=str(error)) from error
    audit.record(
        action="detection_rule.promote",
        resource=f"detection-rule:{rule_id}",
        actor=str(account.id),
        after={"status": promotion.rule.status},
        request_id=_request_id(http_request),
    )
    return promotion


# --- Blocklist Entries -----------------------------------------------------


@app.get("/blocklist", response_model=list[BlocklistEntry])
def list_blocklist_route(
    customer_id: UUID | None = Query(default=None),
    account: Account = Depends(current_account),
) -> list[BlocklistEntry]:
    try:
        return blocklist_service.list_entries(account, customer_id=customer_id)
    except blocklist_service.BlocklistError as error:
        raise HTTPException(status_code=403, detail=str(error)) from error


@app.post("/blocklist", response_model=BlocklistEntry, status_code=201)
def create_blocklist_entry_route(
    payload: BlocklistEntryCreate,
    http_request: Request,
    account: Account = Depends(current_account),
) -> BlocklistEntry:
    try:
        entry = blocklist_service.create_entry(payload, account)
    except blocklist_service.BlocklistError as error:
        raise HTTPException(status_code=400, detail=str(error)) from error
    audit.record(
        action="blocklist.create",
        resource=f"blocklist:{entry.id}",
        actor=str(account.id),
        after=entry.model_dump(mode="json"),
        request_id=_request_id(http_request),
    )
    return entry


@app.post("/blocklist/{entry_id}/simulate", response_model=BlocklistSimulationResult)
def simulate_blocklist_entry_route(
    entry_id: UUID,
    http_request: Request,
    account: Account = Depends(current_account),
) -> BlocklistSimulationResult:
    try:
        result = blocklist_service.simulate_entry(entry_id, account)
    except blocklist_service.BlocklistError as error:
        raise HTTPException(status_code=400, detail=str(error)) from error
    audit.record(
        action="blocklist.simulate",
        resource=f"blocklist:{entry_id}",
        actor=str(account.id),
        after={"affected_agents": result.affected_agents},
        request_id=_request_id(http_request),
    )
    return result


@app.post("/blocklist/{entry_id}/activate", response_model=BlocklistActivateResult)
def activate_blocklist_entry_route(
    entry_id: UUID,
    http_request: Request,
    account: Account = Depends(current_account),
) -> BlocklistActivateResult:
    try:
        result = blocklist_service.activate_entry(entry_id, account)
    except blocklist_service.BlocklistError as error:
        raise HTTPException(status_code=400, detail=str(error)) from error
    audit.record(
        action="blocklist.activate",
        resource=f"blocklist:{entry_id}",
        actor=str(account.id),
        after={"status": "active"},
        request_id=_request_id(http_request),
    )
    return result


@app.post("/blocklist/{entry_id}/disable", status_code=200)
def disable_blocklist_entry_route(
    entry_id: UUID,
    http_request: Request,
    account: Account = Depends(current_account),
) -> dict[str, str]:
    try:
        blocklist_service.disable_entry(entry_id, account)
    except blocklist_service.BlocklistError as error:
        raise HTTPException(status_code=400, detail=str(error)) from error
    audit.record(
        action="blocklist.disable",
        resource=f"blocklist:{entry_id}",
        actor=str(account.id),
        request_id=_request_id(http_request),
    )
    return {"status": "disabled"}


# --- Agentic AI Investigation ----------------------------------------------


@app.get("/agentic/cases", response_model=list[AgentCase])
def list_agentic_cases_route(
    account: Account = Depends(current_account),
) -> list[AgentCase]:
    from app.services import agentic as agentic_service
    try:
        return agentic_service.list_cases(account)
    except agentic_service.AgenticError as error:
        raise HTTPException(status_code=403, detail=str(error)) from error


@app.post("/agentic/cases/{case_id}/approve", response_model=AgentCaseActionResult)
def approve_agentic_case_route(
    case_id: UUID,
    http_request: Request,
    account: Account = Depends(current_account),
) -> AgentCaseActionResult:
    from app.services import agentic as agentic_service
    try:
        result = agentic_service.approve_case(case_id, account)
    except agentic_service.AgenticError as error:
        raise HTTPException(status_code=400, detail=str(error)) from error
    audit.record(
        action="agentic.approve",
        resource=f"agentic_case:{case_id}",
        actor=str(account.id),
        after={"status": result.case.status},
        request_id=_request_id(http_request),
    )
    return result


@app.post("/agentic/cases/{case_id}/dismiss", response_model=AgentCaseActionResult)
def dismiss_agentic_case_route(
    case_id: UUID,
    http_request: Request,
    account: Account = Depends(current_account),
) -> AgentCaseActionResult:
    from app.services import agentic as agentic_service
    try:
        result = agentic_service.dismiss_case(case_id, account)
    except agentic_service.AgenticError as error:
        raise HTTPException(status_code=400, detail=str(error)) from error
    audit.record(
        action="agentic.dismiss",
        resource=f"agentic_case:{case_id}",
        actor=str(account.id),
        after={"status": result.case.status},
        request_id=_request_id(http_request),
    )
    return result


# --- Policy Engine v2 ------------------------------------------------------


@app.post("/policies", response_model=PolicyCreateResponse, status_code=201)
def create_policy_v2_route(
    payload: PolicyDocumentV2Input,
    http_request: Request,
    account: Account = Depends(current_account),
) -> PolicyCreateResponse:
    try:
        created = policy_v2_service.create_policy(payload, actor=account)
    except policy_v2_service.PolicyV2Error as error:
        raise HTTPException(status_code=400, detail=str(error)) from error
    audit.record(
        action="policy_v2.create",
        resource=f"policy:{created.policy.id}",
        actor=str(account.id),
        after={"version": created.version.version, "name": created.policy.name},
        request_id=_request_id(http_request),
    )
    return created


@app.get("/policies", response_model=PolicyListResponse)
def list_policies_v2_route(
    status: str | None = Query(default=None, pattern="^(draft|active|archived)$"),
    customer_id: UUID | None = Query(default=None),
    module: str | None = Query(default=None, max_length=120),
    limit: int = Query(default=50, ge=1, le=500),
    offset: int = Query(default=0, ge=0),
    account: Account = Depends(current_account),
) -> PolicyListResponse:
    try:
        return policy_v2_service.list_policies(
            account,
            status=status,
            customer_id=customer_id,
            module=module,
            limit=limit,
            offset=offset,
        )
    except policy_v2_service.PolicyV2Error as error:
        raise HTTPException(status_code=400, detail=str(error)) from error


@app.post("/policies/assign", response_model=PolicyAssignmentV2, status_code=201)
def assign_policy_v2_route(
    payload: PolicyAssignRequest,
    http_request: Request,
    account: Account = Depends(current_account),
) -> PolicyAssignmentV2:
    try:
        assignment = policy_v2_service.assign_policy(payload, account)
    except policy_v2_service.PolicyV2Error as error:
        raise HTTPException(status_code=400, detail=str(error)) from error
    audit.record(
        action="policy_v2.assign",
        resource=f"policy:{assignment.policy_id}",
        actor=str(account.id),
        after=assignment.model_dump(mode="json"),
        request_id=_request_id(http_request),
    )
    return assignment


@app.get("/policies/effective", response_model=EffectivePolicyResponse)
def effective_policy_v2_route(
    endpoint_id: str | None = Query(default=None),
    partner_id: UUID | None = Query(default=None),
    customer_id: UUID | None = Query(default=None),
    group_id: UUID | None = Query(default=None),
    account: Account = Depends(current_account),
) -> EffectivePolicyResponse:
    try:
        return policy_v2_service.effective_policy(
            account,
            endpoint_id=endpoint_id,
            partner_id=partner_id,
            customer_id=customer_id,
            group_id=group_id,
        )
    except policy_v2_service.PolicyV2Error as error:
        raise HTTPException(status_code=400, detail=str(error)) from error


@app.get("/policies/{policy_id}", response_model=PolicyGetResponse)
def get_policy_v2_route(
    policy_id: UUID,
    account: Account = Depends(current_account),
) -> PolicyGetResponse:
    try:
        return policy_v2_service.get_policy(policy_id, account)
    except policy_v2_service.PolicyV2Error as error:
        raise HTTPException(status_code=404, detail=str(error)) from error


@app.put("/policies/{policy_id}", response_model=PolicyCreateResponse)
def update_policy_v2_route(
    policy_id: UUID,
    payload: PolicyUpdateInput,
    http_request: Request,
    account: Account = Depends(current_account),
) -> PolicyCreateResponse:
    try:
        result = policy_v2_service.update_policy(policy_id, payload, actor=account)
    except policy_v2_service.PolicyV2Error as error:
        raise HTTPException(status_code=400, detail=str(error)) from error
    audit.record(
        action="policy_v2.update",
        resource=f"policy:{policy_id}",
        actor=str(account.id),
        after={"version": result.version.version, "name": result.policy.name},
        request_id=_request_id(http_request),
    )
    return result


@app.delete("/policies/{policy_id}", status_code=204)
def delete_policy_v2_route(
    policy_id: UUID,
    http_request: Request,
    hard: bool = Query(default=False),
    account: Account = Depends(current_account),
) -> None:
    try:
        policy_v2_service.delete_policy(policy_id, hard=hard, actor=account)
    except policy_v2_service.PolicyV2Error as error:
        raise HTTPException(status_code=400, detail=str(error)) from error
    audit.record(
        action="policy_v2.delete" if hard else "policy_v2.archive",
        resource=f"policy:{policy_id}",
        actor=str(account.id),
        request_id=_request_id(http_request),
    )


@app.get("/policies/{policy_id}/versions", response_model=list[PolicyVersionSummary])
def list_policy_versions_route(
    policy_id: UUID,
    limit: int = Query(default=50, ge=1, le=500),
    offset: int = Query(default=0, ge=0),
    account: Account = Depends(current_account),
) -> list[PolicyVersionSummary]:
    try:
        return policy_v2_service.list_policy_versions(policy_id, account, limit=limit, offset=offset)
    except policy_v2_service.PolicyV2Error as error:
        raise HTTPException(status_code=404, detail=str(error)) from error


@app.get("/policies/{policy_id}/versions/{version}", response_model=PolicyVersion)
def get_policy_version_route(
    policy_id: UUID,
    version: int,
    account: Account = Depends(current_account),
) -> PolicyVersion:
    try:
        return policy_v2_service.get_policy_version(policy_id, version, account)
    except policy_v2_service.PolicyV2Error as error:
        raise HTTPException(status_code=404, detail=str(error)) from error


@app.post("/policies/{policy_id}/simulate", response_model=PolicySimulationRecord)
def simulate_policy_v2_route(
    policy_id: UUID,
    http_request: Request,
    account: Account = Depends(current_account),
) -> PolicySimulationRecord:
    try:
        simulation = policy_v2_service.simulate_policy(policy_id, account)
    except policy_v2_service.PolicyV2Error as error:
        raise HTTPException(status_code=400, detail=str(error)) from error
    audit.record(
        action="policy_v2.simulate",
        resource=f"policy:{policy_id}",
        actor=str(account.id),
        after=simulation.summary.model_dump(mode="json"),
        request_id=_request_id(http_request),
    )
    return simulation


@app.post("/policies/{policy_id}/promote", response_model=PolicyVersion)
def promote_policy_v2_route(
    policy_id: UUID,
    payload: PolicyPromoteRequest,
    http_request: Request,
    account: Account = Depends(current_account),
) -> PolicyVersion:
    try:
        version = policy_v2_service.promote_policy(policy_id, payload, account)
    except policy_v2_service.PolicyV2Error as error:
        raise HTTPException(status_code=400, detail=str(error)) from error
    audit.record(
        action="policy_v2.promote",
        resource=f"policy:{policy_id}",
        actor=str(account.id),
        after={
            "version": version.version,
            "promoted_from_simulation_id": str(version.promoted_from_simulation_id)
            if version.promoted_from_simulation_id
            else None,
        },
        request_id=_request_id(http_request),
    )
    return version


@app.get("/policy/assignments", response_model=list[PolicyAssignmentListItemSchema])
def list_policy_assignments_v2_route(
    partner_id: UUID | None = Query(default=None),
    customer_id: UUID | None = Query(default=None),
    account: Account = Depends(current_account),
) -> list[PolicyAssignmentListItemSchema]:
    try:
        return policy_v2_service.list_assignments_v2(
            account,
            partner_id=partner_id,
            customer_id=customer_id,
        )
    except policy_v2_service.PolicyV2Error as error:
        raise HTTPException(status_code=400, detail=str(error)) from error


@app.post("/policy/assignments/{assignment_id}/apply", status_code=200)
def apply_policy_assignment_diff_route(
    assignment_id: UUID,
    http_request: Request,
    account: Account = Depends(current_account),
) -> dict[str, str]:
    try:
        policy_v2_service.apply_assignment_diff(assignment_id, account)
        audit.record(
            action="policy_v2.apply_diff",
            resource=f"assignment:{assignment_id}",
            actor=str(account.id),
            request_id=_request_id(http_request),
        )
        return {"status": "applied"}
    except policy_v2_service.PolicyV2Error as error:
        raise HTTPException(status_code=400, detail=str(error)) from error


@app.post("/policies/{policy_id}/rollback", response_model=PolicyVersion)
def rollback_policy_v2_route(
    policy_id: UUID,
    payload: PolicyRollbackRequest,
    http_request: Request,
    account: Account = Depends(current_account),
) -> PolicyVersion:
    try:
        version = policy_v2_service.rollback_policy(policy_id, payload, account)
    except policy_v2_service.PolicyV2Error as error:
        raise HTTPException(status_code=400, detail=str(error)) from error
    audit.record(
        action="policy_v2.rollback",
        resource=f"policy:{policy_id}",
        actor=str(account.id),
        after={
            "version": version.version,
            "target_version": payload.target_version,
        },
        request_id=_request_id(http_request),
    )
    return version


@app.get("/agent/policy", response_model=AgentPolicyResponse)
def agent_effective_policy_route(
    endpoint_id: str = Query(..., min_length=1),
    authorization: str | None = Header(default=None, alias="Authorization"),
    token: str | None = Query(default=None, min_length=8),
) -> AgentPolicyResponse:
    resolved = _resolve_agent_token(authorization, token)
    try:
        return policy_v2_service.effective_policy_for_agent(endpoint_id=endpoint_id, token=resolved)
    except policy_v2_service.PolicyV2Error as error:
        raise HTTPException(status_code=401, detail=str(error)) from error


@app.post("/agent/dlp-evidence", response_model=EvidenceEvent)
def agent_dlp_evidence_route(
    payload: AgentDlpEvidenceIngest,
    endpoint_id: str = Query(..., min_length=1),
    authorization: str | None = Header(default=None, alias="Authorization"),
    token: str | None = Query(default=None, min_length=8),
) -> EvidenceEvent:
    resolved = _resolve_agent_token(authorization, token)
    try:
        return policy_v2_service.ingest_agent_dlp_evidence(
            endpoint_id=endpoint_id,
            token=resolved,
            payload=payload,
        )
    except policy_v2_service.PolicyV2Error as error:
        raise HTTPException(status_code=401, detail=str(error)) from error


@app.post("/agent/policy/ack", response_model=AgentPolicyAck, status_code=201)
def agent_policy_ack_route(
    payload: AgentPolicyAckRequest,
    endpoint_id: str = Query(..., min_length=1),
    authorization: str | None = Header(default=None, alias="Authorization"),
    token: str | None = Query(default=None, min_length=8),
) -> AgentPolicyAck:
    resolved = _resolve_agent_token(authorization, token)
    try:
        return policy_v2_service.agent_acknowledge_policy(endpoint_id, resolved, payload)
    except policy_v2_service.PolicyV2Error as error:
        raise HTTPException(status_code=401, detail=str(error)) from error


@app.get("/agent/actions", response_model=list[ModuleActionResult])
def agent_get_actions(
    endpoint_id: str = Query(..., min_length=1),
    authorization: str | None = Header(default=None, alias="Authorization"),
    token: str | None = Query(default=None, min_length=8),
) -> list[ModuleActionResult]:
    resolved = _resolve_agent_token(authorization, token)
    try:
        policy_v2_service._authenticate_agent(endpoint_id, resolved)
    except policy_v2_service.PolicyV2Error as error:
        raise HTTPException(status_code=401, detail=str(error)) from error

    with db.connection() as conn, conn.cursor() as cur:
        cur.execute(
            "select id, endpoint_id, action, payload, status, approval_required, evidence_controls, created_at from module_actions where endpoint_id = %s and status = 'queued' order by created_at asc",
            (endpoint_id,),
        )
        rows = cur.fetchall()

    results: list[ModuleActionResult] = []
    for row in rows:
        results.append(
            ModuleActionResult(
                id=str(row["id"]),
                target_id=row["endpoint_id"],
                action=row["action"],
                status=row["status"],
                approval_required=bool(row["approval_required"]),
                payload=row["payload"] or None,
                evidence_controls=row["evidence_controls"] or [],
                created_at=row["created_at"],
            )
        )
    return results


@app.post("/agent/actions/{action_id}/ack", response_model=ModuleActionResult)
def agent_ack_action(
    action_id: UUID,
    endpoint_id: str = Query(..., min_length=1),
    authorization: str | None = Header(default=None, alias="Authorization"),
    token: str | None = Query(default=None, min_length=8),
) -> ModuleActionResult:
    resolved = _resolve_agent_token(authorization, token)
    try:
        policy_v2_service._authenticate_agent(endpoint_id, resolved)
    except policy_v2_service.PolicyV2Error as error:
        raise HTTPException(status_code=401, detail=str(error)) from error

    now = datetime.now(UTC)
    with db.connection() as conn, conn.cursor() as cur:
        cur.execute(
            "update module_actions set status = %s, processed_by = %s, processed_at = %s where id = %s and endpoint_id = %s returning *",
            ("completed", endpoint_id, now, action_id, endpoint_id),
        )
        row = cur.fetchone()

    if row is None:
        raise HTTPException(status_code=404, detail="action not found")

    return ModuleActionResult(
        id=str(row["id"]),
        target_id=row["endpoint_id"],
        action=row["action"],
        status=row["status"],
        approval_required=bool(row["approval_required"]),
        payload=row["payload"] or None,
        evidence_controls=row["evidence_controls"] or [],
        created_at=row["created_at"],
    )


# --- Subscriptions catalog -------------------------------------------------


@app.get("/subscriptions", response_model=list[Subscription])
def list_subscriptions_route(
    _: Account = Depends(current_account),
) -> list[Subscription]:
    licensing.ensure_default_catalog()
    return licensing.list_subscriptions()


@app.post("/subscriptions", response_model=Subscription, status_code=201)
def create_subscription_route(
    payload: SubscriptionCreate,
    http_request: Request,
    actor: Account = Depends(require("licensing", "manage")),
) -> Subscription:
    # The global catalog is platform-owned: scoped MSP partners can manage
    # their customers' licenses but must not create or rename SKUs.
    if not tenancy.compute_scope(actor).is_platform:
        raise HTTPException(
            status_code=403,
            detail="only platform_owner may manage the subscription catalog",
        )
    try:
        subscription = licensing.create_subscription(payload)
    except LicensingError as error:
        raise HTTPException(status_code=400, detail=str(error)) from error
    audit.record(
        action="subscription.create",
        resource=f"subscription:{subscription.id}",
        actor=str(actor.id),
        after={"sku": subscription.sku, "tier": subscription.tier},
        request_id=_request_id(http_request),
    )
    return subscription


# --- Company license -------------------------------------------------------


@app.get("/companies/{customer_id}/license", response_model=CompanyLicense | None)
def get_company_license_route(
    customer_id: UUID,
    account: Account = Depends(current_account),
) -> CompanyLicense | None:
    _require_company_access(customer_id, "licensing", "view", account)
    return licensing.get_license(customer_id)


@app.put("/companies/{customer_id}/license", response_model=CompanyLicense)
def assign_company_license_route(
    customer_id: UUID,
    payload: CompanyLicenseAssign,
    http_request: Request,
    account: Account = Depends(current_account),
) -> CompanyLicense:
    _require_company_access(customer_id, "licensing", "manage", account)
    try:
        license_ = licensing.assign_license(
            customer_id, payload, actor=str(account.id)
        )
    except LicensingError as error:
        raise HTTPException(status_code=400, detail=str(error)) from error
    audit.record(
        action="company.license.assign",
        resource=f"company:{customer_id}",
        actor=str(account.id),
        after={
            "subscription_sku": payload.subscription_sku,
            "payment_plan": payload.payment_plan,
            "total_seats": payload.total_seats,
            "reserved_seats": payload.reserved_seats,
            "addons": payload.addons,
        },
        request_id=_request_id(http_request),
    )
    return license_


@app.get(
    "/companies/{customer_id}/license/usage",
    response_model=list[LicenseUsageDay],
)
def get_company_license_usage_route(
    customer_id: UUID,
    since: str | None = None,
    until: str | None = None,
    account: Account = Depends(current_account),
) -> list[LicenseUsageDay]:
    from datetime import date as _date

    _require_company_access(customer_id, "licensing", "view", account)
    try:
        since_d = _date.fromisoformat(since) if since else None
        until_d = _date.fromisoformat(until) if until else None
    except ValueError as error:
        raise HTTPException(status_code=400, detail=str(error)) from error
    return licensing.list_usage(customer_id, since=since_d, until=until_d)


# --- Subscription lifecycle (P1 #5) ----------------------------------------


def _subscription_audit(
    *,
    action: str,
    customer_id: UUID,
    actor: Account,
    after: dict,
    http_request: Request,
) -> None:
    audit.record(
        action=action,
        resource=f"company:{customer_id}",
        actor=str(actor.id),
        after=after,
        request_id=_request_id(http_request),
    )


@app.get(
    "/companies/{customer_id}/subscription",
    response_model=SubscriptionInstance | None,
)
def get_company_subscription_route(
    customer_id: UUID,
    account: Account = Depends(current_account),
) -> SubscriptionInstance | None:
    _require_company_access(customer_id, "licensing", "view", account)
    return subscriptions_service.get_subscription_for(customer_id)


@app.post(
    "/companies/{customer_id}/subscription/trial",
    response_model=SubscriptionInstance,
)
def start_company_trial_route(
    customer_id: UUID,
    payload: StartTrialRequest,
    http_request: Request,
    account: Account = Depends(current_account),
) -> SubscriptionInstance:
    _require_company_access(customer_id, "licensing", "manage", account)
    try:
        instance = subscriptions_service.start_trial(customer_id, payload)
    except SubscriptionError as error:
        raise HTTPException(status_code=400, detail=str(error)) from error
    _subscription_audit(
        action="company.subscription.trial",
        customer_id=customer_id,
        actor=account,
        after={
            "subscription_sku": payload.subscription_sku,
            "trial_days": payload.trial_days,
            "seats": payload.seats,
        },
        http_request=http_request,
    )
    return instance


@app.post(
    "/companies/{customer_id}/subscription",
    response_model=SubscriptionInstance,
)
def subscribe_company_route(
    customer_id: UUID,
    payload: SubscribeRequest,
    http_request: Request,
    account: Account = Depends(current_account),
) -> SubscriptionInstance:
    _require_company_access(customer_id, "licensing", "manage", account)
    try:
        instance = subscriptions_service.subscribe(customer_id, payload)
    except SubscriptionError as error:
        raise HTTPException(status_code=400, detail=str(error)) from error
    _subscription_audit(
        action="company.subscription.subscribe",
        customer_id=customer_id,
        actor=account,
        after={
            "subscription_sku": payload.subscription_sku,
            "seats": payload.seats,
            "provider": payload.provider,
        },
        http_request=http_request,
    )
    return instance


@app.post(
    "/companies/{customer_id}/subscription/cancel",
    response_model=SubscriptionInstance,
)
def cancel_company_subscription_route(
    customer_id: UUID,
    payload: CancelSubscriptionRequest,
    http_request: Request,
    account: Account = Depends(current_account),
) -> SubscriptionInstance:
    _require_company_access(customer_id, "licensing", "manage", account)
    try:
        instance = subscriptions_service.cancel(customer_id, payload)
    except SubscriptionError as error:
        raise HTTPException(status_code=400, detail=str(error)) from error
    _subscription_audit(
        action="company.subscription.cancel",
        customer_id=customer_id,
        actor=account,
        after={
            "at_period_end": payload.at_period_end,
            "reason": payload.reason,
        },
        http_request=http_request,
    )
    return instance


@app.post(
    "/companies/{customer_id}/subscription/resume",
    response_model=SubscriptionInstance,
)
def resume_company_subscription_route(
    customer_id: UUID,
    http_request: Request,
    account: Account = Depends(current_account),
) -> SubscriptionInstance:
    _require_company_access(customer_id, "licensing", "manage", account)
    try:
        instance = subscriptions_service.resume(customer_id)
    except SubscriptionError as error:
        raise HTTPException(status_code=400, detail=str(error)) from error
    _subscription_audit(
        action="company.subscription.resume",
        customer_id=customer_id,
        actor=account,
        after={},
        http_request=http_request,
    )
    return instance


@app.post(
    "/companies/{customer_id}/subscription/suspend",
    response_model=SubscriptionInstance,
)
def suspend_company_subscription_route(
    customer_id: UUID,
    http_request: Request,
    account: Account = Depends(current_account),
    reason: str | None = None,
) -> SubscriptionInstance:
    # Suspending billing is a platform-owner-only action; we don't let
    # MSP partners pause their own customers' service.
    if not tenancy.compute_scope(account).is_platform:
        raise HTTPException(
            status_code=403,
            detail="only platform_owner may suspend a subscription",
        )
    _require_company_access(customer_id, "licensing", "manage", account)
    try:
        instance = subscriptions_service.suspend(customer_id, reason=reason)
    except SubscriptionError as error:
        raise HTTPException(status_code=400, detail=str(error)) from error
    _subscription_audit(
        action="company.subscription.suspend",
        customer_id=customer_id,
        actor=account,
        after={"reason": reason},
        http_request=http_request,
    )
    return instance


@app.get(
    "/companies/{customer_id}/subscription/events",
    response_model=list[SubscriptionEvent],
)
def list_company_subscription_events_route(
    customer_id: UUID,
    limit: int = 100,
    account: Account = Depends(current_account),
) -> list[SubscriptionEvent]:
    _require_company_access(customer_id, "licensing", "view", account)
    if limit <= 0 or limit > 1000:
        raise HTTPException(status_code=400, detail="limit must be in 1..1000")
    return subscriptions_service.list_events(customer_id, limit=limit)


@app.post("/webhooks/billing/{provider}", status_code=202)
async def billing_webhook_route(
    provider: str,
    http_request: Request,
) -> dict:
    """Unauthenticated webhook for billing providers.

    Authenticity is verified via HMAC-SHA256 over the raw request body
    keyed with ``AETHERIX_WEBHOOK_SECRET``; the signature MUST be sent
    in the ``X-Aetherix-Webhook-Signature`` header. We accept ``mock``
    as a test provider, ``stripe`` and ``manual`` for production use.
    """

    if provider not in {"stripe", "manual", "mock"}:
        raise HTTPException(status_code=404, detail="unknown billing provider")
    raw = await http_request.body()
    signature = http_request.headers.get("x-aetherix-webhook-signature")
    if not subscriptions_service.verify_webhook_signature(raw, signature):
        raise HTTPException(status_code=401, detail="invalid webhook signature")
    try:
        body = json.loads(raw.decode("utf-8")) if raw else {}
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise HTTPException(status_code=400, detail="invalid webhook body") from error
    event_kind = body.get("event_kind")
    payload = body.get("data") or {}
    if not isinstance(event_kind, str) or not event_kind:
        raise HTTPException(status_code=400, detail="missing event_kind")
    if not isinstance(payload, dict):
        raise HTTPException(status_code=400, detail="invalid event payload")
    try:
        instance = subscriptions_service.handle_webhook_event(
            provider, event_kind, payload
        )
    except SubscriptionError as error:
        raise HTTPException(status_code=400, detail=str(error)) from error
    return {"accepted": True, "instance_id": str(instance.id) if instance else None}


# --- AI providers + per-company AI settings --------------------------------


@app.get("/ai/providers", response_model=list[AiProvider])
def list_ai_providers_route(
    _: Account = Depends(current_account),
) -> list[AiProvider]:
    return ai_settings_service.list_providers()


@app.get(
    "/companies/{customer_id}/ai",
    response_model=CustomerAiSettings | None,
)
def get_company_ai_settings_route(
    customer_id: UUID,
    account: Account = Depends(current_account),
) -> CustomerAiSettings | None:
    _require_company_access(customer_id, "companies", "view", account)
    return ai_settings_service.get_settings(customer_id)


@app.put(
    "/companies/{customer_id}/ai",
    response_model=CustomerAiSettings,
)
def upsert_company_ai_settings_route(
    customer_id: UUID,
    payload: CustomerAiSettingsUpdate,
    http_request: Request,
    account: Account = Depends(current_account),
) -> CustomerAiSettings:
    _require_company_access(customer_id, "companies", "manage", account)
    try:
        settings = ai_settings_service.upsert_settings(
            customer_id, payload, actor_id=account.id
        )
    except AiSettingsError as error:
        raise HTTPException(status_code=400, detail=str(error)) from error
    audit.record(
        action="company.ai.update",
        resource=f"company:{customer_id}",
        actor=str(account.id),
        after={
            "provider": settings.provider_slug,
            "model": settings.model,
            "enabled": settings.enabled,
            "has_api_key": settings.has_api_key,
            "redact_pii_before_send": settings.redact_pii_before_send,
        },
        request_id=_request_id(http_request),
    )
    return settings


@app.delete("/companies/{customer_id}/ai", status_code=204)
def delete_company_ai_settings_route(
    customer_id: UUID,
    http_request: Request,
    account: Account = Depends(current_account),
) -> None:
    _require_company_access(customer_id, "companies", "manage", account)
    removed = ai_settings_service.delete_settings(customer_id)
    if not removed:
        raise HTTPException(status_code=404, detail="ai settings not found")
    audit.record(
        action="company.ai.delete",
        resource=f"company:{customer_id}",
        actor=str(account.id),
        request_id=_request_id(http_request),
    )


@app.post(
    "/companies/{customer_id}/ai/test",
    response_model=AiProbeResult,
)
def test_company_ai_settings_route(
    customer_id: UUID,
    http_request: Request,
    account: Account = Depends(current_account),
) -> AiProbeResult:
    _require_company_access(customer_id, "companies", "manage", account)
    result = ai_settings_service.test_settings(customer_id)
    audit.record(
        action="company.ai.test",
        resource=f"company:{customer_id}",
        actor=str(account.id),
        after={
            "ok": result.ok,
            "provider": result.provider_slug,
            "model": result.model,
            "status_code": result.status_code,
        },
        request_id=_request_id(http_request),
    )
    return result


# --- Compliance Evidence Engine v0.5 -----------------------------------------


def _scoped_customer_id(
    x_aetherix_customer: UUID | None = Header(default=None, alias="X-Aetherix-Customer"),
    customer_id: UUID | None = Query(default=None),
) -> UUID:
    resolved = x_aetherix_customer or customer_id
    if resolved is None:
        raise HTTPException(status_code=400, detail="missing tenant customer_id")
    return resolved


@app.get(
    "/compliance/reviews",
    response_model=list[ComplianceReviewQueueItem],
    tags=["compliance"],
    description="Lists pending and completed evidence reviews for auditor readiness, including ISO 27001 Annex A control mappings.",
)
def list_compliance_reviews_route(
    framework: str = Query(...),
    source_table: ComplianceSourceTable = Query(...),
    customer_id: UUID = Depends(_scoped_customer_id),
    account: Account = Depends(current_account),
) -> list[ComplianceReviewQueueItem]:
    _require_company_access(customer_id, "companies", "view", account)
    try:
        return [ComplianceReviewQueueItem.model_validate(r) for r in compliance.list_review_items(customer_id, framework, source_table)]
    except compliance.ComplianceServiceError as error:
        raise HTTPException(status_code=400, detail=str(error)) from error
    except Exception as error:
        _logger.error(f"Failed to list compliance reviews: {error}")
        raise HTTPException(status_code=400, detail="Failed to retrieve compliance reviews") from error


@app.post(
    "/compliance/reviews",
    response_model=ComplianceReview,
    status_code=201,
    tags=["compliance"],
    description="Records an append-only operator review for evidence mapped to ISO 27001 controls and companion frameworks.",
)
def create_compliance_review_route(
    payload: ComplianceReviewCreate,
    customer_id: UUID = Depends(_scoped_customer_id),
    account: Account = Depends(current_account),
) -> ComplianceReview:
    _require_company_access(customer_id, "companies", "manage", account)
    try:
        review = compliance.create_review(
            customer_id=customer_id,
            source_table=payload.source_table,
            source_id=payload.source_id,
            framework=payload.framework,
            control_id=payload.control_id,
            decision=payload.decision,
            note=payload.note,
            reviewed_by_account_id=account.id,
            reviewed_by_role=payload.reviewed_by_role,
            reviewed_by_name=payload.reviewed_by_name,
        )
        return ComplianceReview.model_validate(review)
    except compliance.ComplianceServiceError as error:
        raise HTTPException(status_code=400, detail=str(error)) from error
    except Exception as error:
        _logger.error(f"Failed to create compliance review: {error}")
        raise HTTPException(status_code=400, detail="Failed to create compliance review") from error


@app.get(
    "/compliance/attestations",
    response_model=list[ComplianceAttestation],
    tags=["compliance"],
    description="Lists signed tenant attestations for auditor packs, filtered by ISO 27001-compatible framework and period end.",
)
def list_compliance_attestations_route(
    framework: str = Query(...),
    period_end: date | None = Query(default=None),
    customer_id: UUID = Depends(_scoped_customer_id),
    account: Account = Depends(current_account),
) -> list[ComplianceAttestation]:
    _require_company_access(customer_id, "companies", "view", account)
    try:
        return [ComplianceAttestation.model_validate(a) for a in compliance.list_attestations(customer_id, framework, period_end)]
    except compliance.ComplianceServiceError as error:
        raise HTTPException(status_code=400, detail=str(error)) from error
    except Exception as error:
        _logger.error(f"Failed to list compliance attestations: {error}")
        raise HTTPException(status_code=400, detail="Failed to retrieve compliance attestations") from error


@app.post(
    "/compliance/attestations",
    response_model=ComplianceAttestation,
    status_code=201,
    tags=["compliance"],
    description="Creates a signed, tenant-scoped attestation over an existing evidence bundle SHA-256 for ISO 27001 auditor review.",
)
def create_compliance_attestation_route(
    payload: ComplianceAttestationCreate,
    customer_id: UUID = Depends(_scoped_customer_id),
    account: Account = Depends(current_account),
) -> ComplianceAttestation:
    _require_company_access(customer_id, "companies", "manage", account)
    try:
        attestation = compliance.create_attestation(
            customer_id=customer_id,
            framework=payload.framework,
            period_start=payload.period_start,
            period_end=payload.period_end,
            attested_by_account_id=account.id,
            attested_role=payload.attested_role,
            attested_name=payload.attested_name,
            statement=payload.statement,
            bundle_sha256=payload.bundle_sha256,
            signature=payload.signature,
            signature_algo=payload.signature_algo,
        )
        return ComplianceAttestation.model_validate(attestation)
    except compliance.DuplicateAttestationError as error:
        raise HTTPException(status_code=409, detail=str(error)) from error
    except compliance.ComplianceServiceError as error:
        raise HTTPException(status_code=400, detail=str(error)) from error
    except Exception as error:
        _logger.error(f"Failed to create compliance attestation: {error}")
        raise HTTPException(status_code=400, detail="Failed to create compliance attestation") from error

# --- Digital Risk Protection -----------------------------------------------

@app.get("/drp/findings", response_model=list[DRPFinding])
def list_drp_findings_route(
    customer_id: UUID | None = Query(default=None),
    partner_id: UUID | None = Query(default=None),
    status: str | None = Query(default=None),
    account: Account = Depends(current_account),
) -> list[DRPFinding]:
    try:
        return drp_easm_service.list_findings(
            account,
            customer_id=customer_id,
            partner_id=partner_id,
            status=status,
        )
    except drp_easm_service.ExternalRiskError as error:
        raise HTTPException(status_code=403, detail=str(error)) from error


@app.post("/drp/findings", response_model=DRPFinding, status_code=201)
def create_drp_finding_route(
    payload: DRPFindingCreate,
    http_request: Request,
    customer_id: UUID = Query(...),
    account: Account = Depends(current_account),
) -> DRPFinding:
    try:
        finding = drp_easm_service.create_finding(payload, account, customer_id=customer_id)
    except drp_easm_service.ExternalRiskError as error:
        _logger.error(f"Failed to create DRP finding: {error}")
        raise HTTPException(status_code=400, detail="Failed to create DRP finding") from error
    audit.record(
        action="drp.finding.create",
        resource=f"drp-finding:{finding.id}",
        actor=str(account.id),
        after={"finding_type": finding.finding_type, "severity": finding.severity},
        request_id=_request_id(http_request),
    )
    return finding


@app.post("/drp/findings/{finding_id}/validate", response_model=DRPFinding)
def validate_drp_finding_route(
    finding_id: UUID,
    http_request: Request,
    account: Account = Depends(current_account),
) -> DRPFinding:
    try:
        finding = drp_easm_service.validate_finding(finding_id, account)
    except drp_easm_service.ExternalRiskError as error:
        raise HTTPException(status_code=400, detail=str(error)) from error
    audit.record(
        action="drp.finding.validate",
        resource=f"drp-finding:{finding_id}",
        actor=str(account.id),
        after={"status": finding.status},
        request_id=_request_id(http_request),
    )
    return finding


@app.post("/drp/findings/{finding_id}/takedown", response_model=DRPFinding)
def takedown_drp_finding_route(
    finding_id: UUID,
    http_request: Request,
    account: Account = Depends(current_account),
) -> DRPFinding:
    try:
        finding = drp_easm_service.confirm_takedown(finding_id, account)
    except drp_easm_service.ExternalRiskError as error:
        raise HTTPException(status_code=400, detail=str(error)) from error
    audit.record(
        action="drp.finding.takedown",
        resource=f"drp-finding:{finding_id}",
        actor=str(account.id),
        after={"status": finding.status},
        request_id=_request_id(http_request),
    )
    return finding


# --- External Attack Surface Management ------------------------------------

@app.get("/easm/exposures", response_model=list[EASMExposure])
def list_easm_exposures_route(
    customer_id: UUID | None = Query(default=None),
    partner_id: UUID | None = Query(default=None),
    status: str | None = Query(default=None),
    account: Account = Depends(current_account),
) -> list[EASMExposure]:
    try:
        return drp_easm_service.list_exposures(
            account,
            customer_id=customer_id,
            partner_id=partner_id,
            status=status,
        )
    except drp_easm_service.ExternalRiskError as error:
        raise HTTPException(status_code=403, detail=str(error)) from error


@app.post("/easm/exposures", response_model=EASMExposure, status_code=201)
def create_easm_exposure_route(
    payload: EASMExposureCreate,
    http_request: Request,
    customer_id: UUID = Query(...),
    account: Account = Depends(current_account),
) -> EASMExposure:
    try:
        exposure = drp_easm_service.create_exposure(payload, account, customer_id=customer_id)
    except drp_easm_service.ExternalRiskError as error:
        raise HTTPException(status_code=400, detail=str(error)) from error
    audit.record(
        action="easm.exposure.create",
        resource=f"easm-exposure:{exposure.id}",
        actor=str(account.id),
        after={"exposure_type": exposure.exposure_type, "severity": exposure.severity},
        request_id=_request_id(http_request),
    )
    return exposure


@app.post("/easm/exposures/{exposure_id}/investigate", response_model=EASMExposure)
def investigate_easm_exposure_route(
    exposure_id: UUID,
    http_request: Request,
    account: Account = Depends(current_account),
) -> EASMExposure:
    try:
        exposure = drp_easm_service.investigate_exposure(exposure_id, account)
    except drp_easm_service.ExternalRiskError as error:
        raise HTTPException(status_code=400, detail=str(error)) from error
    audit.record(
        action="easm.exposure.investigate",
        resource=f"easm-exposure:{exposure_id}",
        actor=str(account.id),
        after={"status": exposure.status},
        request_id=_request_id(http_request),
    )
    return exposure


@app.post("/easm/exposures/{exposure_id}/remediate", response_model=EASMExposure)
def remediate_easm_exposure_route(
    exposure_id: UUID,
    http_request: Request,
    account: Account = Depends(current_account),
) -> EASMExposure:
    try:
        exposure = drp_easm_service.remediate_exposure(exposure_id, account)
    except drp_easm_service.ExternalRiskError as error:
        raise HTTPException(status_code=400, detail=str(error)) from error
    audit.record(
        action="easm.exposure.remediate",
        resource=f"easm-exposure:{exposure_id}",
        actor=str(account.id),
        after={"status": exposure.status},
        request_id=_request_id(http_request),
    )
    return exposure


@app.get("/easm/policy", response_model=ExternalRiskPolicyView)
def easm_policy_route(
    customer_id: UUID | None = None,
    account: Account = Depends(current_account),
) -> ExternalRiskPolicyView:
    if customer_id is not None:
        _require_customer_access(customer_id, account, "easm", "view")
    return drp_easm_service.easm_policy_view(account, customer_id)


@app.get("/drp/policy", response_model=ExternalRiskPolicyView)
def drp_policy_route(
    customer_id: UUID | None = None,
    account: Account = Depends(current_account),
) -> ExternalRiskPolicyView:
    if customer_id is not None:
        _require_customer_access(customer_id, account, "drp", "view")
    return drp_easm_service.drp_policy_view(account, customer_id)


@app.post(
    "/easm/exposures/{exposure_id}/simulate",
    response_model=ExternalRiskSimulationPreview,
)
def simulate_easm_exposure_route(
    exposure_id: UUID,
    payload: ExternalRiskSimulateRequest,
    http_request: Request,
    account: Account = Depends(current_account),
) -> ExternalRiskSimulationPreview:
    try:
        preview = drp_easm_service.simulate_exposure(exposure_id, payload.action, account)
    except drp_easm_service.ExternalRiskError as error:
        raise HTTPException(status_code=400, detail=str(error)) from error
    audit.record(
        action="easm.exposure.simulate",
        resource=f"easm-exposure:{exposure_id}",
        actor=str(account.id),
        after={"action": payload.action, "destructive": preview.destructive},
        request_id=_request_id(http_request),
    )
    return preview


@app.post(
    "/drp/findings/{finding_id}/simulate",
    response_model=ExternalRiskSimulationPreview,
)
def simulate_drp_finding_route(
    finding_id: UUID,
    payload: ExternalRiskSimulateRequest,
    http_request: Request,
    account: Account = Depends(current_account),
) -> ExternalRiskSimulationPreview:
    try:
        preview = drp_easm_service.simulate_finding(finding_id, payload.action, account)
    except drp_easm_service.ExternalRiskError as error:
        raise HTTPException(status_code=400, detail=str(error)) from error
    audit.record(
        action="drp.finding.simulate",
        resource=f"drp-finding:{finding_id}",
        actor=str(account.id),
        after={"action": payload.action, "destructive": preview.destructive},
        request_id=_request_id(http_request),
    )
    return preview

import uuid
import psycopg
from contextlib import asynccontextmanager
from uuid import UUID

from fastapi import Depends, FastAPI, Header, HTTPException, Query, Request
from fastapi.middleware.cors import CORSMiddleware

from app.db import init_schema
from app import db
from app.schemas import AgentHeartbeat, Alert, Customer, CustomerCreate, CustomerGroup, CustomerQuickCreateRequest, CustomerQuickCreateResult, DlpScanRequest, DlpScanResponse, Endpoint, EnrollmentRequest, EnrollmentResult, EnrollmentTokenIssued, EnrollmentTokenRequest, InstallerBuild, InstallerBuildRequest, Policy, PolicyDocument, PolicyDocumentDraft, PolicyPackage, PolicySimulationRequest, PolicySimulationResponse, QuickDeployLink, QuickDeployManifest, SimulationRequest, TelemetryEvent, SecurityAlert, IncidentCase, Account, AccountCreate, MeResponse, PermissionLevel, Role, RoleAssignment, RoleAssignmentRequest, CompanyLicense, CompanyLicenseAssign, LicenseUsageDay, Subscription, SubscriptionCreate
from app.services import audit
from app.services import tenancy
from app.services import licensing
from app.services.tenancy import TenancyError
from app.services.licensing import LicensingError
from app.services.customers import CustomerError, assigned_policy, create_customer, create_quick_deploy_links, customer_groups, generate_installers, get_customer, list_customers, list_policy_packages, policy_package_for_agent, quick_create, resolve_quick_deploy
from app.services.dlp import apply_policy, scan_text
from app.services.enrollment import EnrollmentError, consume_enrollment_token, issue_enrollment_token
from app.services.policy import active_policy_document, list_policy_documents, promote_policy_document, simulate as simulate_policy
from app.services.state import PolicyNotConfigured, acknowledge_alert, active_policy as load_active_policy, create_dlp_alert, list_alerts, list_endpoints, upsert_heartbeat


@asynccontextmanager
async def lifespan(_: FastAPI):
    # Postgres is the single source of truth. Ensure the schema exists
    # before serving the first request; do not seed any sample data.
    init_schema()
    yield


app = FastAPI(title="Aetherix DLP API", version="0.1.0", lifespan=lifespan)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://127.0.0.1:5173", "http://localhost:5173"],
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


def _request_id(request: Request) -> str | None:
    return getattr(request.state, "request_id", None)


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
def create_enrollment_token(payload: EnrollmentTokenRequest, http_request: Request) -> EnrollmentTokenIssued:
    issued = issue_enrollment_token(payload)
    audit.record(
        action="enrollment.token.issued",
        resource="enrollment:token",
        actor="operator",
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
def endpoints() -> list[Endpoint]:
    return list_endpoints()


@app.get("/policies/active", response_model=Policy)
def active_policy() -> Policy:
    try:
        return load_active_policy()
    except PolicyNotConfigured as error:
        raise HTTPException(status_code=409, detail=str(error)) from error


@app.get("/policy-packages", response_model=list[PolicyPackage])
def policy_packages() -> list[PolicyPackage]:
    return list_policy_packages()


@app.get("/customers", response_model=list[Customer])
def customers() -> list[Customer]:
    return list_customers()


@app.post("/customers", response_model=Customer, status_code=201)
def create_customer_route(payload: CustomerCreate, http_request: Request) -> Customer:
    try:
        customer, assignment = create_customer(payload)
    except CustomerError as error:
        raise HTTPException(status_code=400, detail=str(error)) from error
    audit.record(
        action="customer.create",
        resource=f"customer:{customer.id}",
        actor=payload.created_by,
        after={"customer": customer.model_dump(mode="json"), "assignment": assignment.model_dump(mode="json")},
        request_id=_request_id(http_request),
    )
    return customer


@app.post("/customers/quick-create", response_model=CustomerQuickCreateResult, status_code=201)
def quick_create_customer_route(payload: CustomerQuickCreateRequest, http_request: Request) -> CustomerQuickCreateResult:
    try:
        result = quick_create(payload)
    except CustomerError as error:
        raise HTTPException(status_code=400, detail=str(error)) from error
    audit.record(
        action="customer.quick_create",
        resource=f"customer:{result.customer.id}",
        actor=payload.created_by,
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
def customer_detail(customer_id: UUID) -> Customer:
    customer = get_customer(customer_id)
    if customer is None:
        raise HTTPException(status_code=404, detail="Customer not found")
    return customer


@app.get("/customers/{customer_id}/groups", response_model=list[CustomerGroup])
def customer_group_list(customer_id: UUID) -> list[CustomerGroup]:
    if get_customer(customer_id) is None:
        raise HTTPException(status_code=404, detail="Customer not found")
    return customer_groups(customer_id)


@app.post("/customers/{customer_id}/installers", response_model=list[InstallerBuild], status_code=201)
def generate_customer_installers(customer_id: UUID, payload: InstallerBuildRequest, http_request: Request) -> list[InstallerBuild]:
    try:
        installers = generate_installers(customer_id, payload)
    except CustomerError as error:
        raise HTTPException(status_code=400, detail=str(error)) from error
    audit.record(
        action="installer.generate",
        resource=f"customer:{customer_id}",
        actor=payload.created_by,
        after={"installer_ids": [str(installer.id) for installer in installers], "platforms": payload.platforms},
        request_id=_request_id(http_request),
    )
    return installers


@app.post("/customers/{customer_id}/quick-deploy", response_model=list[QuickDeployLink], status_code=201)
def create_quick_deploy(customer_id: UUID, payload: InstallerBuildRequest, http_request: Request) -> list[QuickDeployLink]:
    try:
        links = create_quick_deploy_links(customer_id, payload)
    except CustomerError as error:
        raise HTTPException(status_code=400, detail=str(error)) from error
    audit.record(
        action="quick_deploy.create",
        resource=f"customer:{customer_id}",
        actor=payload.created_by,
        after={"link_ids": [str(link.id) for link in links], "platforms": payload.platforms},
        request_id=_request_id(http_request),
    )
    return links


@app.get("/quick-deploy/{link_id}", response_model=QuickDeployManifest)
def quick_deploy_manifest(link_id: UUID, secret: str, http_request: Request) -> QuickDeployManifest:
    try:
        manifest = resolve_quick_deploy(link_id, secret)
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
        after={"customer_id": str(manifest.customer.id), "platform": manifest.installer.platform},
        request_id=_request_id(http_request),
    )
    return manifest


@app.get("/agent/{agent_id}/policy", response_model=PolicyPackage)
def agent_policy(agent_id: str) -> PolicyPackage:
    package = policy_package_for_agent(agent_id)
    if package is None:
        raise HTTPException(status_code=404, detail="Assigned policy package not found")
    return package


@app.get("/policies/document", response_model=PolicyDocument | None)
def active_policy_document_route() -> PolicyDocument | None:
    return active_policy_document()


@app.get("/policies/documents", response_model=list[PolicyDocument])
def policy_document_history(limit: int = Query(default=50, ge=1, le=500)) -> list[PolicyDocument]:
    return list_policy_documents(limit=limit)


@app.post("/policies/document", response_model=PolicyDocument, status_code=201)
def promote_policy(draft: PolicyDocumentDraft, http_request: Request) -> PolicyDocument:
    previous = active_policy_document()
    document = promote_policy_document(draft, actor="operator")
    audit.record(
        action="policy.promote",
        resource=f"policy:{document.id}",
        actor="operator",
        before=previous.model_dump(mode="json") if previous else None,
        after=document.model_dump(mode="json"),
        request_id=_request_id(http_request),
    )
    return document


@app.post("/policies/document/simulate", response_model=PolicySimulationResponse)
def simulate_policy_route(payload: PolicySimulationRequest, http_request: Request) -> PolicySimulationResponse:
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
        actor="operator",
        before={"draft": payload.draft.model_dump(mode="json"), "samples": [s.model_dump(mode="json") for s in payload.samples]},
        after=result.summary.model_dump(mode="json"),
        request_id=_request_id(http_request),
    )
    return result


@app.get("/alerts", response_model=list[Alert])
def alerts() -> list[Alert]:
    return list_alerts()


@app.patch("/alerts/{alert_id}/acknowledge", response_model=Alert)
def acknowledge(alert_id: str, http_request: Request) -> Alert:
    alert = acknowledge_alert(alert_id)
    if alert is None:
        raise HTTPException(status_code=404, detail="Alert not found")

    audit.record(
        action="alert.ack",
        resource=f"alert:{alert.id}",
        actor="operator",
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
) -> list[audit.AuditRecord]:
    return audit.list_records(limit=limit, action=action, actor=actor, resource=resource)


@app.get("/audit/verify")
def audit_verify() -> dict[str, object]:
    ok, first_bad = audit.verify_chain()
    return {"ok": ok, "first_bad_seq": first_bad}


@app.post("/simulate/scenario")
def simulate_scenario(req: SimulationRequest):
    """Simulate security events for testing and demo purposes."""
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
                "insert into security_alerts (id, customer_id, agent_id, category, severity, confidence, recommended_action, payload, status, created_at) values (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)",
                (alert_id, customer_id, req.agent_id, category, severity, 85, action, psycopg.types.json.Jsonb(payload), "new", ts)
            )

            cur.execute(
                "insert into incident_cases (id, customer_id, title, description, severity, status, recommended_response, created_at, updated_at) values (%s, %s, %s, %s, %s, %s, %s, %s, %s)",
                (incident_id, customer_id, f"Simulated {req.scenario}", "Generated by simulation", severity, "open", "Investigate", ts, ts)
            )

            return {"status": "ok", "alert_id": alert_id, "incident_id": incident_id}

@app.get("/customers/{customer_id}/telemetry", response_model=list[TelemetryEvent])
def get_customer_telemetry(customer_id: UUID):
    with db.connection() as conn:
        with conn.cursor() as cur:
            cur.execute("select * from telemetry_events where customer_id = %s order by timestamp desc", (customer_id,))
            return cur.fetchall()

@app.get("/customers/{customer_id}/security-alerts", response_model=list[SecurityAlert])
def get_customer_security_alerts(customer_id: UUID):
    with db.connection() as conn:
        with conn.cursor() as cur:
            cur.execute("select * from security_alerts where customer_id = %s order by created_at desc", (customer_id,))
            return cur.fetchall()

@app.get("/customers/{customer_id}/incidents", response_model=list[IncidentCase])
def get_customer_incidents(customer_id: UUID):
    with db.connection() as conn:
        with conn.cursor() as cur:
            cur.execute("select * from incident_cases where customer_id = %s order by updated_at desc", (customer_id,))
            return cur.fetchall()


# --- Accounts + RBAC --------------------------------------------------------
#
# Authentication is intentionally minimal until session auth ships: the
# caller identifies themselves with the ``X-Aetherix-Account`` header
# containing an account UUID. Every protected endpoint depends on
# ``current_account`` and (where applicable) ``require(...)``.


def current_account(
    x_aetherix_account: str | None = Header(default=None, alias="X-Aetherix-Account"),
) -> Account:
    if not x_aetherix_account:
        raise HTTPException(status_code=401, detail="missing X-Aetherix-Account header")
    try:
        account_id = UUID(x_aetherix_account)
    except ValueError as error:
        raise HTTPException(status_code=401, detail="invalid account id") from error
    account = tenancy.get_account(account_id)
    if account is None:
        raise HTTPException(status_code=401, detail="unknown account")
    if account.status in ("locked", "suspended"):
        raise HTTPException(status_code=403, detail=f"account is {account.status}")
    return account


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


@app.get("/me", response_model=MeResponse)
def me(account: Account = Depends(current_account)) -> MeResponse:
    return tenancy.me(account)


@app.get("/roles", response_model=list[Role])
def list_roles_route(_: Account = Depends(current_account)) -> list[Role]:
    return tenancy.list_roles()


@app.get("/accounts", response_model=list[Account])
def list_accounts_route(
    _: Account = Depends(require("accounts", "view")),
) -> list[Account]:
    return tenancy.list_accounts()


@app.post("/accounts", response_model=Account, status_code=201)
def create_account_route(
    payload: AccountCreate,
    http_request: Request,
    actor: Account = Depends(require("accounts", "manage")),
) -> Account:
    payload.created_by = str(actor.id)
    try:
        account = tenancy.create_account(payload)
    except TenancyError as error:
        raise HTTPException(status_code=400, detail=str(error)) from error
    audit.record(
        action="account.create",
        resource=f"account:{account.id}",
        actor=str(actor.id),
        after={"email": account.email, "full_name": account.full_name},
        request_id=_request_id(http_request),
    )
    return account


@app.get("/accounts/{account_id}", response_model=Account)
def get_account_route(
    account_id: UUID,
    _: Account = Depends(require("accounts", "view")),
) -> Account:
    account = tenancy.get_account(account_id)
    if account is None:
        raise HTTPException(status_code=404, detail="account not found")
    return account


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
    try:
        assignment = tenancy.assign_role(account_id, payload, granted_by=str(actor.id))
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


@app.get("/companies/{customer_id}", response_model=Customer)
def get_company_route(
    customer_id: UUID,
    account: Account = Depends(current_account),
) -> Customer:
    return _require_company_access(customer_id, "companies", "view", account)


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


@app.get("/companies/{customer_id}/license", response_model=CompanyLicense)
def get_company_license_route(
    customer_id: UUID,
    account: Account = Depends(current_account),
) -> CompanyLicense:
    _require_company_access(customer_id, "licensing", "view", account)
    license_ = licensing.get_license(customer_id)
    if license_ is None:
        raise HTTPException(status_code=404, detail="license not assigned")
    return license_


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

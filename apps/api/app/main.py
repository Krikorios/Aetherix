import uuid
import logging
import os
import psycopg
from contextlib import asynccontextmanager
from uuid import UUID

from fastapi import Depends, FastAPI, Header, HTTPException, Query, Request
from fastapi.middleware.cors import CORSMiddleware

from app.db import init_schema
from app import db
from app.schemas import AgentHeartbeat, Alert, AiProvider, BulkActionFailure, BulkActionResult, BulkIdsRequest, CompanyBulkStatusRequest, Customer, CustomerAiSettings, CustomerAiSettingsUpdate, CustomerCreate, CustomerGroup, CustomerQuickCreateRequest, CustomerQuickCreateResult, CustomerStatusUpdate, CustomerUpdate, DlpScanRequest, DlpScanResponse, Endpoint, EnrollmentRequest, EnrollmentResult, EnrollmentTokenIssued, EnrollmentTokenRequest, InstallerBuild, InstallerBuildRequest, LoginRequest, PasswordSetRequest, TotpChallenge, TotpVerifyRequest, Partner, Policy, PolicyDocument, PolicyDocumentDraft, PolicyPackage, PolicySimulationRequest, PolicySimulationResponse, QuickDeployLink, QuickDeployManifest, SimulationRequest, TelemetryEvent, SecurityAlert, IncidentCase, Account, AccountCreate, AccountCreated, InviteAcceptRequest, MeResponse, PermissionLevel, Role, RoleAssignment, RoleAssignmentRequest, CompanyLicense, CompanyLicenseAssign, CompanySummary, CompanySummaryPage, LicenseUsageDay, Subscription, SubscriptionCreate
from app.services import audit
from app.services import tenancy
from app.services import licensing
from app.services import totp as totp_service
from app.services import ai_settings as ai_settings_service
from app.services.ai_settings import AiSettingsError
from app.services.tenancy import TenancyError
from app.services.licensing import LicensingError
from app.services.customers import CustomerError, assigned_policy, create_customer, create_quick_deploy_links, customer_groups, delete_customer, generate_installers, get_customer, list_customers, list_customers_page, list_partners, list_policy_packages, policy_package_for_agent, quick_create, resolve_quick_deploy, update_customer, update_customer_status
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


@app.put("/customers/{customer_id}", response_model=Customer)
def update_customer_route(customer_id: UUID, payload: CustomerUpdate, http_request: Request) -> Customer:
    try:
        customer = update_customer(customer_id, payload)
    except CustomerError as error:
        raise HTTPException(status_code=400, detail=str(error)) from error
    if customer is None:
        raise HTTPException(status_code=404, detail="Customer not found")
    audit.record(
        action="customer.update",
        resource=f"customer:{customer_id}",
        actor=payload.updated_by,
        after={"customer": customer.model_dump(mode="json")},
        request_id=_request_id(http_request),
    )
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
        )

    challenge_id = tenancy.create_login_challenge(
        account_id, "totp_verify", _TOTP_VERIFY_TTL_SECONDS
    )
    return TotpChallenge(
        status="totp_required",
        challenge_id=challenge_id,
        email=snapshot["email"],
    )


@app.post("/auth/totp/verify", response_model=MeResponse)
def auth_totp_verify(payload: TotpVerifyRequest, http_request: Request) -> MeResponse:
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
    audit.record(
        action="auth.login",
        resource=f"account:{account.id}",
        actor=str(account.id),
        after={"email": account.email, "via": ctx["purpose"]},
        request_id=_request_id(http_request),
    )
    return tenancy.me(account)


@app.post("/accounts/{account_id}/password", status_code=204)
def set_account_password_route(
    account_id: UUID,
    payload: PasswordSetRequest,
    http_request: Request,
    actor: Account = Depends(current_account),
) -> None:
    # Self-service password change is always allowed; otherwise the actor
    # needs ``accounts:manage`` on the target's scope. We delegate the
    # scope check to ``has_permission`` (manage on accounts implies any
    # tenant they cover).
    if actor.id != account_id:
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
    _: Account = Depends(require("accounts", "view")),
) -> list[Account]:
    return tenancy.list_accounts()


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
        account = tenancy.create_account(payload)
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
    _: Account = Depends(require("accounts", "view")),
) -> Account:
    account = tenancy.get_account(account_id)
    if account is None:
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

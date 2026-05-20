from datetime import datetime
from typing import Literal, Any
from uuid import UUID

from pydantic import BaseModel, Field


class DlpScanRequest(BaseModel):
    text: str = Field(min_length=1)
    language: str = "en"
    endpoint_id: str | None = None
    source: str | None = None
    customer_id: UUID | None = None


class DlpFinding(BaseModel):
    entity_type: str
    start: int
    end: int
    score: float
    text: str


RiskBand = Literal["low", "medium", "high", "critical"]


class DlpScanResponse(BaseModel):
    findings: list[DlpFinding]
    action: Literal["allow", "review", "block"]
    risk_score: int = Field(default=0, ge=0, le=100)
    risk_band: RiskBand = "low"
    context_signals: list[str] = Field(default_factory=list)
    rationale: str = ""


class AgentSignals(BaseModel):
    blocked_events: int = Field(default=0, ge=0)
    dlp_events: int = Field(default=0, ge=0)
    pending_updates: int = Field(default=0, ge=0)
    cpu_percent: float | None = Field(default=None, ge=0, le=100)
    memory_percent: float | None = Field(default=None, ge=0, le=100)


class AgentHeartbeat(BaseModel):
    agent_id: str = Field(min_length=1)
    hostname: str = Field(min_length=1)
    os: str = Field(min_length=1)
    collected_at: datetime
    policy_version: str = Field(min_length=1)
    agent_version: str = Field(default="0.1.0", min_length=1)
    signature: str | None = None
    nonce: int | None = Field(default=None, ge=1)
    signals: AgentSignals = Field(default_factory=AgentSignals)


class Endpoint(BaseModel):
    id: str
    hostname: str
    os: str
    status: Literal["healthy", "attention", "offline"]
    risk_score: int
    last_seen: datetime
    policy_version: str
    agent_version: str


class Policy(BaseModel):
    id: str
    name: str
    mode: Literal["monitor", "review", "block"]
    protected_entities: list[str]
    genai_guardrail: bool = True
    escalate_at: RiskBand = "high"


class Alert(BaseModel):
    id: str
    title: str
    severity: Literal["low", "medium", "high"]
    endpoint_id: str | None = None
    recommended_action: str
    status: Literal["open", "acknowledged"] = "open"
    created_at: datetime
    source: str
    entity_types: list[str] = Field(default_factory=list)


# --- MSP tenancy + customer deployment -------------------------------------

DeploymentMode = Literal["cloud", "on_prem"]
CompanySize = Literal["1-10", "11-50", "51-250", "251-1000", "1000+"]
CompanyType = Literal["partner", "customer"]
InstallerPlatform = Literal["windows_msi", "windows_exe", "macos_pkg", "linux_deb", "linux_rpm"]


class Partner(BaseModel):
    id: UUID
    name: str
    slug: str
    deployment_mode: DeploymentMode = "cloud"
    created_at: datetime


class CustomerCreate(BaseModel):
    name: str = Field(min_length=1, max_length=160)
    company_type: CompanyType = "customer"
    industry: str | None = Field(default=None, max_length=80)
    country: str | None = Field(default=None, max_length=80)
    company_size: CompanySize | None = None
    policy_package_id: UUID | None = None
    created_by: str = Field(default="operator", min_length=1, max_length=120)


class CustomerUpdate(BaseModel):
    name: str = Field(min_length=1, max_length=160)
    industry: str | None = Field(default=None, max_length=80)
    country: str | None = Field(default=None, max_length=80)
    company_size: CompanySize | None = None
    policy_package_id: UUID | None = None
    updated_by: str = Field(default="operator", min_length=1, max_length=120)


class Customer(CustomerCreate):
    id: UUID
    partner_id: UUID
    customer_number: str
    status: Literal["active", "suspended", "archived"] = "active"
    default_group_id: UUID | None = None
    assigned_policy_package_id: UUID | None = None
    assigned_policy_name: str | None = None
    created_at: datetime


class CompanySummary(BaseModel):
    customer: Customer
    license: "CompanyLicense | None" = None


class CompanySummaryPage(BaseModel):
    items: list[CompanySummary] = Field(default_factory=list)
    total: int = 0
    limit: int = 50
    offset: int = 0


class CustomerStatusUpdate(BaseModel):
    status: Literal["active", "suspended", "archived"]


class BulkIdsRequest(BaseModel):
    ids: list[UUID] = Field(min_length=1, max_length=500)


class CompanyBulkStatusRequest(BulkIdsRequest):
    status: Literal["active", "suspended", "archived"]


class BulkActionFailure(BaseModel):
    id: UUID
    error: str


class BulkActionResult(BaseModel):
    ok_count: int = 0
    failures: list[BulkActionFailure] = Field(default_factory=list)


class CustomerGroup(BaseModel):
    id: UUID
    customer_id: UUID
    name: str
    created_at: datetime


class PolicyPackage(BaseModel):
    id: UUID
    partner_id: UUID | None = None
    name: str
    description: str | None = None
    package_type: Literal["default", "industry", "custom"] = "custom"
    payload: dict
    version: int = Field(ge=1)
    signature: str
    created_by: str
    created_at: datetime


class PolicyAssignment(BaseModel):
    id: UUID
    customer_id: UUID
    group_id: UUID | None = None
    policy_package_id: UUID
    policy_name: str
    assigned_by: str
    assigned_at: datetime


class InstallerBuildRequest(BaseModel):
    platforms: list[InstallerPlatform] = Field(default_factory=lambda: ["windows_msi"], min_length=1, max_length=5)
    group_id: UUID | None = None
    ttl_seconds: int = Field(default=86_400, ge=300, le=604_800)
    created_by: str = Field(default="operator", min_length=1, max_length=120)


class InstallerBuild(BaseModel):
    id: UUID
    customer_id: UUID
    group_id: UUID | None = None
    policy_package_id: UUID
    platform: InstallerPlatform
    status: Literal["queued", "ready", "failed", "expired"]
    artifact_url: str | None = None
    artifact_sha256: str | None = None
    signing_status: Literal["unsigned", "signed", "notarized"] = "signed"
    expires_at: datetime | None = None
    install_profile: dict | None = None
    enrollment_token: str | None = None
    created_by: str
    created_at: datetime


class QuickDeployLink(BaseModel):
    id: UUID
    customer_id: UUID
    group_id: UUID | None = None
    installer_build_id: UUID | None = None
    platform: InstallerPlatform | None = None
    url: str
    max_downloads: int | None = None
    download_count: int = 0
    expires_at: datetime
    revoked_at: datetime | None = None
    created_by: str
    created_at: datetime


class CustomerQuickCreateRequest(CustomerCreate):
    platforms: list[InstallerPlatform] = Field(default_factory=lambda: ["windows_msi", "macos_pkg"], min_length=1, max_length=5)
    installer_ttl_seconds: int = Field(default=86_400, ge=300, le=604_800)


class CustomerQuickCreateResult(BaseModel):
    customer: Customer
    assignment: PolicyAssignment
    installers: list[InstallerBuild]
    quick_deploy_links: list[QuickDeployLink]


class QuickDeployManifest(BaseModel):
    customer: Customer
    installer: InstallerBuild
    enrollment_token: str


# --- Policy Document v1 -----------------------------------------------------
#
# A policy is stored as a versioned, signed document. The runtime ``Policy``
# above is a summary derived from this document; the document is the
# system of record. See docs/architecture.md sections 3 and 4.2.

PolicyRuleKind = Literal["entity", "regex", "keyword"]
PolicyAction = Literal["allow", "review", "block"]


class PolicyRule(BaseModel):
    id: str = Field(min_length=1)
    kind: PolicyRuleKind
    action: PolicyAction = "review"
    # Used by kind == "entity"
    entity_type: str | None = None
    # Used by kind == "regex" / "keyword". Stored, not yet evaluated.
    pattern: str | None = None
    description: str | None = None


class PolicyDocumentDraft(BaseModel):
    """Inbound payload for promoting a new policy version."""

    name: str = Field(min_length=1)
    mode_default: Literal["monitor", "review", "block"] = "monitor"
    escalate_at: RiskBand = "high"
    genai_guardrail: bool = True
    rules: list[PolicyRule] = Field(default_factory=list)


class PolicyDocument(PolicyDocumentDraft):
    """The stored, signed representation of a policy."""

    id: str
    version: int = Field(ge=1)
    signed_by: str
    signature: str
    created_at: datetime
    created_by: str = "system"


# --- Policy simulation ------------------------------------------------------


class PolicySimulationRequest(BaseModel):
    draft: PolicyDocumentDraft
    samples: list[DlpScanRequest] = Field(min_length=1, max_length=50)


class PolicySimulationOutcomeSide(BaseModel):
    action: Literal["allow", "review", "block"]
    risk_band: RiskBand
    entity_types: list[str] = Field(default_factory=list)


class PolicySimulationOutcome(BaseModel):
    source: str | None = None
    endpoint_id: str | None = None
    before: PolicySimulationOutcomeSide
    after: PolicySimulationOutcomeSide
    changed: bool


class PolicySimulationSummary(BaseModel):
    total: int
    changed: int
    would_block: int
    would_review: int
    would_allow: int


class PolicySimulationResponse(BaseModel):
    summary: PolicySimulationSummary
    results: list[PolicySimulationOutcome]


# --- Enrollment -------------------------------------------------------------


class EnrollmentTokenRequest(BaseModel):
    note: str | None = Field(default=None, max_length=200)
    ttl_seconds: int = Field(default=900, ge=60, le=86_400)
    partner_id: UUID | None = None
    customer_id: UUID | None = None
    group_id: UUID | None = None
    policy_package_id: UUID | None = None
    max_uses: int = Field(default=1, ge=1, le=10_000)
    purpose: Literal["agent_enrollment", "installer_download"] = "agent_enrollment"
    created_by: str = Field(default="operator", min_length=1, max_length=120)


class EnrollmentTokenIssued(BaseModel):
    token: str
    expires_at: datetime
    note: str | None = None


class EnrollmentRequest(BaseModel):
    enrollment_token: str = Field(min_length=8)
    hostname: str = Field(min_length=1)
    os: str = Field(min_length=1)
    agent_version: str = Field(default="0.1.0", min_length=1)


class EnrollmentResult(BaseModel):
    """One-time response. ``agent_secret`` is shown exactly once."""

    agent_id: str
    agent_secret: str
    enrolled_at: datetime
    customer_id: UUID | None = None
    group_id: UUID | None = None
    policy_package_id: UUID | None = None


class EnrolledAgent(BaseModel):
    agent_id: str
    hostname: str
    os: str
    enrolled_at: datetime
    last_nonce: int
    revoked: bool = False


class TelemetryEvent(BaseModel):
    id: UUID
    customer_id: UUID
    agent_id: str
    event_type: str
    payload: dict[str, Any]
    timestamp: datetime


class SecurityAlert(BaseModel):
    id: UUID
    customer_id: UUID
    agent_id: str
    category: str
    severity: str
    confidence: int
    recommended_action: str
    ai_summary: str | None = None
    payload: dict[str, Any]
    status: str = "new"
    created_at: datetime


class IncidentCase(BaseModel):
    id: UUID
    customer_id: UUID
    title: str
    description: str | None = None
    severity: str
    status: str = "open"
    recommended_response: str | None = None
    created_at: datetime
    updated_at: datetime


class SimulationRequest(BaseModel):
    scenario: str
    agent_id: str


# --- Companies + Licensing + Accounts module --------------------------------

RoleCode = Literal[
    "platform_owner",
    "msp_partner",
    "company_admin",
    "company_tech",
    "company_viewer",
]
PermissionLevel = Literal["none", "view", "edit", "manage"]
AccountStatus = Literal["invited", "active", "locked", "suspended"]
TwoFactorState = Literal["missing", "enabled", "enforced"]


class Role(BaseModel):
    code: RoleCode
    display_name: str
    permissions: dict[str, PermissionLevel]


class RoleAssignment(BaseModel):
    id: UUID
    role_code: RoleCode
    partner_id: UUID | None = None
    customer_id: UUID | None = None
    granted_by: str
    granted_at: datetime


class RoleAssignmentRequest(BaseModel):
    role_code: RoleCode
    partner_id: UUID | None = None
    customer_id: UUID | None = None


class AccountCreate(BaseModel):
    email: str = Field(min_length=3, max_length=240)
    full_name: str = Field(min_length=1, max_length=160)
    initial_role: RoleAssignmentRequest | None = None
    password: str | None = Field(default=None, min_length=8, max_length=200)
    # Delivery method for the invitation when ``password`` is not provided.
    # ``email`` queues an email to the invitee (stubbed/logged for now).
    # ``link`` returns a one-time setup URL in the response so the creator
    # can send it to the invitee through their own channel.
    delivery: Literal["email", "link"] = "email"
    created_by: str = Field(default="operator", min_length=1, max_length=120)


class InviteAcceptRequest(BaseModel):
    token: str = Field(min_length=16, max_length=200)
    password: str = Field(min_length=8, max_length=200)
    full_name: str | None = Field(default=None, max_length=160)


class LoginRequest(BaseModel):
    email: str = Field(min_length=3, max_length=240)
    password: str = Field(min_length=1, max_length=200)


class TotpVerifyRequest(BaseModel):
    challenge_id: UUID
    code: str = Field(min_length=6, max_length=8)


class TotpChallenge(BaseModel):
    """Returned by /auth/login when 2FA is required.

    ``status`` is the discriminator the frontend uses:
    - ``totp_setup_required`` — first login: ``otpauth_url`` + ``secret`` are
      included so the client can render the QR code for enrollment.
    - ``totp_required`` — subsequent logins: only the challenge id is
      returned; the client just asks for the 6-digit code.
    """

    status: Literal["totp_setup_required", "totp_required"]
    challenge_id: UUID
    email: str
    otpauth_url: str | None = None
    secret: str | None = None
    issuer: str | None = None


class PasswordSetRequest(BaseModel):
    password: str = Field(min_length=8, max_length=200)


class Account(BaseModel):
    id: UUID
    email: str
    full_name: str
    status: AccountStatus = "invited"
    two_factor: TwoFactorState = "missing"
    password_expires_at: datetime | None = None
    locked_until: datetime | None = None
    last_login_at: datetime | None = None
    created_at: datetime
    roles: list[RoleAssignment] = Field(default_factory=list)


class AccountCreated(BaseModel):
    """Response returned by ``POST /accounts``.

    ``invite_url`` is only populated when the creator requested
    ``delivery="link"`` so they can hand-deliver the setup link to the
    invitee. When ``delivery="email"`` the link is sent by the system
    (or logged in dev) and never returned to the creator.
    """

    account: Account
    delivery: Literal["email", "link"] = "email"
    invite_url: str | None = None
    invite_expires_at: datetime | None = None


class TenantScope(BaseModel):
    """Effective tenant visibility derived from an account's role assignments."""

    is_platform: bool = False
    partner_ids: list[UUID] = Field(default_factory=list)
    customer_ids: list[UUID] = Field(default_factory=list)


class Branding(BaseModel):
    """Resolved white-label theme for the signed-in scope.

    Field resolution: customer.branding overrides partner.branding which
    overrides the platform default. Each field is merged independently so
    partners can override only the keys they care about.
    """

    product_name: str = "Aetherix"
    tagline: str = "MSP Console"
    primary_color: str = "#0b6b57"
    accent_color: str = "#0b6b57"
    logo_url: str | None = None
    support_email: str | None = None
    support_url: str | None = None
    footer_note: str | None = None
    source: Literal["platform", "partner", "customer"] = "platform"


DEFAULT_BRANDING = Branding()


class MeResponse(BaseModel):
    account: Account
    permissions: dict[str, PermissionLevel]
    scope: TenantScope
    branding: Branding = Field(default_factory=Branding)


# --- Subscriptions + Licensing ---------------------------------------------

BillingModel = Literal["monthly", "annual", "usage"]
PaymentPlan = BillingModel
LicenseStatus = Literal["active", "expired", "suspended", "trial"]
ProtectionModel = Literal["a_la_carte", "bundled"]


class SubscriptionCreate(BaseModel):
    sku: str = Field(min_length=1, max_length=80)
    display_name: str = Field(min_length=1, max_length=200)
    tier: Literal["core", "advanced", "enterprise"] = "core"
    core_features: list[str] = Field(default_factory=list)
    available_addons: list[str] = Field(default_factory=list)
    billing_model: BillingModel = "monthly"
    list_price_per_seat: float = Field(default=0, ge=0)


class Subscription(SubscriptionCreate):
    id: UUID
    created_at: datetime


class LicenseProduct(BaseModel):
    id: UUID
    license_id: UUID
    product_code: str
    product_name: str
    product_type: str
    protection_model: ProtectionModel
    status: Literal["active", "suspended"] = "active"
    total_seats: int = 0
    used_seats: int = 0
    reserved_seats: int = 0


class LicenseProductSeats(BaseModel):
    total_seats: int = Field(ge=0)
    reserved_seats: int = Field(ge=0)


class CompanyLicense(BaseModel):
    id: UUID
    customer_id: UUID
    subscription_id: UUID
    subscription_sku: str
    license_key: str
    company_hash: str
    payment_plan: PaymentPlan
    status: LicenseStatus
    issued_at: datetime
    expires_at: datetime | None = None
    total_seats: int = 0
    reserved_seats: int = 0
    auto_renewal: bool = True
    minimum_usage: int = 0
    addons: list[str] = Field(default_factory=list)
    products: list[LicenseProduct] = Field(default_factory=list)
    created_at: datetime


class CompanyLicenseAssign(BaseModel):
    subscription_sku: str = Field(min_length=1, max_length=80)
    payment_plan: PaymentPlan = "monthly"
    total_seats: int = Field(default=0, ge=0)
    reserved_seats: int = Field(default=0, ge=0)
    addons: list[str] = Field(default_factory=list)
    auto_renewal: bool = True
    minimum_usage: int = Field(default=0, ge=0)
    expires_at: datetime | None = None
    products: list[LicenseProduct] | None = None


class LicenseUsageDay(BaseModel):
    product_code: str
    day: datetime  # midnight UTC of the bucketed day
    active_seats: int
    peak_seats: int


# --- AI provider catalog + per-company AI settings -------------------------

AiProviderKind = Literal["classifier", "chat", "embedding"]


class AiProvider(BaseModel):
    slug: str
    display_name: str
    kind: AiProviderKind = "classifier"
    requires_byo_key: bool = True
    default_endpoint: str | None = None
    supported_models: list[str] = Field(default_factory=list)
    notes: str | None = None


class CustomerAiSettings(BaseModel):
    customer_id: UUID
    provider_slug: str
    model: str
    endpoint: str | None = None
    api_key_last4: str | None = None
    has_api_key: bool = False
    data_residency: str | None = None
    redact_pii_before_send: bool = True
    enabled: bool = False
    max_calls_per_day: int = Field(default=1000, ge=0)
    updated_at: datetime
    updated_by: UUID | None = None


class CustomerAiSettingsUpdate(BaseModel):
    provider_slug: str = Field(min_length=1, max_length=80)
    model: str = Field(min_length=1, max_length=120)
    endpoint: str | None = Field(default=None, max_length=500)
    api_key: str | None = Field(default=None, min_length=1, max_length=2000)
    clear_api_key: bool = False
    data_residency: str | None = Field(default=None, max_length=40)
    redact_pii_before_send: bool = True
    enabled: bool = False
    max_calls_per_day: int = Field(default=1000, ge=0, le=1_000_000)


class AiProbeResult(BaseModel):
    ok: bool
    provider_slug: str | None = None
    model: str | None = None
    latency_ms: int | None = None
    status_code: int | None = None
    message: str = ""

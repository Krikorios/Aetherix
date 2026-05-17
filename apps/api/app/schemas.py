from datetime import datetime
from typing import Literal, Any
from uuid import UUID

from pydantic import BaseModel, Field


class DlpScanRequest(BaseModel):
    text: str = Field(min_length=1)
    language: str = "en"
    endpoint_id: str | None = None
    source: str | None = None


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
InstallerPlatform = Literal["windows_msi", "windows_exe", "macos_pkg", "linux_deb", "linux_rpm"]


class Partner(BaseModel):
    id: UUID
    name: str
    slug: str
    deployment_mode: DeploymentMode = "cloud"
    created_at: datetime


class CustomerCreate(BaseModel):
    name: str = Field(min_length=1, max_length=160)
    industry: str | None = Field(default=None, max_length=80)
    country: str | None = Field(default=None, max_length=80)
    company_size: CompanySize | None = None
    policy_package_id: UUID | None = None
    created_by: str = Field(default="operator", min_length=1, max_length=120)


class Customer(CustomerCreate):
    id: UUID
    partner_id: UUID
    customer_number: str
    status: Literal["active", "suspended", "archived"] = "active"
    default_group_id: UUID | None = None
    assigned_policy_package_id: UUID | None = None
    assigned_policy_name: str | None = None
    created_at: datetime


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

from datetime import date, datetime
from typing import Literal, Any
from uuid import UUID

from pydantic import AliasChoices, BaseModel, ConfigDict, Field, model_validator


class DlpScanRequest(BaseModel):
    text: str = Field(min_length=1)
    language: str = "en"
    endpoint_id: str | None = None
    source: str | None = None
    customer_id: UUID | None = None
    sha256_hash: str | None = None


class DlpFinding(BaseModel):
    entity_type: str
    start: int
    end: int
    score: float
    text: str


RiskBand = Literal["low", "medium", "high", "critical"]
DetectionRuleSeverity = Literal["low", "medium", "high", "critical"]
DetectionRuleStatus = Literal["draft", "simulated", "active"]


class DlpScanResponse(BaseModel):
    findings: list[DlpFinding]
    action: Literal["allow", "review", "block"]
    risk_score: int = Field(default=0, ge=0, le=100)
    risk_band: RiskBand = "low"
    context_signals: list[str] = Field(default_factory=list)
    rationale: str = ""


class DetectionRuleCreate(BaseModel):
    customer_id: UUID | None = None
    partner_id: UUID | None = None
    name: str = Field(min_length=1, max_length=160)
    description: str = Field(min_length=1, max_length=500)
    severity: DetectionRuleSeverity = "medium"
    status: DetectionRuleStatus = "draft"
    query: str = Field(min_length=1, max_length=1024)
    author: str | None = Field(default=None, max_length=160)
    mitre_attacks: list[str] = Field(default_factory=list, max_length=16)


class DetectionRule(BaseModel):
    id: UUID
    partner_id: UUID | None = None
    customer_id: UUID | None = None
    name: str
    description: str
    severity: DetectionRuleSeverity
    status: DetectionRuleStatus
    query: str
    author: str
    mitre_attacks: list[str]
    last_modified: datetime
    last_simulation_run: datetime | None = None
    scanned_agents_count: int = Field(default=0, ge=0)


class DetectionRuleSimulation(BaseModel):
    rule: DetectionRule
    matched_events: int = Field(ge=0)
    evidence_controls: list[str]
    created_at: datetime


class DetectionRulePromotion(BaseModel):
    rule: DetectionRule
    evidence_controls: list[str]
    promoted_at: datetime


# --- Blocklist -------------------------------------------------------------

BlocklistEntryKind = Literal["hash", "domain", "url", "user", "process"]
BlocklistEntryStatus = Literal["active", "review", "disabled"]


class BlocklistEntryCreate(BaseModel):
    customer_id: UUID | None = None
    partner_id: UUID | None = None
    kind: BlocklistEntryKind
    value: str = Field(min_length=1, max_length=1024)
    description: str = Field(min_length=1, max_length=500)
    severity: RiskBand = "medium"
    added_by: str | None = Field(default=None, max_length=160)


class BlocklistEntry(BaseModel):
    id: UUID
    partner_id: UUID | None = None
    customer_id: UUID | None = None
    kind: BlocklistEntryKind
    value: str
    description: str
    severity: RiskBand
    status: BlocklistEntryStatus = "review"
    added_by: str
    hit_count: int = 0
    last_triggered: datetime | None = None
    created_at: datetime


class BlocklistSimulationResult(BaseModel):
    entry: BlocklistEntry
    affected_agents: int
    evidence_controls: list[str]
    created_at: datetime


class BlocklistActivateResult(BaseModel):
    entry: BlocklistEntry
    evidence_controls: list[str]
    activated_at: datetime


# --- Agentic AI Investigation ----------------------------------------------

AgentInvestigationStatus = Literal["open", "in_progress", "awaiting_approval", "resolved", "dismissed"]
AgentConfidenceLevel = Literal["low", "medium", "high", "confirmed"]


class InvestigationStep(BaseModel):
    id: str
    description: str
    completed: bool = False
    timestamp: datetime | None = None
    evidence: str | None = None


class AgentCase(BaseModel):
    id: UUID
    customer_id: UUID
    title: str
    summary: str
    status: AgentInvestigationStatus = "open"
    confidence: AgentConfidenceLevel = "medium"
    confidence_pct: int = Field(default=50, ge=0, le=100)
    severity: RiskBand = "medium"
    affected_endpoints: list[str] = Field(default_factory=list)
    related_events: int = 0
    mitre_tactics: list[str] = Field(default_factory=list)
    recommended_response: str = ""
    steps: list[InvestigationStep] = Field(default_factory=list)
    created_at: datetime
    updated_at: datetime
    resolved_at: datetime | None = None


class AgentCaseActionResult(BaseModel):
    case: AgentCase
    evidence_controls: list[str]
    actioned_at: datetime


# --- System banners --------------------------------------------------------

SystemBannerSeverity = Literal["info", "warning", "critical"]


class SystemBannerCreate(BaseModel):
    message: str = Field(min_length=1, max_length=280)
    link_label: str | None = Field(default=None, max_length=80)
    link_url: str | None = Field(default=None, max_length=500)
    severity: SystemBannerSeverity = "warning"
    starts_at: datetime | None = None
    ends_at: datetime | None = None
    active: bool = True


class SystemBanner(BaseModel):
    id: UUID
    message: str
    link_label: str | None = None
    link_url: str | None = None
    severity: SystemBannerSeverity
    starts_at: datetime
    ends_at: datetime | None = None
    active: bool
    created_by: UUID | None = None
    created_at: datetime


class AgentSignals(BaseModel):
    blocked_events: int = Field(default=0, ge=0)
    dlp_events: int = Field(default=0, ge=0)
    pending_updates: int = Field(default=0, ge=0)
    cpu_percent: float | None = Field(default=None, ge=0, le=100)
    memory_percent: float | None = Field(default=None, ge=0, le=100)


class SystemInventory(BaseModel):
    hostname: str
    os_name: str
    os_version: str
    kernel_version: str
    total_memory: int
    used_memory: int
    total_swap: int
    used_swap: int
    cpu_count: int
    processes_count: int
    networks: dict[str, dict[str, Any]]
    timestamp: str


class FimEvent(BaseModel):
    event_type: Literal["added", "modified", "deleted"]
    file_path: str
    sha256_hash: str | None = None
    timestamp: str


class YaraStringMatch(BaseModel):
    identifier: str
    matched_data: str | None = None
    offset: int | None = None
    length: int | None = None


class EdrEvent(BaseModel):
    kind: Literal["yara_match", "ioc_match", "ransomware_canary", "suspicious_process_chain", "response_action"]
    rule_id: str
    action: Literal["monitor", "review", "quarantine", "quarantine_list", "quarantine_restore", "kill", "isolate", "rollback", "rollback_restore"]
    process_path: str | None = None
    process_pid: int | None = None
    parent_pid: int | None = None
    file_path: str | None = None
    file_sha256: str | None = None
    matched_indicator: str | None = None
    policy_version: str
    collected_at: str
    tags: list[str] = []
    matched_strings: list[YaraStringMatch] = []
    rule_metadata: dict[str, str] = {}
    scan_duration_ms: int | None = None
    matched_rules: list[str] = []
    evidence_controls: list[str] = []
    response: dict[str, Any] | None = None
    # Populated by the agent when a rollback completes: the file paths
    # that were successfully restored from a recovery point.  The
    # correlation engine uses this list to link the rollback alert back
    # to prior FIM/DLP events on the same paths.
    rollback_file_paths: list[str] = []


class CisCheckResult(BaseModel):
    rule_id: str
    title: str
    status: Literal["pass", "fail", "error"]
    actual_value: str


class RecoveryPointSummary(BaseModel):
    id: str
    provider: str
    created_at: str
    expires_at: str | None = None
    protected_root: str
    verified: bool


class RollbackReadiness(BaseModel):
    model_config = ConfigDict(extra="allow")

    provider_available: bool = True
    provider_name: str = ""
    provider_version: str = ""
    recovery_points: list[RecoveryPointSummary] = Field(default_factory=list)
    os_platform: str = ""

    # Probe-derived fields
    functional: bool = True
    diagnosis: str = ""
    recovery_point_count: int = 0
    available_filesystems: list[str] = Field(default_factory=list)
    service_available: bool = True
    sufficient_privilege: bool = True

    # Provider-hardening fields
    volume_capabilities: list[str] = Field(default_factory=list)
    snapshot_service_info: str | None = None
    privilege_boundary: str | None = None

    # Correlation-friendly data
    provider_metadata: dict[str, Any] | None = None
    recent_fim_paths: list[str] = Field(default_factory=list)

    @model_validator(mode="before")
    @classmethod
    def _normalize_payload(cls, value: Any) -> Any:
        if not isinstance(value, dict):
            return value

        data = dict(value)
        provider_name = str(data.get("provider_name") or "")
        raw_points = data.get("recovery_points")

        normalized_points: list[dict[str, Any]] = []
        if isinstance(raw_points, list):
            for point in raw_points:
                if not isinstance(point, dict):
                    continue

                point_id = point.get("id") or point.get("recovery_point_id") or point.get("snapshot_id")
                if not point_id:
                    continue

                created_at = point.get("created_at") or point.get("created") or point.get("timestamp") or ""
                protected_root = point.get("protected_root") or point.get("path") or point.get("mount_point") or ""
                verified_value = point.get("verified")
                if verified_value is None:
                    verified_value = point.get("is_verified")

                normalized: dict[str, Any] = {
                    "id": str(point_id),
                    "provider": str(point.get("provider") or provider_name),
                    "created_at": str(created_at),
                    "protected_root": str(protected_root),
                    "verified": bool(verified_value) if verified_value is not None else False,
                }
                expires_at = point.get("expires_at") or point.get("expires")
                if expires_at is not None:
                    normalized["expires_at"] = str(expires_at)
                normalized_points.append(normalized)

        data["recovery_points"] = normalized_points

        try:
            count = int(data.get("recovery_point_count") or 0)
        except (TypeError, ValueError):
            count = 0
        data["recovery_point_count"] = max(count, len(normalized_points))

        raw_paths = data.get("recent_fim_paths")
        if isinstance(raw_paths, list):
            data["recent_fim_paths"] = [str(path) for path in raw_paths if path is not None]

        return data


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
    inventory: SystemInventory | None = None
    fim_events: list[FimEvent] = Field(default_factory=list)
    edr_events: list[EdrEvent] = Field(default_factory=list)
    cis_results: list[CisCheckResult] = Field(default_factory=list)
    rollback_readiness: dict[str, Any] | None = None
    rollback_readiness: RollbackReadiness | None = None



class Endpoint(BaseModel):
    id: str
    hostname: str
    os: str
    status: Literal["healthy", "attention", "offline"]
    risk_score: int
    last_seen: datetime
    policy_version: str
    agent_version: str
    rollback_readiness: RollbackReadiness | None = None


class EndpointHealthRecord(BaseModel):
    id: str
    customer_id: UUID | None = None
    endpoint_name: str
    hostname: str
    os: str
    agent_version: str
    latest_agent_version: str
    policy_version: str
    active_policy_version: str
    status: Literal["healthy", "attention", "offline", "drifted"]
    last_heartbeat: datetime
    risk_score: int = Field(ge=0, le=100)
    open_alerts: int = Field(default=0, ge=0)
    pending_actions: int = Field(default=0, ge=0)
    tags: list[str] = Field(default_factory=list)
    cpu_percent: float | None = None
    memory_percent: float | None = None
    dlp_events: int = Field(default=0, ge=0)
    blocked_events: int = Field(default=0, ge=0)
    rollback_readiness: RollbackReadiness | None = None


class ModuleActionRequest(BaseModel):
    action: str = Field(min_length=1, max_length=120)
    payload: dict[str, Any] | None = None


class ModuleSimulationResult(BaseModel):
    id: str
    detection_id: str
    action: str
    destructive: bool = False
    approval_required: bool = False
    affected_systems: int = Field(default=1, ge=0)
    estimated_impact: list[str] = Field(default_factory=list)
    evidence_controls: list[str] = Field(default_factory=list)
    created_at: datetime


class ModuleActionResult(BaseModel):
    id: str
    target_id: str
    action: str
    status: Literal["queued", "awaiting_approval", "completed", "failed", "denied", "cancelled"] = "queued"
    approval_required: bool = False
    payload: dict[str, Any] | None = None
    evidence_controls: list[str] = Field(default_factory=list)
    created_at: datetime
    # Populated when the agent acks the action and returns ResponseEvidence,
    # or when a heartbeat-borne EdrEvent with kind=response_action references
    # this action via matched_indicator. Schema matches the agent's
    # `ResponseEvidence` Rust struct.
    result: dict[str, Any] | None = None
    processed_at: datetime | None = None
    requested_by: str | None = None
    approved_by: str | None = None
    approved_at: datetime | None = None


class AgentActionAck(BaseModel):
    """Optional body the agent may post when acknowledging a queued action.

    `result` carries the `ResponseEvidence` payload (status, decision_trace,
    quarantine manifest, quarantine_items, etc.) so the control plane can
    surface executed state and quarantine inventories without waiting for the
    next heartbeat.
    """

    status: Literal["completed", "failed"] = "completed"
    result: dict[str, Any] | None = None


class QuarantineRestoreRequest(BaseModel):
    """Operator request to restore a previously quarantined artifact."""

    quarantine_id: str = Field(min_length=1, max_length=256)
    target_path: str | None = Field(default=None, max_length=4096)
    severity_hint: RiskBand = "medium"
    reason: str = Field(default="", max_length=1000)


class RollbackRestoreRequest(BaseModel):
    """Operator request to execute a previously authorized ransomware rollback or direct rollback on an endpoint."""

    simulation_id: str | None = Field(default=None, max_length=256)
    candidate_set_hash: str | None = Field(default=None, max_length=256)
    affected_paths: list[str] = Field(default_factory=list)
    recovery_point_id: str | None = Field(default=None, max_length=256)
    provider: str | None = Field(default=None, max_length=256)
    provider_metadata: dict[str, Any] | None = None
    severity_hint: RiskBand = "medium"
    reason: str = Field(default="", max_length=1000)


class QuarantineListRequest(BaseModel):
    """Operator request to refresh the endpoint quarantine inventory."""

    reason: str = Field(default="", max_length=1000)


class QuarantineInventoryItem(BaseModel):
    """Operator-facing view of a single quarantined artifact.

    Mirrors the agent's ``QuarantineListItem`` (see
    ``agent/src/edr/mod.rs``). Field names match the agent's serde
    serialization so the console can consume cached and live payloads
    interchangeably. ``AliasChoices`` keeps the older ``sha256`` /
    ``size_bytes`` names accepted for forward-compat.

    ``extra="allow"`` keeps newer agent builds from being silently
    truncated.
    """

    model_config = ConfigDict(extra="allow", populate_by_name=True)

    quarantine_id: str
    original_path: str | None = None
    quarantined_at: datetime | None = None
    sha256_hash: str | None = Field(
        default=None,
        validation_alias=AliasChoices("sha256_hash", "sha256"),
    )
    rule_id: str | None = None
    file_size: int | None = Field(
        default=None,
        ge=0,
        validation_alias=AliasChoices("file_size", "size_bytes"),
    )
    severity_hint: RiskBand | None = None
    can_restore: bool = True
    restore_requires_approval: bool = False
    approval_hint: str | None = None
    encrypted: bool = False
    manifest_hash: str | None = None
    # Optional extras some agent builds include but the canonical
    # ``QuarantineListItem`` does not. Kept typed for stable console use.
    stored_path: str | None = None
    reason: str | None = None


class QuarantineInventoryResponse(BaseModel):
    endpoint_id: str
    customer_id: UUID | None = None
    items: list[QuarantineInventoryItem] = Field(default_factory=list)
    source_action_id: str | None = None
    refreshed_at: datetime | None = None


class QuarantineRestoreDecision(BaseModel):
    """Optional body for approve / deny on an awaiting-approval restore.

    ``reason`` is stored in the action ``payload`` (under
    ``approval_reason`` / ``denial_reason``) and surfaced through the
    compliance evidence trail so auditors can see *why* a destructive
    response was authorized or rejected.
    """

    reason: str = Field(default="", max_length=1000)


class PendingQuarantineRestore(BaseModel):
    """Approval-inbox entry: a single awaiting-approval restore plus the
    endpoint context Agent 2 needs to render the row without an extra
    fan-out call per endpoint."""

    action: ModuleActionResult
    endpoint_id: str
    hostname: str | None = None
    customer_id: UUID | None = None


class PendingRollbackIntent(BaseModel):
    """Approval-inbox entry: a single awaiting-approval rollback intent plus the
    endpoint context needed to render the row."""

    action: ModuleActionResult
    endpoint_id: str
    hostname: str | None = None
    customer_id: UUID | None = None
    rollback_readiness: RollbackReadiness | None = None


class RollbackIntentRequest(BaseModel):
    """Operator request to queue a ransomware rollback on an endpoint.

    The ``simulation_id`` and ``candidate_set_hash`` tie this request to a
    specific simulation the agent already ran, ensuring the control plane only
    authorises intents whose outcome is known and bounded.  ``valid_until``
    mirrors the field the agent populates in ``RollbackSimulation`` — the
    request is rejected at queue time if the simulation has already expired.
    """

    simulation_id: str = Field(min_length=1, max_length=256)
    candidate_set_hash: str = Field(min_length=1, max_length=256)
    affected_paths: list[str] = Field(min_length=1)
    recovery_point_id: str = Field(min_length=1, max_length=256)
    provider: str = Field(min_length=1, max_length=64)
    provider_metadata: dict[str, Any] | None = None
    valid_until: datetime
    severity_hint: RiskBand = "medium"
    reason: str = Field(default="", max_length=1000)


class RollbackIntentDecision(BaseModel):
    """Optional body for approve / deny on an awaiting-approval rollback intent."""

    reason: str = Field(default="", max_length=1000)


DeviceType = Literal["usb_storage", "usb_other", "printer", "bluetooth", "optical", "thunderbolt", "clipboard"]


class DeviceEvent(BaseModel):
    id: str
    customer_id: UUID | None = None
    hostname: str
    user: str
    device_type: DeviceType
    device_name: str
    vendor_id: str
    product_id: str
    serial: str | None = None
    action: Literal["connected", "blocked", "allowed_once", "read_attempted", "write_attempted", "paste_attempted", "print_job"]
    severity: RiskBand
    status: Literal["blocked", "pending_approval", "allowed", "review"]
    timestamp: datetime
    bytes_written: int | None = None
    destination: str | None = None
    policy_rule: str | None = None
    approval_required: bool = False


QuarantineItemKind = Literal["file", "email", "process", "network_connection"]


class QuarantineItem(BaseModel):
    id: str
    customer_id: UUID | None = None
    hostname: str
    kind: QuarantineItemKind
    name: str
    path: str | None = None
    hash: str | None = None
    quarantine_reason: str
    severity: RiskBand
    status: Literal["quarantined", "restore_requested", "restored", "deleted"]
    quarantined_at: datetime
    quarantined_by: str
    detection_id: str | None = None


class PatchItem(BaseModel):
    id: str
    customer_id: UUID | None = None
    hostname: str
    os: str
    cve_id: str | None = None
    kb_id: str | None = None
    title: str
    description: str
    severity: RiskBand
    status: Literal["missing", "pending", "applied", "failed", "excluded"]
    category: Literal["os", "application", "driver", "security"]
    vendor: str
    release_date: datetime
    installed_at: datetime | None = None
    tags: list[str] = Field(default_factory=list)
    cvss_score: float | None = None


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


# --- Policy Document v2 ----------------------------------------------------


PolicyInheritanceMode = Literal["inherit_with_overrides", "replace"]
PolicyDocumentStatus = Literal["draft", "active", "archived"]
PolicyVersionStatus = Literal["draft", "active", "archived"]
PolicyPromotionStatus = Literal["approved", "rejected"]


class PolicyScopeV2(BaseModel):
    partner_id: UUID | None = None
    customer_id: UUID | None = None
    group_id: UUID | None = None
    endpoint_id: str | None = None


class PolicyLineageV2(BaseModel):
    parent_policy_id: UUID | None = None
    inheritance_mode: PolicyInheritanceMode = "inherit_with_overrides"


DRPAssetCategory = Literal[
    "brand",
    "executive",
    "domain",
    "subdomain",
    "social_account",
    "repository",
    "keyword",
]


DRPFindingType = Literal[
    "impersonation",
    "typosquatting",
    "homoglyph",
    "phishing",
    "credential_harvesting",
    "brand_abuse",
    "trademark_infringement",
    "data_leak",
    "compromised_credential",
    "darkweb_mention",
    "marketplace_listing",
]


EASMAssetType = Literal[
    "domain",
    "subdomain",
    "ip",
    "service",
    "certificate",
    "cloud_asset",
    "web_application",
    "repository",
]


ExternalRiskStatus = Literal["active", "paused", "archived"]


FindingSeverity = Literal["low", "medium", "high", "critical"]


FindingStatus = Literal["new", "triaged", "monitoring", "resolved", "false_positive"]


DRPFindingStatus = Literal["new", "reviewing", "validated", "false_positive", "confirmed"]


EASMExposureType = Literal[
    "unpatched_vulnerability",
    "misconfiguration",
    "exposed_service",
    "data_leak",
    "shadow_it",
]


EASMExposureAssetType = Literal[
    "domain",
    "subdomain",
    "ip_address",
    "cloud_resource",
    "certificate",
    "open_port",
]


EASMExposureStatus = Literal["new", "investigating", "confirmed", "remediated", "false_positive"]


class DigitalRiskProtectionModule(BaseModel):
    """Policy v2 module payload for DRP.

    Matches Default Policy v1.01 direction: disabled unless licensed,
    and findings are review-first by default.
    """

    enabled: bool = False
    default_action: Literal["allow", "review", "block"] = "review"
    monitored_assets: list[DRPAssetCategory] = Field(
        default_factory=lambda: [
            "brand",
            "executive",
            "domain",
            "social_account",
            "repository",
            "keyword",
        ]
    )
    detections_enabled: list[DRPFindingType] = Field(
        default_factory=lambda: [
            "impersonation",
            "typosquatting",
            "homoglyph",
            "phishing",
            "credential_harvesting",
            "brand_abuse",
            "trademark_infringement",
            "data_leak",
            "compromised_credential",
            "darkweb_mention",
            "marketplace_listing",
        ]
    )
    collection_sources: list[Literal["social", "darkweb", "paste_sites", "repositories", "marketplaces"]] = Field(
        default_factory=lambda: ["social", "darkweb", "paste_sites", "repositories", "marketplaces"]
    )
    ai_nlp_enabled: bool = True
    ai_cv_enabled: bool = True
    ai_llm_validation_enabled: bool = True
    confidence_threshold: int = Field(default=70, ge=0, le=100)
    auto_takedown_enabled: bool = False
    evidence_controls: list[str] = Field(default_factory=lambda: ["iso27001-2022:A.5.12", "soc2-2017:CC6.1"])


class ExternalAttackSurfaceManagementModule(BaseModel):
    """Policy v2 module payload for EASM discovery and exposure management."""

    enabled: bool = False
    default_action: Literal["allow", "review", "block"] = "review"
    discovery_sources: list[
        Literal[
            "passive_dns",
            "certificate_transparency",
            "reverse_dns",
            "whois",
            "cloud_inventory",
            "safe_port_scan",
            "shadow_it",
        ]
    ] = Field(
        default_factory=lambda: [
            "passive_dns",
            "certificate_transparency",
            "reverse_dns",
            "whois",
            "cloud_inventory",
            "safe_port_scan",
            "shadow_it",
        ]
    )
    continuous_monitoring_enabled: bool = True
    change_detection_enabled: bool = True
    vulnerability_enrichment: list[Literal["cvss", "epss", "cisa_kev"]] = Field(
        default_factory=lambda: ["cvss", "epss", "cisa_kev"]
    )
    ai_recommendations_enabled: bool = True
    correlate_with_drp: bool = True
    max_safe_ports_per_asset: int = Field(default=100, ge=1, le=1000)
    evidence_controls: list[str] = Field(default_factory=lambda: ["iso27001-2022:A.8.16", "nist-csf-2.0:DE.CM"])


class DeploymentProfileModule(BaseModel):
    """Policy v2 module payload for deployment profile settings.

    Controls how agents are deployed, updated, and how they communicate
    with relays and cloud services.
    """

    enabled: bool = True
    update_channel: Literal["stable", "slow", "fast"] = "stable"
    update_interval_hours: int = Field(default=1, ge=1, le=72)
    proxy_enabled: bool = False
    proxy_server: str = ""
    proxy_port: str = "8080"
    silent_mode: bool = False
    show_alerts: bool = True
    show_notifications: bool = True
    endpoint_issues_visibility: bool = True
    telemetry_enabled: bool = False
    siem_url: str = ""
    siem_token: str = ""
    uninstall_password: str | None = None
    power_user_password: str | None = None
    deployment_ring: Literal["slow", "fast", "stable"] = "stable"
    rollout_percentage: int = Field(default=100, ge=1, le=100)
    relay_auto_discovery: bool = False
    allowed_upload_domains: list[str] = Field(default_factory=list)
    update_locations: list[dict[str, Any]] = Field(default_factory=list)
    communication_assignments: list[dict[str, Any]] = Field(default_factory=list)
    use_proxy_for_relay: bool = True
    use_proxy_for_cloud: bool = True
    use_proxy_for_siem: bool = False
    reboot_postpone: bool = True
    reboot_time: Literal["daily", "weekly", "manual"] = "daily"
    managed_update_fallback: bool = True


class PolicyDocumentV2Input(BaseModel):
    schema_version: Literal["2.0"] = "2.0"
    name: str = Field(min_length=1, max_length=200)
    scope: PolicyScopeV2 = Field(default_factory=PolicyScopeV2)
    lineage: PolicyLineageV2 = Field(default_factory=PolicyLineageV2)
    modules: dict[str, dict[str, Any]] = Field(default_factory=dict)
    white_label_names: dict[str, str] = Field(default_factory=dict)

    def digital_risk_protection(self) -> DigitalRiskProtectionModule:
        return DigitalRiskProtectionModule.model_validate(
            self.modules.get("digital_risk_protection", {})
        )

    def external_attack_surface_management(self) -> ExternalAttackSurfaceManagementModule:
        return ExternalAttackSurfaceManagementModule.model_validate(
            self.modules.get("external_attack_surface_management", {})
        )

    def deployment_profile(self) -> DeploymentProfileModule:
        return DeploymentProfileModule.model_validate(
            self.modules.get("deployment_profile", {})
        )


class PolicyDocumentV2(BaseModel):
    id: UUID
    schema_version: Literal["2.0"] = "2.0"
    name: str
    scope: PolicyScopeV2
    lineage: PolicyLineageV2
    modules: dict[str, dict[str, Any]] = Field(default_factory=dict)
    white_label_names: dict[str, str] = Field(default_factory=dict)
    status: PolicyDocumentStatus = "draft"
    latest_version: int = 1
    active_version: int | None = None
    created_at: datetime
    created_by: str
    updated_at: datetime
    updated_by: str


class PolicyVersion(BaseModel):
    id: UUID
    policy_id: UUID
    version: int = Field(ge=1)
    status: PolicyVersionStatus = "draft"
    payload: PolicyDocumentV2Input
    payload_hash: str
    signed_by: str
    signature: str
    signed_payload: dict[str, Any] = Field(default_factory=dict)
    created_at: datetime
    created_by: str
    promoted_from_simulation_id: UUID | None = None


class PolicyVersionSummary(BaseModel):
    id: UUID
    version: int
    status: PolicyVersionStatus
    payload_hash: str
    signed_by: str
    created_at: datetime
    created_by: str
    promoted_from_simulation_id: UUID | None = None


class PolicyUpdateInput(BaseModel):
    name: str | None = Field(default=None, min_length=1, max_length=200)
    modules: dict[str, dict[str, Any]] | None = Field(default=None)
    lineage: PolicyLineageV2 | None = None
    white_label_names: dict[str, str] | None = None


class PolicyCreateResponse(BaseModel):
    policy: PolicyDocumentV2
    version: PolicyVersion


class PolicyListItemV2(BaseModel):
    id: UUID
    name: str
    status: PolicyDocumentStatus
    latest_version: int
    active_version: int | None = None
    scope: PolicyScopeV2
    created_at: datetime
    updated_at: datetime


class PolicyListResponse(BaseModel):
    items: list[PolicyListItemV2] = Field(default_factory=list)
    total: int = 0
    limit: int = 50
    offset: int = 0


class PolicySimulationModuleOutcome(BaseModel):
    module: str
    enabled: bool
    outcome: Literal["enabled", "reviewed", "blocked", "disabled"] = "enabled"
    risk_delta: int = 0
    destructive_actions: list[str] = Field(default_factory=list)
    would_trigger_gate: bool
    evidence_tags: list[str] = Field(default_factory=list)
    notes: list[str] = Field(default_factory=list)


class PolicySimulationSummaryV2(BaseModel):
    modules_total: int
    modules_enabled: int
    modules_with_destructive_actions: int
    would_block: int
    would_isolate: int
    would_rollback: int
    risk_delta_total: int = 0
    approval_required: bool


class PolicySimulationRecord(BaseModel):
    id: UUID
    policy_id: UUID
    policy_version_id: UUID
    status: Literal["completed", "approved", "rejected"]
    summary: PolicySimulationSummaryV2
    outcomes: list[PolicySimulationModuleOutcome] = Field(default_factory=list)
    approval_required: bool = False
    approved: bool = False
    approved_by: str | None = None
    approval_reason: str | None = None
    evidence_event_id: UUID | None = None
    evidence_controls: list[str] = Field(default_factory=list)
    created_at: datetime
    created_by: str
    approved_at: datetime | None = None


class PolicyPromotion(BaseModel):
    id: UUID
    policy_id: UUID
    policy_version_id: UUID
    simulation_id: UUID
    status: PolicyPromotionStatus
    operator_approved: bool
    approval_reason: str | None = None
    approver: str
    approved_at: datetime
    evidence_event_id: UUID | None = None
    evidence_controls: list[str] = Field(default_factory=list)


class EvidenceEvent(BaseModel):
    id: UUID
    action: str
    resource: str
    actor: str
    scope: dict[str, Any] = Field(default_factory=dict)
    payload: dict[str, Any] = Field(default_factory=dict)
    evidence_controls: list[str] = Field(default_factory=list)
    created_at: datetime


class PolicyPromoteRequest(BaseModel):
    simulation_id: UUID
    operator_approved: bool = False
    approval_reason: str | None = Field(default=None, max_length=500)


class PolicyRollbackRequest(BaseModel):
    target_version: int = Field(ge=1)
    operator_approved: bool = False
    approval_reason: str | None = Field(default=None, max_length=500)


class PolicyAssignmentV2(BaseModel):
    id: UUID
    policy_id: UUID
    policy_version_id: UUID
    partner_id: UUID | None = None
    customer_id: UUID | None = None
    group_id: UUID | None = None
    endpoint_id: str | None = None
    assigned_by: str
    assigned_at: datetime


class PolicyAssignRequest(BaseModel):
    policy_id: UUID
    policy_version: int | None = Field(default=None, ge=1)
    partner_id: UUID | None = None
    customer_id: UUID | None = None
    group_id: UUID | None = None
    endpoint_id: str | None = None


class PolicyAssignmentListItem(BaseModel):
    """Console-facing assignment view with scope, drift, and diff info."""

    id: UUID
    scope: Literal["platform", "partner", "company", "group", "endpoint"]
    scope_id: str
    scope_name: str
    policy_id: UUID
    policy_name: str
    policy_version: str
    inherited: bool = False
    override: bool = False
    effective_since: datetime
    last_diff: str | None = None
    pending_diff: str | None = None
    endpoint_count: int = 0
    drift_count: int = 0


class PolicyGetResponse(BaseModel):
    policy: PolicyDocumentV2
    latest_version: PolicyVersion
    resolved_preview: PolicyDocumentV2Input
    locked_modules: list[str] = Field(default_factory=list)


class EffectivePolicyResponse(BaseModel):
    endpoint_id: str | None = None
    scope: PolicyScopeV2
    assignments_applied: list[PolicyAssignmentV2] = Field(default_factory=list)
    resolved_policy: PolicyDocumentV2Input
    policy_ids_applied: list[UUID] = Field(default_factory=list)
    policy_version_hash: str | None = None
    evidence_controls: list[str] = Field(default_factory=list)


class AgentPolicyResponse(BaseModel):
    endpoint_id: str
    policy_version_hash: str
    resolved_policy: PolicyDocumentV2Input
    evidence_controls: list[str] = Field(default_factory=list)


class AgentDlpEvidenceIngest(BaseModel):
    action_type: str = Field(min_length=1, max_length=120)
    decision: Literal["allow", "review", "block", "redact"]
    destination: str | None = Field(default=None, max_length=255)
    label_detected: str | None = Field(default=None, max_length=120)
    content_hash: str = Field(min_length=8, max_length=255)
    sha256_hash: str | None = Field(default=None, min_length=64, max_length=64)
    policy_version: str = Field(min_length=1, max_length=255)
    endpoint_id: str = Field(min_length=1, max_length=120)
    event_type: Literal["paste", "upload", "copy"]
    policy_action_field: Literal["paste_sensitive", "upload_restricted", "copy_to_genai"]
    process_name: str | None = Field(default=None, max_length=255)


class AgentPolicyAckRequest(BaseModel):
    policy_version_hash: str = Field(min_length=8, max_length=255)
    agent_version: str = Field(min_length=1, max_length=50)


class AgentPolicyAck(BaseModel):
    id: UUID
    endpoint_id: str
    policy_version_hash: str
    agent_version: str
    acknowledged_at: datetime


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


class CustomerRiskSummary(BaseModel):
    customer_id: UUID
    company_name: str
    risk_score: int = Field(ge=0, le=100)
    risk_band: RiskBand
    open_alerts: int = Field(default=0, ge=0)
    enrolled_agents: int = Field(default=0, ge=0)
    license_status: Literal["active", "trial", "expired", "suspended"]
    last_seen: datetime
    policy_version: str
    ai_efficiency_score: int = Field(default=0, ge=0, le=100)


class ReportRecord(BaseModel):
    id: UUID
    type: Literal["executive_summary", "ransomware_readiness", "integrity_report", "compliance_export", "incident_timeline", "ai_efficiency"]
    title: str
    description: str
    status: Literal["ready", "generating", "failed", "scheduled"]
    customer_id: UUID | None = None
    generated_at: datetime | None = None
    scheduled_for: datetime | None = None
    size_bytes: int | None = None
    confidence: int | None = Field(default=None, ge=0, le=100)
    source_event_count: int | None = None
    download_url: str | None = None


class ReportGenerateRequest(BaseModel):
    type: Literal["executive_summary", "ransomware_readiness", "integrity_report", "compliance_export", "incident_timeline", "ai_efficiency"]
    customer_id: UUID | None = None


class UsageMetrics(BaseModel):
    customer_id: UUID
    customer_name: str
    endpoint_count: int = 0
    events_30d: int = 0
    ai_calls_30d: int = 0
    ai_efficiency_score: int = Field(default=0, ge=0, le=100)
    dlp_events_30d: int = 0
    alerts_30d: int = 0
    blocked_30d: int = 0
    storage_gb: float = 0
    trend_events: int = 0
    trend_ai: int = 0


class PlatformUsage(BaseModel):
    total_endpoints: int = 0
    total_events_30d: int = 0
    total_ai_calls_30d: int = 0
    avg_ai_efficiency_score: int = 0
    total_dlp_events_30d: int = 0
    total_blocked_30d: int = 0
    total_storage_gb: float = 0
    customers: list[UsageMetrics] = Field(default_factory=list)


class Connector(BaseModel):
    id: str
    name: str
    category: Literal["psa", "rmm", "siem", "identity", "billing", "email"]
    description: str
    status: Literal["connected", "disconnected", "error", "configuring"]
    icon_emoji: str
    last_sync: datetime | None = None
    error_message: str | None = None
    config_fields: list[str] = Field(default_factory=list)


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


# --- External Risk (DRP + EASM) -------------------------------------------


class DRPAsset(BaseModel):
    id: UUID
    customer_id: UUID
    asset_type: DRPAssetCategory
    display_name: str
    value: str
    normalized_value: str | None = None
    metadata: dict[str, Any] = Field(default_factory=dict)
    status: ExternalRiskStatus = "active"
    created_at: datetime
    updated_at: datetime
    created_by: str


class DRPFinding(BaseModel):
    id: UUID
    customer_id: UUID
    asset_id: UUID | None = None
    asset_display_name: str = ""
    asset_type: DRPAssetCategory | None = None
    finding_type: DRPFindingType
    title: str
    summary: str
    source: str
    severity: FindingSeverity = "medium"
    status: DRPFindingStatus = "new"
    risk_score: int = Field(default=0, ge=0, le=100)
    confidence_score: int = Field(default=0, ge=0, le=100)
    llm_validation: str | None = None
    screenshot_url: str | None = None
    evidence_links: list[str] = Field(default_factory=list)
    related_easm_asset_id: UUID | None = None
    detected_at: datetime
    created_at: datetime


class EASMAsset(BaseModel):
    id: UUID
    customer_id: UUID
    asset_type: EASMAssetType
    display_name: str
    external_id: str | None = None
    ip_address: str | None = None
    fqdn: str | None = None
    provider: str | None = None
    tags: list[str] = Field(default_factory=list)
    metadata: dict[str, Any] = Field(default_factory=dict)
    risk_score: int = Field(default=0, ge=0, le=100)
    shadow_it: bool = False
    status: ExternalRiskStatus = "active"
    first_seen_at: datetime
    last_seen_at: datetime
    created_at: datetime
    updated_at: datetime


class EASMExposure(BaseModel):
    id: UUID
    customer_id: UUID
    asset_id: UUID | None = None
    asset_display_name: str
    asset_type: EASMExposureAssetType
    exposure_type: EASMExposureType
    title: str
    summary: str
    severity: FindingSeverity = "medium"
    status: EASMExposureStatus = "new"
    risk_score: int = Field(default=0, ge=0, le=100)
    confidence_score: int = Field(default=0, ge=0, le=100)
    ip_address: str | None = None
    fqdn: str | None = None
    cloud_provider: str | None = None
    open_ports: list[int] = Field(default_factory=list)
    tags: list[str] = Field(default_factory=list)
    metadata: dict[str, Any] = Field(default_factory=dict)
    first_seen: datetime
    last_seen: datetime
    created_at: datetime
    updated_at: datetime


class DRPFindingCreate(BaseModel):
    asset_display_name: str
    asset_type: DRPAssetCategory
    finding_type: DRPFindingType
    title: str
    summary: str
    source: str
    severity: FindingSeverity = "medium"
    risk_score: int = Field(default=0, ge=0, le=100)
    confidence_score: int = Field(default=0, ge=0, le=100)
    llm_validation: str | None = None
    screenshot_url: str | None = None
    evidence_links: list[str] = Field(default_factory=list)
    detected_at: datetime | None = None


class EASMExposureCreate(BaseModel):
    asset_display_name: str
    asset_type: EASMExposureAssetType
    exposure_type: EASMExposureType
    title: str
    summary: str
    severity: FindingSeverity = "medium"
    risk_score: int = Field(default=0, ge=0, le=100)
    confidence_score: int = Field(default=0, ge=0, le=100)
    ip_address: str | None = None
    fqdn: str | None = None
    cloud_provider: str | None = None
    open_ports: list[int] = Field(default_factory=list)
    tags: list[str] = Field(default_factory=list)


class ExternalRiskPolicyView(BaseModel):
    """Effective policy snapshot for an EASM or DRP module, sized to UI shape."""

    policy_version: str
    last_updated: datetime
    status: Literal["protected", "monitor_only", "off"]
    approval_required: bool
    controls: dict[str, bool] = Field(default_factory=dict)


class ExternalRiskSimulateRequest(BaseModel):
    action: str


class ExternalRiskSimulationPreview(BaseModel):
    id: str
    detection_id: str
    action: str
    destructive: bool
    approval_required: bool
    estimated_impact: list[str]
    affected_systems: int = 1
    evidence_controls: list[str] = Field(default_factory=list)
    created_at: datetime


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


class RecoveryCodeVerifyRequest(BaseModel):
    challenge_id: UUID
    code: str = Field(min_length=8, max_length=24)


class TotpChallenge(BaseModel):
    """Returned by /auth/login when 2FA is required.

    ``status`` is the discriminator the frontend uses:
    - ``totp_setup_required`` — first login: ``otpauth_url`` + ``secret`` are
      included so the client can render the QR code for enrollment.
      ``recovery_codes`` are returned on first setup only.
    - ``totp_required`` — subsequent logins: only the challenge id is
      returned; the client just asks for the 6-digit code.
    """

    status: Literal["totp_setup_required", "totp_required", "recovery_code_accepted"]
    challenge_id: UUID
    email: str
    otpauth_url: str | None = None
    secret: str | None = None
    issuer: str | None = None
    recovery_codes: list[str] | None = None


class RecoveryCodeList(BaseModel):
    codes: list[str]
    remaining: int


class PasswordSetRequest(BaseModel):
    password: str = Field(min_length=8, max_length=200)


# --- OAuth2 / SSO ------------------------------------------------------------

OAuth2ProviderType = Literal["google", "microsoft", "github", "oidc_generic"]


class OAuth2ProviderCreate(BaseModel):
    partner_id: UUID | None = None
    name: str = Field(min_length=1, max_length=80)
    provider_type: OAuth2ProviderType = "oidc_generic"
    client_id: str = Field(min_length=1)
    client_secret: str = Field(min_length=1)
    issuer_url: str | None = None
    authorization_url: str | None = None
    token_url: str | None = None
    userinfo_url: str | None = None
    scopes: str = "openid email profile"


class OAuth2Provider(BaseModel):
    id: UUID
    partner_id: UUID | None = None
    name: str
    provider_type: OAuth2ProviderType
    client_id: str
    issuer_url: str | None = None
    authorization_url: str | None = None
    token_url: str | None = None
    userinfo_url: str | None = None
    scopes: str
    enabled: bool
    created_at: datetime


class OAuth2ProviderUpdate(BaseModel):
    name: str | None = None
    client_id: str | None = None
    client_secret: str | None = None
    issuer_url: str | None = None
    authorization_url: str | None = None
    token_url: str | None = None
    userinfo_url: str | None = None
    scopes: str | None = None
    enabled: bool | None = None


class OAuth2Identity(BaseModel):
    id: UUID
    account_id: UUID
    provider_id: UUID
    provider_subject: str
    email: str | None = None
    created_at: datetime


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


class LoginResult(BaseModel):
    """Returned by ``/auth/totp/verify`` once both factors succeed.

    The client persists ``access_token`` and sends it as
    ``Authorization: Bearer <token>`` on subsequent requests. ``me``
    carries the same payload as ``/me`` so the console does not need a
    second round trip after login.
    """

    access_token: str
    token_type: Literal["Bearer"] = "Bearer"
    expires_at: datetime
    me: MeResponse


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


# --- Subscription lifecycle (P1 #5) ----------------------------------------

SubscriptionStatus = Literal[
    "trialing", "active", "past_due", "canceled", "paused", "incomplete"
]
BillingProvider = Literal["stripe", "manual", "mock"]


class BillingCustomer(BaseModel):
    customer_id: UUID
    provider: BillingProvider
    external_id: str
    default_payment_method: str | None = None
    status: str = "active"
    created_at: datetime
    updated_at: datetime


class SubscriptionInstance(BaseModel):
    id: UUID
    customer_id: UUID
    subscription_id: UUID
    subscription_sku: str
    status: SubscriptionStatus
    trial_ends_at: datetime | None = None
    current_period_start: datetime | None = None
    current_period_end: datetime | None = None
    cancel_at_period_end: bool = False
    canceled_at: datetime | None = None
    provider: BillingProvider | None = None
    provider_subscription_id: str | None = None
    seats: int = 0
    created_at: datetime
    updated_at: datetime


class SubscriptionEvent(BaseModel):
    id: UUID
    subscription_instance_id: UUID
    kind: str
    payload: dict = Field(default_factory=dict)
    source: Literal["internal", "webhook"]
    received_at: datetime


class StartTrialRequest(BaseModel):
    subscription_sku: str = Field(min_length=1, max_length=80)
    trial_days: int = Field(default=14, ge=1, le=180)
    seats: int = Field(default=0, ge=0)


class SubscribeRequest(BaseModel):
    subscription_sku: str = Field(min_length=1, max_length=80)
    seats: int = Field(default=0, ge=0)
    provider: BillingProvider = "manual"
    provider_subscription_id: str | None = None


class CancelSubscriptionRequest(BaseModel):
    at_period_end: bool = True
    reason: str | None = Field(default=None, max_length=500)


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


# --- Compliance Evidence Engine v0.5 --------------------------------------

ComplianceFramework = Literal["iso27001-2022", "soc2-2017", "nist-csf-2.0", "gdpr", "hipaa-security-rule"]
ComplianceSourceTable = Literal["compliance_controls", "policy_documents", "evidence_events", "security_alerts", "audit_log"]
ComplianceReviewDecision = Literal["accept", "reject", "needs_more"]


class ComplianceReviewCreate(BaseModel):
    model_config = ConfigDict(extra="forbid")

    source_table: ComplianceSourceTable
    source_id: str = Field(min_length=1, max_length=160)
    framework: ComplianceFramework
    control_id: str = Field(min_length=1, max_length=100)
    decision: ComplianceReviewDecision
    note: str | None = Field(default=None, max_length=2000)
    reviewed_by_role: str = Field(min_length=1, max_length=120)
    reviewed_by_name: str = Field(min_length=1, max_length=160)


class ComplianceReview(BaseModel):
    id: UUID
    customer_id: UUID
    source_table: str
    source_id: str
    framework: str
    control_id: str
    reviewed_by_account_id: UUID | None = None
    reviewed_by_role: str
    reviewed_by_name: str
    decision: str
    note: str | None = None
    reviewed_at: datetime


class ComplianceReviewQueueItem(BaseModel):
    source_table: str
    source_id: str
    framework: str
    control_id: str
    evidence_summary: str
    evidence_created_at: datetime | None = None
    review_status: Literal["pending", "completed"]
    latest_review: ComplianceReview | None = None


class ComplianceAttestationCreate(BaseModel):
    model_config = ConfigDict(extra="forbid")

    framework: ComplianceFramework
    period_start: date
    period_end: date
    attested_role: str = Field(min_length=1, max_length=120)
    attested_name: str = Field(min_length=1, max_length=160)
    statement: str = Field(min_length=1, max_length=4000)
    bundle_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    signature: str = Field(min_length=16, max_length=2048)
    signature_algo: str = Field(min_length=1, max_length=80)

    @model_validator(mode="after")
    def validate_period(self) -> "ComplianceAttestationCreate":
        if self.period_end < self.period_start:
            raise ValueError("period_end must be on or after period_start")
        return self


class ComplianceAttestation(BaseModel):
    id: UUID
    customer_id: UUID
    framework: str
    period_start: date
    period_end: date
    attested_by_account_id: UUID | None = None
    attested_role: str
    attested_name: str
    bundle_sha256: str
    signature: str
    signature_algo: str
    statement: str
    created_at: datetime
    evidence_summary_count: int = Field(default=0, ge=0)


class ComplianceVaultReference(BaseModel):
    id: UUID
    customer_id: UUID
    framework: str
    vault_provider: str
    reference_uri: str
    bundle_hash: str
    status: str
    exported_at: datetime


class QueuedActionItem(ModuleActionResult):
    """ModuleActionResult enriched with endpoint hostname and company name
    for the cross-tenant MSP queue view."""

    hostname: str
    customer_name: str | None = None

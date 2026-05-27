export const API = import.meta.env.VITE_API_URL ?? "http://127.0.0.1:8000";

// ---------------------------------------------------------------------------
// Domain types
// ---------------------------------------------------------------------------

export type RiskBand = "low" | "medium" | "high" | "critical";
export type PolicyAction = "allow" | "review" | "block";
export type PolicyRuleKind = "entity" | "regex" | "keyword";

export type Endpoint = {
  id: string;
  hostname: string;
  os: string;
  status: "healthy" | "attention" | "offline";
  risk_score: number;
  last_seen: string;
  policy_version: string;
  agent_version: string;
};

export type Policy = {
  id: string;
  name: string;
  mode: "monitor" | "review" | "block";
  protected_entities: string[];
  genai_guardrail: boolean;
  escalate_at: RiskBand;
};

export type Alert = {
  id: string;
  title: string;
  severity: "low" | "medium" | "high";
  endpoint_id: string | null;
  recommended_action: string;
  status: "open" | "acknowledged";
  created_at: string;
  source: string;
  entity_types: string[];
};

export type DlpFinding = {
  entity_type: string;
  start: number;
  end: number;
  score: number;
  text: string;
};

export type DlpScanResponse = {
  findings: DlpFinding[];
  action: PolicyAction;
  risk_score: number;
  risk_band: RiskBand;
  context_signals: string[];
  rationale: string;
};

export type PolicyRule = {
  id: string;
  kind: PolicyRuleKind;
  action: PolicyAction;
  entity_type?: string | null;
  pattern?: string | null;
  description?: string | null;
};

export type PolicyDocument = {
  id: string;
  name: string;
  version: number;
  mode_default: "monitor" | "review" | "block";
  escalate_at: RiskBand;
  genai_guardrail: boolean;
  rules: PolicyRule[];
  signed_by: string;
  signature: string;
  created_at: string;
  created_by: string;
};

export type PolicyDocumentDraft = {
  name: string;
  mode_default: "monitor" | "review" | "block";
  escalate_at: RiskBand;
  genai_guardrail: boolean;
  rules: PolicyRule[];
};

export type PolicySimulationSummary = {
  total: number;
  changed: number;
  would_block: number;
  would_review: number;
  would_allow: number;
};

export type PolicySimulationResponse = {
  summary: PolicySimulationSummary;
  results: {
    source: string | null;
    endpoint_id: string | null;
    before: { action: PolicyAction; risk_band: RiskBand; entity_types: string[] };
    after: { action: PolicyAction; risk_band: RiskBand; entity_types: string[] };
    changed: boolean;
  }[];
};

export type PolicyScopeV2 = {
  partner_id: string | null;
  customer_id: string | null;
  group_id: string | null;
  endpoint_id: string | null;
};

export type PolicyLineageV2 = {
  parent_policy_id: string | null;
  inheritance_mode: "inherit_with_overrides" | "replace";
};

export type PolicyDocumentV2Input = {
  schema_version: "2.0";
  name: string;
  scope: PolicyScopeV2;
  lineage: PolicyLineageV2;
  modules: Record<string, Record<string, unknown>>;
  white_label_names: Record<string, string>;
};

export type PolicyDocumentV2 = PolicyDocumentV2Input & {
  id: string;
  status: "draft" | "active" | "archived";
  latest_version: number;
  active_version: number | null;
  created_at: string;
  created_by: string;
  updated_at: string;
  updated_by: string;
};

export type PolicyVersion = {
  id: string;
  policy_id: string;
  version: number;
  status: "draft" | "active" | "archived";
  payload: PolicyDocumentV2Input;
  payload_hash: string;
  signed_by: string;
  signature: string;
  created_at: string;
  created_by: string;
  promoted_from_simulation_id: string | null;
};

export type PolicyCreateResponse = {
  policy: PolicyDocumentV2;
  version: PolicyVersion;
};

export type PolicyListItemV2 = {
  id: string;
  name: string;
  status: "draft" | "active" | "archived";
  latest_version: number;
  active_version: number | null;
  scope: PolicyScopeV2;
  created_at: string;
  updated_at: string;
};

export type PolicyListResponseV2 = {
  items: PolicyListItemV2[];
  total: number;
  limit: number;
  offset: number;
};

export type PolicySimulationModuleOutcome = {
  module: string;
  enabled: boolean;
  destructive_actions: string[];
  would_trigger_gate: boolean;
  notes: string[];
};

export type PolicySimulationSummaryV2 = {
  modules_total: number;
  modules_enabled: number;
  modules_with_destructive_actions: number;
  would_block: number;
  would_isolate: number;
  would_rollback: number;
  approval_required: boolean;
};

export type PolicySimulationRecord = {
  id: string;
  policy_id: string;
  policy_version_id: string;
  status: "completed" | "approved" | "rejected";
  summary: PolicySimulationSummaryV2;
  outcomes: PolicySimulationModuleOutcome[];
  approval_required: boolean;
  approved: boolean;
  approved_by: string | null;
  approval_reason: string | null;
  evidence_controls: string[];
  created_at: string;
  created_by: string;
  approved_at: string | null;
};

export type PolicyAssignmentV2 = {
  id: string;
  policy_id: string;
  policy_version_id: string;
  partner_id: string | null;
  customer_id: string | null;
  group_id: string | null;
  endpoint_id: string | null;
  assigned_by: string;
  assigned_at: string;
};

export type EffectivePolicyResponse = {
  endpoint_id: string | null;
  scope: PolicyScopeV2;
  assignments_applied: PolicyAssignmentV2[];
  resolved_policy: PolicyDocumentV2Input;
  policy_ids_applied: string[];
  evidence_controls: string[];
};

export type PolicyGetResponse = {
  policy: PolicyDocumentV2;
  latest_version: PolicyVersion;
  resolved_preview: PolicyDocumentV2Input;
  locked_modules: string[];
};

export type EnrollmentTokenIssued = {
  token: string;
  expires_at: string;
  note: string | null;
};

export type EnrollmentResult = {
  agent_id: string;
  agent_secret: string;
  enrolled_at: string;
  customer_id?: string | null;
  group_id?: string | null;
  policy_package_id?: string | null;
};

export type InstallerPlatform = "windows_msi" | "windows_exe" | "macos_pkg" | "linux_deb" | "linux_rpm";

export type PolicyPackage = {
  id: string;
  partner_id: string | null;
  name: string;
  description: string | null;
  package_type: "default" | "industry" | "custom";
  payload: Record<string, unknown>;
  version: number;
  signature: string;
  created_by: string;
  created_at: string;
};

export type Partner = {
  id: string;
  name: string;
  slug: string;
  deployment_mode: "cloud" | "on_prem";
  created_at: string;
};

export type Customer = {
  id: string;
  partner_id: string;
  customer_number: string;
  company_type: "partner" | "customer";
  name: string;
  industry: string | null;
  country: string | null;
  company_size: "1-10" | "11-50" | "51-250" | "251-1000" | "1000+" | null;
  status: "active" | "suspended" | "archived";
  policy_package_id?: string | null;
  default_group_id: string | null;
  assigned_policy_package_id: string | null;
  assigned_policy_name: string | null;
  created_by: string;
  created_at: string;
};

export type CustomerUpdatePayload = {
  name: string;
  industry?: string | null;
  country?: string | null;
  company_size?: Customer["company_size"];
  policy_package_id?: string | null;
  updated_by?: string;
};

export type PolicyAssignment = {
  id: string;
  customer_id: string;
  group_id: string | null;
  policy_package_id: string;
  policy_name: string;
  assigned_by: string;
  assigned_at: string;
};

export type CustomerGroup = {
  id: string;
  customer_id: string;
  name: string;
  created_at: string;
};

export type InstallerBuild = {
  id: string;
  customer_id: string;
  group_id: string | null;
  policy_package_id: string;
  platform: InstallerPlatform;
  status: "queued" | "ready" | "failed" | "expired";
  artifact_url: string | null;
  artifact_sha256: string | null;
  signing_status: "unsigned" | "signed" | "notarized";
  expires_at: string | null;
  install_profile: Record<string, unknown> | null;
  enrollment_token: string | null;
  created_by: string;
  created_at: string;
};

export type QuickDeployLink = {
  id: string;
  customer_id: string;
  group_id: string | null;
  installer_build_id: string | null;
  platform: InstallerPlatform | null;
  url: string;
  max_downloads: number | null;
  download_count: number;
  expires_at: string;
  revoked_at: string | null;
  created_by: string;
  created_at: string;
};

export type CustomerQuickCreateResult = {
  customer: Customer;
  assignment: PolicyAssignment;
  installers: InstallerBuild[];
  quick_deploy_links: QuickDeployLink[];
};

export type CompanySummary = {
  customer: Customer;
  license: CompanyLicense | null;
};

export type CompanySummaryPage = {
  items: CompanySummary[];
  total: number;
  limit: number;
  offset: number;
};

export type BulkActionResult = {
  ok_count: number;
  failures: { id: string; error: string }[];
};

// ---------------------------------------------------------------------------
// Tenancy & licensing
// ---------------------------------------------------------------------------

export type RoleCode =
  | "platform_owner"
  | "msp_partner"
  | "company_admin"
  | "company_tech"
  | "company_viewer";

export type PermissionLevel = "none" | "view" | "edit" | "manage";

export type AccountStatus = "invited" | "active" | "locked" | "suspended";
export type TwoFactorState = "missing" | "enabled" | "enforced";

export type Account = {
  id: string;
  email: string;
  full_name: string;
  status: AccountStatus;
  two_factor: TwoFactorState;
  password_expires_at: string | null;
  locked_until: string | null;
  last_login_at: string | null;
  created_at: string;
  roles: RoleAssignment[];
};

export type RoleAssignment = {
  id: string;
  role_code: RoleCode;
  partner_id: string | null;
  customer_id: string | null;
  granted_by: string;
  granted_at: string;
};

export type RoleAssignmentRequest = {
  role_code: RoleCode;
  partner_id?: string | null;
  customer_id?: string | null;
};

export type AccountCreatePayload = {
  email: string;
  full_name: string;
  initial_role?: RoleAssignmentRequest | null;
  password?: string | null;
  delivery?: InviteDelivery;
  created_by?: string;
};

export type InviteDelivery = "email" | "link";

export type AccountCreated = {
  account: Account;
  delivery: InviteDelivery;
  invite_url: string | null;
  invite_expires_at: string | null;
};

export type InviteAcceptPayload = {
  token: string;
  password: string;
  full_name?: string | null;
};

export type Role = {
  code: RoleCode;
  display_name: string;
  permissions: Record<string, PermissionLevel>;
};

export type Branding = {
  product_name: string;
  tagline: string;
  primary_color: string;
  accent_color: string;
  logo_url: string | null;
  support_email: string | null;
  support_url: string | null;
  footer_note: string | null;
  source: "platform" | "partner" | "customer";
};

export type MeResponse = {
  account: Account;
  scope: {
    is_platform: boolean;
    partner_ids: string[];
    customer_ids: string[];
  };
  permissions: Record<string, PermissionLevel>;
  branding: Branding;
};

export type SystemBannerSeverity = "info" | "warning" | "critical";

export type SystemBanner = {
  id: string;
  message: string;
  link_label: string | null;
  link_url: string | null;
  severity: SystemBannerSeverity;
  starts_at: string;
  ends_at: string | null;
  active: boolean;
  created_by: string | null;
  created_at: string;
};

export type SystemBannerCreate = {
  message: string;
  link_label?: string | null;
  link_url?: string | null;
  severity?: SystemBannerSeverity;
  starts_at?: string | null;
  ends_at?: string | null;
  active?: boolean;
};

// ---------------------------------------------------------------------------
// External risk: DRP findings + EASM exposures + customer security alerts
// ---------------------------------------------------------------------------

export type FindingSeverity = "low" | "medium" | "high" | "critical";

export type EASMExposureStatus =
  | "new"
  | "investigating"
  | "confirmed"
  | "remediated"
  | "false_positive";

export type EASMExposure = {
  id: string;
  customer_id: string;
  asset_id: string | null;
  asset_display_name: string;
  asset_type: string;
  exposure_type: string;
  title: string;
  summary: string;
  severity: FindingSeverity;
  status: EASMExposureStatus;
  risk_score: number;
  confidence_score: number;
  ip_address: string | null;
  fqdn: string | null;
  cloud_provider: string | null;
  open_ports: number[];
  tags: string[];
  metadata: Record<string, unknown>;
  first_seen: string;
  last_seen: string;
  created_at: string;
  updated_at: string;
};

export type DRPFindingStatus =
  | "new"
  | "reviewing"
  | "validated"
  | "false_positive"
  | "confirmed";

export type DRPFinding = {
  id: string;
  customer_id: string;
  asset_id: string | null;
  asset_display_name: string;
  asset_type: string | null;
  finding_type: string;
  title: string;
  summary: string;
  source: string;
  severity: FindingSeverity;
  status: DRPFindingStatus;
  risk_score: number;
  confidence_score: number;
  llm_validation: string | null;
  screenshot_url: string | null;
  evidence_links: string[];
  related_easm_asset_id: string | null;
  detected_at: string;
  created_at: string;
};

export type SecurityAlert = {
  id: string;
  customer_id: string;
  agent_id: string | null;
  category: string;
  severity: FindingSeverity;
  status: string;
  confidence?: number | null;
  payload?: Record<string, any> | null;
  ai_summary?: string | null;
  recommended_action?: string | null;
  created_at: string;
};

export type Subscription = {
  id: string;
  sku: string;
  display_name: string;
  tier: "core" | "advanced" | "enterprise";
  core_features: string[];
  available_addons: string[];
  billing_model: "monthly" | "annual" | "usage";
  list_price_per_seat: number;
  created_at: string;
};

export type LicenseStatus = "active" | "trial" | "expired" | "suspended";
export type ProtectionModel = "bundled" | "a_la_carte";

export type LicenseProduct = {
  id: string;
  license_id: string;
  product_code: string;
  product_name: string;
  product_type: string;
  protection_model: ProtectionModel;
  status: LicenseStatus;
  total_seats: number;
  used_seats: number;
  reserved_seats: number;
};

export type CompanyLicense = {
  id: string;
  customer_id: string;
  subscription_id: string;
  subscription_sku: string;
  license_key: string;
  company_hash: string;
  payment_plan: "monthly" | "annual" | "usage";
  status: LicenseStatus;
  issued_at: string;
  expires_at: string | null;
  total_seats: number;
  reserved_seats: number;
  auto_renewal: boolean;
  minimum_usage: number;
  addons: string[];
  products: LicenseProduct[];
  created_at: string;
};

export type CompanyLicenseAssign = {
  subscription_sku: string;
  payment_plan?: "monthly" | "annual" | "usage";
  total_seats: number;
  reserved_seats?: number;
  expires_at?: string | null;
  auto_renewal?: boolean;
  minimum_usage?: number;
  addons?: string[];
};

export type LicenseUsageDay = {
  product_code: string;
  day: string;
  active_seats: number;
  peak_seats: number;
};

// ---------------------------------------------------------------------------
// AI provider settings (per-tenant)
// ---------------------------------------------------------------------------

export type AiProviderKind = "classifier" | "chat" | "embedding";

export type AiProvider = {
  slug: string;
  display_name: string;
  kind: AiProviderKind;
  requires_byo_key: boolean;
  default_endpoint: string | null;
  supported_models: string[];
  notes: string | null;
};

export type CustomerAiSettings = {
  customer_id: string;
  provider_slug: string;
  model: string;
  endpoint: string | null;
  has_api_key: boolean;
  api_key_last4: string | null;
  data_residency: string | null;
  redact_pii_before_send: boolean;
  enabled: boolean;
  max_calls_per_day: number;
  updated_at: string;
  updated_by: string | null;
};

export type CustomerAiSettingsUpdate = {
  provider_slug: string;
  model: string;
  endpoint?: string | null;
  api_key?: string | null;
  clear_api_key?: boolean;
  data_residency?: string | null;
  redact_pii_before_send?: boolean;
  enabled?: boolean;
  max_calls_per_day?: number;
};

export type AiProbeResult = {
  ok: boolean;
  provider_slug: string | null;
  model: string | null;
  latency_ms: number | null;
  status_code: number | null;
  message: string;
};

// ---------------------------------------------------------------------------
// HTTP helpers
// ---------------------------------------------------------------------------

const ACCESS_TOKEN_STORAGE_KEY = "aetherix.access_token";
const AUTH_CHANGED_EVENT = "aetherix:auth-changed";

export function isTokenExpired(token: string): boolean {
  try {
    const parts = token.split(".");
    if (parts.length < 2) return true;
    const base64Url = parts[1];
    const base64 = base64Url.replace(/-/g, "+").replace(/_/g, "/");
    const jsonPayload = decodeURIComponent(
      atob(base64)
        .split("")
        .map((c) => "%" + ("00" + c.charCodeAt(0).toString(16)).slice(-2))
        .join("")
    );
    const payload = JSON.parse(jsonPayload) as { exp?: number };
    if (!payload.exp) return false;
    const now = Math.floor(Date.now() / 1000);
    return payload.exp < now;
  } catch {
    return true;
  }
}

export function getAccessToken(): string | null {
  try {
    if (typeof window === "undefined") return null;
    const token = window.localStorage.getItem(ACCESS_TOKEN_STORAGE_KEY);
    if (token && isTokenExpired(token)) {
      logout();
      return null;
    }
    return token;
  } catch {
    return null;
  }
}

export function setAccessToken(token: string | null): void {
  try {
    if (typeof window === "undefined") return;
    if (token) window.localStorage.setItem(ACCESS_TOKEN_STORAGE_KEY, token);
    else window.localStorage.removeItem(ACCESS_TOKEN_STORAGE_KEY);
    window.dispatchEvent(new CustomEvent(AUTH_CHANGED_EVENT, { detail: token }));
  } catch {
    // ignore
  }
}

async function apiFetch<T>(path: string, init?: RequestInit): Promise<T> {
  const headers = new Headers(init?.headers);
  const token = getAccessToken();
  if (token) headers.set("Authorization", `Bearer ${token}`);
  if (init?.body && !headers.has("Content-Type")) {
    headers.set("Content-Type", "application/json");
  }
  const res = await fetch(`${API}${path}`, { ...init, headers });
  if (res.status === 401) {
    logout();
  }
  if (!res.ok) {
    let detail = `${res.status}`;
    try {
      const json = (await res.json()) as { detail?: unknown };
      if (typeof json.detail === "string") {
        detail = json.detail;
      } else if (json.detail !== undefined) {
        detail = JSON.stringify(json.detail);
      }
    } catch {
      // ignore parse errors — use status code message
    }
    throw new Error(detail);
  }
  if (res.status === 204) return undefined as T;
  return res.json() as Promise<T>;
}

export function apiGet<T>(path: string): Promise<T> {
  return apiFetch<T>(path);
}

export function apiPost<T>(path: string, body: unknown): Promise<T> {
  return apiFetch<T>(path, { method: "POST", body: JSON.stringify(body) });
}

export function apiPut<T>(path: string, body: unknown): Promise<T> {
  return apiFetch<T>(path, { method: "PUT", body: JSON.stringify(body) });
}

export function apiDelete<T = void>(path: string): Promise<T> {
  return apiFetch<T>(path, { method: "DELETE" });
}

export function apiPatch<T>(path: string, body?: unknown): Promise<T> {
  return apiFetch<T>(path, {
    method: "PATCH",
    body: body === undefined ? undefined : JSON.stringify(body),
  });
}

export function logout(): void {
  setAccessToken(null);
}

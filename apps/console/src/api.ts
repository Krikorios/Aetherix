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

// ---------------------------------------------------------------------------
// HTTP helpers
// ---------------------------------------------------------------------------

const ACCOUNT_STORAGE_KEY = "aetherix.account_id";

export function getAccountId(): string | null {
  try {
    return typeof window === "undefined" ? null : window.localStorage.getItem(ACCOUNT_STORAGE_KEY);
  } catch {
    return null;
  }
}

export function setAccountId(id: string | null): void {
  try {
    if (typeof window === "undefined") return;
    if (id) window.localStorage.setItem(ACCOUNT_STORAGE_KEY, id);
    else window.localStorage.removeItem(ACCOUNT_STORAGE_KEY);
    window.dispatchEvent(new CustomEvent("aetherix:account-changed", { detail: id }));
  } catch {
    // ignore
  }
}

async function apiFetch<T>(path: string, init?: RequestInit): Promise<T> {
  const headers = new Headers(init?.headers);
  const accountId = getAccountId();
  if (accountId) headers.set("X-Aetherix-Account", accountId);
  if (init?.body && !headers.has("Content-Type")) {
    headers.set("Content-Type", "application/json");
  }
  const res = await fetch(`${API}${path}`, { ...init, headers });
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
  setAccountId(null);
}

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

export type Customer = {
  id: string;
  partner_id: string;
  customer_number: string;
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

// ---------------------------------------------------------------------------
// HTTP helpers
// ---------------------------------------------------------------------------

async function apiFetch<T>(path: string, init?: RequestInit): Promise<T> {
  const res = await fetch(`${API}${path}`, init);
  if (!res.ok) {
    let detail = `${res.status}`;
    try {
      const json = (await res.json()) as { detail?: string };
      if (json.detail) detail = String(json.detail);
    } catch {
      // ignore parse errors — use status code message
    }
    throw new Error(detail);
  }
  return res.json() as Promise<T>;
}

export function apiGet<T>(path: string): Promise<T> {
  return apiFetch<T>(path);
}

export function apiPost<T>(path: string, body: unknown): Promise<T> {
  return apiFetch<T>(path, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body),
  });
}

export function apiPatch<T>(path: string): Promise<T> {
  return apiFetch<T>(path, { method: "PATCH" });
}

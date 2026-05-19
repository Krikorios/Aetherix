import { type ReactNode, useEffect, useState } from "react";
import {
  Activity,
  AlertTriangle,
  BarChart3,
  Building2,
  ChartSpline,
  FileText,
  FlaskConical,
  Globe2,
  Inbox,
  Landmark,
  LockKeyhole,
  Mail,
  Network,
  Puzzle,
  ScanText,
  Settings,
  ShieldCheck,
  Smartphone,
  UserCog,
} from "lucide-react";
import { DashboardPage } from "./pages/Dashboard";
import { AlertsPage } from "./pages/AlertsPage";
import { DlpScanPage } from "./pages/DlpScanPage";
import { PolicyPage } from "./pages/PolicyPage";
import { EnrollmentPage } from "./pages/EnrollmentPage";
import { AccountsPage } from "./pages/AccountsPage";
import { CompaniesPage } from "./pages/CompaniesPage";
import { apiGet, getAccountId, type Branding, type MeResponse } from "./api";

const DEFAULT_BRANDING: Branding = {
  product_name: "Aetherix",
  tagline: "MSP Console",
  primary_color: "#0b6b57",
  accent_color: "#0b6b57",
  logo_url: null,
  support_email: null,
  support_url: null,
  footer_note: null,
  source: "platform",
};

type Page =
  | "dashboard"
  | "executive"
  | "health"
  | "asm"
  | "alerts"
  | "blocklist"
  | "customRules"
  | "agenticInvestigation"
  | "scan"
  | "network"
  | "risk"
  | "policy"
  | "reports"
  | "quarantine"
  | "companies"
  | "accounts"
  | "sandbox"
  | "email"
  | "mobile"
  | "insights"
  | "integrations"
  | "configuration"
  | "enrollment";

const NAV: { group: string; items: { id: Page; label: string; icon: ReactNode }[] }[] = [
  {
    group: "Monitoring",
    items: [
      { id: "dashboard", label: "Dashboard", icon: <Activity size={18} /> },
      { id: "executive", label: "Executive Summary", icon: <BarChart3 size={18} /> },
      { id: "health", label: "Health", icon: <ShieldCheck size={18} /> },
      { id: "asm", label: "ASM", icon: <Globe2 size={18} /> },
    ],
  },
  {
    group: "Incidents",
    items: [
      { id: "alerts", label: "Search", icon: <AlertTriangle size={18} /> },
      { id: "blocklist", label: "Blocklist", icon: <LockKeyhole size={18} /> },
      { id: "customRules", label: "Custom Rules", icon: <FileText size={18} /> },
      { id: "agenticInvestigation", label: "Agentic AI Investigation", icon: <ScanText size={18} /> },
    ],
  },
  {
    group: "Protection",
    items: [
      { id: "scan", label: "Threats Xplorer", icon: <ScanText size={18} /> },
      { id: "network", label: "Network", icon: <Network size={18} /> },
      { id: "risk", label: "Risk Management", icon: <ChartSpline size={18} /> },
      { id: "policy", label: "Policies", icon: <FileText size={18} /> },
      { id: "reports", label: "Reports", icon: <BarChart3 size={18} /> },
      { id: "quarantine", label: "Quarantine", icon: <Inbox size={18} /> },
    ],
  },
  {
    group: "MSP Control",
    items: [
      { id: "companies", label: "Companies", icon: <Building2 size={18} /> },
      { id: "accounts", label: "Accounts", icon: <UserCog size={18} /> },
      { id: "enrollment", label: "Installers", icon: <Landmark size={18} /> },
    ],
  },
  {
    group: "Add-ons",
    items: [
      { id: "sandbox", label: "Sandbox Analyzer", icon: <FlaskConical size={18} /> },
      { id: "email", label: "Email Security", icon: <Mail size={18} /> },
      { id: "mobile", label: "Mobile Security", icon: <Smartphone size={18} /> },
      { id: "insights", label: "Data Insights", icon: <BarChart3 size={18} /> },
      { id: "integrations", label: "Integrations", icon: <Puzzle size={18} /> },
      { id: "configuration", label: "Configuration", icon: <Settings size={18} /> },
    ],
  },
];

export function App() {
  const [page, setPage] = useState<Page>("companies");
  const [branding, setBranding] = useState<Branding>(DEFAULT_BRANDING);

  useEffect(() => {
    let cancelled = false;
    async function load() {
      if (!getAccountId()) {
        if (!cancelled) setBranding(DEFAULT_BRANDING);
        return;
      }
      try {
        const me = await apiGet<MeResponse>("/me");
        if (!cancelled) setBranding(me.branding ?? DEFAULT_BRANDING);
      } catch {
        if (!cancelled) setBranding(DEFAULT_BRANDING);
      }
    }
    void load();
    const onAccountChange = () => void load();
    window.addEventListener("aetherix:account-changed", onAccountChange);
    window.addEventListener("storage", onAccountChange);
    return () => {
      cancelled = true;
      window.removeEventListener("aetherix:account-changed", onAccountChange);
      window.removeEventListener("storage", onAccountChange);
    };
  }, []);

  useEffect(() => {
    const root = document.documentElement;
    root.style.setProperty("--accent", branding.accent_color || branding.primary_color);
    root.style.setProperty("--brand-primary", branding.primary_color);
    document.title = `${branding.product_name} — ${branding.tagline}`;
  }, [branding.accent_color, branding.primary_color, branding.product_name, branding.tagline]);

  return (
    <main className="shell">
      <aside className="rail" aria-label="Primary navigation">
        <div className="brandMark">
          {branding.logo_url ? (
            <img className="railLogo" src={branding.logo_url} alt="" aria-hidden="true" />
          ) : (
            <ShieldCheck className="railLogo" aria-hidden="true" />
          )}
          <div>
            <strong>{branding.product_name}</strong>
            <span>{branding.tagline}</span>
          </div>
        </div>
        {NAV.map((section) => (
          <nav className="navGroup" key={section.group} aria-label={section.group}>
            <span>{section.group}</span>
            {section.items.map(({ id, label, icon }) => (
              <button
                key={id}
                className={page === id ? "active" : ""}
                title={label}
                aria-label={label}
                aria-current={page === id ? "page" : undefined}
                onClick={() => setPage(id)}
              >
                {icon}
                <span>{label}</span>
              </button>
            ))}
          </nav>
        ))}
      </aside>

      <section className="workspace">
        {page === "dashboard" && <DashboardPage />}
        {page === "alerts" && <AlertsPage />}
        {page === "scan" && <DlpScanPage />}
        {page === "policy" && <PolicyPage />}
        {page === "enrollment" && <EnrollmentPage />}
        {page === "companies" && <CompaniesPage />}
        {page === "accounts" && <AccountsPage />}
        {!["dashboard", "alerts", "scan", "policy", "enrollment", "companies", "accounts"].includes(page) ? (
          <PlaceholderPage page={page} />
        ) : null}
      </section>
    </main>
  );
}

type PlaceholderStatus = "designing" | "planned" | "add-on";

const STATUS_LABEL: Record<PlaceholderStatus, string> = {
  designing: "Designing",
  planned: "Planned",
  "add-on": "Add-on entitlement",
};

type PlaceholderMeta = {
  title: string;
  eyebrow: string;
  status: PlaceholderStatus;
  summary: string;
  depends: string[];
};

const PLACEHOLDERS: Record<Exclude<Page, "dashboard" | "alerts" | "scan" | "policy" | "enrollment" | "companies" | "accounts">, PlaceholderMeta> = {
  executive: {
    title: "Executive Summary",
    eyebrow: "Partner reporting",
    status: "planned",
    summary:
      "AI-generated portfolio summary for MSP partners: customer risk, license utilisation, top incidents, and weekly delta. Builds on /companies, /alerts, and the upcoming ai_reports table.",
    depends: ["ai_reports table", "/companies tenant scope", "LLM gateway contract"],
  },
  health: {
    title: "Endpoint Health",
    eyebrow: "Company operations",
    status: "planned",
    summary:
      "Per-company endpoint health view with policy drift, agent version skew, and action queues. Aggregates the existing /endpoints heartbeat data once company-scoped queries land.",
    depends: ["tenant-scoped /endpoints", "policy drift signal", "action queue API"],
  },
  asm: {
    title: "Attack Surface Management",
    eyebrow: "External exposure",
    status: "planned",
    summary:
      "External attack surface discovery (DNS, CT logs, passive DNS, safe scanners) feeding easm_assets and easm_findings. Tracks domains, subdomains, certificates, exposed services, and risky DNS.",
    depends: ["easm_assets table", "asset-based licensing", "EASM collector workers"],
  },
  blocklist: {
    title: "Blocklist",
    eyebrow: "Response controls",
    status: "planned",
    summary:
      "Tenant-scoped blocklists for hashes, domains, URLs, users, and processes. Pulled into agent policy on heartbeat alongside the existing signed policy document.",
    depends: ["block list table", "policy document merge", "agent policy fetch"],
  },
  customRules: {
    title: "Custom Detection Rules",
    eyebrow: "Detection engineering",
    status: "planned",
    summary:
      "Customer-authored detection rules layered on top of platform rules. Same partner/company isolation as policy documents, with simulation before promotion.",
    depends: ["rules table", "rule simulator", "policy promotion flow"],
  },
  agenticInvestigation: {
    title: "Agentic AI Investigation",
    eyebrow: "Autonomous response",
    status: "designing",
    summary:
      "Investigation agents correlate endpoint telemetry, DLP events, asset criticality, and threat intel into auditable timelines with confidence-scored response recommendations and approval gates.",
    depends: ["incident_cases correlation", "LLM gateway", "response_actions table"],
  },
  network: {
    title: "Network & Patch",
    eyebrow: "Asset hardening",
    status: "planned",
    summary:
      "Patch inventory, installation packages, tasks, and tags scoped to a company. Reuses the customer hierarchy already enforced on /companies and installer builds.",
    depends: ["patch inventory ingestion", "task runner", "tag schema"],
  },
  risk: {
    title: "Risk Management",
    eyebrow: "Continuous threat exposure",
    status: "planned",
    summary:
      "CVE ingestion enriched with EPSS, CISA KEV, exploit availability, compensating controls, and business criticality. Rolls up by company with PHASR and compliance evidence mapping.",
    depends: ["vulnerability ingestion", "business-context model", "compliance map"],
  },
  reports: {
    title: "Reports",
    eyebrow: "Executive deliverables",
    status: "planned",
    summary:
      "Templated AI executive reports, ransomware readiness, and integrity reports backed by ai_reports with structured confidence, source references, and deterministic fallbacks.",
    depends: ["ai_reports table", "report templates", "object storage for evidence"],
  },
  quarantine: {
    title: "Quarantine",
    eyebrow: "Containment",
    status: "planned",
    summary:
      "Scoped restore and release workflows for quarantined files, email items, and processes. Audit-trail mirrors the existing signed policy and enrollment audit events.",
    depends: ["quarantine store", "restore workflow", "audit hash chain"],
  },
  sandbox: {
    title: "Sandbox Analyzer",
    eyebrow: "Add-on entitlement",
    status: "add-on",
    summary:
      "Detonation and behavioural analysis of suspicious artefacts. Surfaces only when the subscription_entitlements row grants sandbox access for the customer.",
    depends: ["subscription_entitlements", "sandbox worker", "verdict pipeline"],
  },
  email: {
    title: "Email Security",
    eyebrow: "Add-on entitlement",
    status: "add-on",
    summary:
      "Inline and journaling protection for mailboxes. Gated on subscription_entitlements and integrated with quarantine, blocklist, and incident correlation.",
    depends: ["mail connector", "subscription_entitlements", "quarantine integration"],
  },
  mobile: {
    title: "Mobile Security",
    eyebrow: "Add-on entitlement",
    status: "add-on",
    summary:
      "iOS and Android protection with MDM bridge. Gated on subscription_entitlements; reuses the policy engine and enrollment token flow already shipping for desktop agents.",
    depends: ["MDM bridge", "subscription_entitlements", "mobile agent profile"],
  },
  insights: {
    title: "Data Insights",
    eyebrow: "Usage and billing",
    status: "planned",
    summary:
      "Usage, AI efficiency, and billing signals across partners and customers. Feeds the AI Efficiency Score already shown on the Companies hub.",
    depends: ["usage metering", "billing export", "AI efficiency model"],
  },
  integrations: {
    title: "Integrations",
    eyebrow: "Ecosystem connectors",
    status: "planned",
    summary:
      "PSA, RMM, SIEM, identity, and billing connectors. Wraps the existing FastAPI control plane behind a connector contract with per-tenant credentials.",
    depends: ["connector framework", "credential vault", "SIEM event export"],
  },
  configuration: {
    title: "Configuration",
    eyebrow: "Platform settings",
    status: "designing",
    summary:
      "MSP white-label branding, support contacts, and global defaults. Builds on the live /me branding resolver that already drives accent colour and product name in this console.",
    depends: ["branding write API", "support contact schema", "global defaults"],
  },
};

function PlaceholderPage({ page }: { page: Page }) {
  const meta = PLACEHOLDERS[page as keyof typeof PLACEHOLDERS];
  if (!meta) return null;
  return (
    <section className="panel placeholderPanel">
      <div className="panelHeader">
        <div>
          <p className="placeholderEyebrow">{meta.eyebrow}</p>
          <h2>{meta.title}</h2>
          <span>{meta.summary}</span>
        </div>
        <span className={`badge placeholderStatus status-${meta.status}`}>{STATUS_LABEL[meta.status]}</span>
      </div>
      <div className="placeholderDepends">
        <span>Backend dependencies</span>
        <ul>
          {meta.depends.map((d) => (
            <li key={d}>{d}</li>
          ))}
        </ul>
      </div>
    </section>
  );
}



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

function PlaceholderPage({ page }: { page: Page }) {
  const landing: Record<Page, string> = {
    dashboard: "Platform Owner opens with partner revenue, AI efficiency, and cross-tenant risk.",
    executive: "MSP Partner opens with a customer portfolio summary and executive report queue.",
    health: "Company Administrator opens with endpoint health, policy drift, and action queues.",
    asm: "External attack surface and asset exposure will land here.",
    alerts: "Incident search is already wired to API alerts.",
    blocklist: "Blocklist controls will cover hashes, domains, users, and tenant scope.",
    customRules: "Custom detection rules will inherit the same partner/company isolation model.",
    agenticInvestigation: "AI investigation will show auditable reasoning, evidence, and response playbooks.",
    scan: "Threats Xplorer is currently backed by the DLP scanner POC.",
    network: "Patch inventory, installation packages, tasks, and tags will share company scope.",
    risk: "Findings, vulnerabilities, PHASR, EASM, and compliance will roll up by company.",
    policy: "Policies are already backed by signed policy documents.",
    reports: "Reports will start with AI executive summaries, ransomware, and integrity templates.",
    quarantine: "Quarantine will provide scoped restore/release workflows.",
    companies: "Companies are the MSP tenant hub.",
    accounts: "Accounts are the hierarchy and permissions control plane.",
    sandbox: "Sandbox Analyzer will be an add-on entitlement in licensing.",
    email: "Email Security will be exposed as a subscription add-on.",
    mobile: "Mobile Security will be exposed as a subscription add-on.",
    insights: "Data Insights will report usage, efficiency, and billing signals.",
    integrations: "Integrations will cover PSA, RMM, SIEM, identity, and billing systems.",
    configuration: "Configuration will host MSP white-label branding, support, and global defaults.",
    enrollment: "Installers are already backed by customer quick-deploy APIs.",
  };

  return (
    <section className="panel placeholderPanel">
      <div className="panelHeader">
        <div>
          <h2>{page.replace(/([A-Z])/g, " $1")}</h2>
          <span>{landing[page]}</span>
        </div>
        <span className="badge">Roadmap</span>
      </div>
      <div className="roadmapSteps">
        <article><strong>1</strong><span>Enforce tenant scope and role gates.</span></article>
        <article><strong>2</strong><span>Add API contracts and audit events.</span></article>
        <article><strong>3</strong><span>Connect dashboards, workflows, and reports.</span></article>
      </div>
    </section>
  );
}



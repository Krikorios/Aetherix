import { FormEvent, useEffect, useMemo, useRef, useState } from "react";
import { Building2, CheckCircle2, Download, Palette, Plus, RefreshCw, ShieldCheck, Sparkles } from "lucide-react";
import { apiGet, apiPost } from "../api";
import type { Customer, CustomerQuickCreateResult, InstallerPlatform, PolicyPackage } from "../api";
import { EmptyState, ErrorBanner, LoadingRow, PageHeader, SuccessBanner } from "../components";

const COMPANY_SIZES = ["1-10", "11-50", "51-250", "251-1000", "1000+"] as const;
const PLATFORMS: { value: InstallerPlatform; label: string }[] = [
  { value: "windows_msi", label: "Windows MSI" },
  { value: "macos_pkg", label: "macOS PKG" },
  { value: "linux_deb", label: "Linux DEB" },
];

const ADD_ONS = [
  { name: "Agentic Response", status: "Included", margin: "58%", detail: "Playbooks, investigation summaries, and guided remediation" },
  { name: "Semantic DLP", status: "Included", margin: "56%", detail: "AI-native data loss prevention with explainable decisions" },
  { name: "Sandbox Analyzer", status: "Add-on", margin: "49%", detail: "Detonation and artifact enrichment" },
  { name: "Email Security", status: "Add-on", margin: "47%", detail: "Mailbox protection and phishing workflows" },
  { name: "Mobile Security", status: "Add-on", margin: "45%", detail: "MDM-light posture and threat signals" },
];

const ROADMAP = [
  "Build tenant model: Platform Owner, MSP Partner, Company, Company User, audit impersonation.",
  "Ship Companies, Accounts, Licensing, policy assignment, and installer generation as the first console milestone.",
  "Add dashboard variants per role, then incidents, risk, reports, and add-on billing telemetry.",
  "Connect PSA/RMM integrations, white-label domains, usage-based pricing, and customer executive reporting.",
];

export function CompaniesPage() {
  const [customers, setCustomers] = useState<Customer[]>([]);
  const [policyPackages, setPolicyPackages] = useState<PolicyPackage[]>([]);
  const [result, setResult] = useState<CustomerQuickCreateResult | null>(null);
  const [isLoading, setIsLoading] = useState(true);
  const [isCreating, setIsCreating] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [success, setSuccess] = useState<string | null>(null);
  const mountedRef = useRef(true);

  const [name, setName] = useState("");
  const [industry, setIndustry] = useState("Healthcare");
  const [companySize, setCompanySize] = useState<(typeof COMPANY_SIZES)[number]>("11-50");
  const [policyPackageId, setPolicyPackageId] = useState("");
  const [platforms, setPlatforms] = useState<InstallerPlatform[]>(["windows_msi", "macos_pkg"]);

  async function load() {
    try {
      const [nextCustomers, nextPackages] = await Promise.all([apiGet<Customer[]>("/customers"), apiGet<PolicyPackage[]>("/policy-packages")]);
      if (mountedRef.current) {
        setCustomers(nextCustomers);
        setPolicyPackages(nextPackages);
        setPolicyPackageId((current) => current || nextPackages[0]?.id || "");
        setError(null);
      }
    } catch (err) {
      if (mountedRef.current) setError(err instanceof Error ? err.message : "Failed to load companies");
    } finally {
      if (mountedRef.current) setIsLoading(false);
    }
  }

  useEffect(() => {
    mountedRef.current = true;
    queueMicrotask(() => void load());
    return () => { mountedRef.current = false; };
  }, []);

  const selectedPackage = useMemo(() => policyPackages.find((item) => item.id === policyPackageId) ?? policyPackages[0] ?? null, [policyPackageId, policyPackages]);
  const protectedEndpointEstimate = customers.reduce((total, customer) => total + sizeEstimate(customer.company_size), 0);
  const averageEfficiency = customers.length > 0 ? Math.round(customers.reduce((total, customer) => total + efficiencyScore(customer), 0) / customers.length) : 92;

  function togglePlatform(platform: InstallerPlatform) {
    setPlatforms((current) => current.includes(platform) ? current.filter((item) => item !== platform) : [...current, platform]);
  }

  async function submit(event: FormEvent) {
    event.preventDefault();
    setIsCreating(true);
    setError(null);
    setSuccess(null);
    setResult(null);
    try {
      const created = await apiPost<CustomerQuickCreateResult>("/customers/quick-create", {
        name: name.trim(),
        industry,
        country: "US",
        company_size: companySize,
        policy_package_id: selectedPackage?.id ?? null,
        platforms,
        installer_ttl_seconds: 86_400,
        created_by: "msp-partner",
      });
      setResult(created);
      setSuccess(`${created.customer.name} is created, licensed, assigned to policy, and ready for installer deployment.`);
      setName("");
      await load();
    } catch (err) {
      setError(err instanceof Error ? err.message : "Company creation failed");
    } finally {
      setIsCreating(false);
    }
  }

  return (
    <>
      <PageHeader
        eyebrow="MSP tenant foundation"
        title="Companies + Licensing"
        subtitle="Create customer companies, attach Core + add-ons, assign policies, and generate installers from one calm workflow"
      />
      {error ? <ErrorBanner message={error} /> : null}
      {success ? <SuccessBanner message={success} /> : null}

      <section className="metrics mspMetrics" aria-label="MSP company metrics">
        <Metric label="Companies" value={isLoading ? "..." : String(customers.length)} />
        <Metric label="Protected endpoints" value={String(protectedEndpointEstimate)} />
        <Metric label="AI efficiency score" value={`${averageEfficiency}%`} />
        <Metric label="Partner margin target" value="45-60%" />
      </section>

      <section className="grid companyFoundationGrid">
        <form className="panel companyCreatePanel" onSubmit={submit}>
          <div className="panelHeader">
            <div><h2>Add Company</h2><span>Company creation flows directly into policy assignment and customized installer generation.</span></div>
            <span className="badge">Core</span>
          </div>
          <div className="formRow"><label htmlFor="companyName">Company name</label><input id="companyName" required maxLength={160} value={name} onChange={(event) => setName(event.target.value)} placeholder="Northwind Dental" /></div>
          <div className="formGrid2">
            <div className="formRow"><label htmlFor="industry">Industry</label><input id="industry" value={industry} onChange={(event) => setIndustry(event.target.value)} /></div>
            <div className="formRow"><label htmlFor="companySize">Company size</label><select id="companySize" value={companySize} onChange={(event) => setCompanySize(event.target.value as typeof companySize)}>{COMPANY_SIZES.map((size) => <option key={size}>{size}</option>)}</select></div>
          </div>
          <div className="formRow"><label htmlFor="policyPackage">Configuration profile</label><select id="policyPackage" value={policyPackageId} onChange={(event) => setPolicyPackageId(event.target.value)}>{policyPackages.map((item) => <option key={item.id} value={item.id}>{item.name}</option>)}</select></div>
          <div className="platformCheckGrid">
            {PLATFORMS.map((platform) => <label key={platform.value} className={platforms.includes(platform.value) ? "platformCheck active" : "platformCheck"}><input type="checkbox" checked={platforms.includes(platform.value)} onChange={() => togglePlatform(platform.value)} /><span>{platform.label.split(" ").at(-1)}</span>{platform.label}</label>)}
          </div>
          <div className="formActions"><button className="btnPrimary" type="submit" disabled={isCreating || !name.trim() || platforms.length === 0}>{isCreating ? <RefreshCw size={16} className="spinIcon" /> : <Plus size={16} />} {isCreating ? "Creating" : "Create Company"}</button></div>
        </form>

        <aside className="panel licensePanel">
          <div className="panelHeader">
            <div><h2>Licensing</h2><span>Subscription-aware Core + add-ons for high-margin MSP packaging.</span></div>
            <ShieldCheck size={20} />
          </div>
          <div className="licenseBase"><strong>Aetherix Core</strong><span>EDR, DLP, policies, endpoint health, installers, and executive reporting</span><b>$6.80 endpoint / month</b></div>
          <div className="addonList">
            {ADD_ONS.map((addon) => <article key={addon.name}><div><strong>{addon.name}</strong><span>{addon.detail}</span></div><b>{addon.status}</b><em>{addon.margin}</em></article>)}
          </div>
        </aside>
      </section>

      {result ? <section className="panel readyFlow"><div className="panelHeader"><div><h2>{result.customer.name} deployment path</h2><span>Direct link: Company creation → Policy assignment → Customized installer generation.</span></div><span className="badge">Ready</span></div><div className="flowSteps"><article><CheckCircle2 size={18} /><strong>Company</strong><span>{result.customer.customer_number}</span></article><article><ShieldCheck size={18} /><strong>Policy</strong><span>{result.assignment.policy_name}</span></article><article><Download size={18} /><strong>Installers</strong><span>{result.installers.length} generated</span></article><article><Sparkles size={18} /><strong>AI Efficiency</strong><span>{efficiencyScore(result.customer)}%</span></article></div></section> : null}

      <section className="panel companyTablePanel">
        <div className="panelHeader"><div><h2>Company Hub</h2><span>Platform Owner sees all partners; MSP Partners see only their own company tree; company users see one assigned company.</span></div><button className="btnSecondary" type="button"><Palette size={16} /> White-label</button></div>
        <div className="companyTableHead"><span>Company</span><span>Policy</span><span>Core</span><span>Add-ons</span><span>AI Efficiency</span><span>Status</span></div>
        {customers.map((customer) => <article className="companyTableRow" key={customer.id}><div><Building2 size={17} /><strong>{customer.name}</strong><span>{customer.customer_number} · {customer.industry ?? "General"}</span></div><span>{customer.assigned_policy_name ?? "Unassigned"}</span><span>{sizeEstimate(customer.company_size)} endpoints</span><span>Semantic DLP, Agentic Response</span><span>{efficiencyScore(customer)}%</span><span className="statusPill status-active">{customer.status}</span></article>)}
        {isLoading ? <LoadingRow label="Loading companies" /> : null}
        {!isLoading && customers.length === 0 ? <EmptyState>No companies yet. Create the first company to seed the MSP hierarchy.</EmptyState> : null}
      </section>

      <section className="architectureGrid">
        <article className="panel"><div className="panelHeader"><div><h2>Console Architecture</h2><span>High-level service split for the next implementation phase.</span></div></div><div className="architectureList"><span>React console with role-aware navigation, partner theme tokens, and scoped API clients.</span><span>FastAPI control plane for tenants, accounts, policies, licensing, installers, and audit.</span><span>Postgres as source of truth with tenant-scoped rows and immutable audit chain.</span><span>Agent services for enrollment, heartbeat, policy delivery, telemetry, and response.</span></div></article>
        <article className="panel"><div className="panelHeader"><div><h2>Implementation Roadmap</h2><span>Foundation first, then the rest of the platform surface.</span></div></div><ol className="roadmapList">{ROADMAP.map((item) => <li key={item}>{item}</li>)}</ol></article>
      </section>
    </>
  );
}

function Metric({ label, value }: { label: string; value: string }) {
  return <article className="metric"><span>{label}</span><strong>{value}</strong></article>;
}

function sizeEstimate(size: Customer["company_size"]): number {
  if (size === "1-10") return 8;
  if (size === "11-50") return 34;
  if (size === "51-250") return 140;
  if (size === "251-1000") return 620;
  if (size === "1000+") return 1450;
  return 25;
}

function efficiencyScore(customer: Customer): number {
  return Math.min(98, 86 + (customer.name.length % 9));
}
import { FormEvent, useEffect, useMemo, useRef, useState } from "react";
import { Check, Copy, Download, Link as LinkIcon, Plus, RefreshCw, Search } from "lucide-react";
import { apiGet, apiPost, apiPut } from "../api";
import type { Customer, CustomerQuickCreateResult, CustomerUpdatePayload, InstallerBuild, InstallerPlatform, PolicyPackage, QuickDeployLink } from "../api";
import { EmptyState, ErrorBanner, LoadingRow, PageHeader, SideSheet, SuccessBanner } from "../components";
import { formatDate } from "../utils";

const PLATFORM_OPTIONS: { value: InstallerPlatform; label: string; suffix: string }[] = [
  { value: "windows_msi", label: "Windows MSI", suffix: "MSI" },
  { value: "windows_exe", label: "Windows EXE", suffix: "EXE" },
  { value: "macos_pkg", label: "macOS PKG", suffix: "PKG" },
  { value: "linux_deb", label: "Linux DEB", suffix: "DEB" },
  { value: "linux_rpm", label: "Linux RPM", suffix: "RPM" },
];

const COMPANY_SIZES = ["1-10", "11-50", "51-250", "251-1000", "1000+"] as const;

type DeploymentResult = {
  customer: Customer;
  policyName: string;
  installers: InstallerBuild[];
  quick_deploy_links: QuickDeployLink[];
};

function platformLabel(platform: InstallerPlatform | null): string {
  return PLATFORM_OPTIONS.find((option) => option.value === platform)?.label ?? "Installer";
}

function CopyButton({ value, label = "Copy" }: { value: string; label?: string }) {
  const [copied, setCopied] = useState(false);

  function copy() {
    void navigator.clipboard.writeText(value).then(() => {
      setCopied(true);
      setTimeout(() => setCopied(false), 1600);
    });
  }

  return (
    <button type="button" className="btnSecondary" onClick={copy} aria-label={label}>
      {copied ? <Check size={16} /> : <Copy size={16} />}
      {copied ? "Copied" : label}
    </button>
  );
}

export function EnrollmentPage() {
  const [customers, setCustomers] = useState<Customer[]>([]);
  const [policyPackages, setPolicyPackages] = useState<PolicyPackage[]>([]);
  const [isLoading, setIsLoading] = useState(true);
  const [isCreating, setIsCreating] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [success, setSuccess] = useState<string | null>(null);
  const [result, setResult] = useState<DeploymentResult | null>(null);
  const mountedRef = useRef(true);

  const [name, setName] = useState("");
  const [industry, setIndustry] = useState("Professional Services");
  const [country, setCountry] = useState("US");
  const [companySize, setCompanySize] = useState<(typeof COMPANY_SIZES)[number]>("11-50");
  const [policyPackageId, setPolicyPackageId] = useState("");
  const [platforms, setPlatforms] = useState<InstallerPlatform[]>(["windows_msi", "macos_pkg"]);
  const [showCreate, setShowCreate] = useState(false);
  const [editing, setEditing] = useState<Customer | null>(null);
  const [filterQuery, setFilterQuery] = useState("");

  async function load() {
    try {
      const [nextCustomers, nextPackages] = await Promise.all([
        apiGet<Customer[]>("/customers"),
        apiGet<PolicyPackage[]>("/policy-packages"),
      ]);
      if (mountedRef.current) {
        setCustomers(nextCustomers);
        setPolicyPackages(nextPackages);
        setPolicyPackageId((current) => current || nextPackages[0]?.id || "");
        setError(null);
      }
    } catch (err) {
      if (mountedRef.current) setError(err instanceof Error ? err.message : "Failed to load enrollment data");
    } finally {
      if (mountedRef.current) setIsLoading(false);
    }
  }

  useEffect(() => {
    mountedRef.current = true;
    void load();
    return () => { mountedRef.current = false; };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  const selectedPackage = useMemo(
    () => policyPackages.find((policyPackage) => policyPackage.id === policyPackageId) ?? policyPackages[0] ?? null,
    [policyPackageId, policyPackages],
  );

  function togglePlatform(platform: InstallerPlatform) {
    setPlatforms((current) => {
      if (current.includes(platform)) {
        return current.length === 1 ? current : current.filter((item) => item !== platform);
      }
      return [...current, platform];
    });
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
        industry: industry.trim() || null,
        country: country.trim() || null,
        company_size: companySize,
        policy_package_id: selectedPackage?.id ?? null,
        platforms,
        installer_ttl_seconds: 86_400,
        created_by: "msp-admin",
      });
      setResult({
        customer: created.customer,
        policyName: created.assignment.policy_name,
        installers: created.installers,
        quick_deploy_links: created.quick_deploy_links,
      });
      setSuccess(`${created.customer.name} is ready for deployment.`);
      setName("");
      setShowCreate(false);
      await load();
    } catch (err) {
      setError(err instanceof Error ? err.message : "Customer deployment failed");
    } finally {
      setIsCreating(false);
    }
  }

  const filteredCustomers = useMemo(() => {
    const q = filterQuery.trim().toLowerCase();
    if (!q) return customers;
    return customers.filter((c) =>
      `${c.name} ${c.customer_number} ${c.industry ?? ""} ${c.company_size ?? ""}`.toLowerCase().includes(q),
    );
  }, [customers, filterQuery]);

  return (
    <>
      <PageHeader eyebrow="MSP onboarding" title="Installers" />

      {error ? <ErrorBanner message={error} /> : null}
      {success ? <SuccessBanner message={success} /> : null}

      {result ? (
        <section className="panel deployResult">
          <div className="panelHeader">
            <div>
              <h2>{result.customer.name}</h2>
              <span>{result.customer.customer_number} · {result.policyName}</span>
            </div>
            <div className="panelActions">
              <span className="badge">Ready</span>
              <button type="button" className="btnGhost" onClick={() => setResult(null)} aria-label="Dismiss">Dismiss</button>
            </div>
          </div>

          <div className="artifactGrid">
            {result.quick_deploy_links.map((link) => (
              <article className="artifactCard" key={link.id}>
                <header>
                  <LinkIcon size={18} />
                  <strong>{platformLabel(link.platform)}</strong>
                </header>
                <code className="tokenValue">{link.url}</code>
                <div className="artifactActions">
                  <CopyButton value={link.url} label="Copy link" />
                  <span>Expires {formatDate(link.expires_at)}</span>
                </div>
              </article>
            ))}
          </div>

          <div className="artifactGrid directInstallers">
            {result.installers.map((installer) => (
              <article className="artifactCard" key={installer.id}>
                <header>
                  <Download size={18} />
                  <strong>{platformLabel(installer.platform)}</strong>
                </header>
                <div className="policyMeta compactMeta">
                  <div className="metaItem">
                    <span>Signing</span>
                    <strong>{installer.signing_status}</strong>
                  </div>
                  <div className="metaItem">
                    <span>SHA-256</span>
                    <code>{installer.artifact_sha256?.slice(0, 16)}...</code>
                  </div>
                </div>
                {installer.enrollment_token ? <CopyButton value={installer.enrollment_token} label="Copy token" /> : null}
              </article>
            ))}
          </div>
        </section>
      ) : null}

      <section className="panel companyTablePanel">
        <div className="panelHeader">
          <div>
            <h2>Deployments</h2>
          </div>
          <div className="panelActions">
            <div className="searchField">
              <Search size={14} />
              <input
                placeholder="Search deployments"
                value={filterQuery}
                onChange={(e) => setFilterQuery(e.target.value)}
              />
            </div>
            <button type="button" className="btnGhost" onClick={() => void load()} aria-label="Refresh">
              <RefreshCw size={16} /> Refresh
            </button>
            <button type="button" className="btnPrimary" onClick={() => setShowCreate(true)}>
              <Plus size={16} /> New deployment
            </button>
          </div>
        </div>

        <div className="accountTableHead enrollmentTableHead">
          <span>Name</span>
          <span>Customer #</span>
          <span>Industry</span>
          <span>Size</span>
          <span>Assigned policy</span>
        </div>
        {isLoading ? <LoadingRow label="Loading customers" /> : null}
        {!isLoading && filteredCustomers.length === 0 ? (
          <EmptyState>No customers match the current filters.</EmptyState>
        ) : null}
        {filteredCustomers.map((customer) => (
          <button className="accountRow enrollmentRow" key={customer.id} type="button" onClick={() => setEditing(customer)}>
            <strong>{customer.name}</strong>
            <span>{customer.customer_number}</span>
            <span>{customer.industry ?? "—"}</span>
            <span>{customer.company_size ?? "—"}</span>
            <span>{customer.assigned_policy_name ?? "No policy"}</span>
          </button>
        ))}
      </section>

      <SideSheet open={showCreate} onClose={() => setShowCreate(false)} title="New deployment" width={560}>
        <form className="formStack" onSubmit={submit}>
          <div className="formRow">
            <label htmlFor="customerName">Company name</label>
            <input
              id="customerName"
              required
              value={name}
              onChange={(event) => setName(event.target.value)}
              placeholder="Northwind Dental"
              maxLength={160}
              autoFocus
            />
          </div>

          <div className="formGrid2">
            <div className="formRow">
              <label htmlFor="industry">Industry</label>
              <input id="industry" value={industry} onChange={(event) => setIndustry(event.target.value)} />
            </div>
            <div className="formRow">
              <label htmlFor="country">Country</label>
              <input id="country" value={country} onChange={(event) => setCountry(event.target.value)} maxLength={80} />
            </div>
          </div>

          <div className="formGrid2">
            <div className="formRow">
              <label htmlFor="companySize">Company size</label>
              <select id="companySize" value={companySize} onChange={(event) => setCompanySize(event.target.value as typeof companySize)}>
                {COMPANY_SIZES.map((size) => <option key={size} value={size}>{size} endpoints</option>)}
              </select>
            </div>
            <div className="formRow">
              <label htmlFor="policyPackage">Policy package</label>
              <select
                id="policyPackage"
                value={policyPackageId}
                onChange={(event) => setPolicyPackageId(event.target.value)}
                disabled={policyPackages.length === 0}
              >
                {policyPackages.map((policyPackage) => (
                  <option key={policyPackage.id} value={policyPackage.id}>{policyPackage.name}</option>
                ))}
              </select>
            </div>
          </div>

          {selectedPackage ? (
            <div className="policyMeta compactMeta">
              <div className="metaItem">
                <span>Version</span>
                <strong>v{selectedPackage.version}</strong>
              </div>
              <div className="metaItem">
                <span>DLP rules</span>
                <strong>{Array.isArray(selectedPackage.payload.dlp_rules) ? selectedPackage.payload.dlp_rules.length : 0}</strong>
              </div>
              <div className="metaItem">
                <span>Hardening</span>
                <strong>{selectedPackage.payload.hardening_rules ? "Enabled" : "Custom"}</strong>
              </div>
            </div>
          ) : null}

          <div className="formRow">
            <label>Installer platforms</label>
            <div className="platformCheckGrid">
              {PLATFORM_OPTIONS.map((platform) => (
                <label key={platform.value} className={platforms.includes(platform.value) ? "platformCheck active" : "platformCheck"}>
                  <input
                    type="checkbox"
                    checked={platforms.includes(platform.value)}
                    onChange={() => togglePlatform(platform.value)}
                  />
                  <span>{platform.suffix}</span>
                  {platform.label}
                </label>
              ))}
            </div>
          </div>

          <div className="formActions">
            <button type="button" className="btnGhost" onClick={() => setShowCreate(false)}>Cancel</button>
            <button className="btnPrimary" type="submit" disabled={isCreating || !name.trim() || !selectedPackage}>
              {isCreating ? <RefreshCw size={16} className="spinIcon" /> : <Download size={16} />}
              {isCreating ? "Generating" : "Create & Generate"}
            </button>
          </div>
        </form>
      </SideSheet>

      <ExistingDeploymentSheet
        customer={editing}
        policyPackages={policyPackages}
        onClose={() => setEditing(null)}
        onUpdated={(updated) => {
          setCustomers((current) => current.map((customer) => (customer.id === updated.id ? updated : customer)));
          setEditing(updated);
          setSuccess(`${updated.name} updated.`);
        }}
        onGenerated={(nextResult) => {
          setResult(nextResult);
          setSuccess(`${nextResult.customer.name} installers and quick-deploy links are ready.`);
        }}
        onError={(message) => setError(message)}
      />
    </>
  );
}

function ExistingDeploymentSheet({
  customer,
  policyPackages,
  onClose,
  onUpdated,
  onGenerated,
  onError,
}: {
  customer: Customer | null;
  policyPackages: PolicyPackage[];
  onClose: () => void;
  onUpdated: (customer: Customer) => void;
  onGenerated: (result: DeploymentResult) => void;
  onError: (message: string) => void;
}) {
  const [name, setName] = useState("");
  const [industry, setIndustry] = useState("");
  const [country, setCountry] = useState("");
  const [companySize, setCompanySize] = useState<Customer["company_size"]>("11-50");
  const [policyPackageId, setPolicyPackageId] = useState("");
  const [platforms, setPlatforms] = useState<InstallerPlatform[]>(["windows_msi", "macos_pkg"]);
  const [busy, setBusy] = useState<"none" | "save" | "generate">("none");

  useEffect(() => {
    if (!customer) return;
    setName(customer.name);
    setIndustry(customer.industry ?? "");
    setCountry(customer.country ?? "");
    setCompanySize(customer.company_size ?? "11-50");
    setPolicyPackageId(customer.assigned_policy_package_id ?? policyPackages[0]?.id ?? "");
    setPlatforms(["windows_msi", "macos_pkg"]);
  }, [customer, policyPackages]);

  if (!customer) return null;

  const selectedPackage = policyPackages.find((policyPackage) => policyPackage.id === policyPackageId) ?? null;

  function togglePlatform(platform: InstallerPlatform) {
    setPlatforms((current) => {
      if (current.includes(platform)) return current.length === 1 ? current : current.filter((item) => item !== platform);
      return [...current, platform];
    });
  }

  async function save(): Promise<Customer> {
    if (!customer) throw new Error("No deployment selected");
    const payload: CustomerUpdatePayload = {
      name: name.trim(),
      industry: industry.trim() || null,
      country: country.trim() || null,
      company_size: companySize,
      policy_package_id: policyPackageId || null,
      updated_by: "msp-admin",
    };
    const updated = await apiPut<Customer>(`/customers/${customer.id}`, payload);
    onUpdated(updated);
    return updated;
  }

  async function submitSave(event: FormEvent) {
    event.preventDefault();
    setBusy("save");
    try {
      await save();
    } catch (err) {
      onError(err instanceof Error ? err.message : "Failed to update deployment");
    } finally {
      setBusy("none");
    }
  }

  async function saveAndGenerate() {
    setBusy("generate");
    try {
      const updated = await save();
      const body = { platforms, ttl_seconds: 86_400, created_by: "msp-admin" };
      const [installers, links] = await Promise.all([
        apiPost<InstallerBuild[]>(`/customers/${updated.id}/installers`, body),
        apiPost<QuickDeployLink[]>(`/customers/${updated.id}/quick-deploy`, body),
      ]);
      onGenerated({
        customer: updated,
        policyName: updated.assigned_policy_name ?? selectedPackage?.name ?? "No policy",
        installers,
        quick_deploy_links: links,
      });
      onClose();
    } catch (err) {
      onError(err instanceof Error ? err.message : "Failed to generate deployment artifacts");
    } finally {
      setBusy("none");
    }
  }

  return (
    <SideSheet open={!!customer} onClose={onClose} title={customer.name} subtitle={customer.customer_number} width={620}>
      <form className="formStack" onSubmit={submitSave}>
        <div className="formRow">
          <label htmlFor="editDeploymentName">Company name</label>
          <input id="editDeploymentName" required value={name} onChange={(event) => setName(event.target.value)} maxLength={160} />
        </div>
        <div className="formGrid2">
          <div className="formRow">
            <label htmlFor="editDeploymentIndustry">Industry</label>
            <input id="editDeploymentIndustry" value={industry} onChange={(event) => setIndustry(event.target.value)} maxLength={80} />
          </div>
          <div className="formRow">
            <label htmlFor="editDeploymentCountry">Country</label>
            <input id="editDeploymentCountry" value={country} onChange={(event) => setCountry(event.target.value)} maxLength={80} />
          </div>
        </div>
        <div className="formGrid2">
          <div className="formRow">
            <label htmlFor="editDeploymentSize">Company size</label>
            <select id="editDeploymentSize" value={companySize ?? ""} onChange={(event) => setCompanySize(event.target.value as NonNullable<Customer["company_size"]>)}>
              {COMPANY_SIZES.map((size) => <option key={size} value={size}>{size} endpoints</option>)}
            </select>
          </div>
          <div className="formRow">
            <label htmlFor="editDeploymentPolicy">Policy package</label>
            <select id="editDeploymentPolicy" value={policyPackageId} onChange={(event) => setPolicyPackageId(event.target.value)}>
              {policyPackages.map((policyPackage) => (
                <option key={policyPackage.id} value={policyPackage.id}>{policyPackage.name}</option>
              ))}
            </select>
          </div>
        </div>
        <div className="formRow">
          <label>Installer platforms</label>
          <div className="platformCheckGrid">
            {PLATFORM_OPTIONS.map((platform) => (
              <label key={platform.value} className={platforms.includes(platform.value) ? "platformCheck active" : "platformCheck"}>
                <input type="checkbox" checked={platforms.includes(platform.value)} onChange={() => togglePlatform(platform.value)} />
                <span>{platform.suffix}</span>
                {platform.label}
              </label>
            ))}
          </div>
        </div>
        <div className="formActions">
          <button type="button" className="btnGhost" onClick={onClose}>Cancel</button>
          <button type="submit" className="btnSecondary" disabled={busy !== "none" || !name.trim()}>
            {busy === "save" ? <RefreshCw size={16} className="spinIcon" /> : <Check size={16} />} Save changes
          </button>
          <button type="button" className="btnPrimary" onClick={() => void saveAndGenerate()} disabled={busy !== "none" || !name.trim() || platforms.length === 0 || !policyPackageId}>
            {busy === "generate" ? <RefreshCw size={16} className="spinIcon" /> : <Download size={16} />} Upgrade & generate
          </button>
        </div>
      </form>
    </SideSheet>
  );
}
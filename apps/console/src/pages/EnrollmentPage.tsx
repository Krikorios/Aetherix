import { FormEvent, useEffect, useMemo, useRef, useState } from "react";
import { Building2, Check, Copy, Download, Link as LinkIcon, RefreshCw } from "lucide-react";
import { apiGet, apiPost } from "../api";
import type { Customer, CustomerQuickCreateResult, InstallerPlatform, PolicyPackage } from "../api";
import { EmptyState, ErrorBanner, LoadingRow, PageHeader, SuccessBanner } from "../components";
import { formatDate } from "../utils";

const PLATFORM_OPTIONS: { value: InstallerPlatform; label: string; suffix: string }[] = [
  { value: "windows_msi", label: "Windows MSI", suffix: "MSI" },
  { value: "windows_exe", label: "Windows EXE", suffix: "EXE" },
  { value: "macos_pkg", label: "macOS PKG", suffix: "PKG" },
  { value: "linux_deb", label: "Linux DEB", suffix: "DEB" },
  { value: "linux_rpm", label: "Linux RPM", suffix: "RPM" },
];

const COMPANY_SIZES = ["1-10", "11-50", "51-250", "251-1000", "1000+"] as const;

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
  const [result, setResult] = useState<CustomerQuickCreateResult | null>(null);
  const mountedRef = useRef(true);

  const [name, setName] = useState("");
  const [industry, setIndustry] = useState("Professional Services");
  const [country, setCountry] = useState("US");
  const [companySize, setCompanySize] = useState<(typeof COMPANY_SIZES)[number]>("11-50");
  const [policyPackageId, setPolicyPackageId] = useState("");
  const [platforms, setPlatforms] = useState<InstallerPlatform[]>(["windows_msi", "macos_pkg"]);

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
      setResult(created);
      setSuccess(`${created.customer.name} is ready for deployment.`);
      setName("");
      await load();
    } catch (err) {
      setError(err instanceof Error ? err.message : "Customer deployment failed");
    } finally {
      setIsCreating(false);
    }
  }

  return (
    <>
      <PageHeader
        eyebrow="MSP onboarding"
        title="Customer Quick Deploy"
        subtitle="Create an SMB tenant, assign protection, and generate signed installers from one workspace"
      />

      {error ? <ErrorBanner message={error} /> : null}
      {success ? <SuccessBanner message={success} /> : null}

      <section className="grid enrollmentGrid">
        <form className="panel quickDeployForm" onSubmit={submit}>
          <div className="panelHeader">
            <div>
              <h2>New Customer</h2>
              <span>Default group and policy assignment are created automatically</span>
            </div>
            <span className="badge">Under 2 min</span>
          </div>

          <div className="formRow">
            <label htmlFor="customerName">Company name</label>
            <input
              id="customerName"
              required
              value={name}
              onChange={(event) => setName(event.target.value)}
              placeholder="Northwind Dental"
              maxLength={160}
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
            <button className="btnPrimary" type="submit" disabled={isCreating || !name.trim() || !selectedPackage}>
              {isCreating ? <RefreshCw size={16} className="spinIcon" /> : <Download size={16} />}
              {isCreating ? "Generating" : "Create & Generate"}
            </button>
          </div>
        </form>

        <aside className="panel">
          <div className="panelHeader">
            <div>
              <h2>Assigned Package</h2>
              <span>{selectedPackage ? selectedPackage.package_type : "Loading"}</span>
            </div>
          </div>
          {selectedPackage ? (
            <div className="policyMeta">
              <div className="metaItem">
                <span>Name</span>
                <strong>{selectedPackage.name}</strong>
              </div>
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
          ) : isLoading ? <LoadingRow label="Loading policy packages" /> : <EmptyState>No policy packages found.</EmptyState>}
        </aside>
      </section>

      {result ? (
        <section className="panel deployResult">
          <div className="panelHeader">
            <div>
              <h2>{result.customer.name}</h2>
              <span>{result.customer.customer_number} · {result.assignment.policy_name}</span>
            </div>
            <span className="badge">Ready</span>
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

      <section className="panel">
        <div className="panelHeader">
          <div>
            <h2>Customers</h2>
            <span>{isLoading ? "Loading" : `${customers.length} active tenant${customers.length === 1 ? "" : "s"}`}</span>
          </div>
        </div>
        <div className="customerList">
          {customers.map((customer) => (
            <article className="customerRow" key={customer.id}>
              <Building2 size={18} />
              <div>
                <strong>{customer.name}</strong>
                <p>{customer.customer_number} · {customer.industry ?? "General"} · {customer.company_size ?? "Unspecified"}</p>
              </div>
              <span>{customer.assigned_policy_name ?? "No policy"}</span>
            </article>
          ))}
          {isLoading ? <LoadingRow label="Loading customers" /> : null}
          {!isLoading && customers.length === 0 ? <EmptyState>No customers have been created yet.</EmptyState> : null}
        </div>
      </section>
    </>
  );
}
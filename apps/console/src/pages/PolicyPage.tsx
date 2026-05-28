import { useEffect, useMemo, useRef, useState } from "react";
import { Columns3, Copy, CircleMinus, Plus, RefreshCw, ShieldCheck } from "lucide-react";
import {
  apiGet,
  apiPost,
  type CompanySummaryPage,
  type CustomerGroup,
  type EffectivePolicyResponse,
  type Endpoint,
  type InstallerPlatform,
  type PolicyAssignmentV2,
  type PolicyListItemV2,
  type PolicyListResponseV2,
  type Subscription,
} from "../api";
import { EmptyState, ErrorBanner, LoadingRow, SideSheet, SuccessBanner } from "../components";
import { formatDate } from "../utils";

const PLATFORM_OPTIONS: InstallerPlatform[] = ["windows_msi", "macos_pkg", "linux_deb"];

export function PolicyPage() {
  // PolicyPage is strictly a catalog / listing page only.
  // All creation and editing of policy *content* happens in the dedicated
  // PolicyEditorPage (reached via "policyEditor" custom navigation event).
  // This ensures that when a policy is assigned to agents/network, updates
  // made in the powerful editor reflect directly on the next agent heartbeat.
  const [isLoading, setIsLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [success, setSuccess] = useState<string | null>(null);
  const [policies, setPolicies] = useState<PolicyListItemV2[]>([]);
  const [companyRows, setCompanyRows] = useState<CompanySummaryPage["items"]>([]);
  const [endpoints, setEndpoints] = useState<Endpoint[]>([]);
  const [subscriptions, setSubscriptions] = useState<Subscription[]>([]);
  const [groups, setGroups] = useState<CustomerGroup[]>([]);

  const [assignmentOpen, setAssignmentOpen] = useState(false);
  const [assignment, setAssignment] = useState({
    target: "customer" as "customer" | "group" | "endpoint",
    customerId: "",
    groupId: "",
    endpointId: "",
    quickDeploy: false,
    platforms: ["windows_msi"] as InstallerPlatform[],
    search: "",
  });
  const [effectivePreview, setEffectivePreview] = useState<EffectivePolicyResponse | null>(null);

  const [filterStatus, setFilterStatus] = useState<string>("");
  const [filterName, setFilterName] = useState("");
  const [filterCompany, setFilterCompany] = useState("");
  const [selectedPolicyIds, setSelectedPolicyIds] = useState<Set<string>>(new Set());
  const [isWorking, setIsWorking] = useState(false);

  const mountedRef = useRef(true);

  const companyMap = useMemo(() => {
    const m = new Map<string, CompanySummaryPage["items"][number]>();
    for (const row of companyRows) m.set(row.customer.id, row);
    return m;
  }, [companyRows]);

  const visibleCompanies = useMemo(() => {
    const q = assignment.search.trim().toLowerCase();
    if (!q) return companyRows;
    return companyRows.filter((r) => r.customer.name.toLowerCase().includes(q));
  }, [companyRows, assignment.search]);

  const visibleEndpoints = useMemo(() => {
    const q = assignment.search.trim().toLowerCase();
    if (!q) return endpoints;
    return endpoints.filter((e) => (e.hostname || "").toLowerCase().includes(q) || e.id.toLowerCase().includes(q));
  }, [endpoints, assignment.search]);

  async function loadPolicies() {
    const page = await apiGet<PolicyListResponseV2>(
      `/policies${queryString({ status: filterStatus || null })}`,
    );
    if (!mountedRef.current) return;
    setPolicies(page.items || []);
  }

  async function loadBaseData() {
    const [summary, endpointRows, subs] = await Promise.all([
      apiGet<CompanySummaryPage>("/companies/summary?limit=250&offset=0"),
      apiGet<Endpoint[]>("/endpoints"),
      apiGet<Subscription[]>("/subscriptions"),
    ]);
    if (!mountedRef.current) return;
    setCompanyRows(summary.items || []);
    setEndpoints(endpointRows || []);
    setSubscriptions(subs || []);
  }

  useEffect(() => {
    mountedRef.current = true;
    setIsLoading(true);
    setError(null);
    Promise.all([loadPolicies(), loadBaseData()])
      .catch((err: unknown) => {
        if (mountedRef.current) setError(err instanceof Error ? err.message : "Failed to load policies");
      })
      .finally(() => {
        if (mountedRef.current) setIsLoading(false);
      });
    return () => {
      mountedRef.current = false;
    };
  }, [filterStatus]);

  useEffect(() => {
    if (!assignmentOpen) {
      setEffectivePreview(null);
      return;
    }
    const endpointId = assignment.target === "endpoint" ? assignment.endpointId : null;
    const customerId = assignment.target === "customer" || assignment.target === "group" ? assignment.customerId : null;
    const groupId = assignment.target === "group" ? assignment.groupId : null;
    if (!endpointId && !customerId) {
      setEffectivePreview(null);
      return;
    }
    void apiGet<EffectivePolicyResponse>(
      `/policies/effective${queryString({ endpoint_id: endpointId || null, customer_id: customerId || null, group_id: groupId || null })}`,
    )
      .then((preview) => {
        if (mountedRef.current) setEffectivePreview(preview);
      })
      .catch(() => {
        if (mountedRef.current) setEffectivePreview(null);
      });
  }, [assignmentOpen, assignment.target, assignment.endpointId, assignment.customerId, assignment.groupId]);

  useEffect(() => {
    if (!assignment.customerId || assignment.target !== "group") {
      setGroups([]);
      return;
    }
    void apiGet<CustomerGroup[]>(`/customers/${assignment.customerId}/groups`)
      .then((gs) => {
        if (mountedRef.current) setGroups(gs || []);
      })
      .catch(() => {
        if (mountedRef.current) setGroups([]);
      });
  }, [assignment.customerId, assignment.target]);

  function queryString(filters: Record<string, string | null | undefined>): string {
    const params = new URLSearchParams();
    for (const [key, value] of Object.entries(filters)) {
      if (value) params.set(key, value);
    }
    const raw = params.toString();
    return raw ? `?${raw}` : "";
  }

  const visiblePolicies = useMemo(() => {
    const nameQuery = filterName.trim().toLowerCase();
    const companyFilter = filterCompany;
    return policies.filter((p) => {
      if (nameQuery && !p.name.toLowerCase().includes(nameQuery)) return false;
      if (companyFilter) {
        if (companyFilter === "global") {
          if (p.scope.customer_id) return false;
        } else if (p.scope.customer_id !== companyFilter) {
          return false;
        }
      }
      return true;
    });
  }, [policies, filterName, filterCompany]);

  function togglePolicySelection(policyId: string) {
    setSelectedPolicyIds((current) => {
      const next = new Set(current);
      if (next.has(policyId)) next.delete(policyId);
      else next.add(policyId);
      return next;
    });
  }

  function toggleVisiblePolicySelection() {
    setSelectedPolicyIds((current) => {
      const allVisibleSelected = visiblePolicies.length > 0 && visiblePolicies.every((policy) => current.has(policy.id));
      if (allVisibleSelected) {
        return new Set([...current].filter((id) => !visiblePolicies.some((policy) => policy.id === id)));
      }
      const next = new Set(current);
      for (const policy of visiblePolicies) next.add(policy.id);
      return next;
    });
  }

  const selectedCount = selectedPolicyIds.size;
  const allVisibleSelected = visiblePolicies.length > 0 && visiblePolicies.every((policy) => selectedPolicyIds.has(policy.id));
  const primarySelectedId = selectedCount === 1 ? Array.from(selectedPolicyIds)[0] : null;

  function openNewPolicy() {
    const event = new CustomEvent("aetherix:navigate", {
      detail: { page: "policyEditor", policyId: null },
    });
    window.dispatchEvent(event);
  }

  function openEditPolicy(policyId: string) {
    const event = new CustomEvent("aetherix:navigate", {
      detail: { page: "policyEditor", policyId },
    });
    window.dispatchEvent(event);
  }

  async function assignPolicy() {
    const policyId = primarySelectedId;
    if (!policyId) {
      setError("Select exactly one policy to assign");
      return;
    }
    if (!assignment.customerId && !assignment.endpointId) {
      setError("Select a target company or endpoint before assigning policy");
      return;
    }
    setError(null);
    setSuccess(null);
    setIsWorking(true);
    try {
      const payload = {
        policy_id: policyId,
        customer_id: assignment.target === "customer" || assignment.target === "group" ? assignment.customerId : null,
        group_id: assignment.target === "group" ? assignment.groupId : null,
        endpoint_id: assignment.target === "endpoint" ? assignment.endpointId : null,
      };
      await apiPost<PolicyAssignmentV2>("/policies/assign", payload);

      if (assignment.quickDeploy && payload.customer_id) {
        await apiPost(`/customers/${payload.customer_id}/installers`, {
          platforms: assignment.platforms,
          group_id: payload.group_id,
          ttl_seconds: 86400,
          created_by: "policy-list",
        });
      }

      setAssignmentOpen(false);
      setSuccess(assignment.quickDeploy ? "Policy assigned and installers queued." : "Policy assigned successfully.");
      setSelectedPolicyIds(new Set());
    } catch (err) {
      setError(err instanceof Error ? err.message : "Assignment failed");
    } finally {
      setIsWorking(false);
    }
  }

  function openAssignmentForSelected() {
    if (!primarySelectedId) {
      setError("Select exactly one policy to assign");
      return;
    }
    setAssignmentOpen(true);
  }

  return (
    <>
      <div className="policyCatalogPage">
        <header className="policyCatalogTopbar">
          <div className="policyCatalogTitleGroup">
            <p>Protection</p>
            <h1>Policies</h1>
            <span>Manage tenant-scoped security policies. Edit opens the dedicated editor so changes reflect directly on assigned agents and endpoints.</span>
          </div>
          <div className="policyCatalogActions" aria-label="Policy actions">
            <button
              className="btn btnPrimary"
              type="button"
              onClick={openNewPolicy}
            >
              <Plus size={14} /> Add policy
            </button>
            <button className="btn" type="button" onClick={() => void loadPolicies()} disabled={isLoading}>
              <RefreshCw size={14} className={isLoading ? "spin" : ""} /> Refresh
            </button>
          </div>
        </header>

        {error ? <ErrorBanner message={error} /> : null}
        {success ? <SuccessBanner message={success} /> : null}

        <section className="policyCatalogPanel" aria-label="Policies table">
          <div className="policyCatalogToolbar">
            <span className="policySelectionHint">
              {selectedCount > 0 ? `${selectedCount} selected` : "Select policies for bulk actions or assignment"}
            </span>
            <div className="policyBulkActions" aria-label="Selected policy actions">
              <button
                className="policyToolbarButton"
                type="button"
                disabled={selectedCount !== 1}
                onClick={() => primarySelectedId && openEditPolicy(primarySelectedId)}
              >
                Edit policy
              </button>
              <button
                className="policyToolbarButton"
                type="button"
                disabled={selectedCount !== 1}
                onClick={openAssignmentForSelected}
              >
                Assign to agent / network
              </button>
              <button className="policyToolbarButton" type="button" disabled={selectedCount !== 1}>
                <Copy size={15} /> Clone
              </button>
              <button className="policyToolbarButton danger" type="button" disabled={selectedCount === 0}>
                <CircleMinus size={15} /> Delete
              </button>
            </div>
            <button className="policyColumnsButton" type="button" aria-label="Columns"><Columns3 size={20} /></button>
          </div>

          <div className="policyCatalogGrid policyCatalogHead">
            <label className="policyCheckCell" aria-label="Select all policies">
              <input type="checkbox" checked={allVisibleSelected} onChange={toggleVisiblePolicySelection} />
            </label>
            <label>
              <span>Policy name</span>
              <input value={filterName} onChange={(event) => setFilterName(event.target.value)} aria-label="Filter by policy name" placeholder="Filter by name..." />
            </label>
            <label>
              <span>Status</span>
              <select value={filterStatus} onChange={(event) => setFilterStatus(event.target.value)} aria-label="Filter by status">
                <option value="">All statuses</option>
                <option value="draft">Draft</option>
                <option value="simulated">Simulated</option>
                <option value="promoted">Promoted</option>
                <option value="active">Active</option>
              </select>
            </label>
            <label>
              <span>Scope</span>
              <select value={filterCompany} onChange={(event) => setFilterCompany(event.target.value)} aria-label="Filter by company">
                <option value="">All scopes</option>
                <option value="global">Global / Partner</option>
                {companyRows.map((row) => (
                  <option key={row.customer.id} value={row.customer.id}>{row.customer.name}</option>
                ))}
              </select>
            </label>
            <span>Last modified</span>
          </div>

          {isLoading ? <LoadingRow label="Loading policies" /> : null}
          {!isLoading && visiblePolicies.length === 0 ? <EmptyState>No policies found for the current filters.</EmptyState> : null}

          <div className="policyCatalogRows">
            {visiblePolicies.map((policy) => {
              const companyId = policy.scope.customer_id ?? "";
              const companyName = companyId ? companyMap.get(companyId)?.customer.name ?? "-" : "-";
              const statusLabel = policy.status === "active" ? "Active" : (policy.status || "Draft");
              const statusClass = policy.status === "active" ? "policy-badge-active" : "policy-badge-draft";

              return (
                <article key={policy.id} className={`policyCatalogGrid policyCatalogRow ${selectedPolicyIds.has(policy.id) ? "selected" : ""}`}>
                  <label className="policyCheckCell" aria-label={`Select ${policy.name}`}>
                    <input type="checkbox" checked={selectedPolicyIds.has(policy.id)} onChange={() => togglePolicySelection(policy.id)} />
                  </label>
                  <div className="policyNameContainer" style={{ display: "flex", alignItems: "center", gap: "8px" }}>
                    <button
                      type="button"
                      className="policyNameLink"
                      onClick={() => openEditPolicy(policy.id)}
                      style={{ fontWeight: 600 }}
                    >
                      {policy.name}
                    </button>
                    <span className="policyVersionLabel" style={{ fontSize: "11px", padding: "1px 5px", background: "var(--line)", borderRadius: "4px", color: "var(--text-muted)", fontWeight: "bold" }}>
                      v{policy.latest_version}
                    </span>
                  </div>
                  <span>
                    <span className={`policyStatusPill ${statusClass}`}>{statusLabel}</span>
                  </span>
                  <span className="policyScopeText" style={{ fontSize: "13px" }}>
                    {companyId ? (
                      <strong className="tenantScopeCompany" style={{ color: "var(--text-primary)", fontWeight: 500 }}>{companyName}</strong>
                    ) : (
                      <span className="tenantScopeGlobal" style={{ color: "var(--text-muted)", fontSize: "12px", fontStyle: "italic" }}>Global / Partner</span>
                    )}
                  </span>
                  <time dateTime={policy.updated_at} style={{ fontSize: "13px", color: "var(--text-muted)" }}>
                    {formatDate(policy.updated_at)}
                  </time>
                </article>
              );
            })}
          </div>

          <footer className="policyCatalogFooter">
            <div className="policyPager">
              <button type="button" disabled>First Page</button>
              <button type="button" disabled aria-label="Previous page">&lt;</button>
              <span>Page</span>
              <input value="1" readOnly aria-label="Current page" />
              <span>of 1</span>
              <button type="button" disabled aria-label="Next page">&gt;</button>
              <button type="button" disabled>Last Page</button>
              <select value="20" onChange={() => undefined} aria-label="Rows per page">
                <option value="20">20</option>
              </select>
            </div>
            <span>{visiblePolicies.length} item{visiblePolicies.length === 1 ? "" : "s"}</span>
          </footer>
        </section>
      </div>

      {/* Assignment sheet — the only non-list UI allowed on this page.
          This is the operational "assign this policy to agents / network / groups / endpoints".
          Policy *definition* changes always go through the dedicated editor so they propagate cleanly. */}
      <SideSheet
        open={assignmentOpen}
        onClose={() => setAssignmentOpen(false)}
        title="Assign policy"
        subtitle="Choose a target scope and preview effective inheritance"
      >
        <div className="policyAssignBody">
          <label>
            Search
            <input
              value={assignment.search}
              onChange={(event) => setAssignment((current) => ({ ...current, search: event.target.value }))}
              placeholder="Search company or endpoint"
            />
          </label>
          <div className="policyAssignTypeSwitch">
            {(["customer", "group", "endpoint"] as const).map((type) => (
              <button
                key={type}
                type="button"
                className={assignment.target === type ? "active" : ""}
                onClick={() => setAssignment((current) => ({ ...current, target: type }))}
              >
                {type}
              </button>
            ))}
          </div>

          {assignment.target === "endpoint" ? (
            <label>
              Endpoint
              <select
                value={assignment.endpointId}
                onChange={(event) => setAssignment((current) => ({ ...current, endpointId: event.target.value }))}
              >
                <option value="">Select endpoint</option>
                {visibleEndpoints.map((endpoint) => (
                  <option key={endpoint.id} value={endpoint.id}>{endpoint.hostname} ({endpoint.id})</option>
                ))}
              </select>
            </label>
          ) : (
            <label>
              Company
              <select
                value={assignment.customerId}
                onChange={(event) => setAssignment((current) => ({ ...current, customerId: event.target.value, groupId: "" }))}
              >
                <option value="">Select company</option>
                {visibleCompanies.map((row) => (
                  <option key={row.customer.id} value={row.customer.id}>{row.customer.name}</option>
                ))}
              </select>
            </label>
          )}

          {assignment.target === "group" ? (
            <label>
              Group
              <select
                value={assignment.groupId}
                onChange={(event) => setAssignment((current) => ({ ...current, groupId: event.target.value }))}
              >
                <option value="">Select group</option>
                {groups.map((group) => (
                  <option key={group.id} value={group.id}>{group.name}</option>
                ))}
              </select>
            </label>
          ) : null}

          {assignment.target !== "endpoint" ? (
            <>
              <label className="toggleRow">
                <input
                  type="checkbox"
                  checked={assignment.quickDeploy}
                  onChange={(event) => setAssignment((current) => ({ ...current, quickDeploy: event.target.checked }))}
                />
                One-click assign and generate installers
              </label>
              {assignment.quickDeploy ? (
                <label>
                  Platforms
                  <select
                    value={assignment.platforms[0]}
                    onChange={(event) => setAssignment((current) => ({ ...current, platforms: [event.target.value as InstallerPlatform] }))}
                  >
                    {PLATFORM_OPTIONS.map((platform) => (
                      <option key={platform} value={platform}>{platform}</option>
                    ))}
                  </select>
                </label>
              ) : null}
            </>
          ) : null}

          <div className="policyAssignPreview" style={{ marginTop: "24px", paddingTop: "16px", borderTop: "1px solid var(--line)" }}>
            <h3 style={{ fontSize: "14px", fontWeight: "bold", marginBottom: "12px", color: "var(--text-primary)" }}>Cascaded Inheritance Topology</h3>
            {!effectivePreview ? (
              <p className="muted" style={{ fontSize: "12px", color: "var(--text-muted)" }}>Select an assignment target above to render the graphical inheritance hierarchy cascade.</p>
            ) : (
              <>
                <div className="inheritanceFlowGraph" style={{ background: "var(--line)", padding: "16px", borderRadius: "8px", marginBottom: "16px" }}>
                  <div className="flowLevelMSP" style={{ background: "white", padding: "10px", borderRadius: "6px", borderLeft: "4px solid var(--primary)", fontSize: "12px", boxShadow: "0 1px 2px var(--shadow)" }}>
                    <div style={{ display: "flex", justifyContent: "space-between", fontWeight: 600 }}>
                      <span>🌐 Level 1: Global Partner Template</span>
                      <span style={{ color: "var(--primary)" }}>Root baseline</span>
                    </div>
                    <p style={{ margin: "2px 0 0 0", fontSize: "11px", color: "var(--text-muted)" }}>Establishes default EDR, GenAI rulesets and security exclusions.</p>
                  </div>

                  <div className="flowConnector" style={{ height: "16px", width: "2px", background: "var(--text-muted)", margin: "0 auto", opacity: 0.3 }} />

                  <div className="flowLevelCustomer" style={{ background: "white", padding: "10px", borderRadius: "6px", borderLeft: "4px solid #6366f1", fontSize: "12px", boxShadow: "0 1px 2px var(--shadow)" }}>
                    <div style={{ display: "flex", justifyContent: "space-between", fontWeight: 600 }}>
                      <span>🏢 Level 2: Customer / Tenant Level</span>
                      <span style={{ color: "#6366f1" }}>Tenant overrides</span>
                    </div>
                    <p style={{ margin: "2px 0 0 0", fontSize: "11px", color: "var(--text-muted)" }}>
                      {assignment.customerId ? `Active Tenant: ${companyMap.get(assignment.customerId)?.customer.name ?? "Custom Overrides"}` : "Inherited from global template"}
                    </p>
                  </div>

                  <div className="flowConnector" style={{ height: "16px", width: "2px", background: "var(--text-muted)", margin: "0 auto", opacity: 0.3 }} />

                  <div className="flowLevelGroup" style={{ background: "white", padding: "10px", borderRadius: "6px", borderLeft: "4px solid #f59e0b", fontSize: "12px", boxShadow: "0 1px 2px var(--shadow)" }}>
                    <div style={{ display: "flex", justifyContent: "space-between", fontWeight: 600 }}>
                      <span>👥 Level 3: Organizational Group</span>
                      <span style={{ color: "#f59e0b" }}>Group overrides</span>
                    </div>
                    <p style={{ margin: "2px 0 0 0", fontSize: "11px", color: "var(--text-muted)" }}>
                      Custom endpoint groupings (e.g. High-Risk production, Servers).
                    </p>
                  </div>

                  <div className="flowConnector" style={{ height: "16px", width: "2px", background: "var(--text-muted)", margin: "0 auto", opacity: 0.3 }} />

                  <div className="flowLevelEndpoint" style={{ background: "white", padding: "10px", borderRadius: "6px", borderLeft: "4px solid var(--danger)", fontSize: "12px", boxShadow: "0 1px 2px var(--shadow)" }}>
                    <div style={{ display: "flex", justifyContent: "space-between", fontWeight: 600 }}>
                      <span>💻 Level 4: Target Enrolled Endpoint</span>
                      <span style={{ color: "var(--danger)" }}>Effective target</span>
                    </div>
                    <p style={{ margin: "2px 0 0 0", fontSize: "11px", color: "var(--text-muted)" }}>
                      {assignment.endpointId ? `Enrolled Host: ${assignment.endpointId}` : "Applies to all devices in scope"}
                    </p>
                  </div>
                </div>

                <div className="resolvedPolicySummary" style={{ display: "flex", flexDirection: "column", gap: "8px" }}>
                  <p style={{ fontSize: "12px", color: "var(--text-muted)", margin: 0 }}>
                    <strong>Resolved Policy Modules ({Object.keys(effectivePreview.resolved_policy.modules).length}):</strong>
                  </p>
                  <div className="policyPreviewModules" style={{ display: "flex", flexWrap: "wrap", gap: "6px" }}>
                    {Object.entries(effectivePreview.resolved_policy.modules).map(([key, value]) => (
                      <span key={key} className={value.enabled ? "badge" : "badge band-medium"} style={{ fontSize: "11px", padding: "2px 6px", borderRadius: "4px", background: value.enabled ? "rgba(16, 185, 129, 0.1)" : "rgba(100, 116, 139, 0.1)", color: value.enabled ? "var(--primary)" : "var(--text-muted)", fontWeight: "bold" }}>
                        {key} {value.enabled ? "✓" : "✗"}
                      </span>
                    ))}
                  </div>
                </div>
              </>
            )}
          </div>

          <div className="policyAssignActions">
            <button className="btnGhost" type="button" onClick={() => setAssignmentOpen(false)}>Cancel</button>
            <button className="btnPrimary" type="button" disabled={isWorking || !primarySelectedId} onClick={() => void assignPolicy()}>
              Assign policy
            </button>
          </div>
        </div>
      </SideSheet>
    </>
  );
}

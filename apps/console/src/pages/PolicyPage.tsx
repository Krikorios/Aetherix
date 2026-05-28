import { useEffect, useMemo, useRef, useState } from "react";
import { Plus, RefreshCw, ShieldCheck } from "lucide-react";
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
  type PolicySimulationRecord,
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
  const [promotionOpen, setPromotionOpen] = useState(false);
  const [promotionApproved, setPromotionApproved] = useState(false);
  const [promotionReason, setPromotionReason] = useState("");
  const [lastSimulation, setLastSimulation] = useState<{ policyId: string; simulationId: string } | null>(null);
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
    const pendingSelection = window.sessionStorage.getItem("aetherix.pending_policy_selection");
    if (pendingSelection && page.items.some((policy) => policy.id === pendingSelection)) {
      window.sessionStorage.removeItem("aetherix.pending_policy_selection");
      setSelectedPolicyIds(new Set([pendingSelection]));
    }
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

  async function simulateSelectedPolicy() {
    const policyId = primarySelectedId;
    if (!policyId) {
      setError("Select exactly one policy to simulate");
      return;
    }
    setError(null);
    setSuccess(null);
    setIsWorking(true);
    try {
      const simulation = await apiPost<PolicySimulationRecord>(`/policies/${policyId}/simulate`, {});
      setLastSimulation({ policyId, simulationId: simulation.id });
      setSuccess(`Simulation complete: ${simulation.summary.modules_with_destructive_actions} module(s) trigger approval gates.`);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Policy simulation failed");
    } finally {
      setIsWorking(false);
    }
  }

  function openPromotionForSelected() {
    if (!primarySelectedId) {
      setError("Select exactly one policy to promote");
      return;
    }
    if (!lastSimulation || lastSimulation.policyId !== primarySelectedId) {
      setError("Run simulation before promoting this policy");
      return;
    }
    setPromotionApproved(false);
    setPromotionReason("");
    setPromotionOpen(true);
  }

  async function promoteSelectedPolicy() {
    const policyId = primarySelectedId;
    if (!policyId || !lastSimulation || lastSimulation.policyId !== policyId) return;
    setError(null);
    setSuccess(null);
    setIsWorking(true);
    try {
      await apiPost(`/policies/${policyId}/promote`, {
        simulation_id: lastSimulation.simulationId,
        operator_approved: promotionApproved,
        approval_reason: promotionReason,
      });
      setPromotionOpen(false);
      setSuccess("Policy promoted successfully.");
      await loadPolicies();
    } catch (err) {
      setError(err instanceof Error ? err.message : "Policy promotion failed");
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
      <div className="policyCatalogPage" aria-hidden={assignmentOpen || promotionOpen ? true : undefined}>
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
                onClick={() => void simulateSelectedPolicy()}
              >
                Simulate selected
              </button>
              <button
                className="policyToolbarButton"
                type="button"
                disabled={selectedCount !== 1 || !lastSimulation || lastSimulation.policyId !== primarySelectedId}
                onClick={openPromotionForSelected}
              >
                Promote selected
              </button>
              <button
                className="policyToolbarButton"
                type="button"
                disabled={selectedCount !== 1}
                onClick={openAssignmentForSelected}
              >
                Assign selected
              </button>
              <button className="policyToolbarButton" type="button" disabled title="Policy cloning is not available yet">
                Clone
              </button>
              <button className="policyToolbarButton danger" type="button" disabled title="Policy deletion is not available yet">
                Delete
              </button>
            </div>
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
                  <div className="policyNameRow">
                    <button
                      type="button"
                      className="policyNameLink policyNameButton"
                      onClick={() => togglePolicySelection(policy.id)}
                    >
                      {policy.name}
                    </button>
                    <span className="policyVersionLabel">v{policy.latest_version}</span>
                  </div>
                  <span>
                    <span className={`policyStatusPill ${statusClass}`}>{statusLabel}</span>
                  </span>
                  <span className="policyScopeText">
                    {companyId ? (
                      <strong className="tenantScopeCompany">{companyName}</strong>
                    ) : (
                      <span className="tenantScopeGlobal">Global / Partner</span>
                    )}
                  </span>
                  <time dateTime={policy.updated_at} className="policyUpdatedTime">
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

          <div className="policyAssignPreview">
            <h3 className="previewTitle">Cascaded Inheritance Topology</h3>
            {!effectivePreview ? (
              <p className="muted previewHint">Select an assignment target above to render the graphical inheritance hierarchy cascade.</p>
            ) : (
              <>
                <div className="inheritanceFlowGraph">
                  <div className="flowLevel flowLevel-msp">
                    <div className="flowLevelHead">
                      <span>🌐 Level 1: Global Partner Template</span>
                      <span className="root">Root baseline</span>
                    </div>
                    <p className="flowLevelDesc">Establishes default EDR, GenAI rulesets and security exclusions.</p>
                  </div>

                  <div className="flowConnector" />

                  <div className="flowLevel flowLevel-customer">
                    <div className="flowLevelHead">
                      <span>🏢 Level 2: Customer / Tenant Level</span>
                      <span className="tenant">Tenant overrides</span>
                    </div>
                    <p className="flowLevelDesc">
                      {assignment.customerId ? `Active Tenant: ${companyMap.get(assignment.customerId)?.customer.name ?? "Custom Overrides"}` : "Inherited from global template"}
                    </p>
                  </div>

                  <div className="flowConnector" />

                  <div className="flowLevel flowLevel-group">
                    <div className="flowLevelHead">
                      <span>👥 Level 3: Organizational Group</span>
                      <span className="group">Group overrides</span>
                    </div>
                    <p className="flowLevelDesc">
                      Custom endpoint groupings (e.g. High-Risk production, Servers).
                    </p>
                  </div>

                  <div className="flowConnector" />

                  <div className="flowLevel flowLevel-endpoint">
                    <div className="flowLevelHead">
                      <span>💻 Level 4: Target Enrolled Endpoint</span>
                      <span className="endpoint">Effective target</span>
                    </div>
                    <p className="flowLevelDesc">
                      {assignment.endpointId ? `Enrolled Host: ${assignment.endpointId}` : "Applies to all devices in scope"}
                    </p>
                  </div>
                </div>

                <div className="resolvedPolicySummary">
                  <p className="resolvedCount">
                    <strong>Resolved Policy Modules ({Object.keys(effectivePreview.resolved_policy.modules).length}):</strong>
                  </p>
                  <div className="policyPreviewModules">
                    {Object.entries(effectivePreview.resolved_policy.modules).map(([key, value]) => (
                      <span key={key} className={`policyModuleChip ${value.enabled ? "enabled" : "disabled"}`}>
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

      {promotionOpen ? (
        <div className="modalOverlay" role="presentation">
          <section className="modalContent" role="dialog" aria-modal="true" aria-label="Production Promotion gate">
            <h2>Production Promotion gate</h2>
            <p className="modalMessage">
              Confirm that simulation results have been reviewed before promoting this policy to active enforcement.
            </p>
            <label className="toggleRow">
              <input
                type="checkbox"
                checked={promotionApproved}
                onChange={(event) => setPromotionApproved(event.target.checked)}
              />
              I approve this policy promotion
            </label>
            <label>
              Approval reason
              <textarea
                value={promotionReason}
                onChange={(event) => setPromotionReason(event.target.value)}
                placeholder="Document the promotion reason"
              />
            </label>
            <div className="modalActions">
              <button className="btnGhost" type="button" onClick={() => setPromotionOpen(false)} disabled={isWorking}>
                Cancel
              </button>
              <button className="btnPrimary" type="button" onClick={() => void promoteSelectedPolicy()} disabled={isWorking || !promotionApproved}>
                Confirm & Promote
              </button>
            </div>
          </section>
        </div>
      ) : null}
    </>
  );
}

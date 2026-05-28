import { useEffect, useMemo, useState } from "react";
import {
  Building2,
  CheckCircle,
  ChevronDown,
  ChevronRight,
  Laptop,
  Loader2,
  Radio,
  RefreshCw,
  Search,
  Shield,
  Siren,
  Tag,
  Trash2,
} from "lucide-react";
import { apiGet, apiPost } from "../api";
import type { Customer, MeResponse } from "../api";
import { ErrorBanner, LoadingRow, SuccessBanner } from "../components";

type EndpointStatus = "healthy" | "attention" | "offline" | "drifted";

type NetworkEndpoint = {
  id: string;
  customer_id?: string | null;
  endpoint_name: string;
  hostname: string;
  os: string;
  agent_version: string;
  latest_agent_version: string;
  policy_version: string;
  active_policy_version: string;
  status: EndpointStatus;
  last_heartbeat: string;
  risk_score: number;
  open_alerts: number;
  pending_actions: number;
  tags: string[];
};

type EndpointAction = {
  value: string;
  label: string;
};

const ACTIONS: EndpointAction[] = [
  { value: "assign_policy", label: "Assign policy" },
  { value: "update_agent", label: "Update agent" },
  { value: "malware_scan", label: "Malware scan" },
  { value: "risk_scan", label: "Risk scan" },
  { value: "isolate_endpoint", label: "Isolate endpoint" },
];

function statusLabel(status: EndpointStatus) {
  if (status === "drifted") return "Policy drift";
  if (status === "attention") return "Needs attention";
  if (status === "offline") return "Offline";
  return "Managed";
}

function statusClass(status: EndpointStatus) {
  if (status === "healthy") return "ok";
  if (status === "offline") return "bad";
  return "warn";
}

function timeLabel(value: string) {
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return "-";
  const seconds = Math.max(0, Math.floor((Date.now() - date.getTime()) / 1000));
  if (seconds < 60) return "Now";
  if (seconds < 3600) return `${Math.floor(seconds / 60)}m ago`;
  if (seconds < 86400) return `${Math.floor(seconds / 3600)}h ago`;
  return date.toLocaleDateString();
}

function companyCountLabel(count: number) {
  return `${count} endpoint${count === 1 ? "" : "s"}`;
}

export function NetworkPage({ me }: { me: MeResponse }) {
  const [customers, setCustomers] = useState<Customer[]>([]);
  const [endpoints, setEndpoints] = useState<NetworkEndpoint[]>([]);
  const [expanded, setExpanded] = useState<Set<string>>(new Set());
  const [selectedCustomerId, setSelectedCustomerId] = useState<string | null>(null);
  const [selectedEndpointIds, setSelectedEndpointIds] = useState<Set<string>>(new Set());
  const [query, setQuery] = useState("");
  const [activeAction, setActiveAction] = useState(ACTIONS[0].value);
  const [isLoading, setIsLoading] = useState(true);
  const [isWorking, setIsWorking] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [success, setSuccess] = useState<string | null>(null);

  async function load() {
    setIsLoading(true);
    setError(null);
    try {
      const [nextCustomers, nextEndpoints] = await Promise.all([
        apiGet<Customer[]>("/customers"),
        apiGet<NetworkEndpoint[]>("/endpoints/health"),
      ]);
      setCustomers(nextCustomers);
      setEndpoints(nextEndpoints);
      const customerIds = nextCustomers.map((customer) => customer.id);
      setExpanded(new Set(customerIds));
      setSelectedCustomerId((current) => current ?? customerIds[0] ?? null);
      if (nextEndpoints.length > 0) setSelectedEndpointIds(new Set([nextEndpoints[0].id]));
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to load network inventory.");
    } finally {
      setIsLoading(false);
    }
  }

  useEffect(() => {
    void load();
  }, []);

  const customerById = useMemo(() => {
    return new Map(customers.map((customer) => [customer.id, customer]));
  }, [customers]);

  const visibleCustomers = useMemo(() => {
    const allowed = new Set(me.scope.customer_ids);
    return customers.filter((customer) => allowed.size === 0 || allowed.has(customer.id));
  }, [customers, me.scope.customer_ids]);

  const endpointsByCustomer = useMemo(() => {
    const grouped = new Map<string, NetworkEndpoint[]>();
    for (const endpoint of endpoints) {
      const key = endpoint.customer_id ?? "unassigned";
      if (!grouped.has(key)) grouped.set(key, []);
      grouped.get(key)!.push(endpoint);
    }
    return grouped;
  }, [endpoints]);

  const selectedRows = useMemo(() => {
    const text = query.trim().toLowerCase();
    const rows = endpoints.filter((endpoint) => {
      const matchesCustomer = selectedCustomerId === null || endpoint.customer_id === selectedCustomerId;
      if (!matchesCustomer) return false;
      if (!text) return true;
      const customerName = endpoint.customer_id ? customerById.get(endpoint.customer_id)?.name ?? "" : "";
      return [endpoint.hostname, endpoint.os, endpoint.agent_version, endpoint.policy_version, customerName]
        .some((value) => value.toLowerCase().includes(text));
    });
    return rows.sort((left, right) => left.hostname.localeCompare(right.hostname));
  }, [customerById, endpoints, query, selectedCustomerId]);

  const activeCustomer = selectedCustomerId ? customerById.get(selectedCustomerId) : null;
  const selectedEndpoints = endpoints.filter((endpoint) => selectedEndpointIds.has(endpoint.id));
  const selectedCount = selectedEndpointIds.size;
  const allVisibleSelected = selectedRows.length > 0 && selectedRows.every((endpoint) => selectedEndpointIds.has(endpoint.id));

  function toggleCustomer(customerId: string) {
    setExpanded((current) => {
      const next = new Set(current);
      if (next.has(customerId)) next.delete(customerId);
      else next.add(customerId);
      return next;
    });
  }

  function selectCustomer(customerId: string) {
    setSelectedCustomerId(customerId);
    const firstEndpoint = endpointsByCustomer.get(customerId)?.[0];
    setSelectedEndpointIds(firstEndpoint ? new Set([firstEndpoint.id]) : new Set());
  }

  function toggleEndpoint(endpointId: string) {
    setSelectedEndpointIds((current) => {
      const next = new Set(current);
      if (next.has(endpointId)) next.delete(endpointId);
      else next.add(endpointId);
      return next;
    });
  }

  function toggleAllVisible() {
    if (allVisibleSelected) {
      setSelectedEndpointIds(new Set());
      return;
    }
    setSelectedEndpointIds(new Set(selectedRows.map((endpoint) => endpoint.id)));
  }

  async function runAction() {
    if (selectedEndpoints.length === 0) return;
    setIsWorking(true);
    setError(null);
    setSuccess(null);
    try {
      await Promise.all(
        selectedEndpoints.map(async (endpoint) => {
          await apiPost(`/endpoints/${endpoint.id}/simulate-remediation`, { action: activeAction });
          await apiPost(`/endpoints/${endpoint.id}/remediate`, { action: activeAction });
        }),
      );
      setEndpoints((current) =>
        current.map((endpoint) =>
          selectedEndpointIds.has(endpoint.id)
            ? { ...endpoint, pending_actions: endpoint.pending_actions + 1 }
            : endpoint,
        ),
      );
      const label = ACTIONS.find((action) => action.value === activeAction)?.label ?? "Action";
      setSuccess(`${label} queued for ${selectedEndpoints.length} endpoint${selectedEndpoints.length === 1 ? "" : "s"}.`);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to queue endpoint action.");
    } finally {
      setIsWorking(false);
    }
  }

  if (isLoading) {
    return (
      <main className="networkPage">
        <LoadingRow label="Loading network inventory" />
      </main>
    );
  }

  return (
    <main className="networkPage">
      <header className="networkHeader">
        <div>
          <h1>Network</h1>
          <p>{endpoints.length} managed endpoint{endpoints.length === 1 ? "" : "s"} enrolled through customer installation packages.</p>
        </div>
        <button type="button" className="installIconButton" onClick={() => void load()} aria-label="Refresh network inventory">
          <RefreshCw size={15} />
        </button>
      </header>

      {error ? <ErrorBanner message={error} /> : null}
      {success ? <SuccessBanner message={success} /> : null}

      <section className="networkShell" aria-label="Network inventory">
        <aside className="networkTreePanel" aria-label="Company tree">
          <div className="networkTreeToolbar">
            <span>Tree view</span>
            <Shield size={15} />
          </div>
          <label className="networkSearch">
            <Search size={14} />
            <input value={query} onChange={(event) => setQuery(event.target.value)} placeholder="Search in tree view" />
          </label>
          <div className="networkTreeRoot">
            <div className="networkTreeRootItem">
              <Building2 size={15} />
              <span>{me.branding.product_name}</span>
            </div>
            {visibleCustomers.map((customer) => {
              const companyEndpoints = endpointsByCustomer.get(customer.id) ?? [];
              const isExpanded = expanded.has(customer.id);
              const isSelected = customer.id === selectedCustomerId;
              return (
                <div key={customer.id} className="networkTreeGroup">
                  <button
                    type="button"
                    className={`networkTreeCustomer${isSelected ? " selected" : ""}`}
                    onClick={() => selectCustomer(customer.id)}
                  >
                    <span
                      className="networkTreeTwisty"
                      onClick={(event) => {
                        event.stopPropagation();
                        toggleCustomer(customer.id);
                      }}
                    >
                      {isExpanded ? <ChevronDown size={14} /> : <ChevronRight size={14} />}
                    </span>
                    <Building2 size={14} />
                    <span>{customer.name}</span>
                    <small>{companyCountLabel(companyEndpoints.length)}</small>
                  </button>
                  {isExpanded ? (
                    <div className="networkTreeChildren">
                      {companyEndpoints.length === 0 ? (
                        <span className="networkTreeEmpty">No endpoints yet</span>
                      ) : (
                        companyEndpoints.map((endpoint) => (
                          <button
                            key={endpoint.id}
                            type="button"
                            className={`networkTreeEndpoint${selectedEndpointIds.has(endpoint.id) ? " selected" : ""}`}
                            onClick={() => {
                              setSelectedCustomerId(customer.id);
                              setSelectedEndpointIds(new Set([endpoint.id]));
                            }}
                          >
                            <Laptop size={14} />
                            <span>{endpoint.hostname}</span>
                          </button>
                        ))
                      )}
                    </div>
                  ) : null}
                </div>
              );
            })}
          </div>
        </aside>

        <section className="networkMainPanel">
          <div className="networkActionBar">
            <div>
              <strong>{activeCustomer?.name ?? "All companies"}</strong>
              <span>{selectedRows.length} visible endpoint{selectedRows.length === 1 ? "" : "s"}</span>
            </div>
            <div className="networkActionControls">
              <select value={activeAction} onChange={(event) => setActiveAction(event.target.value)} aria-label="Endpoint action">
                {ACTIONS.map((action) => (
                  <option key={action.value} value={action.value}>{action.label}</option>
                ))}
              </select>
              <button type="button" className="installPrimary" onClick={() => void runAction()} disabled={selectedCount === 0 || isWorking}>
                {isWorking ? <Loader2 size={14} className="spinIcon" /> : <Radio size={14} />}
                Run action
              </button>
            </div>
          </div>

          <div className="dataTableWrap compact">
            <table className="dataTable networkTable">
              <thead>
                <tr>
                  <th className="checkboxCell"><input type="checkbox" checked={allVisibleSelected} onChange={toggleAllVisible} aria-label="Select all visible endpoints" /></th>
                  <th>Name</th>
                  <th>Company</th>
                  <th>OS</th>
                  <th>Management status</th>
                  <th>Security issues</th>
                  <th>Policy</th>
                  <th>Last seen</th>
                  <th>Queued</th>
                </tr>
              </thead>
              <tbody>
                {selectedRows.length === 0 ? (
                  <tr>
                    <td colSpan={9} className="networkEmptyCell">No endpoints match this view.</td>
                  </tr>
                ) : (
                  selectedRows.map((endpoint) => (
                    <tr key={endpoint.id} className={selectedEndpointIds.has(endpoint.id) ? "selected" : ""} onClick={() => toggleEndpoint(endpoint.id)}>
                      <td className="checkboxCell">
                        <input
                          type="checkbox"
                          checked={selectedEndpointIds.has(endpoint.id)}
                          onChange={() => toggleEndpoint(endpoint.id)}
                          onClick={(event) => event.stopPropagation()}
                          aria-label={`Select ${endpoint.hostname}`}
                        />
                      </td>
                      <td><span className="networkNameCell"><Laptop size={14} />{endpoint.hostname}</span></td>
                      <td>{endpoint.customer_id ? customerById.get(endpoint.customer_id)?.name ?? "Unknown" : "Unassigned"}</td>
                      <td>{endpoint.os}</td>
                      <td><span className={`statusPill ${statusClass(endpoint.status)}`}>{statusLabel(endpoint.status)}</span></td>
                      <td>{endpoint.open_alerts > 0 ? <span className="networkIssue"><Siren size={13} />{endpoint.open_alerts} open</span> : "Without issues"}</td>
                      <td>{endpoint.policy_version === endpoint.active_policy_version ? <CheckCircle size={14} /> : <Tag size={14} />} {endpoint.policy_version}</td>
                      <td>{timeLabel(endpoint.last_heartbeat)}</td>
                      <td>{endpoint.pending_actions}</td>
                    </tr>
                  ))
                )}
              </tbody>
            </table>
          </div>
          <div className="networkFooter">
            <span>{selectedCount} selected</span>
            <button type="button" className="installTextButton" disabled={selectedCount === 0} onClick={() => setSelectedEndpointIds(new Set())}>Clear selection</button>
            <button type="button" className="installTextButton danger" disabled title="Endpoint retirement is not available yet"><Trash2 size={14} /> Retire endpoint</button>
          </div>
        </section>
      </section>
    </main>
  );
}

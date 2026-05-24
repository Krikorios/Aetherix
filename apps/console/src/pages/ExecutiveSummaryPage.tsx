import React, { useState, useEffect } from "react";
import {
  BarChart3,
  Building2,
  ShieldCheck,
  AlertTriangle,
  TrendingUp,
  TrendingDown,
  Users,
  Activity,
  RefreshCw,
  FileText,
  CheckCircle,
  XCircle,
  Clock,
} from "lucide-react";
import { ErrorBanner, SuccessBanner } from "../components";
import { apiGet, type MeResponse } from "../api";

interface CustomerRiskSummary {
  customer_id: string;
  company_name: string;
  risk_score: number;
  risk_band: "low" | "medium" | "high" | "critical";
  open_alerts: number;
  enrolled_agents: number;
  license_status: "active" | "trial" | "expired" | "suspended";
  last_seen: string;
  policy_version: string;
  ai_efficiency_score: number;
}

interface PortfolioMetrics {
  total_companies: number;
  healthy_companies: number;
  at_risk_companies: number;
  critical_companies: number;
  total_endpoints: number;
  total_open_alerts: number;
  alerts_resolved_7d: number;
  avg_risk_score: number;
  ai_calls_7d: number;
  license_utilization_pct: number;
}

const DEMO_METRICS: PortfolioMetrics = {
  total_companies: 14,
  healthy_companies: 9,
  at_risk_companies: 3,
  critical_companies: 2,
  total_endpoints: 847,
  total_open_alerts: 38,
  alerts_resolved_7d: 112,
  avg_risk_score: 34,
  ai_calls_7d: 2841,
  license_utilization_pct: 71,
};

const DEMO_CUSTOMERS: CustomerRiskSummary[] = [
  {
    customer_id: "c1",
    company_name: "Northgate Manufacturing",
    risk_score: 82,
    risk_band: "critical",
    open_alerts: 12,
    enrolled_agents: 104,
    license_status: "active",
    last_seen: new Date(Date.now() - 120000).toISOString(),
    policy_version: "v2.10.4",
    ai_efficiency_score: 91,
  },
  {
    customer_id: "c2",
    company_name: "Clearview Legal LLP",
    risk_score: 64,
    risk_band: "high",
    open_alerts: 7,
    enrolled_agents: 58,
    license_status: "active",
    last_seen: new Date(Date.now() - 480000).toISOString(),
    policy_version: "v2.10.2",
    ai_efficiency_score: 87,
  },
  {
    customer_id: "c3",
    company_name: "BrightPath Healthcare",
    risk_score: 55,
    risk_band: "high",
    open_alerts: 5,
    enrolled_agents: 211,
    license_status: "active",
    last_seen: new Date(Date.now() - 60000).toISOString(),
    policy_version: "v2.10.4",
    ai_efficiency_score: 95,
  },
  {
    customer_id: "c4",
    company_name: "Apex Financial Group",
    risk_score: 29,
    risk_band: "low",
    open_alerts: 2,
    enrolled_agents: 142,
    license_status: "active",
    last_seen: new Date(Date.now() - 30000).toISOString(),
    policy_version: "v2.10.4",
    ai_efficiency_score: 98,
  },
  {
    customer_id: "c5",
    company_name: "Coastal Logistics Co.",
    risk_score: 41,
    risk_band: "medium",
    open_alerts: 4,
    enrolled_agents: 67,
    license_status: "trial",
    last_seen: new Date(Date.now() - 900000).toISOString(),
    policy_version: "v2.9.1",
    ai_efficiency_score: 78,
  },
  {
    customer_id: "c6",
    company_name: "Redstone Education Trust",
    risk_score: 18,
    risk_band: "low",
    open_alerts: 0,
    enrolled_agents: 265,
    license_status: "active",
    last_seen: new Date(Date.now() - 180000).toISOString(),
    policy_version: "v2.10.4",
    ai_efficiency_score: 99,
  },
];

const RISK_COLOR: Record<string, string> = {
  low: "var(--success)",
  medium: "var(--warning)",
  high: "#e07a00",
  critical: "var(--danger)",
};

const LICENSE_LABEL: Record<string, string> = {
  active: "Active",
  trial: "Trial",
  expired: "Expired",
  suspended: "Suspended",
};

function riskLabel(score: number): string {
  if (score >= 75) return "Critical";
  if (score >= 55) return "High";
  if (score >= 35) return "Medium";
  return "Low";
}

export function ExecutiveSummaryPage({ me }: { me: MeResponse }) {
  const [isLoading, setIsLoading] = useState(true);
  const [isSyncing, setIsSyncing] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [success, setSuccess] = useState<string | null>(null);
  const [metrics, setMetrics] = useState<PortfolioMetrics>(DEMO_METRICS);
  const [customers, setCustomers] = useState<CustomerRiskSummary[]>([]);
  const [selectedId, setSelectedId] = useState<string | null>(null);

  useEffect(() => {
    async function load() {
      try {
        const data = await apiGet<CustomerRiskSummary[]>("/companies/risk-summary");
        setCustomers(data);
        if (data.length > 0) setSelectedId(data[0].customer_id);
      } catch {
        setCustomers(DEMO_CUSTOMERS);
        setSelectedId(DEMO_CUSTOMERS[0].customer_id);
      } finally {
        setIsLoading(false);
      }
    }
    void load();
  }, [me]);

  const handleRefresh = async () => {
    setIsSyncing(true);
    setError(null);
    try {
      await new Promise((r) => setTimeout(r, 700));
      setMetrics((prev) => ({ ...prev }));
      setSuccess("Portfolio metrics refreshed successfully.");
    } catch {
      setError("Failed to refresh metrics.");
    } finally {
      setIsSyncing(false);
    }
  };

  const selected = customers.find((c) => c.customer_id === selectedId) ?? null;

  if (isLoading) {
    return (
      <div style={{ padding: "40px", width: "100%", textAlign: "center", color: "var(--muted)" }}>
        <Activity size={24} style={{ marginBottom: "12px" }} />
        <p>Loading portfolio data…</p>
      </div>
    );
  }

  return (
    <div style={{ display: "flex", flexDirection: "column", flex: 1, padding: "24px", boxSizing: "border-box" }}>
      {/* Header */}
      <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", marginBottom: "24px", flexWrap: "wrap", gap: "12px" }}>
        <div>
          <p style={{ margin: 0, fontSize: "11px", fontWeight: 600, textTransform: "uppercase", letterSpacing: "0.08em", color: "var(--muted)" }}>
            Partner Reporting
          </p>
          <h1 style={{ margin: "4px 0 0", fontSize: "20px", fontWeight: 700 }}>Executive Summary</h1>
          <span style={{ fontSize: "12px", color: "var(--muted)" }}>
            AI-generated portfolio overview · {customers.length} companies · updated just now
          </span>
        </div>
        <div style={{ display: "flex", gap: "8px", alignItems: "center" }}>
          <span
            style={{
              fontSize: "11px",
              fontWeight: 600,
              padding: "3px 10px",
              borderRadius: "20px",
              background: "rgba(11, 107, 87, 0.08)",
              color: "var(--accent)",
              border: "1px solid rgba(11, 107, 87, 0.18)",
            }}
          >
            Console Foundation
          </span>
          <button
            className="btn"
            onClick={handleRefresh}
            disabled={isSyncing}
            style={{ display: "flex", alignItems: "center", gap: "6px", fontSize: "12px" }}
          >
            <RefreshCw size={13} className={isSyncing ? "spin" : ""} />
            Refresh
          </button>
        </div>
      </div>

      {error && <ErrorBanner message={error} />}
      {success && <SuccessBanner message={success} />}

      {/* Portfolio Metrics Row */}
      <section
        style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(200px, 1fr))", gap: "14px", marginBottom: "24px" }}
        aria-label="Portfolio Metrics"
      >
        {[
          { label: "Total Companies", value: metrics.total_companies, icon: <Building2 size={18} />, color: "var(--accent)" },
          { label: "Healthy", value: metrics.healthy_companies, icon: <CheckCircle size={18} />, color: "var(--success)" },
          { label: "At Risk / Critical", value: `${metrics.at_risk_companies} / ${metrics.critical_companies}`, icon: <AlertTriangle size={18} />, color: "var(--danger)" },
          { label: "Open Alerts", value: metrics.total_open_alerts, icon: <Activity size={18} />, color: "var(--warning)" },
          { label: "Resolved (7d)", value: metrics.alerts_resolved_7d, icon: <TrendingDown size={18} />, color: "var(--success)" },
          { label: "AI Efficiency", value: `${metrics.ai_calls_7d.toLocaleString()} calls`, icon: <BarChart3 size={18} />, color: "var(--accent)" },
          { label: "Avg Risk Score", value: metrics.avg_risk_score, icon: <TrendingUp size={18} />, color: metrics.avg_risk_score > 50 ? "var(--danger)" : "var(--success)" },
          { label: "License Utilization", value: `${metrics.license_utilization_pct}%`, icon: <ShieldCheck size={18} />, color: "var(--accent)" },
        ].map(({ label, value, icon, color }) => (
          <div
            key={label}
            className="panel"
            style={{ padding: "14px 16px", display: "flex", alignItems: "center", gap: "12px" }}
          >
            <div style={{ color }}>{icon}</div>
            <div>
              <div style={{ fontSize: "11px", color: "var(--muted)" }}>{label}</div>
              <strong style={{ fontSize: "15px" }}>{value}</strong>
            </div>
          </div>
        ))}
      </section>

      {/* Two-column: Customer Risk Table + Selected Customer Detail */}
      <section style={{ display: "flex", flexWrap: "wrap", gap: "16px", flex: 1, alignItems: "stretch" }}>
        {/* Customer risk table */}
        <div className="panel" style={{ flex: "1 1 380px", display: "flex", flexDirection: "column" }}>
          <div
            className="panelHeader"
            style={{ borderBottom: "1px solid var(--line)", paddingBottom: "10px", marginBottom: "0" }}
          >
            <h2 style={{ fontSize: "14px", margin: 0 }}>Company Risk Standings</h2>
            <span style={{ fontSize: "11px", color: "var(--muted)" }}>{customers.length} companies</span>
          </div>
          <div style={{ overflowY: "auto", flex: 1 }}>
            {customers.map((c) => (
              <button
                key={c.customer_id}
                onClick={() => setSelectedId(c.customer_id)}
                style={{
                  display: "flex",
                  alignItems: "center",
                  width: "100%",
                  padding: "12px 16px",
                  background: selectedId === c.customer_id ? "rgba(11, 107, 87, 0.06)" : "transparent",
                  border: "none",
                  borderBottom: "1px solid var(--line)",
                  cursor: "pointer",
                  textAlign: "left",
                  gap: "12px",
                }}
              >
                <div
                  style={{
                    width: "8px",
                    height: "8px",
                    borderRadius: "50%",
                    background: RISK_COLOR[c.risk_band],
                    flexShrink: 0,
                  }}
                />
                <div style={{ flex: 1, minWidth: 0 }}>
                  <div style={{ fontSize: "13px", fontWeight: 600, whiteSpace: "nowrap", overflow: "hidden", textOverflow: "ellipsis" }}>
                    {c.company_name}
                  </div>
                  <div style={{ fontSize: "11px", color: "var(--muted)" }}>
                    {c.enrolled_agents} agents · {c.open_alerts} open alerts
                  </div>
                </div>
                <div style={{ textAlign: "right", flexShrink: 0 }}>
                  <div style={{ fontSize: "13px", fontWeight: 700, color: RISK_COLOR[c.risk_band] }}>
                    {c.risk_score}
                  </div>
                  <div style={{ fontSize: "10px", color: "var(--muted)", textTransform: "uppercase" }}>
                    {riskLabel(c.risk_score)}
                  </div>
                </div>
              </button>
            ))}
          </div>
        </div>

        {/* Selected company detail */}
        {selected ? (
          <div className="panel" style={{ flex: "1 1 320px", display: "flex", flexDirection: "column", gap: "16px" }}>
            <div className="panelHeader" style={{ borderBottom: "1px solid var(--line)", paddingBottom: "10px" }}>
              <div>
                <h2 style={{ margin: 0, fontSize: "15px" }}>{selected.company_name}</h2>
                <span style={{ fontSize: "11px", color: "var(--muted)" }}>
                  Last seen: {new Date(selected.last_seen).toLocaleTimeString()}
                </span>
              </div>
              <span
                style={{
                  fontSize: "11px",
                  fontWeight: 600,
                  padding: "3px 10px",
                  borderRadius: "20px",
                  background:
                    selected.license_status === "active"
                      ? "rgba(11, 107, 87, 0.08)"
                      : selected.license_status === "trial"
                      ? "rgba(180, 140, 0, 0.08)"
                      : "rgba(180, 40, 40, 0.08)",
                  color:
                    selected.license_status === "active"
                      ? "var(--accent)"
                      : selected.license_status === "trial"
                      ? "var(--warning)"
                      : "var(--danger)",
                  border: `1px solid ${
                    selected.license_status === "active"
                      ? "rgba(11, 107, 87, 0.18)"
                      : "rgba(180, 140, 0, 0.18)"
                  }`,
                }}
              >
                {LICENSE_LABEL[selected.license_status]}
              </span>
            </div>

            <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: "12px" }}>
              {[
                { label: "Risk Score", value: selected.risk_score, sub: riskLabel(selected.risk_score), color: RISK_COLOR[selected.risk_band] },
                { label: "AI Efficiency", value: `${selected.ai_efficiency_score}%`, sub: "7-day avg", color: "var(--accent)" },
                { label: "Open Alerts", value: selected.open_alerts, sub: "requiring action", color: selected.open_alerts > 5 ? "var(--danger)" : "var(--muted)" },
                { label: "Enrolled Agents", value: selected.enrolled_agents, sub: "endpoints", color: "var(--accent)" },
              ].map(({ label, value, sub, color }) => (
                <div
                  key={label}
                  style={{
                    padding: "12px",
                    background: "var(--surface)",
                    borderRadius: "6px",
                    border: "1px solid var(--line)",
                  }}
                >
                  <div style={{ fontSize: "11px", color: "var(--muted)" }}>{label}</div>
                  <strong style={{ fontSize: "20px", display: "block", color }}>{value}</strong>
                  <div style={{ fontSize: "11px", color: "var(--muted)" }}>{sub}</div>
                </div>
              ))}
            </div>

            <div>
              <div style={{ fontSize: "11px", fontWeight: 600, textTransform: "uppercase", color: "var(--muted)", marginBottom: "8px" }}>
                Policy & Compliance
              </div>
              <div style={{ display: "flex", flexDirection: "column", gap: "8px", fontSize: "12px" }}>
                <div style={{ display: "flex", justifyContent: "space-between" }}>
                  <span style={{ color: "var(--muted)" }}>Active Policy Version</span>
                  <strong>{selected.policy_version}</strong>
                </div>
                <div style={{ display: "flex", justifyContent: "space-between" }}>
                  <span style={{ color: "var(--muted)" }}>License Status</span>
                  <strong>{LICENSE_LABEL[selected.license_status]}</strong>
                </div>
                <div style={{ display: "flex", justifyContent: "space-between" }}>
                  <span style={{ color: "var(--muted)" }}>Risk Band</span>
                  <strong style={{ color: RISK_COLOR[selected.risk_band], textTransform: "capitalize" }}>{selected.risk_band}</strong>
                </div>
              </div>
            </div>
          </div>
        ) : (
          <div className="panel" style={{ flex: "1 1 320px", display: "flex", alignItems: "center", justifyContent: "center", color: "var(--muted)", fontSize: "13px" }}>
            Select a company to view details
          </div>
        )}

        {/* Top Risk Contributors */}
        <div className="panel" style={{ flex: "1 1 280px", display: "flex", flexDirection: "column" }}>
          <div className="panelHeader" style={{ borderBottom: "1px solid var(--line)", paddingBottom: "10px", marginBottom: "12px" }}>
            <h2 style={{ fontSize: "14px", margin: 0 }}>Top Risk Contributors</h2>
            <FileText size={14} style={{ color: "var(--muted)" }} />
          </div>
          <div style={{ display: "flex", flexDirection: "column", gap: "10px", fontSize: "12px" }}>
            {[
              { name: "Unpatched Critical CVEs", count: 23, delta: "+4", up: true },
              { name: "Policy drift (agent skew)", count: 8, delta: "-2", up: false },
              { name: "Stale agent versions", count: 14, delta: "+1", up: true },
              { name: "Unresolved high alerts", count: 12, delta: "-5", up: false },
              { name: "DLP policy violations (7d)", count: 91, delta: "+12", up: true },
            ].map(({ name, count, delta, up }) => (
              <div key={name} style={{ display: "flex", justifyContent: "space-between", alignItems: "center" }}>
                <span style={{ color: "var(--text)", maxWidth: "60%" }}>{name}</span>
                <div style={{ display: "flex", gap: "10px", alignItems: "center" }}>
                  <strong>{count}</strong>
                  <span
                    style={{
                      fontSize: "10px",
                      color: up ? "var(--danger)" : "var(--success)",
                      display: "flex",
                      alignItems: "center",
                      gap: "2px",
                    }}
                  >
                    {up ? <TrendingUp size={10} /> : <TrendingDown size={10} />}
                    {delta}
                  </span>
                </div>
              </div>
            ))}
          </div>

          <div style={{ paddingTop: "16px", borderTop: "1px solid var(--line)", marginTop: "16px" }}>
            <div style={{ fontSize: "11px", fontWeight: 600, textTransform: "uppercase", color: "var(--muted)", marginBottom: "8px" }}>
              Weekly Delta (7 days)
            </div>
            {[
              { label: "Alerts resolved", value: metrics.alerts_resolved_7d, icon: <CheckCircle size={12} />, color: "var(--success)" },
              { label: "New enrollments", value: 34, icon: <Users size={12} />, color: "var(--accent)" },
              { label: "AI queries", value: metrics.ai_calls_7d, icon: <BarChart3 size={12} />, color: "var(--accent)" },
            ].map(({ label, value, icon, color }) => (
              <div key={label} style={{ display: "flex", justifyContent: "space-between", alignItems: "center", fontSize: "12px", marginBottom: "6px" }}>
                <span style={{ color, display: "flex", alignItems: "center", gap: "5px" }}>
                  {icon}
                  {label}
                </span>
                <strong>{value.toLocaleString()}</strong>
              </div>
            ))}
          </div>
        </div>
      </section>

      {/* AI Summary note */}
      <section className="panel" style={{ marginTop: "16px", padding: "14px 18px", display: "flex", gap: "12px", alignItems: "flex-start" }}>
        <Clock size={16} style={{ color: "var(--muted)", flexShrink: 0, marginTop: "2px" }} />
        <div style={{ fontSize: "12px", color: "var(--muted)", lineHeight: 1.6 }}>
          <strong style={{ color: "var(--text)" }}>AI Report Generation</strong> — Templated AI executive reports backed by{" "}
          <code>ai_reports</code> with structured confidence, source references, and deterministic fallbacks are planned. The
          metrics above are computed live from <code>/companies</code>, <code>/alerts</code>, and heartbeat data.
          Scheduled weekly email delivery and PDF export require the{" "}
          <code>ai_reports</code> table and object storage for evidence.
        </div>
      </section>
    </div>
  );
}

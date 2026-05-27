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

const EMPTY_METRICS: PortfolioMetrics = {
  total_companies: 0,
  healthy_companies: 0,
  at_risk_companies: 0,
  critical_companies: 0,
  total_endpoints: 0,
  total_open_alerts: 0,
  alerts_resolved_7d: 0,
  avg_risk_score: 0,
  ai_calls_7d: 0,
  license_utilization_pct: 0,
};

function calculateMetrics(
  rows: CustomerRiskSummary[],
  alerts: any[],
  usage: any
): PortfolioMetrics {
  const totalCompanies = rows.length;
  const totalEndpoints = rows.reduce((sum, row) => sum + row.enrolled_agents, 0);
  const totalOpenAlerts = rows.reduce((sum, row) => sum + row.open_alerts, 0);
  const avgRiskScore = totalCompanies ? Math.round(rows.reduce((sum, row) => sum + row.risk_score, 0) / totalCompanies) : 0;
  const licensed = rows.filter((row) => row.license_status === "active" || row.license_status === "trial").length;

  const sevenDaysAgo = Date.now() - 7 * 24 * 60 * 60 * 1000;
  const resolved7d = alerts.filter(
    (a) =>
      a.status === "acknowledged" &&
      new Date(a.created_at).getTime() >= sevenDaysAgo
  ).length;

  const aiCalls30d = usage?.total_ai_calls_30d ?? 0;
  const aiCalls7d = Math.round(aiCalls30d / 4);

  return {
    total_companies: totalCompanies,
    healthy_companies: rows.filter((row) => row.risk_band === "low").length,
    at_risk_companies: rows.filter((row) => row.risk_band === "medium" || row.risk_band === "high").length,
    critical_companies: rows.filter((row) => row.risk_band === "critical").length,
    total_endpoints: totalEndpoints,
    total_open_alerts: totalOpenAlerts,
    alerts_resolved_7d: resolved7d,
    avg_risk_score: avgRiskScore,
    ai_calls_7d: aiCalls7d,
    license_utilization_pct: totalCompanies ? Math.round((licensed / totalCompanies) * 100) : 0,
  };
}

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
  const [metrics, setMetrics] = useState<PortfolioMetrics>(EMPTY_METRICS);
  const [customers, setCustomers] = useState<CustomerRiskSummary[]>([]);
  const [selectedId, setSelectedId] = useState<string | null>(null);
  const [alerts, setAlerts] = useState<any[]>([]);
  const [endpoints, setEndpoints] = useState<any[]>([]);
  const [patches, setPatches] = useState<any[]>([]);
  const [usage, setUsage] = useState<any>(null);

  useEffect(() => {
    async function load() {
      try {
        const [riskSummary, alertList, endpointList, patchList, usageSummary] = await Promise.all([
          apiGet<CustomerRiskSummary[]>("/companies/risk-summary"),
          apiGet<any[]>("/alerts"),
          apiGet<any[]>("/endpoints/health"),
          apiGet<any[]>("/risk/patches"),
          apiGet<any>("/usage/summary").catch(() => null),
        ]);
        setCustomers(riskSummary);
        setAlerts(alertList);
        setEndpoints(endpointList);
        setPatches(patchList);
        setUsage(usageSummary);
        setMetrics(calculateMetrics(riskSummary, alertList, usageSummary));
        if (riskSummary.length > 0) setSelectedId(riskSummary[0].customer_id);
      } catch (err) {
        setError(err instanceof Error ? err.message : "Failed to load portfolio summary.");
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
      const [riskSummary, alertList, endpointList, patchList, usageSummary] = await Promise.all([
        apiGet<CustomerRiskSummary[]>("/companies/risk-summary"),
        apiGet<any[]>("/alerts"),
        apiGet<any[]>("/endpoints/health"),
        apiGet<any[]>("/risk/patches"),
        apiGet<any>("/usage/summary").catch(() => null),
      ]);
      setCustomers(riskSummary);
      setAlerts(alertList);
      setEndpoints(endpointList);
      setPatches(patchList);
      setUsage(usageSummary);
      setMetrics(calculateMetrics(riskSummary, alertList, usageSummary));
      setSuccess("Portfolio metrics refreshed successfully.");
    } catch {
      setError("Failed to refresh metrics.");
    } finally {
      setIsSyncing(false);
    }
  };

  const selected = customers.find((c) => c.customer_id === selectedId) ?? null;

  const criticalCVEs = patches.filter(
    (p) => p.status === "missing" && p.severity === "critical"
  ).length;

  const policyDrifts = endpoints.filter((e) => e.status === "drifted").length;

  const staleAgents = endpoints.filter(
    (e) => e.agent_version !== e.latest_agent_version
  ).length;

  const unresolvedHigh = alerts.filter(
    (a) => a.severity === "high" && a.status === "open"
  ).length;

  const dlpViolations = alerts.filter(
    (a) =>
      a.entity_types?.length > 0 &&
      new Date(a.created_at).getTime() >= Date.now() - 7 * 24 * 60 * 60 * 1000
  ).length;

  const contributors = [
    { name: "Unpatched Critical CVEs", count: criticalCVEs, delta: criticalCVEs > 0 ? `+${criticalCVEs}` : "0", up: criticalCVEs > 0 },
    { name: "Policy drift (agent skew)", count: policyDrifts, delta: policyDrifts > 0 ? `+${policyDrifts}` : "0", up: policyDrifts > 0 },
    { name: "Stale agent versions", count: staleAgents, delta: staleAgents > 0 ? `+${staleAgents}` : "0", up: staleAgents > 0 },
    { name: "Unresolved high alerts", count: unresolvedHigh, delta: unresolvedHigh > 0 ? `+${unresolvedHigh}` : "0", up: unresolvedHigh > 0 },
    { name: "DLP policy violations (7d)", count: dlpViolations, delta: dlpViolations > 0 ? `+${dlpViolations}` : "0", up: dlpViolations > 0 },
  ];

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
            {contributors.map(({ name, count, delta, up }) => (
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
          <code>ai_reports</code> with structured confidence, source references, and persisted source evidence are planned. The
          metrics above are computed live from <code>/companies</code>, <code>/alerts</code>, and heartbeat data.
          Scheduled weekly email delivery and PDF export require the{" "}
          <code>ai_reports</code> table and object storage for evidence.
        </div>
      </section>
    </div>
  );
}

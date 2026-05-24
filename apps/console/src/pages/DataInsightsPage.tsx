import React, { useState, useEffect } from "react";
import { TrendingUp, TrendingDown, RefreshCw, Activity, Brain, Cpu, BarChart2, AlertTriangle } from "lucide-react";
import { LoadingState } from "../components/protection/EmptyState";
import { ErrorBanner } from "../components";
import { apiGet, type MeResponse } from "../api";

export interface UsageMetrics {
  customer_id: string;
  customer_name: string;
  endpoint_count: number;
  events_30d: number;
  ai_calls_30d: number;
  ai_efficiency_score: number;
  dlp_events_30d: number;
  alerts_30d: number;
  blocked_30d: number;
  storage_gb: number;
  trend_events: number; // % change vs prior 30d
  trend_ai: number;
}

export interface PlatformUsage {
  total_endpoints: number;
  total_events_30d: number;
  total_ai_calls_30d: number;
  avg_ai_efficiency_score: number;
  total_dlp_events_30d: number;
  total_blocked_30d: number;
  total_storage_gb: number;
  customers: UsageMetrics[];
}

const DEMO_DATA: PlatformUsage = {
  total_endpoints: 127,
  total_events_30d: 184320,
  total_ai_calls_30d: 3760,
  avg_ai_efficiency_score: 74,
  total_dlp_events_30d: 412,
  total_blocked_30d: 2340,
  total_storage_gb: 38.4,
  customers: [
    {
      customer_id: "c-acme",
      customer_name: "Acme Corp",
      endpoint_count: 18,
      events_30d: 42100,
      ai_calls_30d: 810,
      ai_efficiency_score: 82,
      dlp_events_30d: 89,
      alerts_30d: 14,
      blocked_30d: 430,
      storage_gb: 7.2,
      trend_events: 12,
      trend_ai: 8,
    },
    {
      customer_id: "c-northgate",
      customer_name: "Northgate Ltd",
      endpoint_count: 42,
      events_30d: 95600,
      ai_calls_30d: 1900,
      ai_efficiency_score: 71,
      dlp_events_30d: 190,
      alerts_30d: 33,
      blocked_30d: 1100,
      storage_gb: 18.6,
      trend_events: -4,
      trend_ai: 15,
    },
    {
      customer_id: "c-mediq",
      customer_name: "MediQ Health",
      endpoint_count: 31,
      events_30d: 29800,
      ai_calls_30d: 620,
      ai_efficiency_score: 69,
      dlp_events_30d: 78,
      alerts_30d: 11,
      blocked_30d: 540,
      storage_gb: 6.8,
      trend_events: 3,
      trend_ai: -6,
    },
    {
      customer_id: "c-summit",
      customer_name: "Summit Retail",
      endpoint_count: 23,
      events_30d: 13200,
      ai_calls_30d: 390,
      ai_efficiency_score: 79,
      dlp_events_30d: 47,
      alerts_30d: 7,
      blocked_30d: 250,
      storage_gb: 4.8,
      trend_events: -9,
      trend_ai: 2,
    },
    {
      customer_id: "c-logix",
      customer_name: "Logix Freight",
      endpoint_count: 13,
      events_30d: 3620,
      ai_calls_30d: 40,
      ai_efficiency_score: 58,
      dlp_events_30d: 8,
      alerts_30d: 3,
      blocked_30d: 20,
      storage_gb: 1.0,
      trend_events: 21,
      trend_ai: -30,
    },
  ],
};

const fmt = (n: number) =>
  n >= 1_000_000
    ? `${(n / 1_000_000).toFixed(1)}M`
    : n >= 1_000
    ? `${(n / 1000).toFixed(1)}K`
    : String(n);

export function DataInsightsPage({ me }: { me: MeResponse }) {
  const [isLoading, setIsLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [data, setData] = useState<PlatformUsage | null>(null);
  const [sortField, setSortField] = useState<keyof UsageMetrics>("events_30d");
  const [sortAsc, setSortAsc] = useState(false);

  useEffect(() => {
    async function load() {
      try {
        const res = await apiGet<PlatformUsage>("/usage/summary");
        setData(res);
      } catch {
        setData(DEMO_DATA);
      } finally {
        setIsLoading(false);
      }
    }
    void load();
  }, [me]);

  const toggleSort = (field: keyof UsageMetrics) => {
    if (sortField === field) setSortAsc((v) => !v);
    else { setSortField(field); setSortAsc(false); }
  };

  const sorted = data
    ? [...data.customers].sort((a, b) => {
        const av = a[sortField] as number;
        const bv = b[sortField] as number;
        return sortAsc ? av - bv : bv - av;
      })
    : [];

  if (isLoading) {
    return <div style={{ padding: "40px", width: "100%" }}><LoadingState message="Loading usage data…" /></div>;
  }

  if (!data) return null;

  const scoreColor = (s: number) => s >= 80 ? "var(--success)" : s >= 65 ? "var(--warning)" : "var(--danger)";
  const trendEl = (t: number) => (
    <span style={{ display: "inline-flex", alignItems: "center", gap: "3px", fontSize: "11px", color: t >= 0 ? "var(--danger)" : "var(--success)" }}>
      {t >= 0 ? <TrendingUp size={11} /> : <TrendingDown size={11} />}
      {Math.abs(t)}%
    </span>
  );

  const colHdr = (label: string, field: keyof UsageMetrics) => (
    <th
      onClick={() => toggleSort(field)}
      style={{ cursor: "pointer", textAlign: "right", padding: "6px 12px", fontSize: "11px", fontWeight: 600, textTransform: "uppercase", color: sortField === field ? "var(--accent)" : "var(--muted)", whiteSpace: "nowrap" }}
    >
      {label} {sortField === field ? (sortAsc ? "↑" : "↓") : ""}
    </th>
  );

  return (
    <div style={{ display: "flex", flexDirection: "column", flex: 1, padding: "24px", boxSizing: "border-box" }}>
      {/* Header */}
      <div style={{ marginBottom: "20px" }}>
        <div style={{ fontSize: "11px", fontWeight: 600, textTransform: "uppercase", letterSpacing: "0.08em", color: "var(--muted)", marginBottom: "4px" }}>
          Usage & Billing
        </div>
        <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", flexWrap: "wrap", gap: "12px" }}>
          <div>
            <h1 style={{ margin: 0, fontSize: "22px", fontWeight: 700 }}>Data Insights</h1>
            <p style={{ margin: "4px 0 0 0", fontSize: "12px", color: "var(--muted)" }}>
              Usage, AI efficiency, and billing signals across all customers. 30-day rolling window.
            </p>
          </div>
          <div style={{ display: "flex", gap: "8px", alignItems: "center" }}>
            <span style={{ fontSize: "11px", padding: "3px 8px", borderRadius: "4px", background: "rgba(100,116,139,0.15)", color: "var(--muted)", fontWeight: 600 }}>
              PLANNED
            </span>
          </div>
        </div>
      </div>

      {error && <ErrorBanner message={error} />}

      {/* Platform totals */}
      <section
        style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(160px, 1fr))", gap: "12px", marginBottom: "24px" }}
        aria-label="Platform Usage Totals"
      >
        {[
          { label: "Total Endpoints", value: data.total_endpoints, icon: <Cpu size={16} />, color: "var(--accent)" },
          { label: "Events (30d)", value: fmt(data.total_events_30d), icon: <Activity size={16} />, color: "var(--accent)" },
          { label: "AI Calls (30d)", value: fmt(data.total_ai_calls_30d), icon: <Brain size={16} />, color: "var(--accent)" },
          { label: "Avg AI Efficiency", value: `${data.avg_ai_efficiency_score}%`, icon: <BarChart2 size={16} />, color: scoreColor(data.avg_ai_efficiency_score) },
          { label: "DLP Events (30d)", value: fmt(data.total_dlp_events_30d), icon: <AlertTriangle size={16} />, color: "var(--warning)" },
          { label: "Blocked (30d)", value: fmt(data.total_blocked_30d), icon: <AlertTriangle size={16} />, color: "var(--danger)" },
          { label: "Storage Used", value: `${data.total_storage_gb.toFixed(1)} GB`, icon: <BarChart2 size={16} />, color: "var(--muted)" },
        ].map(({ label, value, icon, color }) => (
          <div key={label} className="panel" style={{ padding: "14px 16px", display: "flex", alignItems: "center", gap: "10px" }}>
            <div style={{ color }}>{icon}</div>
            <div>
              <div style={{ fontSize: "11px", color: "var(--muted)" }}>{label}</div>
              <strong style={{ fontSize: "15px" }}>{value}</strong>
            </div>
          </div>
        ))}
      </section>

      {/* Per-customer table */}
      <div className="panel" style={{ flex: 1, overflow: "auto" }}>
        <h3 style={{ margin: "0 0 0 0", fontSize: "13px", fontWeight: 600, padding: "16px 16px 12px" }}>
          Per-Customer Breakdown
        </h3>
        <div style={{ overflowX: "auto" }}>
          <table style={{ width: "100%", borderCollapse: "collapse", fontSize: "12px" }}>
            <thead>
              <tr style={{ borderBottom: "1px solid var(--line)" }}>
                <th style={{ textAlign: "left", padding: "6px 12px", fontSize: "11px", fontWeight: 600, textTransform: "uppercase", color: "var(--muted)" }}>
                  Customer
                </th>
                {colHdr("Endpoints", "endpoint_count")}
                {colHdr("Events (30d)", "events_30d")}
                {colHdr("Trend", "trend_events")}
                {colHdr("AI Calls", "ai_calls_30d")}
                {colHdr("AI Efficiency", "ai_efficiency_score")}
                {colHdr("DLP Events", "dlp_events_30d")}
                {colHdr("Blocked", "blocked_30d")}
                {colHdr("Storage (GB)", "storage_gb")}
              </tr>
            </thead>
            <tbody>
              {sorted.map((c, i) => (
                <tr key={c.customer_id} style={{ borderBottom: "1px solid var(--line)", background: i % 2 === 0 ? "transparent" : "rgba(100,116,139,0.03)" }}>
                  <td style={{ padding: "10px 12px", fontWeight: 500 }}>{c.customer_name}</td>
                  <td style={{ padding: "10px 12px", textAlign: "right" }}>{c.endpoint_count}</td>
                  <td style={{ padding: "10px 12px", textAlign: "right" }}>{fmt(c.events_30d)}</td>
                  <td style={{ padding: "10px 12px", textAlign: "right" }}>{trendEl(c.trend_events)}</td>
                  <td style={{ padding: "10px 12px", textAlign: "right" }}>{fmt(c.ai_calls_30d)}</td>
                  <td style={{ padding: "10px 12px", textAlign: "right" }}>
                    <div style={{ display: "inline-flex", alignItems: "center", gap: "6px" }}>
                      <div style={{ width: "48px", height: "5px", borderRadius: "3px", background: "rgba(100,116,139,0.2)", overflow: "hidden" }}>
                        <div style={{ width: `${c.ai_efficiency_score}%`, height: "100%", borderRadius: "3px", background: scoreColor(c.ai_efficiency_score) }} />
                      </div>
                      <span style={{ color: scoreColor(c.ai_efficiency_score), fontWeight: 600 }}>{c.ai_efficiency_score}%</span>
                    </div>
                  </td>
                  <td style={{ padding: "10px 12px", textAlign: "right" }}>{c.dlp_events_30d}</td>
                  <td style={{ padding: "10px 12px", textAlign: "right" }}>{fmt(c.blocked_30d)}</td>
                  <td style={{ padding: "10px 12px", textAlign: "right" }}>{c.storage_gb.toFixed(1)}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
        <div style={{ padding: "10px 16px", fontSize: "11px", color: "var(--muted)", borderTop: "1px solid var(--line)" }}>
          Billing export, usage metering hooks, and AI efficiency model integration are under active development.
        </div>
      </div>
    </div>
  );
}

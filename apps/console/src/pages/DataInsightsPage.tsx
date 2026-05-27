import React, { useState, useEffect } from "react";
import { TrendingUp, TrendingDown, RefreshCw, Activity, Brain, Cpu, BarChart2, AlertTriangle } from "lucide-react";
import { LoadingState } from "../components/protection/EmptyState";
import { ConsolePage, ErrorBanner, PageHeader } from "../components";
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
      } catch (err) {
        setError(err instanceof Error ? err.message : "Failed to load usage summary.");
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
    <ConsolePage>
      <PageHeader
        eyebrow="Usage & Billing"
        title="Data Insights"
        subtitle="Usage, AI efficiency, and billing signals across partners and customers."
      />

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
    </ConsolePage>
  );
}

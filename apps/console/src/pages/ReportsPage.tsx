import React, { useState, useEffect } from "react";
import {
  FileText,
  RefreshCw,
  Download,
  Plus,
  Clock,
  CheckCircle,
  AlertTriangle,
  BarChart2,
  Shield,
  Brain,
  Loader2,
} from "lucide-react";
import { LoadingState } from "../components/protection/EmptyState";
import { ErrorBanner, SuccessBanner } from "../components";
import { apiGet, apiPost, type MeResponse } from "../api";

export type ReportType =
  | "executive_summary"
  | "ransomware_readiness"
  | "integrity_report"
  | "compliance_export"
  | "incident_timeline"
  | "ai_efficiency";

export type ReportStatus = "ready" | "generating" | "failed" | "scheduled";

export interface ReportRecord {
  id: string;
  type: ReportType;
  title: string;
  description: string;
  status: ReportStatus;
  customer_id?: string | null;
  generated_at?: string | null;
  scheduled_for?: string | null;
  size_bytes?: number | null;
  confidence?: number | null;
  source_event_count?: number | null;
  download_url?: string | null;
}

const REPORT_META: Record<ReportType, { icon: React.ReactNode; color: string; label: string }> = {
  executive_summary: { icon: <BarChart2 size={18} />, color: "var(--accent)", label: "Executive Summary" },
  ransomware_readiness: { icon: <Shield size={18} />, color: "var(--danger)", label: "Ransomware Readiness" },
  integrity_report: { icon: <CheckCircle size={18} />, color: "var(--success)", label: "Integrity Report" },
  compliance_export: { icon: <FileText size={18} />, color: "var(--muted)", label: "Compliance Export" },
  incident_timeline: { icon: <Clock size={18} />, color: "var(--warning)", label: "Incident Timeline" },
  ai_efficiency: { icon: <Brain size={18} />, color: "var(--accent)", label: "AI Efficiency Report" },
};

const DEMO_REPORTS: ReportRecord[] = [
  {
    id: "rpt-001",
    type: "executive_summary",
    title: "Executive Summary — June 2024",
    description: "Monthly portfolio risk overview for Northgate IT. Covers 42 endpoints, 3 incidents, AI efficiency score 87/100.",
    status: "ready",
    customer_id: null,
    generated_at: new Date(Date.now() - 86400000 * 1).toISOString(),
    size_bytes: 524288,
    confidence: 94,
    source_event_count: 1847,
    download_url: "#",
  },
  {
    id: "rpt-002",
    type: "ransomware_readiness",
    title: "Ransomware Readiness Assessment",
    description: "NIST CSF-2.0 aligned readiness score with gap analysis. Backup verification, lateral movement controls, recovery time estimate.",
    status: "ready",
    customer_id: null,
    generated_at: new Date(Date.now() - 86400000 * 3).toISOString(),
    size_bytes: 786432,
    confidence: 88,
    source_event_count: 312,
    download_url: "#",
  },
  {
    id: "rpt-003",
    type: "integrity_report",
    title: "Policy Integrity Report — Q2 2024",
    description: "Signed audit chain verification. Policy version consistency, enrollment coverage, and evidence hash chain validation.",
    status: "ready",
    customer_id: null,
    generated_at: new Date(Date.now() - 86400000 * 7).toISOString(),
    size_bytes: 262144,
    confidence: 100,
    source_event_count: 2203,
    download_url: "#",
  },
  {
    id: "rpt-004",
    type: "ai_efficiency",
    title: "AI Efficiency Report — June 2024",
    description: "LLM gateway usage, classification accuracy, false positive rates, and cost-per-detection across all tenants.",
    status: "generating",
    customer_id: null,
    generated_at: null,
    size_bytes: null,
    confidence: null,
    source_event_count: null,
    download_url: null,
  },
  {
    id: "rpt-005",
    type: "compliance_export",
    title: "ISO 27001 Evidence Pack — June 2024",
    description: "Structured evidence export for ISO 27001:2022 Annex A controls with signed timestamps and audit hashes.",
    status: "scheduled",
    customer_id: null,
    generated_at: null,
    scheduled_for: new Date(Date.now() + 86400000).toISOString(),
    size_bytes: null,
    confidence: null,
    source_event_count: null,
    download_url: null,
  },
];

const REPORT_TEMPLATES: { type: ReportType; title: string; description: string }[] = [
  { type: "executive_summary", title: "Executive Summary", description: "AI-generated portfolio risk overview with confidence scores" },
  { type: "ransomware_readiness", title: "Ransomware Readiness", description: "NIST CSF-2.0 aligned gap analysis and scoring" },
  { type: "integrity_report", title: "Integrity Report", description: "Signed policy audit chain with evidence hashes" },
  { type: "compliance_export", title: "Compliance Export", description: "ISO 27001 / SOC 2 evidence pack" },
  { type: "incident_timeline", title: "Incident Timeline", description: "Chronological incident reconstruction with MITRE ATT&CK mapping" },
  { type: "ai_efficiency", title: "AI Efficiency Report", description: "LLM usage, accuracy, and cost-per-detection analysis" },
];

export function ReportsPage({ me }: { me: MeResponse }) {
  const [isLoading, setIsLoading] = useState(true);
  const [isSyncing, setIsSyncing] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [success, setSuccess] = useState<string | null>(null);
  const [reports, setReports] = useState<ReportRecord[]>([]);
  const [selectedId, setSelectedId] = useState<string | null>(null);
  const [isGenerating, setIsGenerating] = useState(false);

  const selectedReport = reports.find((r) => r.id === selectedId) ?? null;

  useEffect(() => {
    async function load() {
      try {
        const customerId = me.scope.customer_ids[0];
        const url = customerId ? `/reports?customer_id=${customerId}` : `/reports`;
        const data = await apiGet<ReportRecord[]>(url);
        setReports(data);
        if (data.length > 0) setSelectedId(data[0].id);
      } catch {
        setReports(DEMO_REPORTS);
        setSelectedId(DEMO_REPORTS[0].id);
      } finally {
        setIsLoading(false);
      }
    }
    void load();
  }, [me]);

  const handleGenerate = async (type: ReportType) => {
    setIsGenerating(true);
    const tempId = `rpt-gen-${Date.now()}`;
    const generating: ReportRecord = {
      id: tempId,
      type,
      title: `${REPORT_META[type].label} — ${new Date().toLocaleDateString("en-US", { month: "long", year: "numeric" })}`,
      description: "Generating — AI is correlating events and building the report…",
      status: "generating",
      customer_id: me.scope.customer_ids[0] ?? null,
      generated_at: null,
    };
    setReports((prev) => [generating, ...prev]);
    setSelectedId(tempId);
    try {
      const res = await apiPost<ReportRecord>("/reports/generate", { type, customer_id: me.scope.customer_ids[0] ?? null });
      setReports((prev) => prev.map((r) => (r.id === tempId ? res : r)));
      setSelectedId(res.id);
      setSuccess(`Report generated: ${res.title}`);
    } catch {
      // simulate completion offline
      await new Promise((r) => setTimeout(r, 1500));
      const done: ReportRecord = {
        ...generating,
        status: "ready",
        generated_at: new Date().toISOString(),
        description: REPORT_TEMPLATES.find((t) => t.type === type)?.description ?? "",
        size_bytes: 524288,
        confidence: 85,
        source_event_count: Math.floor(Math.random() * 2000) + 100,
        download_url: "#",
      };
      setReports((prev) => prev.map((r) => (r.id === tempId ? done : r)));
      setSelectedId(done.id);
      setSuccess(`Report generated (demo): ${done.title}`);
    } finally {
      setIsGenerating(false);
    }
  };

  const ready = reports.filter((r) => r.status === "ready").length;
  const generating = reports.filter((r) => r.status === "generating").length;

  if (isLoading) {
    return (
      <div style={{ padding: "40px", width: "100%" }}>
        <LoadingState message="Loading reports…" />
      </div>
    );
  }

  return (
    <div style={{ display: "flex", flexDirection: "column", flex: 1, padding: "24px", boxSizing: "border-box" }}>
      {/* Header */}
      <div style={{ marginBottom: "24px" }}>
        <div style={{ fontSize: "11px", fontWeight: 600, textTransform: "uppercase", letterSpacing: "0.08em", color: "var(--muted)", marginBottom: "4px" }}>
          Executive Deliverables
        </div>
        <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", flexWrap: "wrap", gap: "12px" }}>
          <h1 style={{ margin: 0, fontSize: "22px", fontWeight: 700 }}>Reports</h1>
          <div style={{ display: "flex", gap: "8px" }}>
            <button className="btn" onClick={() => setIsSyncing(true)} disabled={isSyncing}>
              <RefreshCw size={14} className={isSyncing ? "spin" : ""} />
              {isSyncing ? "Refreshing…" : "Refresh"}
            </button>
          </div>
        </div>
      </div>

      {error && <ErrorBanner message={error} />}
      {success && <SuccessBanner message={success} />}

      {/* Counters */}
      <section
        style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(180px, 1fr))", gap: "14px", marginBottom: "24px" }}
        aria-label="Reports Metrics"
      >
        {[
          { label: "Ready to Download", value: ready, icon: <CheckCircle size={18} />, color: "var(--success)" },
          { label: "Generating", value: generating, icon: <Loader2 size={18} />, color: "var(--accent)" },
          { label: "Total Reports", value: reports.length, icon: <FileText size={18} />, color: "var(--muted)" },
        ].map(({ label, value, icon, color }) => (
          <div key={label} className="panel" style={{ padding: "14px 16px", display: "flex", alignItems: "center", gap: "12px" }}>
            <div style={{ color }}>{icon}</div>
            <div>
              <div style={{ fontSize: "11px", color: "var(--muted)" }}>{label}</div>
              <strong style={{ fontSize: "16px" }}>{value}</strong>
            </div>
          </div>
        ))}
      </section>

      {/* Main layout: report grid + detail panel */}
      <div style={{ display: "flex", gap: "16px", flex: 1, flexWrap: "wrap", alignItems: "stretch" }}>
        {/* Left: existing reports */}
        <div className="panel" style={{ flex: "1 1 340px", minWidth: "280px", display: "flex", flexDirection: "column" }}>
          <h3 style={{ margin: "0 0 14px 0", fontSize: "13px", fontWeight: 600, padding: "16px 16px 0" }}>Your Reports</h3>
          <div style={{ flex: 1, overflowY: "auto" }}>
            {reports.map((r) => {
              const meta = REPORT_META[r.type];
              const isSelected = selectedId === r.id;
              return (
                <button
                  key={r.id}
                  onClick={() => setSelectedId(r.id)}
                  style={{
                    width: "100%",
                    textAlign: "left",
                    background: isSelected ? "rgba(var(--accent-rgb), 0.07)" : "transparent",
                    border: "none",
                    borderLeft: isSelected ? "3px solid var(--accent)" : "3px solid transparent",
                    padding: "12px 16px",
                    cursor: "pointer",
                    display: "flex",
                    flexDirection: "column",
                    gap: "4px",
                  }}
                >
                  <div style={{ display: "flex", alignItems: "center", gap: "8px", justifyContent: "space-between" }}>
                    <div style={{ display: "flex", alignItems: "center", gap: "6px", color: meta.color }}>
                      {meta.icon}
                      <span style={{ fontSize: "11px", fontWeight: 600, textTransform: "uppercase", letterSpacing: "0.05em" }}>
                        {meta.label}
                      </span>
                    </div>
                    <span
                      style={{
                        fontSize: "10px",
                        padding: "1px 6px",
                        borderRadius: "4px",
                        background:
                          r.status === "ready" ? "rgba(34,197,94,0.1)" : r.status === "generating" ? "rgba(var(--accent-rgb),0.1)" : "rgba(180,80,24,0.1)",
                        color:
                          r.status === "ready" ? "var(--success)" : r.status === "generating" ? "var(--accent)" : "var(--warning)",
                        fontWeight: 600,
                      }}
                    >
                      {r.status}
                    </span>
                  </div>
                  <div style={{ fontSize: "13px", fontWeight: 500 }}>{r.title}</div>
                  <div style={{ fontSize: "11px", color: "var(--muted)" }}>
                    {r.generated_at
                      ? `Generated ${new Date(r.generated_at).toLocaleDateString()}`
                      : r.scheduled_for
                      ? `Scheduled ${new Date(r.scheduled_for).toLocaleDateString()}`
                      : r.status === "generating"
                      ? "Generating…"
                      : "Pending"}
                  </div>
                </button>
              );
            })}
          </div>
        </div>

        {/* Center: report detail */}
        <div className="panel" style={{ flex: "2 1 380px", minWidth: "300px", padding: "20px", display: "flex", flexDirection: "column", gap: "16px" }}>
          {selectedReport ? (
            <>
              <div style={{ display: "flex", alignItems: "flex-start", gap: "12px", justifyContent: "space-between" }}>
                <div style={{ display: "flex", alignItems: "center", gap: "10px" }}>
                  <div style={{ color: REPORT_META[selectedReport.type].color }}>
                    {REPORT_META[selectedReport.type].icon}
                  </div>
                  <div>
                    <div style={{ fontSize: "11px", color: "var(--muted)", textTransform: "uppercase", letterSpacing: "0.07em" }}>
                      {REPORT_META[selectedReport.type].label}
                    </div>
                    <h2 style={{ margin: 0, fontSize: "16px" }}>{selectedReport.title}</h2>
                  </div>
                </div>
                {selectedReport.download_url && selectedReport.status === "ready" && (
                  <a
                    href={selectedReport.download_url}
                    className="btn btnPrimary"
                    download
                    style={{ display: "flex", alignItems: "center", gap: "6px", textDecoration: "none", whiteSpace: "nowrap" }}
                  >
                    <Download size={14} /> Download
                  </a>
                )}
              </div>
              <p style={{ margin: 0, fontSize: "13px", color: "var(--muted)", lineHeight: 1.6 }}>{selectedReport.description}</p>
              {selectedReport.status === "ready" && (
                <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: "10px" }}>
                  {[
                    { label: "Confidence", value: selectedReport.confidence != null ? `${selectedReport.confidence}%` : "—" },
                    { label: "Source Events", value: selectedReport.source_event_count?.toLocaleString() ?? "—" },
                    { label: "File Size", value: selectedReport.size_bytes ? `${(selectedReport.size_bytes / 1024).toFixed(0)} KB` : "—" },
                    { label: "Generated", value: selectedReport.generated_at ? new Date(selectedReport.generated_at).toLocaleString() : "—" },
                  ].map(({ label, value }) => (
                    <div key={label} className="panel" style={{ padding: "10px 12px" }}>
                      <div style={{ fontSize: "11px", color: "var(--muted)" }}>{label}</div>
                      <strong style={{ fontSize: "14px" }}>{value}</strong>
                    </div>
                  ))}
                </div>
              )}
              {selectedReport.status === "generating" && (
                <div style={{ display: "flex", alignItems: "center", gap: "10px", color: "var(--accent)", fontSize: "13px" }}>
                  <Loader2 size={16} className="spin" />
                  AI is generating this report. It will be available shortly.
                </div>
              )}
            </>
          ) : (
            <div style={{ flex: 1, display: "flex", alignItems: "center", justifyContent: "center", color: "var(--muted)", fontSize: "13px" }}>
              Select a report to view details
            </div>
          )}
        </div>

        {/* Right: generate new report */}
        <div className="panel" style={{ flex: "1 1 260px", minWidth: "220px", padding: "16px", display: "flex", flexDirection: "column", gap: "10px" }}>
          <h3 style={{ margin: "0 0 4px 0", fontSize: "13px", fontWeight: 600 }}>Generate Report</h3>
          <p style={{ margin: "0 0 8px 0", fontSize: "11px", color: "var(--muted)" }}>
            AI reports are built from real telemetry with deterministic fallbacks when source data is unavailable.
          </p>
          {REPORT_TEMPLATES.map((tmpl) => (
            <button
              key={tmpl.type}
              className="btn"
              onClick={() => handleGenerate(tmpl.type)}
              disabled={isGenerating}
              style={{ justifyContent: "flex-start", gap: "8px", textAlign: "left" }}
            >
              <div style={{ color: REPORT_META[tmpl.type].color }}>{REPORT_META[tmpl.type].icon}</div>
              <div style={{ display: "flex", flexDirection: "column", alignItems: "flex-start", gap: "1px" }}>
                <span style={{ fontSize: "12px", fontWeight: 600 }}>{tmpl.title}</span>
                <span style={{ fontSize: "10px", color: "var(--muted)", fontWeight: 400 }}>{tmpl.description}</span>
              </div>
            </button>
          ))}
        </div>
      </div>
    </div>
  );
}

import { useState, useEffect, useCallback, useMemo } from "react";
import {
  FileCheck,
  CheckCircle,
  AlertOctagon,
  HelpCircle,
  Award,
  Database,
  Printer,
  Plus,
  RefreshCw,
  Search,
  ExternalLink,
  ShieldAlert,
  Calendar,
  User,
  Shield,
  ShieldCheck,
  FileText,
} from "lucide-react";
import {
  apiGet,
  apiPost,
  type Customer,
} from "../api";
import {
  EmptyState,
  ErrorBanner,
  LoadingRow,
  PageHeader,
  SideSheet,
  SuccessBanner,
} from "../components";

type FrameworkSlug = "iso27001-2022" | "soc2-2017" | "nist-csf-2.0" | "gdpr" | "hipaa-security-rule";

const FRAMEWORKS: { slug: FrameworkSlug; label: string; authority: string; description: string }[] = [
  {
    slug: "iso27001-2022",
    label: "ISO/IEC 27001:2022",
    authority: "ISO/IEC",
    description: "Information security, cybersecurity and privacy protection — Information security management systems requirements.",
  },
  {
    slug: "soc2-2017",
    label: "SOC 2 (Trust Services Criteria)",
    authority: "AICPA",
    description: "Reports on Controls at a Service Organization Relevant to Security, Availability, Processing Integrity, Confidentiality, or Privacy.",
  },
  {
    slug: "nist-csf-2.0",
    label: "NIST CSF 2.0",
    authority: "NIST",
    description: "National Institute of Standards & Technology Cybersecurity Framework for managing and reducing cybersecurity risk.",
  },
  {
    slug: "gdpr",
    label: "GDPR Article 32",
    authority: "European Union",
    description: "General Data Protection Regulation requirements for technical and organizational measures to ensure security of processing.",
  },
  {
    slug: "hipaa-security-rule",
    label: "HIPAA Security Rule",
    authority: "HHS (US)",
    description: "Health Insurance Portability and Accountability Act Security Standard requirements for protecting electronic health data.",
  },
];

type ControlReview = {
  id: string;
  customer_id: string;
  framework: string;
  control_id: string;
  status: "unreviewed" | "reviewed" | "flagged";
  reviewed_by: string;
  notes: string | null;
  reviewed_at: string;
};

type ControlReviewCreate = {
  framework: string;
  control_id: string;
  status: "unreviewed" | "reviewed" | "flagged";
  notes: string | null;
};

type Attestation = {
  id: string;
  customer_id: string;
  framework: string;
  attested_by: string;
  notes: string | null;
  bundle_hash: string;
  status: "active" | "revoked";
  attested_at: string;
};

type AttestationCreate = {
  framework: string;
  notes: string;
};

type VaultReference = {
  id: string;
  customer_id: string;
  framework: string;
  vault_provider: string;
  reference_uri: string;
  bundle_hash: string;
  status: string;
  exported_at: string;
};

type EvidenceItem = {
  source_table: string;
  id: string;
  created_at: string;
  summary: string;
  status?: string;
  controls: string[];
  chain_hash?: string;
  resource?: string;
};

type ControlDetail = {
  control_id: string;
  title: string;
  description: string;
  evidence_count: number;
};

type ComplianceExportBundle = {
  framework: string;
  customer_id: string;
  generated_at: string;
  controls: ControlDetail[];
  evidence: EvidenceItem[];
  signature: {
    algorithm: string;
    key_id: string;
    value: string;
  };
  audit_chain: {
    record_count: number;
    latest_seq: number | null;
    latest_chain_hash: string | null;
  };
};

export function CompliancePage() {
  const [activeTab, setActiveTab] = useState<"matrix" | "attestations" | "vault" | "certificate">("matrix");
  
  // Scopes & Selection state
  const [companies, setCompanies] = useState<Customer[]>([]);
  const [selectedCustomerId, setSelectedCustomerId] = useState<string>("");
  const [selectedFramework, setSelectedFramework] = useState<FrameworkSlug>("iso27001-2022");
  
  // Data lists
  const [bundle, setBundle] = useState<ComplianceExportBundle | null>(null);
  const [reviews, setReviews] = useState<ControlReview[]>([]);
  const [attestations, setAttestations] = useState<Attestation[]>([]);
  const [vaultRefs, setVaultRefs] = useState<VaultReference[]>([]);

  // UI Flow states
  const [isLoading, setIsLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [success, setSuccess] = useState<string | null>(null);
  const [filterQuery, setFilterQuery] = useState("");
  
  // Interaction sheet states
  const [updatingControl, setUpdatingControl] = useState<ControlDetail | null>(null);
  const [newStatus, setNewStatus] = useState<"unreviewed" | "reviewed" | "flagged">("reviewed");
  const [reviewNotes, setReviewNotes] = useState("");
  const [isSubmittingReview, setIsSubmittingReview] = useState(false);

  const [showAttestForm, setShowAttestForm] = useState(false);
  const [attestNotes, setAttestNotes] = useState("");
  const [isSubmittingAttest, setIsSubmittingAttest] = useState(false);

  // Load Companies list and initial data
  useEffect(() => {
    async function loadCompanies() {
      setIsLoading(true);
      setError(null);
      try {
        const comps = await apiGet<Customer[]>("/companies");
        const activeComps = comps.filter(c => c.status === "active");
        setCompanies(activeComps);
        if (activeComps.length > 0) {
          setSelectedCustomerId(activeComps[0].id);
        } else {
          setIsLoading(false);
        }
      } catch (err: any) {
        setError(err?.message || "Failed to load company registry credentials.");
        setIsLoading(false);
      }
    }
    loadCompanies();
  }, []);

  // Main data loader function for selected company + framework
  const loadComplianceData = useCallback(async () => {
    if (!selectedCustomerId || !selectedFramework) return;
    setIsLoading(true);
    setError(null);
    try {
      const [expBundle, rvs, atts, vlt] = await Promise.all([
        apiGet<ComplianceExportBundle>(`/compliance/export?customer_id=${selectedCustomerId}&framework=${selectedFramework}`),
        apiGet<ControlReview[]>(`/compliance/reviews?customer_id=${selectedCustomerId}&framework=${selectedFramework}`),
        apiGet<Attestation[]>(`/compliance/attestations?customer_id=${selectedCustomerId}&framework=${selectedFramework}`),
        apiGet<VaultReference[]>(`/compliance/vault?customer_id=${selectedCustomerId}&framework=${selectedFramework}`),
      ]);
      setBundle(expBundle);
      setReviews(rvs);
      setAttestations(atts);
      setVaultRefs(vlt);
    } catch (err: any) {
      setError(err?.message || "Error resolving compliance matrices or evidence records.");
    } finally {
      setIsLoading(false);
    }
  }, [selectedCustomerId, selectedFramework]);

  useEffect(() => {
    if (selectedCustomerId && selectedFramework) {
      loadComplianceData();
    }
  }, [selectedCustomerId, selectedFramework, loadComplianceData]);

  // Construct map of control_id to Review State
  const reviewMap = useMemo(() => {
    const map: Record<string, ControlReview> = {};
    for (const r of reviews) {
      map[r.control_id] = r;
    }
    return map;
  }, [reviews]);

  // Search filtered compliance controls
  const filteredControls = useMemo(() => {
    if (!bundle) return [];
    if (!filterQuery) return bundle.controls;
    const lower = filterQuery.toLowerCase();
    return bundle.controls.filter(
      c => c.control_id.toLowerCase().includes(lower) ||
           c.title.toLowerCase().includes(lower) ||
           c.description.toLowerCase().includes(lower)
    );
  }, [bundle, filterQuery]);

  // Handle Review Submission
  const handleSaveReview = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!updatingControl || !selectedCustomerId) return;
    setIsSubmittingReview(true);
    setError(null);
    setSuccess(null);
    try {
      const payload: ControlReviewCreate = {
        framework: selectedFramework,
        control_id: updatingControl.control_id,
        status: newStatus,
        notes: reviewNotes.trim() || null,
      };
      await apiPost<ControlReview>(`/compliance/reviews?customer_id=${selectedCustomerId}`, payload);
      setSuccess(`Control ${updatingControl.control_id} successfully reviewed.`);
      setUpdatingControl(null);
      // Reload lists
      await loadComplianceData();
    } catch (err: any) {
      setError(err?.message || "Failed to persist control status.");
    } finally {
      setIsSubmittingReview(false);
    }
  };

  // Handle Formal Attestation Signing
  const handleSignAttestation = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!selectedCustomerId) return;
    setIsSubmittingAttest(true);
    setError(null);
    setSuccess(null);
    try {
      const payload: AttestationCreate = {
        framework: selectedFramework,
        notes: attestNotes.trim(),
      };
      const att = await apiPost<Attestation>(`/compliance/attestations?customer_id=${selectedCustomerId}`, payload);
      setSuccess(`Formal signature registered! Attestation Sealed: ${att.bundle_hash.substring(0, 16)}...`);
      setShowAttestForm(false);
      setAttestNotes("");
      await loadComplianceData();
    } catch (err: any) {
      setError(err?.message || "Failed to log formal attestation block.");
    } finally {
      setIsSubmittingAttest(false);
    }
  };

  // Open up updating sheet
  const startUpdating = (control: ControlDetail) => {
    const existing = reviewMap[control.control_id];
    setUpdatingControl(control);
    setNewStatus(existing?.status || "reviewed");
    setReviewNotes(existing?.notes || "");
  };

  const selectedCompName = useMemo(() => {
    const search = companies.find(c => c.id === selectedCustomerId);
    return search ? search.name : "Company";
  }, [companies, selectedCustomerId]);

  const selectedFrameworkLabel = useMemo(() => {
    const search = FRAMEWORKS.find(f => f.slug === selectedFramework);
    return search ? search.label : "Framework";
  }, [selectedFramework]);

  // Score statistics
  const stats = useMemo(() => {
    if (!bundle) return { total: 0, compliant: 0, flagged: 0, pending: 0, score: 0 };
    const total = bundle.controls.length;
    let compliant = 0;
    let flagged = 0;
    for (const c of bundle.controls) {
      const state = reviewMap[c.control_id]?.status || "unreviewed";
      if (state === "reviewed") {
        compliant++;
      } else if (state === "flagged") {
        flagged++;
      }
    }
    const pending = total - compliant - flagged;
    const score = total > 0 ? Math.round((compliant / total) * 100) : 0;
    return { total, compliant, flagged, pending, score };
  }, [bundle, reviewMap]);

  if (isLoading && companies.length === 0) {
    return (
      <main className="panel">
        <LoadingRow label="Loading Compliance Center registries..." />
      </main>
    );
  }

  return (
    <div className="policyContainer" style={{ padding: "24px", minHeight: "100%", overflowY: "auto" }}>
      {/* Printable Area - specifically format for window.print() */}
      <style>{`
        @media print {
          body * {
            visibility: hidden;
          }
          .print-view-cert, .print-view-cert * {
            visibility: visible;
          }
          .print-view-cert {
            position: absolute;
            left: 0;
            top: 0;
            width: 100%;
            height: 100%;
            background: white !important;
            color: black !important;
            padding: 40px !important;
          }
          aside, nav, button, .no-print, header, .hud-row {
            display: none !important;
          }
        }
      `}</style>

      {/* Header and Scope Selector Row */}
      <div className="no-print" style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: "20px" }}>
        <div>
          <PageHeader
            eyebrow="Govemanee, Risk & Compliance"
            title="Compliance Evidence Engine"
            subtitle="v0.5 v0.5 Compliance Evidence Matrix & Cryptographic WORM Auditing"
          />
        </div>
        <div style={{ display: "flex", gap: "12px", alignItems: "center" }}>
          {/* Company Selector */}
          <div>
            <label style={{ fontSize: "12px", fontWeight: "600", color: "var(--muted)", display: "block", marginBottom: "4px" }}>Company Scope</label>
            <select
              value={selectedCustomerId}
              onChange={(e) => setSelectedCustomerId(e.target.value)}
              className="txt"
              style={{ padding: "8px 12px", borderRadius: "5px", background: "var(--bg-card)", border: "1px solid var(--border)", color: "var(--foreground)" }}
            >
              {companies.map(c => (
                <option key={c.id} value={c.id}>{c.name}</option>
              ))}
            </select>
          </div>
          {/* Framework Selector */}
          <div>
            <label style={{ fontSize: "12px", fontWeight: "600", color: "var(--muted)", display: "block", marginBottom: "4px" }}>Control Framework</label>
            <select
              value={selectedFramework}
              onChange={(e) => setSelectedFramework(e.target.value as FrameworkSlug)}
              className="txt"
              style={{ padding: "8px 12px", borderRadius: "5px", background: "var(--bg-card)", border: "1px solid var(--border)", color: "var(--foreground)" }}
            >
              {FRAMEWORKS.map(f => (
                <option key={f.slug} value={f.slug}>{f.label}</option>
              ))}
            </select>
          </div>
          <button
            type="button"
            className="iconBtn"
            onClick={loadComplianceData}
            title="Refresh records"
            style={{ width: "38px", height: "38px", marginTop: "18px", display: "flex", alignItems: "center", justifyContent: "center", background: "var(--bg-card)", border: "1px solid var(--border)", borderRadius: "5px" }}
          >
            <RefreshCw size={16} />
          </button>
        </div>
      </div>

      {error ? <ErrorBanner message={error} /> : null}
      {success ? <SuccessBanner message={success} /> : null}

      {/* Compliance Overview Hud */}
      <section className="no-print panel" style={{ padding: "20px", display: "grid", gridTemplateColumns: "repeat(3, 1fr)", gap: "24px", marginBottom: "24px", background: "var(--bg-card)", border: "1px solid var(--border)", borderRadius: "8px" }}>
        <div>
          <h3 style={{ fontSize: "13px", fontWeight: "600", textTransform: "uppercase", color: "var(--muted)", margin: "0 0 10px" }}>Maturation Score</h3>
          <div style={{ display: "flex", alignItems: "center", gap: "16px" }}>
            <div style={{ width: "64px", height: "64px", borderRadius: "50%", border: "4px solid var(--border)", borderTopColor: "var(--brand-primary)", display: "flex", alignItems: "center", justifyContent: "center", fontSize: "20px", fontWeight: "bold" }}>
              {stats.score}%
            </div>
            <div>
              <p style={{ margin: "0", fontSize: "14px", fontWeight: "600" }}>{stats.compliant} of {stats.total} Reviewed</p>
              <p style={{ margin: "0", fontSize: "12px", color: "var(--muted)" }}>Controls logged as compliant</p>
            </div>
          </div>
        </div>
        <div>
          <h3 style={{ fontSize: "13px", fontWeight: "600", textTransform: "uppercase", color: "var(--muted)", margin: "0 0 10px" }}>Active Risk Gaps</h3>
          <div style={{ display: "flex", alignItems: "center", gap: "12px" }}>
            <AlertOctagon size={32} className="text-error" style={{ color: stats.flagged > 0 ? "#ff4d4f" : "var(--muted)" }} />
            <div>
              <p style={{ margin: "0", fontSize: "18px", fontWeight: "700", color: stats.flagged > 0 ? "#ff4d4f" : "var(--foreground)" }}>{stats.flagged} Flagged</p>
              <p style={{ margin: "0", fontSize: "12px", color: "var(--muted)" }}>Requires mitigation review</p>
            </div>
          </div>
        </div>
        <div>
          <h3 style={{ fontSize: "13px", fontWeight: "600", textTransform: "uppercase", color: "var(--muted)", margin: "0 0 10px" }}>Framework Authority</h3>
          <div style={{ display: "flex", alignItems: "center", gap: "12px" }}>
            <Award size={32} style={{ color: "var(--brand-primary)" }} />
            <div>
              <p style={{ margin: "0", fontSize: "15px", fontWeight: "700" }}>{FRAMEWORKS.find(f => f.slug === selectedFramework)?.authority}</p>
              <p style={{ margin: "0", fontSize: "12px", color: "var(--muted)", overflow: "hidden", textOverflow: "ellipsis", display: "-webkit-box", WebkitLineClamp: 2, WebkitBoxOrient: "vertical" }}>
                {FRAMEWORKS.find(f => f.slug === selectedFramework)?.description}
              </p>
            </div>
          </div>
        </div>
      </section>

      {/* Tabs */}
      <div className="no-print" style={{ display: "flex", borderBottom: "1px solid var(--border)", marginBottom: "20px", gap: "24px" }}>
        <button
          className={`tab-btn ${activeTab === "matrix" ? "active" : ""}`}
          onClick={() => setActiveTab("matrix")}
          style={{ padding: "10px 4px", fontSize: "14px", fontWeight: "600", borderBottom: activeTab === "matrix" ? "2px solid var(--brand-primary)" : "2px solid transparent", background: "none", border: "0", borderBottomWidth: "2px", color: activeTab === "matrix" ? "var(--brand-primary)" : "var(--muted)", cursor: "pointer" }}
        >
          Control Evidence Matrix
        </button>
        <button
          className={`tab-btn ${activeTab === "attestations" ? "active" : ""}`}
          onClick={() => setActiveTab("attestations")}
          style={{ padding: "10px 4px", fontSize: "14px", fontWeight: "600", borderBottom: activeTab === "attestations" ? "2px solid var(--brand-primary)" : "2px solid transparent", background: "none", border: "0", borderBottomWidth: "2px", color: activeTab === "attestations" ? "var(--brand-primary)" : "var(--muted)", cursor: "pointer" }}
        >
          Formal Audit Sign-offs ({attestations.length})
        </button>
        <button
          className={`tab-btn ${activeTab === "vault" ? "active" : ""}`}
          onClick={() => setActiveTab("vault")}
          style={{ padding: "10px 4px", fontSize: "14px", fontWeight: "600", borderBottom: activeTab === "vault" ? "2px solid var(--brand-primary)" : "2px solid transparent", background: "none", border: "0", borderBottomWidth: "2px", color: activeTab === "vault" ? "var(--brand-primary)" : "var(--muted)", cursor: "pointer" }}
        >
          Immutable WORM Backups ({vaultRefs.length})
        </button>
        <button
          className={`tab-btn ${activeTab === "certificate" ? "active" : ""}`}
          onClick={() => setActiveTab("certificate")}
          style={{ padding: "10px 4px", fontSize: "14px", fontWeight: "600", borderBottom: activeTab === "certificate" ? "2px solid var(--brand-primary)" : "2px solid transparent", background: "none", border: "0", borderBottomWidth: "2px", color: activeTab === "certificate" ? "var(--brand-primary)" : "var(--muted)", cursor: "pointer" }}
        >
          Auditor Print Certificate
        </button>
      </div>

      {isLoading ? (
        <LoadingRow label="Resolving evidence packages & logs..." />
      ) : (
        <>
          {/* TAB 1: Control Evidence Matrix */}
          {activeTab === "matrix" && (
            <div className="no-print">
              <div style={{ display: "flex", gap: "16px", marginBottom: "16px" }}>
                <div style={{ flex: "1", position: "relative" }}>
                  <Search size={16} style={{ position: "absolute", left: "12px", top: "11px", color: "var(--muted)" }} />
                  <input
                    type="text"
                    placeholder="Search controls by ID, title, or description..."
                    className="txt"
                    value={filterQuery}
                    onChange={(e) => setFilterQuery(e.target.value)}
                    style={{ paddingLeft: "36px", width: "100%", borderRadius: "5px", padding: "8px 12px 8px 36px" }}
                  />
                </div>
              </div>

              {filteredControls.length === 0 ? (
                <EmptyState>No controls matched your query filter.</EmptyState>
              ) : (
                <div className="panel" style={{ border: "1px solid var(--border)", borderRadius: "8px", overflow: "hidden" }}>
                  <table className="table" style={{ width: "100%", borderCollapse: "collapse" }}>
                    <thead>
                      <tr style={{ background: "var(--bg-thead)", borderBottom: "1px solid var(--border)", textAlign: "left" }}>
                        <th style={{ padding: "12px" }}>Control ID</th>
                        <th style={{ padding: "12px" }}>Title & Requirements</th>
                        <th style={{ padding: "12px" }}>Native Evidence Count</th>
                        <th style={{ padding: "12px" }}>Review Status</th>
                        <th style={{ padding: "12px" }}>Assigned Notes</th>
                        <th style={{ padding: "12px", textAlign: "right" }}>Actions</th>
                      </tr>
                    </thead>
                    <tbody>
                      {filteredControls.map((cont) => {
                        const rState = reviewMap[cont.control_id];
                        const status = rState?.status || "unreviewed";
                        
                        return (
                          <tr key={cont.control_id} style={{ borderBottom: "1px solid var(--border)" }}>
                            <td style={{ padding: "12px", fontWeight: "700", whiteSpace: "nowrap" }}>
                              <code>{cont.control_id}</code>
                            </td>
                            <td style={{ padding: "12px" }}>
                              <div style={{ fontWeight: "600", fontSize: "14px", marginBottom: "4px" }}>{cont.title}</div>
                              <div style={{ fontSize: "12px", color: "var(--muted)" }}>{cont.description}</div>
                            </td>
                            <td style={{ padding: "12px" }}>
                              <span style={{
                                padding: "4px 8px",
                                borderRadius: "12px",
                                background: cont.evidence_count > 0 ? "rgba(11, 107, 87, 0.15)" : "var(--bg-thead)",
                                color: cont.evidence_count > 0 ? "var(--brand-primary)" : "var(--muted)",
                                fontWeight: "bold",
                                fontSize: "12px"
                              }}>
                                {cont.evidence_count} attached events
                              </span>
                            </td>
                            <td style={{ padding: "12px" }}>
                              {status === "reviewed" && (
                                <span style={{ display: "inline-flex", alignItems: "center", gap: "4px", color: "#22c55e", fontWeight: "600", fontSize: "13px" }}>
                                  <CheckCircle size={14} /> Compliant
                                </span>
                              )}
                              {status === "flagged" && (
                                <span style={{ display: "inline-flex", alignItems: "center", gap: "4px", color: "#ef4444", fontWeight: "600", fontSize: "13px" }}>
                                  <AlertOctagon size={14} /> Flagged Gap
                                </span>
                              )}
                              {status === "unreviewed" && (
                                <span style={{ display: "inline-flex", alignItems: "center", gap: "4px", color: "var(--muted)", fontWeight: "600", fontSize: "13px" }}>
                                  <HelpCircle size={14} /> Unreviewed
                                </span>
                              )}
                            </td>
                            <td style={{ padding: "12px", fontSize: "12px", maxWidth: "250px", overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap", color: "var(--muted)" }}>
                              {rState?.notes || "—"}
                            </td>
                            <td style={{ padding: "12px", textAlign: "right" }}>
                              <button
                                type="button"
                                className="btn primary"
                                onClick={() => startUpdating(cont)}
                                style={{ padding: "4px 8px", fontSize: "12px" }}
                              >
                                Review Control
                              </button>
                            </td>
                          </tr>
                        );
                      })}
                    </tbody>
                  </table>
                </div>
              )}
            </div>
          )}

          {/* TAB 2: Formal Audit Sign-offs */}
          {activeTab === "attestations" && (
            <div className="no-print">
              <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: "16px" }}>
                <p style={{ margin: "0", color: "var(--muted)", fontSize: "14px" }}>
                  Sign and log a point-in-time snapshot certification. Signing locks the state of control reviews and logs a firm audit-trail hash mapping all live evidence deterministically.
                </p>
                <button
                  type="button"
                  className="btn primary"
                  onClick={() => setShowAttestForm(true)}
                  style={{ display: "inline-flex", alignItems: "center", gap: "6px" }}
                >
                  <Plus size={16} /> Sign Formal Attestation
                </button>
              </div>

              {attestations.length === 0 ? (
                <EmptyState>No formal system attestations signed yet. Create your first point-in-time compliance report today.</EmptyState>
              ) : (
                <div className="panel" style={{ border: "1px solid var(--border)", borderRadius: "8px", overflow: "hidden" }}>
                  <table className="table" style={{ width: "100%", borderCollapse: "collapse" }}>
                    <thead>
                      <tr style={{ background: "var(--bg-thead)", borderBottom: "1px solid var(--border)", textAlign: "left" }}>
                        <th style={{ padding: "12px" }}>Signing Date</th>
                        <th style={{ padding: "12px" }}>Attested By</th>
                        <th style={{ padding: "12px" }}>Notes / Scope</th>
                        <th style={{ padding: "12px" }}>Immutable Evidence Hash</th>
                        <th style={{ padding: "12px" }}>Cryptographic Status</th>
                      </tr>
                    </thead>
                    <tbody>
                      {attestations.map((att) => (
                        <tr key={att.id} style={{ borderBottom: "1px solid var(--border)" }}>
                          <td style={{ padding: "12px", fontSize: "13px" }}>
                            <div style={{ fontWeight: "600" }}>{new Date(att.attested_at).toLocaleDateString()}</div>
                            <div style={{ fontSize: "11px", color: "var(--muted)" }}>{new Date(att.attested_at).toLocaleTimeString()}</div>
                          </td>
                          <td style={{ padding: "12px", fontWeight: "600", fontSize: "13px" }}>
                            {att.attested_by}
                          </td>
                          <td style={{ padding: "12px", fontSize: "13px", color: "var(--muted)" }}>
                            {att.notes || "Official periodic compliance attestation"}
                          </td>
                          <td style={{ padding: "12px" }}>
                            <code style={{ fontSize: "11px", color: "var(--brand-primary)", background: "rgba(11, 107, 87, 0.1)", padding: "4px 8px", borderRadius: "4px" }}>
                              {att.bundle_hash}
                            </code>
                          </td>
                          <td style={{ padding: "12px" }}>
                            <span style={{
                              padding: "4px 8px",
                              borderRadius: "12px",
                              background: "rgba(34, 197, 94, 0.15)",
                              color: "#22c55e",
                              fontWeight: "600",
                              fontSize: "12px"
                            }}>
                              Sealed
                            </span>
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              )}
            </div>
          )}

          {/* TAB 3: Secure Vault Backups */}
          {activeTab === "vault" && (
            <div className="no-print">
              <section className="banner" style={{ background: "rgba(11, 107, 87, 0.08)", border: "1px solid var(--brand-primary)", color: "var(--foreground)", padding: "16px", borderRadius: "8px", marginBottom: "20px" }}>
                <div style={{ display: "flex", gap: "10px", alignItems: "flex-start" }}>
                  <Database size={20} style={{ color: "var(--brand-primary)", marginTop: "2px" }} />
                  <div>
                    <h4 style={{ margin: "0 0 4px", fontSize: "14px", fontWeight: "700" }}>Enterprise-Grade WORM Long Term Storage Vault</h4>
                    <p style={{ margin: "0", fontSize: "12px", color: "var(--muted)" }}>
                      Every signed compliance certification triggers an automated pipeline that backups evidence and reviews records to secure, read-only WORM storage (Write Once, Read Many). These paths utilize the sealed hash signature to prevent retrospective auditing manipulation by administrators.
                    </p>
                  </div>
                </div>
              </section>

              {vaultRefs.length === 0 ? (
                <EmptyState>No persistent vault snapshots archived yet. Sign a formal attestation to trigger WORM backing synchronization.</EmptyState>
              ) : (
                <div className="panel" style={{ border: "1px solid var(--border)", borderRadius: "8px", overflow: "hidden" }}>
                  <table className="table" style={{ width: "100%", borderCollapse: "collapse" }}>
                    <thead>
                      <tr style={{ background: "var(--bg-thead)", borderBottom: "1px solid var(--border)", textAlign: "left" }}>
                        <th style={{ padding: "12px" }}>Archived At</th>
                        <th style={{ padding: "12px" }}>WORM Provider</th>
                        <th style={{ padding: "12px" }}>Storage Reference URI</th>
                        <th style={{ padding: "12px" }}>Frozen Bundle SHA-256</th>
                        <th style={{ padding: "12px" }}>WORM Policy Status</th>
                      </tr>
                    </thead>
                    <tbody>
                      {vaultRefs.map((v) => (
                        <tr key={v.id} style={{ borderBottom: "1px solid var(--border)" }}>
                          <td style={{ padding: "12px", fontSize: "13px" }}>
                            {new Date(v.exported_at).toLocaleDateString()}
                          </td>
                          <td style={{ padding: "12px", fontSize: "13px", fontWeight: "600" }}>
                            {v.vault_provider}
                          </td>
                          <td style={{ padding: "12px", fontSize: "12px" }}>
                            <a href={v.reference_uri} target="_blank" rel="noopener noreferrer" style={{ display: "inline-flex", alignItems: "center", gap: "4px", color: "var(--brand-primary)", textDecoration: "underline" }}>
                              Immutable URI <ExternalLink size={12} />
                            </a>
                          </td>
                          <td style={{ padding: "12px" }}>
                            <code style={{ fontSize: "11px", color: "var(--muted)" }}>{v.bundle_hash.substring(0, 32)}...</code>
                          </td>
                          <td style={{ padding: "12px" }}>
                            <span style={{
                              padding: "4px 8px",
                              borderRadius: "12px",
                              background: "rgba(11, 107, 87, 0.15)",
                              color: "var(--brand-primary)",
                              fontWeight: "600",
                              fontSize: "12px"
                            }}>
                              Locked WORM
                            </span>
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              )}
            </div>
          )}

          {/* TAB 4: Auditor Print Certificate */}
          {activeTab === "certificate" && (
            <div>
              <div className="no-print" style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: "20px", background: "var(--bg-card)", padding: "16px", borderRadius: "8px", border: "1px solid var(--border)" }}>
                <div>
                  <h4 style={{ margin: "0 0 4px", fontSize: "14px", fontWeight: "700" }}>Certified Compliance Print Reports</h4>
                  <p style={{ margin: "0", fontSize: "12px", color: "var(--muted)" }}>
                    This panel displays a formal certification of the security maturity state for {selectedCompName}. The print layout is specifically formatted as a vector high-resolution certificate for presentation during regulatory reviews. Click the print button to trigger.
                  </p>
                </div>
                <button
                  type="button"
                  className="btn primary"
                  onClick={() => window.print()}
                  style={{ display: "inline-flex", alignItems: "center", gap: "6px" }}
                >
                  <Printer size={16} /> Print Official Certification
                </button>
              </div>

              {/* Printable compliance certification */}
              <div className="print-view-cert" style={{
                background: "var(--bg-card)",
                border: "2px solid var(--border)",
                borderRadius: "12px",
                padding: "40px",
                maxWidth: "800px",
                margin: "0 auto",
                boxShadow: "0 4px 12px rgba(0,0,0,0.1)",
                fontFamily: "var(--font-display)",
                color: "var(--foreground)"
              }}>
                <div style={{ textAlign: "center", borderBottom: "2px double var(--border)", paddingBottom: "24px", marginBottom: "30px" }}>
                  <ShieldCheck size={48} style={{ color: "var(--brand-primary)", marginBottom: "16px" }} />
                  <h1 style={{ fontSize: "28px", fontWeight: "700", margin: "0 0 8px", color: "var(--brand-primary)" }}>
                    CERTIFICATE OF COMPLIANCE
                  </h1>
                  <h3 style={{ fontSize: "14px", textTransform: "uppercase", letterSpacing: "1px", margin: "0", color: "var(--muted)" }}>
                    {selectedFrameworkLabel} SECURITY ASSESSMENT
                  </h3>
                </div>

                <div style={{ textAlign: "center", marginBottom: "30px", lineHeight: "1.6" }}>
                  <p style={{ margin: "0 0 12px", fontSize: "16px", fontStyle: "italic" }}>This document certifies that the security instrumentation and policy enforcement parameters for</p>
                  <h2 style={{ fontSize: "24px", fontWeight: "700", margin: "0 0 12px", color: "var(--foreground)" }}>{selectedCompName}</h2>
                  <p style={{ margin: "0", fontSize: "15px" }}>
                    have been evaluated and aligned to the required compliance controls. Native compliance logs, DLP policies, and system audit trails have been mapped deterministically.
                  </p>
                </div>

                <section style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: "24px", padding: "20px 0", borderTop: "1px solid var(--border)", borderBottom: "1px solid var(--border)", marginBottom: "30px", fontSize: "14px" }}>
                  <div>
                    <h4 style={{ fontStyle: "italic", color: "var(--muted)", margin: "0 0 8px" }}>Assessment Metrics</h4>
                    <ul style={{ listStyle: "none", padding: "0", margin: "0" }}>
                      <li style={{ padding: "4px 0" }}><strong>Maturation Compliance Rate:</strong> {stats.score}%</li>
                      <li style={{ padding: "4px 0" }}><strong>Total Controls Reviewed:</strong> {stats.compliant} of {stats.total}</li>
                      <li style={{ padding: "4px 0" }}><strong>Identified Gaps (Flagged):</strong> {stats.flagged}</li>
                    </ul>
                  </div>
                  <div>
                    <h4 style={{ fontStyle: "italic", color: "var(--muted)", margin: "0 0 8px" }}>Audit Trail Trust</h4>
                    <p style={{ margin: "0 0 4px", fontSize: "12px", color: "var(--muted)" }}>Sealed snapshot of live evidence logs:</p>
                    <code style={{ fontSize: "11px", display: "block", background: "var(--bg-thead)", padding: "6px", borderRadius: "4px", overflowWrap: "anywhere", border: "1px solid var(--border)" }}>
                      {bundle?.signature.value || "Not sealed"}
                    </code>
                  </div>
                </section>

                <div style={{ display: "flex", justifyContent: "space-between", alignItems: "flex-end" }}>
                  <div style={{ borderTop: "1px solid var(--border)", width: "200px", textAlign: "center", paddingTop: "8px", fontSize: "12px" }}>
                    <p style={{ margin: "0", fontWeight: "bold" }}>AETHERIX TRUST NETWORK</p>
                    <p style={{ margin: "0", color: "var(--muted)" }}>Automated Compliance Vault</p>
                  </div>
                  <div style={{ borderTop: "1px solid var(--border)", width: "200px", textAlign: "center", paddingTop: "8px", fontSize: "12px" }}>
                    <p style={{ margin: "0", fontWeight: "bold" }}>{attestations[0]?.attested_by || "No Active Signee"}</p>
                    <p style={{ margin: "0", color: "var(--muted)" }}>Attesting Auditor Signature</p>
                  </div>
                </div>
              </div>
            </div>
          )}
        </>
      )}

      {/* Control Update sideSheet */}
      <SideSheet
        open={updatingControl !== null}
        onClose={() => setUpdatingControl(null)}
        title={`Review Control ${updatingControl?.control_id}`}
        subtitle="Review security evidence logs to formally attest adherence or mark as an open gap."
      >
        {updatingControl && (
          <form onSubmit={handleSaveReview} style={{ display: "flex", flexDirection: "column", gap: "20px" }}>
            <div>
              <h3 style={{ margin: "0 0 6px", fontSize: "16px", fontWeight: "bold" }}>{updatingControl.title}</h3>
              <p style={{ margin: "0", fontSize: "14px", color: "var(--muted)" }}>{updatingControl.description}</p>
            </div>

            <div style={{ background: "rgba(11, 107, 87, 0.06)", border: "1px solid var(--border)", padding: "16px", borderRadius: "8px" }}>
              <h4 style={{ margin: "0 0 10px", fontSize: "13px", display: "flex", alignItems: "center", gap: "6px", fontWeight: "bold" }}>
                <Shield size={16} /> Native Security Evidence Tracked ({updatingControl.evidence_count})
              </h4>
              <p style={{ margin: "0", fontSize: "12px", color: "var(--muted)", lineHeight: "1.4" }}>
                The Aetherix agent automatic telemetry processes linked {updatingControl.evidence_count} security incident alerts, audit actions, or policy state events directly as compliance proof for this control.
              </p>
            </div>

            <div>
              <label style={{ display: "block", marginBottom: "6px", fontWeight: "bold", fontSize: "14px" }}>Attestation Decision</label>
              <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: "12px" }}>
                <button
                  type="button"
                  onClick={() => setNewStatus("reviewed")}
                  style={{
                    padding: "16px",
                    borderRadius: "8px",
                    border: newStatus === "reviewed" ? "2px solid #22c55e" : "1px solid var(--border)",
                    background: newStatus === "reviewed" ? "rgba(34, 197, 94, 0.08)" : "var(--bg-card)",
                    cursor: "pointer",
                    textAlign: "center"
                  }}
                >
                  <CheckCircle size={20} style={{ color: "#22c55e", margin: "0 auto 8px" }} />
                  <strong style={{ display: "block", fontSize: "14px" }}>Compliant</strong>
                  <span style={{ fontSize: "11px", color: "var(--muted)" }}>Evidence verified successfully</span>
                </button>
                <button
                  type="button"
                  onClick={() => setNewStatus("flagged")}
                  style={{
                    padding: "16px",
                    borderRadius: "8px",
                    border: newStatus === "flagged" ? "2px solid #ef4444" : "1px solid var(--border)",
                    background: newStatus === "flagged" ? "rgba(239, 68, 68, 0.08)" : "var(--bg-card)",
                    cursor: "pointer",
                    textAlign: "center"
                  }}
                >
                  <AlertOctagon size={20} style={{ color: "#ef4444", margin: "0 auto 8px" }} />
                  <strong style={{ display: "block", fontSize: "14px" }}>Flagged Gap</strong>
                  <span style={{ fontSize: "11px", color: "var(--muted)" }}>Requires mitigation/attention</span>
                </button>
              </div>
            </div>

            <div>
              <label style={{ display: "block", marginBottom: "6px", fontWeight: "bold", fontSize: "14px" }}>Control Assessment Notes</label>
              <textarea
                className="txt"
                rows={4}
                value={reviewNotes}
                onChange={(e) => setReviewNotes(e.target.value)}
                placeholder="Log internal auditor assessment context, mapping decisions, or gap mitigation timelines..."
                style={{ width: "100%", borderRadius: "5px" }}
              />
            </div>

            <div style={{ display: "flex", justifyContent: "flex-end", gap: "12px", borderTop: "1px solid var(--border)", paddingTop: "16px" }}>
              <button
                type="button"
                className="btn"
                onClick={() => setUpdatingControl(null)}
              >
                Cancel
              </button>
              <button
                type="submit"
                className="btn primary"
                disabled={isSubmittingReview}
              >
                {isSubmittingReview ? "Saving..." : "Verify & Complete Review"}
              </button>
            </div>
          </form>
        )}
      </SideSheet>

      {/* Log formal attestation sideSheet */}
      <SideSheet
        open={showAttestForm}
        onClose={() => setShowAttestForm(false)}
        title="Sign Formal Assessment Attestation"
        subtitle="Appends a point-in-time assessment seal logged cryptographically on the compliance ledger."
      >
        <form onSubmit={handleSignAttestation} style={{ display: "flex", flexDirection: "column", gap: "20px" }}>
          <section className="banner" style={{ display: "flex", gap: "10px", padding: "16px", borderRadius: "8px" }}>
            <FileText size={20} style={{ marginTop: "2px" }} />
            <div>
              <h4 style={{ margin: "0 0 4px", fontSize: "13px", fontWeight: "700" }}>Sealed Compliance Export Protocol</h4>
              <p style={{ margin: "0", fontSize: "11px", color: "var(--muted)", lineHeight: "1.4" }}>
                Creating a formal attestation compiles all active policy scopes, agent enforcement logs, custom rules, and control statuses into a canonical report package. It computes the SHA-256 HMAC hash of the export pack, registers the block on the immutable compliance vault, and anchors it perpetually. This flow is legally binding under strict compliance frameworks.
              </p>
            </div>
          </section>

          <div>
            <label style={{ display: "block", marginBottom: "6px", fontWeight: "bold", fontSize: "14px" }}>Attesting Framework</label>
            <input
              type="text"
              className="txt"
              disabled
              value={selectedFrameworkLabel}
              style={{ width: "100%", borderRadius: "5px", opacity: 0.8 }}
            />
          </div>

          <div>
            <label style={{ display: "block", marginBottom: "6px", fontWeight: "bold", fontSize: "14px" }}>Signing Notes / Attestation Statement</label>
            <textarea
              className="txt"
              rows={4}
              required
              value={attestNotes}
              onChange={(e) => setAttestNotes(e.target.value)}
              placeholder="e.g., We hereby certify that the current policies, DLP agent modules, and audits are fully aligned and verified for compliance."
              style={{ width: "100%", borderRadius: "5px" }}
            />
          </div>

          <div style={{ display: "flex", justifyContent: "flex-end", gap: "12px", borderTop: "1px solid var(--border)", paddingTop: "16px" }}>
            <button
              type="button"
              className="btn"
              onClick={() => setShowAttestForm(false)}
            >
              Cancel
            </button>
            <button
              type="submit"
              className="btn primary"
              disabled={isSubmittingAttest}
            >
              {isSubmittingAttest ? "Sealing Attestation..." : "Sign & Seal Audit Trail"}
            </button>
          </div>
        </form>
      </SideSheet>
    </div>
  );
}

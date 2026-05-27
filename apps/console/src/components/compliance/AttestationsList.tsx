import { useState, useEffect } from "react";
import { apiGet } from "../../api";
import { LoadingRow, ErrorBanner, EmptyState, SideSheet } from "../../components";

type FrameworkSlug = "iso27001-2022" | "soc2-2017" | "nist-csf-2.0" | "gdpr" | "hipaa-security-rule";

const FRAMEWORKS: { slug: FrameworkSlug; label: string }[] = [
  { slug: "iso27001-2022", label: "ISO/IEC 27001:2022" },
  { slug: "soc2-2017", label: "SOC 2 (Trust Services Criteria)" },
  { slug: "nist-csf-2.0", label: "NIST CSF 2.0" },
  { slug: "gdpr", label: "GDPR Article 32" },
  { slug: "hipaa-security-rule", label: "HIPAA Security Rule" },
];

export interface ComplianceAttestation {
  id: string;
  customer_id: string;
  framework: string;
  period_start: string;
  period_end: string;
  attested_by_account_id: string | null;
  attested_role: string;
  attested_name: string;
  statement: string;
  bundle_sha256: string;
  signature: string;
  signature_algo: string;
  created_at: string;
}

export function AttestationsList({ customerId }: { customerId: string }) {
  const [selectedFramework, setSelectedFramework] = useState<FrameworkSlug>("iso27001-2022");
  const [attestations, setAttestations] = useState<ComplianceAttestation[]>([]);
  const [isLoading, setIsLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  
  const [selectedAttestation, setSelectedAttestation] = useState<ComplianceAttestation | null>(null);

  useEffect(() => {
    if (!customerId) return;
    setIsLoading(true);
    setError(null);
    apiGet<ComplianceAttestation[]>(`/compliance/attestations?customer_id=${customerId}&framework=${selectedFramework}`)
      .then(setAttestations)
      .catch((err: any) => setError(err.message || "Failed to load attestations."))
      .finally(() => setIsLoading(false));
  }, [customerId, selectedFramework]);

  return (
    <div className="no-print">
      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: "16px" }}>
        <p style={{ margin: "0", color: "var(--muted)", fontSize: "14px" }}>
          Read-only view of formal audit sign-offs and automatic attestations.
        </p>
        <div style={{ display: "flex", gap: "12px", alignItems: "center" }}>
          <label style={{ fontSize: "12px", fontWeight: "600", color: "var(--muted)" }}>Filter by Framework:</label>
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
      </div>

      {error && <ErrorBanner message={error} />}

      {isLoading ? (
        <LoadingRow label="Loading attestations..." />
      ) : attestations.length === 0 ? (
        <EmptyState>No formal system attestations signed yet for this framework.</EmptyState>
      ) : (
        <div className="panel" style={{ border: "1px solid var(--border)", borderRadius: "8px", overflow: "hidden" }}>
          <table className="table" style={{ width: "100%", borderCollapse: "collapse" }}>
            <thead>
              <tr style={{ background: "var(--bg-thead)", borderBottom: "1px solid var(--border)", textAlign: "left" }}>
                <th style={{ padding: "12px" }}>Framework</th>
                <th style={{ padding: "12px" }}>Date Created</th>
                <th style={{ padding: "12px" }}>Period</th>
                <th style={{ padding: "12px" }}>Attested By</th>
                <th style={{ padding: "12px" }}>Bundle SHA-256</th>
                <th style={{ padding: "12px", textAlign: "right" }}>Actions</th>
              </tr>
            </thead>
            <tbody>
              {attestations.map((att) => (
                <tr key={att.id} style={{ borderBottom: "1px solid var(--border)" }}>
                  <td style={{ padding: "12px", fontSize: "13px", fontWeight: "600" }}>
                    {FRAMEWORKS.find(f => f.slug === att.framework)?.label || att.framework}
                  </td>
                  <td style={{ padding: "12px", fontSize: "13px" }}>
                    {new Date(att.created_at).toLocaleDateString()}
                  </td>
                  <td style={{ padding: "12px", fontSize: "13px", color: "var(--muted)" }}>
                    {att.period_start} to {att.period_end}
                  </td>
                  <td style={{ padding: "12px", fontSize: "13px" }}>
                    <div style={{ fontWeight: "600" }}>{att.attested_name}</div>
                    <div style={{ fontSize: "11px", color: "var(--muted)" }}>{att.attested_role}</div>
                  </td>
                  <td style={{ padding: "12px" }}>
                    <code style={{ fontSize: "11px", color: "var(--brand-primary)", background: "rgba(11, 107, 87, 0.1)", padding: "4px 8px", borderRadius: "4px" }}>
                      {att.bundle_sha256.substring(0, 16)}...
                    </code>
                  </td>
                  <td style={{ padding: "12px", textAlign: "right" }}>
                    <button
                      type="button"
                      className="btn"
                      onClick={() => setSelectedAttestation(att)}
                      style={{ padding: "4px 8px", fontSize: "12px" }}
                    >
                      View details
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}

      {selectedAttestation && (
        <SideSheet
          open={!!selectedAttestation}
          onClose={() => setSelectedAttestation(null)}
          title="Attestation Details"
          subtitle="Full cryptographic signature and formal statement."
        >
          <div style={{ display: "flex", flexDirection: "column", gap: "20px" }}>
            <div>
              <h4 style={{ margin: "0 0 6px", fontSize: "13px", color: "var(--muted)" }}>Statement</h4>
              <div style={{ background: "var(--bg-card)", padding: "12px", borderRadius: "6px", border: "1px solid var(--border)", fontSize: "14px" }}>
                {selectedAttestation.statement}
              </div>
            </div>
            
            <div>
              <h4 style={{ margin: "0 0 6px", fontSize: "13px", color: "var(--muted)" }}>Bundle SHA-256</h4>
              <code style={{ display: "block", background: "var(--bg-thead)", padding: "12px", borderRadius: "6px", border: "1px solid var(--border)", fontSize: "12px", wordBreak: "break-all" }}>
                {selectedAttestation.bundle_sha256}
              </code>
            </div>

            <div>
              <h4 style={{ margin: "0 0 6px", fontSize: "13px", color: "var(--muted)" }}>Cryptographic Signature</h4>
              <code style={{ display: "block", background: "var(--bg-thead)", padding: "12px", borderRadius: "6px", border: "1px solid var(--border)", fontSize: "12px", wordBreak: "break-all" }}>
                {selectedAttestation.signature}
              </code>
              <p style={{ margin: "6px 0 0", fontSize: "11px", color: "var(--muted)" }}>Algorithm: {selectedAttestation.signature_algo}</p>
            </div>
            
            <div style={{ display: "flex", justifyContent: "flex-end", borderTop: "1px solid var(--border)", paddingTop: "16px" }}>
              <button
                type="button"
                className="btn"
                onClick={() => setSelectedAttestation(null)}
              >
                Close
              </button>
            </div>
          </div>
        </SideSheet>
      )}
    </div>
  );
}

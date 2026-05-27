import { FormEvent, useEffect, useRef, useState } from "react";
import { ExternalLink, ScanText } from "lucide-react";
import { apiGet, apiPost } from "../api";
import type { Alert, DlpScanResponse, Endpoint } from "../api";
import { ErrorBanner, LoadingRow, EmptyState, RiskBadge, ActionBadge, PageHeader } from "../components";
import { timeAgo } from "../utils";

export function DlpScanPage() {
  const [endpoints, setEndpoints] = useState<Endpoint[]>([]);
  const [scanHistory, setScanHistory] = useState<Alert[]>([]);
  const [isLoading, setIsLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const [scanText, setScanText] = useState("");
  const [scanEndpointId, setScanEndpointId] = useState("");
  const [scanResult, setScanResult] = useState<DlpScanResponse | null>(null);
  const [isScanning, setIsScanning] = useState(false);

  const mountedRef = useRef(true);

  async function loadContext() {
    try {
      const [eps, allAlerts] = await Promise.all([
        apiGet<Endpoint[]>("/endpoints"),
        apiGet<Alert[]>("/alerts"),
      ]);
      if (mountedRef.current) {
        setEndpoints(eps);
        // Show alerts that originated from DLP scans
        setScanHistory(allAlerts.filter((a) => a.entity_types.length > 0 || a.source.toLowerCase().includes("scan")));
        setError(null);
      }
    } catch (err) {
      if (mountedRef.current) {
        setError(err instanceof Error ? err.message : "Failed to load context");
      }
    } finally {
      if (mountedRef.current) setIsLoading(false);
    }
  }

  useEffect(() => {
    mountedRef.current = true;
    void loadContext();
    return () => { mountedRef.current = false; };
     
  }, []);

  const resolvedEndpointId = endpoints.some((e) => e.id === scanEndpointId) ? scanEndpointId : "";

  async function runScan(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setIsScanning(true);
    setScanResult(null);
    setError(null);

    try {
      const result = await apiPost<DlpScanResponse>("/dlp/scan", {
        text: scanText,
        endpoint_id: resolvedEndpointId || null,
        source: "console manual scan",
      });
      setScanResult(result);
      await loadContext();
    } catch (err) {
      setError(err instanceof Error ? err.message : "DLP scan failed");
    } finally {
      setIsScanning(false);
    }
  }

  return (
    <>
      <PageHeader
        eyebrow="Data loss prevention"
        title="DLP Scanner"
        subtitle="Inspect text for protected entities using the active policy"
      />

      {error ? <ErrorBanner message={error} /> : null}

      {/* Scanner */}
      <section className="panel scanner">
        <div className="panelHeader">
          <div>
            <h2>Scan Content</h2>
            <span>Submit text to run it through the active DLP policy</span>
          </div>
          <ScanText aria-hidden="true" />
        </div>

        <form onSubmit={runScan}>
          <label>
            <span>Endpoint</span>
            <select
              value={resolvedEndpointId}
              onChange={(e) => setScanEndpointId(e.target.value)}
            >
              <option value="">Unassigned manual scan</option>
              {endpoints.map((ep) => (
                <option key={ep.id} value={ep.id}>
                  {ep.hostname}
                </option>
              ))}
            </select>
          </label>
          <textarea
            aria-label="Text to scan for protected data"
            placeholder="Paste text to inspect for protected data…"
            value={scanText}
            onChange={(e) => setScanText(e.target.value)}
          />
          <button disabled={isScanning || scanText.trim().length === 0}>
            {isScanning ? "Scanning…" : "Scan content"}
          </button>
        </form>

        {scanResult ? (
          <div className="findings">
            {/* Assessment summary */}
            <article className={`assessment band-${scanResult.risk_band}`}>
              <header>
                <strong>Risk assessment</strong>
                <div style={{ display: "flex", gap: "8px", alignItems: "center" }}>
                  <ActionBadge action={scanResult.action} />
                  <RiskBadge band={scanResult.risk_band} />
                </div>
              </header>
              <p>Score {scanResult.risk_score}/100</p>
              {scanResult.rationale ? <small>{scanResult.rationale}</small> : null}
              {scanResult.context_signals.length > 0 ? (
                <ul className="signals">
                  {scanResult.context_signals.map((s) => (
                    <li key={s}>{s.replaceAll("_", " ")}</li>
                  ))}
                </ul>
              ) : null}
            </article>

            {/* Finding cards */}
            {scanResult.findings.map((f) => (
              <article
                className="finding"
                key={`${f.entity_type}-${f.start}-${f.end}`}
              >
                <strong>{f.entity_type.replaceAll("_", " ")}</strong>
                <span>{f.text}</span>
                <small>{Math.round(f.score * 100)}% confidence</small>
              </article>
            ))}
            {scanResult.findings.length === 0 ? (
              <p style={{ gridColumn: "1/-1", margin: 0, color: "var(--muted)" }}>
                No protected entities detected.
              </p>
            ) : null}
          </div>
        ) : null}
      </section>

      {/* Scan history */}
      <section className="panel" style={{ marginTop: "18px" }}>
        <div className="panelHeader">
          <h2>Scan Event History</h2>
          <span>{scanHistory.length} DLP events</span>
        </div>

        <div className="endpointList">
          {scanHistory.slice(0, 20).map((alert) => (
            <article className="endpoint" key={alert.id} style={{ gridTemplateColumns: "1fr auto auto" }}>
              <div>
                <strong
                  className="linkLike"
                  role="button"
                  tabIndex={0}
                  onClick={() => window.dispatchEvent(new CustomEvent("aetherix:navigate", { detail: { page: "alerts" } }))}
                  onKeyDown={(e) => { if (e.key === "Enter") window.dispatchEvent(new CustomEvent("aetherix:navigate", { detail: { page: "alerts" } })); }}
                >
                  {alert.title} <ExternalLink size={12} />
                </strong>
                <p>
                  {alert.source} · {timeAgo(alert.created_at)}
                </p>
                {alert.entity_types.length > 0 ? (
                  <div className="signals" style={{ marginTop: "6px" }}>
                    {alert.entity_types.map((e) => (
                      <li key={e}>{e.replaceAll("_", " ")}</li>
                    ))}
                  </div>
                ) : null}
              </div>
              <span className={alert.status === "open" ? "attention" : "healthy"}>
                {alert.status}
              </span>
            </article>
          ))}
          {isLoading ? <LoadingRow label="Loading scan history" /> : null}
          {!isLoading && scanHistory.length === 0 ? (
            <EmptyState>No DLP scan events recorded yet.</EmptyState>
          ) : null}
        </div>
      </section>
    </>
  );
}

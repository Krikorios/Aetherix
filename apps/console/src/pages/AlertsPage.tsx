import { useEffect, useRef, useState } from "react";
import { TriangleAlert, Check, LoaderCircle, ChevronDown, ChevronRight, FileText, Fingerprint, Expand, ShieldCheck } from "lucide-react";
import { apiGet, apiPatch } from "../api";
import type { Alert, CorrelationResponse, CorrelationLink } from "../api";
import { ErrorBanner, LoadingRow, EmptyState, SeverityBadge, PageHeader } from "../components";
import { timeAgo } from "../utils";

type StatusFilter = "all" | "open" | "acknowledged";
type SeverityFilter = "all" | "high" | "medium" | "low";

function CorrelationDetail({ alert }: { alert: Alert }) {
  const [data, setData] = useState<CorrelationResponse | null>(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    setLoading(true);
    apiGet<CorrelationResponse>(`/security-alerts/${alert.id}/correlations`)
      .then(setData)
      .catch(() => setData(null))
      .finally(() => setLoading(false));
  }, [alert.id]);

  if (loading) return <div className="correlationLoading">Loading correlation data...</div>;
  if (!data || data.correlations.length === 0) return <div className="correlationEmpty">No related signals found for this alert.</div>;

  const evidenceByFile = data.correlations.filter((c) => c.correlation_type === "file_path_match" && c.related_kind !== "dlp_event");
  const evidenceBySha = data.correlations.filter((c) => c.correlation_type === "sha256_match" && c.related_kind !== "dlp_event");
  const evidenceByProcess = data.correlations.filter((c) => c.correlation_type === "process_path_match");
  const evidenceByDlp = data.correlations.filter((c) => c.related_kind === "dlp_event");

  return (
    <div className="correlationDetail">
      {data.severity_uplifted_from ? (
        <div className="correlationUpliftBadge">
          Severity auto-uplifted from <strong>{data.severity_uplifted_from}</strong> to <strong>{data.severity}</strong>
        </div>
      ) : null}
      <div className="correlationCount">{data.correlations.length} supporting signal{data.correlations.length !== 1 ? "s" : ""}</div>

      {evidenceByFile.length > 0 && (
        <div className="correlationSection">
          <h4><FileText size={14} /> File Path Matches</h4>
          <ul>
            {evidenceByFile.map((link) => (
              <li key={link.id}>
                <code>{link.evidence.file_path as string || "unknown path"}</code>
                {link.evidence.event_type ? <span className="corrEventType">{link.evidence.event_type as string}</span> : null}
                <span className="corrTime">{timeAgo(link.created_at)}</span>
              </li>
            ))}
          </ul>
        </div>
      )}

      {evidenceBySha.length > 0 && (
        <div className="correlationSection">
          <h4><Fingerprint size={14} /> SHA-256 Hash Matches</h4>
          <ul>
            {evidenceBySha.map((link) => (
              <li key={link.id}>
                <code className="corrHash">{link.evidence.sha256_hash as string || "—"}</code>
                <span className="corrTime">{timeAgo(link.created_at)}</span>
              </li>
            ))}
          </ul>
        </div>
      )}

      {evidenceByProcess.length > 0 && (
        <div className="correlationSection">
          <h4><Expand size={14} /> Process Path Matches</h4>
          <ul>
            {evidenceByProcess.map((link) => (
              <li key={link.id}>
                <code>{link.evidence.process_path as string || "unknown"}</code>
                <span className="corrTime">{timeAgo(link.created_at)}</span>
              </li>
            ))}
          </ul>
        </div>
      )}

      {evidenceByDlp.length > 0 && (
        <div className="correlationSection">
          <h4><ShieldCheck size={14} /> DLP Detection Matches</h4>
          <ul>
            {evidenceByDlp.map((link) => (
              <li key={link.id}>
                <code>{link.evidence.sha256_hash as string || "—"}</code>
                <span className="corrMeta">
                  {link.evidence.source as string}
                  {link.evidence.risk_band ? ` · ${link.evidence.risk_band as string} risk` : null}
                  {link.evidence.action ? ` · action: ${link.evidence.action as string}` : null}
                </span>
                <span className="corrTime">{timeAgo(link.created_at)}</span>
              </li>
            ))}
          </ul>
        </div>
      )}
    </div>
  );
}

export function AlertsPage() {
  const [alerts, setAlerts] = useState<Alert[]>([]);
  const [isLoading, setIsLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [acknowledgingId, setAcknowledgingId] = useState<string | null>(null);
  const [statusFilter, setStatusFilter] = useState<StatusFilter>("open");
  const [severityFilter, setSeverityFilter] = useState<SeverityFilter>("all");
  const [expandedAlertId, setExpandedAlertId] = useState<string | null>(null);
  const mountedRef = useRef(true);

  async function load() {
    try {
      const next = await apiGet<Alert[]>("/alerts");
      if (mountedRef.current) {
        setAlerts(next);
        setError(null);
      }
    } catch (err) {
      if (mountedRef.current) {
        setError(err instanceof Error ? err.message : "Failed to load alerts");
      }
    } finally {
      if (mountedRef.current) setIsLoading(false);
    }
  }

  useEffect(() => {
    mountedRef.current = true;
    void load();
    const timer = setInterval(() => void load(), 20_000);
    return () => {
      mountedRef.current = false;
      clearInterval(timer);
    };
     
  }, []);

  async function acknowledge(alertId: string) {
    setAcknowledgingId(alertId);
    try {
      await apiPatch(`/alerts/${alertId}/acknowledge`);
      await load();
    } catch (err) {
      setError(err instanceof Error ? err.message : "Acknowledge failed");
    } finally {
      setAcknowledgingId(null);
    }
  }

  function toggleExpand(alertId: string) {
    setExpandedAlertId((prev) => (prev === alertId ? null : alertId));
  }

  const filtered = alerts.filter((a) => {
    if (statusFilter !== "all" && a.status !== statusFilter) return false;
    if (severityFilter !== "all" && a.severity !== severityFilter) return false;
    return true;
  });

  const openCount = alerts.filter((a) => a.status === "open").length;

  return (
    <>
      <PageHeader
        eyebrow="Security operations"
        title="Alerts"
        subtitle={`${openCount} open · ${alerts.length} total`}
      />

      {error ? <ErrorBanner message={error} /> : null}

      {/* Status filters */}
      <div className="filterBar">
        <span className="filterLabel">Status</span>
        {(["open", "all", "acknowledged"] as StatusFilter[]).map((f) => (
          <button
            key={f}
            className={`filterChip${statusFilter === f ? " active" : ""}`}
            onClick={() => setStatusFilter(f)}
          >
            {f === "all" ? "All" : f === "open" ? `Open (${openCount})` : "Acknowledged"}
          </button>
        ))}
        <span className="filterDivider" />
        <span className="filterLabel">Severity</span>
        {(["all", "high", "medium", "low"] as SeverityFilter[]).map((f) => (
          <button
            key={f}
            className={`filterChip${severityFilter === f ? " active" : ""}`}
            onClick={() => setSeverityFilter(f)}
          >
            {f === "all" ? "All" : f}
          </button>
        ))}
      </div>

      <div className="panel alertsPanel">
        <div className="alertsTableHead">
          <span>Alert</span>
          <span>Severity</span>
          <span>Source</span>
          <span>Entities</span>
          <span>Time</span>
          <span />
        </div>

        {filtered.map((alert) => (
          <div key={alert.id}>
            <article
              className={`alertRow${alert.status === "acknowledged" ? " acknowledged" : ""}${expandedAlertId === alert.id ? " expanded" : ""}`}
              onClick={() => toggleExpand(alert.id)}
              role="button"
              tabIndex={0}
              onKeyDown={(e) => { if (e.key === "Enter" || e.key === " ") { e.preventDefault(); toggleExpand(alert.id); }}}
            >
              <div className="alertRowTitle">
                <TriangleAlert aria-hidden="true" />
                <div>
                  <strong>{alert.title}</strong>
                  <p>{alert.recommended_action}</p>
                </div>
              </div>

              <span className="alertSeverityCell">
                <SeverityBadge severity={alert.severity} />
                {alert.severity_uplifted_from ? (
                  <span className="upliftedLabel" title={`Originally ${alert.severity_uplifted_from}`}>
                    ↑ {alert.severity_uplifted_from}
                  </span>
                ) : null}
              </span>

              <span className="alertMeta">{alert.source}</span>

              <span className="alertEntities">
                {alert.entity_types.length > 0
                  ? alert.entity_types.map((e) => (
                      <span key={e} className="entityChip">
                        {e.replaceAll("_", " ")}
                      </span>
                    ))
                  : <span className="dimText">—</span>}
              </span>

              <span className="alertMeta">{timeAgo(alert.created_at)}</span>

              <span className="alertActionCell">
                {expandedAlertId === alert.id ? <ChevronDown size={16} /> : <ChevronRight size={16} />}
                {alert.status === "open" ? (
                  <button
                    className="btnAck"
                    disabled={acknowledgingId === alert.id}
                    onClick={(e) => { e.stopPropagation(); void acknowledge(alert.id); }}
                    aria-label={`Acknowledge: ${alert.title}`}
                  >
                    {acknowledgingId === alert.id ? (
                      <LoaderCircle aria-hidden="true" />
                    ) : (
                      <Check aria-hidden="true" />
                    )}
                    <span>{acknowledgingId === alert.id ? "…" : "Ack"}</span>
                  </button>
                ) : (
                  <span className="ackedLabel">Acknowledged</span>
                )}
              </span>
            </article>

            {expandedAlertId === alert.id ? (
              <div className="alertDetailRow">
                <CorrelationDetail alert={alert} />
              </div>
            ) : null}
          </div>
        ))}

        {isLoading ? <LoadingRow label="Loading alerts" /> : null}
        {!isLoading && filtered.length === 0 ? (
          <EmptyState>No alerts match the current filters.</EmptyState>
        ) : null}
      </div>
    </>
  );
}

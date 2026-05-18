import { useEffect, useRef, useState } from "react";
import { TriangleAlert, Check, LoaderCircle } from "lucide-react";
import { apiGet, apiPatch } from "../api";
import type { Alert } from "../api";
import { ErrorBanner, LoadingRow, EmptyState, SeverityBadge, PageHeader } from "../components";
import { timeAgo } from "../utils";

type StatusFilter = "all" | "open" | "acknowledged";
type SeverityFilter = "all" | "high" | "medium" | "low";

export function AlertsPage() {
  const [alerts, setAlerts] = useState<Alert[]>([]);
  const [isLoading, setIsLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [acknowledgingId, setAcknowledgingId] = useState<string | null>(null);
  const [statusFilter, setStatusFilter] = useState<StatusFilter>("open");
  const [severityFilter, setSeverityFilter] = useState<SeverityFilter>("all");
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
    // eslint-disable-next-line react-hooks/exhaustive-deps
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
          <article
            key={alert.id}
            className={`alertRow${alert.status === "acknowledged" ? " acknowledged" : ""}`}
          >
            <div className="alertRowTitle">
              <TriangleAlert aria-hidden="true" />
              <div>
                <strong>{alert.title}</strong>
                <p>{alert.recommended_action}</p>
              </div>
            </div>

            <span>
              <SeverityBadge severity={alert.severity} />
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

            <span>
              {alert.status === "open" ? (
                <button
                  className="btnAck"
                  disabled={acknowledgingId === alert.id}
                  onClick={() => void acknowledge(alert.id)}
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
        ))}

        {isLoading ? <LoadingRow label="Loading alerts" /> : null}
        {!isLoading && filtered.length === 0 ? (
          <EmptyState>No alerts match the current filters.</EmptyState>
        ) : null}
      </div>
    </>
  );
}

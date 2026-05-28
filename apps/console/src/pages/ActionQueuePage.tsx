import React, { useState, useEffect, useCallback, useRef } from "react";
import {
  RefreshCw,
  ClipboardList,
  CircleX,
  CheckCircle,
  Clock,
  AlertTriangle,
  Ban,
  Loader2,
  Building2,
  Cpu,
  ChevronDown,
  ChevronRight,
  Play,
} from "lucide-react";
import { apiGet, apiPost, type MeResponse, type QueuedActionItem, type ModuleActionStatus } from "../api";
import { ConsolePage, ErrorBanner, PageHeader, SuccessBanner } from "../components";

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

const STATUS_LABEL: Record<ModuleActionStatus, string> = {
  queued: "Queued",
  awaiting_approval: "Awaiting Approval",
  completed: "Completed",
  failed: "Failed",
  denied: "Denied",
  cancelled: "Cancelled",
};

const STATUS_CLASS: Record<ModuleActionStatus, string> = {
  queued: "queueStatusQueued",
  awaiting_approval: "queueStatusPending",
  completed: "queueStatusDone",
  failed: "queueStatusFailed",
  denied: "queueStatusDenied",
  cancelled: "queueStatusCancelled",
};

const STATUS_ICON: Record<ModuleActionStatus, React.ReactNode> = {
  queued: <Clock size={13} />,
  awaiting_approval: <AlertTriangle size={13} />,
  completed: <CheckCircle size={13} />,
  failed: <CircleX size={13} />,
  denied: <Ban size={13} />,
  cancelled: <Ban size={13} />,
};

type LogEntry = {
  id: string;
  time: string;
  message: string;
  kind: "info" | "success" | "error" | "warn";
};

function formatAction(action: string): string {
  return action.replace(/_/g, " ").replace(/\b\w/g, (c) => c.toUpperCase());
}

function formatTs(iso: string): string {
  return new Date(iso).toLocaleString("en-US", {
    month: "short",
    day: "numeric",
    hour: "2-digit",
    minute: "2-digit",
    second: "2-digit",
  });
}

const FILTER_TABS: { key: string; label: string }[] = [
  { key: "", label: "All" },
  { key: "queued", label: "Queued" },
  { key: "awaiting_approval", label: "Awaiting Approval" },
  { key: "completed", label: "Completed" },
  { key: "failed", label: "Failed" },
  { key: "cancelled", label: "Cancelled" },
];

// ---------------------------------------------------------------------------
// Page component
// ---------------------------------------------------------------------------

export function ActionQueuePage({ me }: { me: MeResponse }) {
  const [items, setItems] = useState<QueuedActionItem[]>([]);
  const [isLoading, setIsLoading] = useState(true);
  const [isRefreshing, setIsRefreshing] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [success, setSuccess] = useState<string | null>(null);
  const [statusFilter, setStatusFilter] = useState<string>("");
  const [actionFilter, setActionFilter] = useState<string>("");
  const [autoRefresh, setAutoRefresh] = useState(true);
  const [cancellingId, setCancellingId] = useState<string | null>(null);
  const [expandedId, setExpandedId] = useState<string | null>(null);
  const [log, setLog] = useState<LogEntry[]>([]);
  const logRef = useRef<HTMLDivElement>(null);
  const intervalRef = useRef<ReturnType<typeof setInterval> | null>(null);

  const addLog = useCallback((message: string, kind: LogEntry["kind"] = "info") => {
    const entry: LogEntry = {
      id: `${Date.now()}-${Math.random()}`,
      time: new Date().toLocaleTimeString("en-US", { hour: "2-digit", minute: "2-digit", second: "2-digit" }),
      message,
      kind,
    };
    setLog((prev) => [entry, ...prev].slice(0, 200));
  }, []);

  const fetchQueue = useCallback(
    async (silent = false) => {
      if (!silent) setIsLoading(true);
      else setIsRefreshing(true);
      try {
        const params = new URLSearchParams();
        if (statusFilter) params.set("status", statusFilter);
        if (actionFilter.trim()) params.set("action", actionFilter.trim());
        params.set("limit", "200");
        const qs = params.toString() ? `?${params.toString()}` : "";
        const data = await apiGet<QueuedActionItem[]>(`/actions/queue${qs}`);

        setItems((prev) => {
          // Detect status transitions and log them
          const prevMap = new Map(prev.map((p) => [p.id, p]));
          for (const next of data) {
            const old = prevMap.get(next.id);
            if (old && old.status !== next.status) {
              const kind =
                next.status === "completed"
                  ? "success"
                  : next.status === "failed" || next.status === "denied" || next.status === "cancelled"
                  ? "error"
                  : "info";
              addLog(
                `[${next.hostname}] ${formatAction(next.action)} → ${STATUS_LABEL[next.status]}`,
                kind,
              );
            }
          }
          // Log new arrivals
          const prevIds = new Set(prev.map((p) => p.id));
          for (const next of data) {
            if (!prevIds.has(next.id)) {
              addLog(`[${next.hostname}] ${formatAction(next.action)} queued`, "info");
            }
          }
          return data;
        });

        setError(null);
      } catch (err) {
        if (!silent) setError(err instanceof Error ? err.message : "Failed to load action queue.");
      } finally {
        if (!silent) setIsLoading(false);
        else setIsRefreshing(false);
      }
    },
    [statusFilter, actionFilter, addLog],
  );

  // Initial load + re-load when filters change
  useEffect(() => {
    void fetchQueue(false);
  }, [fetchQueue]);

  // Auto-refresh every 4 s
  useEffect(() => {
    if (!autoRefresh) {
      if (intervalRef.current) clearInterval(intervalRef.current);
      return;
    }
    intervalRef.current = setInterval(() => {
      void fetchQueue(true);
    }, 4000);
    return () => {
      if (intervalRef.current) clearInterval(intervalRef.current);
    };
  }, [autoRefresh, fetchQueue]);

  // Scroll log to top on new entries
  useEffect(() => {
    if (logRef.current) logRef.current.scrollTop = 0;
  }, [log]);

  const handleCancel = async (item: QueuedActionItem) => {
    setCancellingId(item.id);
    setError(null);
    try {
      await apiPost<void>(`/actions/${item.id}/cancel`, {});
      addLog(`[${item.hostname}] ${formatAction(item.action)} cancelled by operator`, "warn");
      setSuccess(`Cancelled: ${formatAction(item.action)} on ${item.hostname}`);
      setItems((prev) =>
        prev.map((i) => (i.id === item.id ? { ...i, status: "cancelled" } : i)),
      );
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to cancel action.");
      addLog(`Failed to cancel ${formatAction(item.action)} on ${item.hostname}`, "error");
    } finally {
      setCancellingId(null);
    }
  };

  // Derived counts for the summary bar
  const counts = {
    queued: items.filter((i) => i.status === "queued").length,
    awaiting_approval: items.filter((i) => i.status === "awaiting_approval").length,
    completed: items.filter((i) => i.status === "completed").length,
    failed: items.filter((i) => i.status === "failed").length,
    cancelled: items.filter((i) => i.status === "cancelled").length,
  };

  const visibleItems = items; // already filtered server-side; client-side action text filter
  const actionTypes = [...new Set(items.map((i) => i.action))].sort();

  return (
    <ConsolePage>
      <div className="queuePage">
        {/* ── Header ── */}
        <div className="queueHeaderRow">
          <PageHeader
            eyebrow="MSP Control"
            title="Queue"
            subtitle={`${items.length} action${items.length === 1 ? "" : "s"} · ${counts.queued} queued · ${counts.awaiting_approval} pending approval`}
          />
          <div className="queueHeaderActions">
            <label className="queueAutoRefreshToggle">
              <input
                type="checkbox"
                checked={autoRefresh}
                onChange={(e) => setAutoRefresh(e.target.checked)}
              />
              Auto-refresh
            </label>
            <button
              className="btn"
              type="button"
              onClick={() => void fetchQueue(false)}
              disabled={isRefreshing}
              title="Refresh now"
            >
              <RefreshCw size={14} className={isRefreshing ? "spin" : ""} />
              Refresh
            </button>
          </div>
        </div>

        {error && <ErrorBanner message={error} />}
        {success && (
          <SuccessBanner
            message={success}
          />
        )}

        {/* ── Summary chips ── */}
        <div className="queueSummaryBar">
          {Object.entries(counts).map(([k, v]) => (
            <button
              key={k}
              type="button"
              className={`queueSummaryChip${statusFilter === k ? " active" : ""}`}
              onClick={() => setStatusFilter((cur) => (cur === k ? "" : k))}
            >
              {STATUS_ICON[k as ModuleActionStatus]}
              <span>{STATUS_LABEL[k as ModuleActionStatus]}</span>
              <strong>{v}</strong>
            </button>
          ))}
        </div>

        {/* ── Filters ── */}
        <div className="queueFilters">
          <div className="queueFilterTabs">
            {FILTER_TABS.map((tab) => (
              <button
                key={tab.key}
                type="button"
                className={`queueFilterTab${statusFilter === tab.key ? " active" : ""}`}
                onClick={() => setStatusFilter(tab.key)}
              >
                {tab.label}
              </button>
            ))}
          </div>
          <div className="queueFilterRight">
            <select
              className="queueActionSelect"
              value={actionFilter}
              onChange={(e) => setActionFilter(e.target.value)}
              aria-label="Filter by action type"
            >
              <option value="">All action types</option>
              {actionTypes.map((a) => (
                <option key={a} value={a}>{formatAction(a)}</option>
              ))}
            </select>
          </div>
        </div>

        {/* ── Table + Log split ── */}
        <div className="queueWorkspace">
          {/* Table */}
          <div className="queueTableWrap">
            {isLoading ? (
              <div className="queueLoadingCell">
                <Loader2 size={20} className="spin" />
                <span>Loading queue…</span>
              </div>
            ) : visibleItems.length === 0 ? (
              <div className="queueEmptyCell">
                <ClipboardList size={32} style={{ opacity: 0.25 }} />
                <span>No actions match the current filters.</span>
              </div>
            ) : (
              <table className="dataTable queueTable">
                <thead>
                  <tr>
                    <th style={{ width: 28 }} />
                    <th>Action</th>
                    <th>Endpoint</th>
                    <th>Company</th>
                    <th>Status</th>
                    <th>Requested By</th>
                    <th>Created</th>
                    <th>Finished</th>
                    <th style={{ width: 100 }}>Actions</th>
                  </tr>
                </thead>
                <tbody>
                  {visibleItems.map((item) => {
                    const isExpanded = expandedId === item.id;
                    return (
                      <React.Fragment key={item.id}>
                        <tr
                          className={`queueRow${item.status === "queued" ? " queueRowActive" : ""}${isExpanded ? " queueRowExpanded" : ""}`}
                          onClick={() => setExpandedId((cur) => (cur === item.id ? null : item.id))}
                        >
                          <td className="queueExpandCell">
                            {isExpanded ? <ChevronDown size={14} /> : <ChevronRight size={14} />}
                          </td>
                          <td>
                            <div className="queueActionCell">
                              <Play size={13} className="queueActionIcon" />
                              <span className="queueActionName">{formatAction(item.action)}</span>
                            </div>
                          </td>
                          <td>
                            <div className="queueEndpointCell">
                              <Cpu size={13} />
                              <span>{item.hostname}</span>
                            </div>
                          </td>
                          <td>
                            {item.customer_name ? (
                              <div className="queueCompanyCell">
                                <Building2 size={13} />
                                <span>{item.customer_name}</span>
                              </div>
                            ) : (
                              <span className="queueMuted">—</span>
                            )}
                          </td>
                          <td onClick={(e) => e.stopPropagation()}>
                            <span className={`queueStatusBadge ${STATUS_CLASS[item.status]}`}>
                              {STATUS_ICON[item.status]}
                              {STATUS_LABEL[item.status]}
                            </span>
                          </td>
                          <td>
                            <span className="queueMuted" style={{ fontSize: 12 }}>
                              {item.requested_by ?? "system"}
                            </span>
                          </td>
                          <td>
                            <time className="queueTs" dateTime={item.created_at}>
                              {formatTs(item.created_at)}
                            </time>
                          </td>
                          <td>
                            {item.processed_at ? (
                              <time className="queueTs" dateTime={item.processed_at}>
                                {formatTs(item.processed_at)}
                              </time>
                            ) : (
                              <span className="queueMuted">—</span>
                            )}
                          </td>
                          <td onClick={(e) => e.stopPropagation()}>
                            {item.status === "queued" ? (
                              <button
                                type="button"
                                className="btn queueCancelBtn"
                                disabled={cancellingId === item.id}
                                onClick={() => void handleCancel(item)}
                                title="Cancel this queued action"
                              >
                                {cancellingId === item.id ? (
                                  <Loader2 size={12} className="spin" />
                                ) : (
                                  <CircleX size={12} />
                                )}
                                Cancel
                              </button>
                            ) : null}
                          </td>
                        </tr>

                        {isExpanded ? (
                          <tr className="queueDetailRow">
                            <td colSpan={9}>
                              <div className="queueDetailBody">
                                <div className="queueDetailSection">
                                  <h4>Action ID</h4>
                                  <code>{item.id}</code>
                                </div>
                                <div className="queueDetailSection">
                                  <h4>Approval Required</h4>
                                  <span>{item.approval_required ? "Yes" : "No"}</span>
                                </div>
                                {item.approved_by ? (
                                  <div className="queueDetailSection">
                                    <h4>Approved By</h4>
                                    <span>{item.approved_by}</span>
                                    {item.approved_at ? (
                                      <time style={{ marginLeft: 8, fontSize: 11, color: "var(--text-muted)" }} dateTime={item.approved_at}>
                                        {formatTs(item.approved_at)}
                                      </time>
                                    ) : null}
                                  </div>
                                ) : null}
                                {item.evidence_controls.length > 0 ? (
                                  <div className="queueDetailSection">
                                    <h4>Evidence Controls</h4>
                                    <div className="queueControlTags">
                                      {item.evidence_controls.map((c) => (
                                        <span key={c} className="queueControlTag">{c}</span>
                                      ))}
                                    </div>
                                  </div>
                                ) : null}
                                {item.payload ? (
                                  <div className="queueDetailSection">
                                    <h4>Payload</h4>
                                    <pre className="queueJsonBlock">{JSON.stringify(item.payload, null, 2)}</pre>
                                  </div>
                                ) : null}
                                {item.result ? (
                                  <div className="queueDetailSection">
                                    <h4>Result</h4>
                                    <pre className="queueJsonBlock">{JSON.stringify(item.result, null, 2)}</pre>
                                  </div>
                                ) : null}
                              </div>
                            </td>
                          </tr>
                        ) : null}
                      </React.Fragment>
                    );
                  })}
                </tbody>
              </table>
            )}
          </div>

          {/* Activity log */}
          <div className="queueLogPanel">
            <div className="queueLogHeader">
              <ClipboardList size={14} />
              <strong>Activity Log</strong>
              <span className="queueMuted" style={{ marginLeft: "auto", fontSize: 11 }}>
                {log.length} event{log.length === 1 ? "" : "s"}
              </span>
              <button
                type="button"
                className="queueLogClear"
                onClick={() => setLog([])}
                title="Clear log"
              >
                Clear
              </button>
            </div>
            <div className="queueLogBody" ref={logRef}>
              {log.length === 0 ? (
                <span className="queueLogEmpty">Listening for events…</span>
              ) : (
                log.map((entry) => (
                  <div key={entry.id} className={`queueLogEntry queueLog${entry.kind.charAt(0).toUpperCase() + entry.kind.slice(1)}`}>
                    <time className="queueLogTime">{entry.time}</time>
                    <span className="queueLogMsg">{entry.message}</span>
                  </div>
                ))
              )}
            </div>
          </div>
        </div>
      </div>
    </ConsolePage>
  );
}

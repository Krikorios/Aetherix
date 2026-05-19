import { useEffect, useRef, useState } from "react";
import { TriangleAlert } from "lucide-react";
import { apiGet, apiPatch } from "../api";
import type { Alert, Endpoint, Policy } from "../api";
import { ErrorBanner, LoadingRow, EmptyState, SeverityBadge, PageHeader } from "../components";
import { timeAgo } from "../utils";

type DashboardData = {
  endpoints: Endpoint[];
  alerts: Alert[];
  policy: Policy | null;
};

async function fetchDashboard(): Promise<DashboardData> {
  const [endpoints, alerts, policyResult] = await Promise.allSettled([
    apiGet<Endpoint[]>("/endpoints"),
    apiGet<Alert[]>("/alerts"),
    apiGet<Policy>("/policies/active"),
  ]);

  return {
    endpoints: endpoints.status === "fulfilled" ? endpoints.value : [],
    alerts: alerts.status === "fulfilled" ? alerts.value : [],
    policy: policyResult.status === "fulfilled" ? policyResult.value : null,
  };
}

export function DashboardPage() {
  const [data, setData] = useState<DashboardData>({ endpoints: [], alerts: [], policy: null });
  const [isLoading, setIsLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [acknowledgingId, setAcknowledgingId] = useState<string | null>(null);
  const mountedRef = useRef(true);

  async function load() {
    try {
      const next = await fetchDashboard();
      if (mountedRef.current) {
        setData(next);
        setError(null);
      }
    } catch (err) {
      if (mountedRef.current) {
        setError(err instanceof Error ? err.message : "Failed to load dashboard");
      }
    } finally {
      if (mountedRef.current) setIsLoading(false);
    }
  }

  useEffect(() => {
    mountedRef.current = true;
    void load();
    const timer = setInterval(() => void load(), 30_000);
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

  const { endpoints, alerts, policy } = data;
  const openAlerts = alerts.filter((a) => a.status === "open");
  const highSeverityOpen = openAlerts.filter((a) => a.severity === "high");
  const healthyCount = endpoints.filter((e) => e.status === "healthy").length;

  return (
    <>
      <PageHeader
        eyebrow="MSP control plane"
        title="Operations dashboard"
        subtitle={policy ? `${policy.name} · ${policy.mode} mode` : isLoading ? "Loading active policy…" : "No active policy"}
      />

      {error ? <ErrorBanner message={error} /> : null}

      {/* Metrics */}
      <section className="metrics" aria-label="Security metrics">
        <Metric label="Protected endpoints" value={isLoading ? "…" : String(endpoints.length)} />
        <Metric label="Healthy" value={isLoading ? "…" : String(healthyCount)} accent />
        <Metric label="Open alerts" value={isLoading ? "…" : String(openAlerts.length)} warn={openAlerts.length > 0} />
        <Metric label="High severity" value={isLoading ? "…" : String(highSeverityOpen.length)} warn={highSeverityOpen.length > 0} />
      </section>

      {/* Main grid */}
      <section className="grid">
        {/* Endpoint inventory */}
        <div className="panel">
          <div className="panelHeader">
            <div>
              <h2>Endpoint Inventory</h2>
            </div>
            <span>{isLoading ? "Loading" : `${endpoints.length} reporting`}</span>
          </div>
          <div className="endpointList">
            {endpoints.map((ep) => (
              <article className="endpoint" key={ep.id}>
                <div>
                  <strong>{ep.hostname}</strong>
                  <p>
                    {ep.os} · agent {ep.agent_version} · {timeAgo(ep.last_seen)}
                  </p>
                </div>
                <meter min={0} max={100} value={ep.risk_score} aria-label={`${ep.hostname} risk score`} />
                <span className={ep.status}>{ep.status}</span>
              </article>
            ))}
            {isLoading ? <LoadingRow label="Loading endpoint telemetry" /> : null}
            {!isLoading && endpoints.length === 0 ? (
              <EmptyState>No endpoints have reported heartbeat telemetry.</EmptyState>
            ) : null}
          </div>
        </div>

        {/* Recent open alerts */}
        <div className="panel alerts">
          <div className="panelHeader">
            <h2>High-Signal Alerts</h2>
            <span>{openAlerts.length} open</span>
          </div>
          {openAlerts.slice(0, 8).map((alert) => (
            <article className="alert" key={alert.id}>
              <TriangleAlert aria-hidden="true" />
              <div>
                <p>{alert.title}</p>
                <small>
                  <SeverityBadge severity={alert.severity} /> · {alert.source} · {timeAgo(alert.created_at)}
                </small>
              </div>
              <button
                className="btnAck"
                disabled={acknowledgingId === alert.id}
                onClick={() => void acknowledge(alert.id)}
                aria-label={`Acknowledge: ${alert.title}`}
              >
                {acknowledgingId === alert.id ? "…" : "Ack"}
              </button>
            </article>
          ))}
          {!isLoading && openAlerts.length === 0 ? (
            <EmptyState>No open alerts from endpoint telemetry or scans.</EmptyState>
          ) : null}
          {isLoading ? <LoadingRow label="Loading alert data" /> : null}
        </div>
      </section>

      {/* Active policy summary */}
      {policy ? (
        <section className="panel policyStrip">
          <div className="panelHeader">
            <div>
              <h2>Active Policy</h2>
              <span>{policy.name}</span>
            </div>
            <div className="policyStripMeta">
              <span className={`modeLabel mode-${policy.mode}`}>{policy.mode}</span>
              <span className="modeDetail">escalate at {policy.escalate_at}</span>
              {policy.genai_guardrail ? <span className="modeDetail">GenAI guardrail on</span> : null}
            </div>
          </div>
          {policy.protected_entities.length > 0 ? (
            <div className="signals">
              {policy.protected_entities.map((e) => (
                <li key={e} className="signals li">{e.replaceAll("_", " ")}</li>
              ))}
            </div>
          ) : null}
        </section>
      ) : null}
    </>
  );
}

function Metric({
  label,
  value,
  accent,
  warn,
}: {
  label: string;
  value: string;
  accent?: boolean;
  warn?: boolean;
}) {
  return (
    <article className="metric">
      <span>{label}</span>
      <strong style={accent ? { color: "var(--healthy)" } : warn ? { color: "var(--warning)" } : undefined}>
        {value}
      </strong>
    </article>
  );
}

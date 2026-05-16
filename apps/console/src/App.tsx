import { FormEvent, useEffect, useState } from "react";
import { Activity, Bell, BrainCircuit, LoaderCircle, ScanText, ShieldCheck, TriangleAlert } from "lucide-react";

type Endpoint = {
  id: string;
  hostname: string;
  os: string;
  status: "healthy" | "attention";
  risk_score: number;
};

type Policy = {
  id: string;
  name: string;
  mode: string;
  protected_entities: string[];
};

type Alert = {
  id: string;
  title: string;
  severity: "low" | "medium" | "high";
  endpoint_id: string;
  recommended_action: string;
};

type DlpFinding = {
  entity_type: string;
  start: number;
  end: number;
  score: number;
  text: string;
};

type DlpScanResponse = {
  findings: DlpFinding[];
  action: "allow" | "review";
};

const apiBaseUrl = import.meta.env.VITE_API_URL ?? "http://127.0.0.1:8000";
const defaultScanText = "Send jane.doe@example.com the finance export before sharing card 4111 1111 1111 1111.";

export function App() {
  const [endpoints, setEndpoints] = useState<Endpoint[]>([]);
  const [alerts, setAlerts] = useState<Alert[]>([]);
  const [policy, setPolicy] = useState<Policy | null>(null);
  const [isLoading, setIsLoading] = useState(true);
  const [loadError, setLoadError] = useState<string | null>(null);
  const [scanText, setScanText] = useState(defaultScanText);
  const [scanResult, setScanResult] = useState<DlpScanResponse | null>(null);
  const [isScanning, setIsScanning] = useState(false);

  useEffect(() => {
    let isMounted = true;

    async function loadDashboard() {
      try {
        const [endpointsResponse, alertsResponse, policyResponse] = await Promise.all([
          fetch(`${apiBaseUrl}/endpoints`),
          fetch(`${apiBaseUrl}/alerts`),
          fetch(`${apiBaseUrl}/policies/active`),
        ]);

        if (!endpointsResponse.ok || !alertsResponse.ok || !policyResponse.ok) {
          throw new Error("Dashboard API request failed");
        }

        const [nextEndpoints, nextAlerts, nextPolicy] = await Promise.all([
          endpointsResponse.json() as Promise<Endpoint[]>,
          alertsResponse.json() as Promise<Alert[]>,
          policyResponse.json() as Promise<Policy>,
        ]);

        if (isMounted) {
          setEndpoints(nextEndpoints);
          setAlerts(nextAlerts);
          setPolicy(nextPolicy);
          setLoadError(null);
        }
      } catch (error) {
        if (isMounted) {
          setLoadError(error instanceof Error ? error.message : "Unable to load dashboard data");
        }
      } finally {
        if (isMounted) {
          setIsLoading(false);
        }
      }
    }

    loadDashboard();

    return () => {
      isMounted = false;
    };
  }, []);

  async function scanSample(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setIsScanning(true);

    try {
      const response = await fetch(`${apiBaseUrl}/dlp/scan`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ text: scanText }),
      });

      if (!response.ok) {
        throw new Error("DLP scan failed");
      }

      setScanResult((await response.json()) as DlpScanResponse);
    } finally {
      setIsScanning(false);
    }
  }

  return (
    <main className="shell">
      <aside className="rail" aria-label="Primary navigation">
        <ShieldCheck aria-hidden="true" />
        <button aria-label="Operations"><Activity /></button>
        <button aria-label="AI investigations"><BrainCircuit /></button>
        <button aria-label="Alerts"><Bell /></button>
      </aside>

      <section className="workspace">
        <header className="hero">
          <p>Aetherix POC</p>
          <h1>Endpoint security console</h1>
          <span>{policy ? `${policy.name}: ${policy.mode}` : "Loading active policy"}</span>
        </header>

        {loadError ? <div className="banner">{loadError}</div> : null}

        <section className="metrics" aria-label="Security metrics">
          <Metric label="Protected endpoints" value={isLoading ? "..." : String(endpoints.length)} />
          <Metric label="Open alerts" value={isLoading ? "..." : String(alerts.length)} />
          <Metric label="DLP action" value={scanResult?.action ?? "Ready"} />
        </section>

        <section className="grid">
          <div className="panel">
            <div className="panelHeader">
              <h2>Endpoint Inventory</h2>
              <span>{isLoading ? "Loading" : "Live API data"}</span>
            </div>
            <div className="endpointList">
              {endpoints.map((endpoint) => (
                <article className="endpoint" key={endpoint.hostname}>
                  <div>
                    <strong>{endpoint.hostname}</strong>
                    <p>{endpoint.os}</p>
                  </div>
                  <meter min="0" max="100" value={endpoint.risk_score} aria-label={`${endpoint.hostname} risk`} />
                  <span className={endpoint.status}>{endpoint.status}</span>
                </article>
              ))}
              {isLoading ? <LoadingRow /> : null}
            </div>
          </div>

          <div className="panel alerts">
            <div className="panelHeader">
              <h2>High-Signal Alerts</h2>
              <span>Human approval required</span>
            </div>
            {alerts.map((alert) => (
              <article className="alert" key={alert.id}>
                <TriangleAlert aria-hidden="true" />
                <div>
                  <p>{alert.title}</p>
                  <small>{alert.severity} severity • {alert.recommended_action}</small>
                </div>
                <button>Review</button>
              </article>
            ))}
          </div>
        </section>

        <section className="panel scanner">
          <div className="panelHeader">
            <div>
              <h2>GenAI DLP Scan</h2>
              <span>Calls the running FastAPI scanner</span>
            </div>
            <ScanText aria-hidden="true" />
          </div>
          <form onSubmit={scanSample}>
            <textarea value={scanText} onChange={(event) => setScanText(event.target.value)} />
            <button disabled={isScanning || scanText.trim().length === 0}>
              {isScanning ? "Scanning" : "Scan sample"}
            </button>
          </form>
          {scanResult ? (
            <div className="findings">
              {scanResult.findings.map((finding) => (
                <article className="finding" key={`${finding.entity_type}-${finding.start}-${finding.end}`}>
                  <strong>{finding.entity_type}</strong>
                  <span>{finding.text}</span>
                  <small>{Math.round(finding.score * 100)}% confidence</small>
                </article>
              ))}
              {scanResult.findings.length === 0 ? <p>No protected data detected.</p> : null}
            </div>
          ) : null}
        </section>
      </section>
    </main>
  );
}

function Metric({ label, value }: { label: string; value: string }) {
  return (
    <article className="metric">
      <span>{label}</span>
      <strong>{value}</strong>
    </article>
  );
}

function LoadingRow() {
  return (
    <article className="loadingRow">
      <LoaderCircle aria-hidden="true" />
      <span>Loading endpoint telemetry</span>
    </article>
  );
}

import { Activity, Bell, BrainCircuit, ShieldCheck, TriangleAlert } from "lucide-react";

type Endpoint = {
  hostname: string;
  os: string;
  status: "healthy" | "attention";
  riskScore: number;
};

const endpoints: Endpoint[] = [
  { hostname: "finance-macbook", os: "macOS", status: "healthy", riskScore: 18 },
  { hostname: "legal-workstation", os: "Windows", status: "attention", riskScore: 72 },
  { hostname: "build-runner", os: "Linux", status: "healthy", riskScore: 31 },
];

const alerts = [
  "Possible customer PII pasted into browser AI session",
  "Legal workstation missing critical browser patch",
  "USB write policy changed to monitor mode",
];

export function App() {
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
          <span>Default GenAI DLP Guardrail: monitor</span>
        </header>

        <section className="metrics" aria-label="Security metrics">
          <Metric label="Protected endpoints" value="3" />
          <Metric label="Open alerts" value="3" />
          <Metric label="DLP action" value="Review" />
        </section>

        <section className="grid">
          <div className="panel">
            <div className="panelHeader">
              <h2>Endpoint Inventory</h2>
              <span>Live contract mock</span>
            </div>
            <div className="endpointList">
              {endpoints.map((endpoint) => (
                <article className="endpoint" key={endpoint.hostname}>
                  <div>
                    <strong>{endpoint.hostname}</strong>
                    <p>{endpoint.os}</p>
                  </div>
                  <meter min="0" max="100" value={endpoint.riskScore} aria-label={`${endpoint.hostname} risk`} />
                  <span className={endpoint.status}>{endpoint.status}</span>
                </article>
              ))}
            </div>
          </div>

          <div className="panel alerts">
            <div className="panelHeader">
              <h2>High-Signal Alerts</h2>
              <span>Human approval required</span>
            </div>
            {alerts.map((alert) => (
              <article className="alert" key={alert}>
                <TriangleAlert aria-hidden="true" />
                <p>{alert}</p>
                <button>Review</button>
              </article>
            ))}
          </div>
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

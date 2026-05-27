import React, { useState, useEffect } from "react";
import { Plug, RefreshCw, CheckCircle, AlertTriangle, Clock, Link, Loader2, Settings, X } from "lucide-react";
import { ConsolePage, ErrorBanner, PageHeader, SuccessBanner } from "../components";
import { apiGet, apiPost, type MeResponse } from "../api";

export type ConnectorStatus = "connected" | "disconnected" | "error" | "configuring";

export interface Connector {
  id: string;
  name: string;
  category: "psa" | "rmm" | "siem" | "identity" | "billing" | "email";
  description: string;
  status: ConnectorStatus;
  icon_emoji: string;
  last_sync?: string | null;
  error_message?: string | null;
  config_fields: string[];
}

const CATEGORY_LABEL: Record<Connector["category"], string> = {
  psa: "PSA",
  rmm: "RMM",
  siem: "SIEM",
  identity: "Identity",
  billing: "Billing",
  email: "Email",
};

const STATUS_ICON: Record<ConnectorStatus, React.ReactNode> = {
  connected: <CheckCircle size={14} style={{ color: "var(--success)" }} />,
  disconnected: <Clock size={14} style={{ color: "var(--muted)" }} />,
  error: <AlertTriangle size={14} style={{ color: "var(--danger)" }} />,
  configuring: <Loader2 size={14} style={{ color: "var(--accent)" }} className="spin" />,
};

const STATUS_TEXT: Record<ConnectorStatus, string> = {
  connected: "Connected",
  disconnected: "Not connected",
  error: "Error",
  configuring: "Configuring…",
};

export function IntegrationsPage({ me }: { me: MeResponse }) {
  const [isLoading, setIsLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [success, setSuccess] = useState<string | null>(null);
  const [connectors, setConnectors] = useState<Connector[]>([]);
  const [configuringId, setConfiguringId] = useState<string | null>(null);
  const [configValues, setConfigValues] = useState<Record<string, string>>({});
  const [isTesting, setIsTesting] = useState(false);

  const configuringConnector = connectors.find((c) => c.id === configuringId) ?? null;

  useEffect(() => {
    async function load() {
      try {
        const data = await apiGet<Connector[]>("/integrations");
        setConnectors(data);
      } catch (err) {
        setError(err instanceof Error ? err.message : "Failed to load integrations.");
      } finally {
        setIsLoading(false);
      }
    }
    void load();
  }, [me]);

  const handleOpenConfig = (id: string) => {
    setConfiguringId(id);
    setConfigValues({});
  };

  const handleSaveConfig = async () => {
    if (!configuringConnector) return;
    setIsTesting(true);
    try {
      const configured = await apiPost<Connector>(`/integrations/${configuringConnector.id}/configure`, configValues);
      setConnectors((prev) => prev.map((c) => (c.id === configured.id ? configured : c)));
      setSuccess(`${configuringConnector.name} configured and connected.`);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to configure connector.");
      setIsTesting(false);
      return;
    }
    setIsTesting(false);
    setConfiguringId(null);
  };

  const handleDisconnect = async (id: string) => {
    try {
      const disconnected = await apiPost<Connector>(`/integrations/${id}/disconnect`, {});
      setConnectors((prev) => prev.map((c) => (c.id === disconnected.id ? disconnected : c)));
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to disconnect connector.");
      return;
    }
    setSuccess("Connector disconnected.");
  };

  const connected = connectors.filter((c) => c.status === "connected").length;
  const errors = connectors.filter((c) => c.status === "error").length;

  if (isLoading) {
    return (
      <div style={{ padding: "40px", width: "100%", display: "flex", alignItems: "center", gap: "12px", color: "var(--muted)", fontSize: "13px" }}>
        <Loader2 size={16} className="spin" /> Loading integrations…
      </div>
    );
  }

  return (
    <ConsolePage>
      <PageHeader eyebrow="Ecosystem Connectors" title="Integrations" />

      {error && <ErrorBanner message={error} />}
      {success && <SuccessBanner message={success} />}

      {/* Counters */}
      <div style={{ display: "flex", gap: "12px", marginBottom: "24px", flexWrap: "wrap" }}>
        <div className="panel" style={{ padding: "12px 16px", display: "flex", gap: "8px", alignItems: "center" }}>
          <CheckCircle size={16} style={{ color: "var(--success)" }} />
          <span style={{ fontSize: "12px" }}><strong>{connected}</strong> connected</span>
        </div>
        {errors > 0 && (
          <div className="panel" style={{ padding: "12px 16px", display: "flex", gap: "8px", alignItems: "center" }}>
            <AlertTriangle size={16} style={{ color: "var(--danger)" }} />
            <span style={{ fontSize: "12px" }}><strong>{errors}</strong> error{errors > 1 ? "s" : ""}</span>
          </div>
        )}
        <div className="panel" style={{ padding: "12px 16px", display: "flex", gap: "8px", alignItems: "center" }}>
          <Plug size={16} style={{ color: "var(--muted)" }} />
          <span style={{ fontSize: "12px" }}><strong>{connectors.length}</strong> available</span>
        </div>
      </div>

      {/* Connector grid */}
      <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fill, minmax(300px, 1fr))", gap: "14px" }}>
        {connectors.map((c) => (
          <div key={c.id} className="panel" style={{ padding: "18px", display: "flex", flexDirection: "column", gap: "12px" }}>
            <div style={{ display: "flex", alignItems: "center", gap: "10px" }}>
              <span style={{ fontSize: "24px" }}>{c.icon_emoji}</span>
              <div style={{ flex: 1, minWidth: 0 }}>
                <div style={{ display: "flex", alignItems: "center", gap: "6px" }}>
                  <strong style={{ fontSize: "13px" }}>{c.name}</strong>
                  <span style={{ fontSize: "10px", padding: "1px 5px", borderRadius: "3px", background: "rgba(100,116,139,0.15)", color: "var(--muted)", fontWeight: 600 }}>
                    {CATEGORY_LABEL[c.category]}
                  </span>
                </div>
                <div style={{ display: "flex", alignItems: "center", gap: "4px", marginTop: "2px" }}>
                  {STATUS_ICON[c.status]}
                  <span style={{ fontSize: "11px", color: "var(--muted)" }}>{STATUS_TEXT[c.status]}</span>
                  {c.last_sync && (
                    <span style={{ fontSize: "10px", color: "var(--muted)" }}>· synced {new Date(c.last_sync).toLocaleTimeString()}</span>
                  )}
                </div>
              </div>
            </div>
            <p style={{ margin: 0, fontSize: "12px", color: "var(--muted)", lineHeight: 1.5 }}>{c.description}</p>
            {c.error_message && (
              <div style={{ fontSize: "11px", color: "var(--danger)", background: "rgba(239,68,68,0.06)", padding: "6px 10px", borderRadius: "5px" }}>
                {c.error_message}
              </div>
            )}
            <div style={{ display: "flex", gap: "6px", marginTop: "auto" }}>
              {c.status === "connected" ? (
                <>
                  <button className="btn" style={{ flex: 1 }} onClick={() => handleOpenConfig(c.id)}>
                    <Settings size={12} /> Settings
                  </button>
                  <button className="btn" onClick={() => handleDisconnect(c.id)}>
                    <X size={12} />
                  </button>
                </>
              ) : (
                <button className="btn btnPrimary" style={{ flex: 1 }} onClick={() => handleOpenConfig(c.id)}>
                  <Link size={12} /> Connect
                </button>
              )}
            </div>
          </div>
        ))}
      </div>

      {/* Config modal */}
      {configuringConnector && (
        <div
          style={{
            position: "fixed", inset: 0, background: "rgba(0,0,0,0.55)", display: "flex",
            alignItems: "center", justifyContent: "center", zIndex: 1000,
          }}
          onClick={() => setConfiguringId(null)}
        >
          <div
            className="panel"
            style={{ width: "420px", maxWidth: "calc(100vw - 48px)", padding: "24px", display: "flex", flexDirection: "column", gap: "16px" }}
            onClick={(e) => e.stopPropagation()}
          >
            <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between" }}>
              <div style={{ display: "flex", alignItems: "center", gap: "8px" }}>
                <span style={{ fontSize: "20px" }}>{configuringConnector.icon_emoji}</span>
                <h3 style={{ margin: 0, fontSize: "14px" }}>Configure {configuringConnector.name}</h3>
              </div>
              <button className="btn" onClick={() => setConfiguringId(null)}><X size={13} /></button>
            </div>
            <div style={{ display: "flex", flexDirection: "column", gap: "10px" }}>
              {configuringConnector.config_fields.map((field) => (
                <div key={field} style={{ display: "flex", flexDirection: "column", gap: "4px", fontSize: "12px", color: "var(--muted)" }}>
                  {field.replace(/_/g, " ")}
                  <input
                    className="input"
                    type={field.includes("key") || field.includes("secret") || field.includes("token") ? "password" : "text"}
                    placeholder={field}
                    value={configValues[field] ?? ""}
                    onChange={(e) => setConfigValues((prev) => ({ ...prev, [field]: e.target.value }))}
                  />
                </div>
              ))}
            </div>
            <div style={{ display: "flex", gap: "8px", justifyContent: "flex-end" }}>
              <button className="btn" onClick={() => setConfiguringId(null)}>Cancel</button>
              <button className="btn btnPrimary" onClick={handleSaveConfig} disabled={isTesting}>
                {isTesting ? <><Loader2 size={13} className="spin" /> Testing…</> : "Save & Connect"}
              </button>
            </div>
          </div>
        </div>
      )}
    </ConsolePage>
  );
}

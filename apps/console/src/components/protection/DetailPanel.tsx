import React from "react";
import { Terminal, User, Cpu } from "lucide-react";
import { Detection } from "./types";
import { EmptyState } from "./EmptyState";

interface DetailPanelProps {
  detection: Detection | null;
  /** Custom renderer for specific contexts (e.g. custom tree view, network connections, complex config). */
  customContextRenderer?: (detection: Detection) => React.ReactNode;
}

export function DetailPanel({ detection, customContextRenderer }: DetailPanelProps) {
  if (!detection) {
    return (
      <article className="panel" style={{ flex: 1, display: "flex", flexDirection: "column", minWidth: "300px" }}>
        <div className="panelHeader" style={{ paddingBottom: "12px", borderBottom: "1px solid var(--line)" }}>
          <div>
            <h2 style={{ fontSize: "16px", margin: 0 }}>Incident Context & Analysis</h2>
            <span style={{ fontSize: "12px", color: "var(--muted)" }}>No alert selected</span>
          </div>
        </div>
        <div style={{ flex: 1, display: "flex", alignItems: "center", justifyContent: "center", padding: "16px" }}>
          <EmptyState message="Select an item from the detections list on the left to inspect detail telemetry, MITRE mappings, and associated process logs." />
        </div>
      </article>
    );
  }

  const { context } = detection;

  return (
    <article className="panel" style={{ flex: 1, display: "flex", flexDirection: "column", minWidth: "300px" }}>
      <div className="panelHeader" style={{ paddingBottom: "12px", borderBottom: "1px solid var(--line)", marginBottom: "16px" }}>
        <div>
          <h2 style={{ fontSize: "16px", margin: 0 }}>Incident Context & Analysis</h2>
          <span style={{ fontSize: "12px", color: "var(--muted)" }}>Threat telemetry for {detection.endpoint_name}</span>
        </div>
      </div>

      <div style={{ flex: 1, overflowY: "auto", display: "flex", flexDirection: "column", gap: "20px" }}>
        {/* Threat summary */}
        <div style={{ padding: "12px", borderRadius: "8px", border: "1px solid var(--line)", background: "rgba(11, 107, 87, 0.01)" }}>
          <h3 style={{ margin: "0 0 6px 0", fontSize: "13px", color: "var(--accent)", fontWeight: 600 }}>AI Threat Summary</h3>
          <p style={{ margin: 0, fontSize: "12px", color: "var(--ink)", lineHeight: 1.5 }}>
            {detection.description}
          </p>
        </div>

        {/* Custom Context or Standard Metadata Fallback */}
        {customContextRenderer ? (
          customContextRenderer(detection)
        ) : (
          <div style={{ display: "flex", flexDirection: "column", gap: "16px" }}>
            {/* Standard Key Properties */}
            <div>
              <h4 style={{ margin: "0 0 10px 0", fontSize: "12px", fontWeight: 600, textTransform: "uppercase", letterSpacing: "0.05em", color: "var(--muted)" }}>
                Execution Properties
              </h4>
              <div style={{ display: "flex", flexDirection: "column", gap: "8px" }}>
                <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", fontSize: "12px" }}>
                  <span style={{ color: "var(--muted)", display: "inline-flex", alignItems: "center", gap: "6px" }}>
                    <Cpu size={14} /> Process
                  </span>
                  <strong style={{ color: "var(--ink)" }}>{detection.recommended_action === "kill_process" ? detection.title : "N/A"}</strong>
                </div>
                <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", fontSize: "12px" }}>
                  <span style={{ color: "var(--muted)", display: "inline-flex", alignItems: "center", gap: "6px" }}>
                    <User size={14} /> Account Scope
                  </span>
                  <strong style={{ color: "var(--ink)" }}>{context?.user || "NT AUTHORITY\\SYSTEM"}</strong>
                </div>
                <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", fontSize: "12px" }}>
                  <span style={{ color: "var(--muted)", display: "inline-flex", alignItems: "center", gap: "6px" }}>
                    <Terminal size={14} /> Launcher Command
                  </span>
                  <code style={{ background: "rgba(19, 32, 27, 0.04)", padding: "2px 4px", borderRadius: "4px", fontSize: "11px", maxWidth: "200px", overflow: "hidden", textOverflow: "ellipsis" }}>
                    {context?.command_line || "sh -c 'execute'"}
                  </code>
                </div>
              </div>
            </div>

            {/* Hashes / Config section */}
            {context?.file_hashes && context.file_hashes.length > 0 && (
              <div>
                <h4 style={{ margin: "0 0 8px 0", fontSize: "12px", fontWeight: 600, textTransform: "uppercase", color: "var(--muted)" }}>
                  Payload Analysis
                </h4>
                <div style={{ display: "flex", flexDirection: "column", gap: "6px", background: "rgba(11, 107, 87, 0.02)", padding: "8px", borderRadius: "6px", border: "1px solid var(--line)" }}>
                  {context.file_hashes.map((hash: any, i: number) => (
                    <div key={i} style={{ fontSize: "11px", display: "flex", flexDirection: "column", gap: "2px" }}>
                      <span style={{ color: "var(--muted)", fontWeight: 600 }}>{hash.algorithm.toUpperCase()}:</span>
                      <code style={{ wordBreak: "break-all", background: "#ffffff", padding: "4px", borderRadius: "4px", border: "1px solid var(--line)" }}>{hash.value}</code>
                    </div>
                  ))}
                </div>
              </div>
            )}

            {/* MITRE Mapping */}
            {context?.mitre_techniques && context.mitre_techniques.length > 0 && (
              <div>
                <h4 style={{ margin: "0 0 8px 0", fontSize: "12px", fontWeight: 600, textTransform: "uppercase", color: "var(--muted)" }}>
                  MITRE ATT&CK Mappings
                </h4>
                <div style={{ display: "flex", flexWrap: "wrap", gap: "6px" }}>
                  {context.mitre_techniques.map((tech: any) => (
                    <span
                      key={tech.id}
                      style={{
                        background: "rgba(180, 80, 24, 0.08)",
                        color: "var(--warning)",
                        border: "1px solid rgba(180, 80, 24, 0.2)",
                        padding: "2px 8px",
                        borderRadius: "4px",
                        fontSize: "11px",
                        fontWeight: 600,
                      }}
                      title={`${tech.tactic}: ${tech.name}`}
                    >
                      {tech.id} - {tech.name}
                    </span>
                  ))}
                </div>
              </div>
            )}
          </div>
        )}
      </div>
    </article>
  );
}

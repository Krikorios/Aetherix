import React from "react";
import { TrendingUp, GitMerge } from "lucide-react";
import type { CorrelationResponse } from "../../api";

interface CorrelationBannerProps {
  data: CorrelationResponse | null | undefined;
  isLoading?: boolean;
}

const SEVERITY_LABEL: Record<string, string> = {
  low: "Low",
  medium: "Medium",
  high: "High",
  critical: "Critical",
};

const SEVERITY_COLOR: Record<string, string> = {
  low: "var(--muted)",
  medium: "var(--warning)",
  high: "#c85000",
  critical: "#d4200c",
};

function severityColor(sev: string): string {
  return SEVERITY_COLOR[sev] ?? "var(--muted)";
}

/**
 * CorrelationBanner
 *
 * Renders an inline callout when a security alert has had its severity
 * uplifted due to cross-module correlation (e.g. FIM ↔ EDR), and lists
 * the supporting correlated events.  Returns null when there is nothing
 * to show.
 */
export function CorrelationBanner({ data, isLoading }: CorrelationBannerProps) {
  if (isLoading || !data) return null;

  const isUplifted = !!data.severity_uplifted_from;
  const fimLinks = data.correlations.filter((c) => c.related_kind === "fim_event");
  const totalLinks = data.correlations.length;

  if (!isUplifted && totalLinks === 0) return null;

  // Derive a representative file path from the first FIM correlation evidence.
  const topFimPath = fimLinks
    .map((c) => c.evidence?.file_path as string | undefined)
    .filter(Boolean)[0];

  const shortPath = topFimPath
    ? topFimPath.replace(/\\/g, "/").split("/").slice(-2).join("/")
    : null;

  return (
    <div
      style={{
        padding: "10px 12px",
        borderRadius: "8px",
        border: "1px solid rgba(180, 80, 24, 0.3)",
        background: "rgba(180, 80, 24, 0.05)",
        display: "flex",
        flexDirection: "column",
        gap: "8px",
      }}
    >
      {/* Uplift headline */}
      {isUplifted && (
        <div style={{ display: "flex", alignItems: "flex-start", gap: "7px" }}>
          <TrendingUp size={14} style={{ color: "var(--warning)", flexShrink: 0, marginTop: "1px" }} />
          <span style={{ fontSize: "12px", lineHeight: 1.45, color: "var(--ink)" }}>
            <strong style={{ color: "var(--warning)" }}>Severity uplifted</strong>
            {" — "}
            <span style={{ color: severityColor(data.severity_uplifted_from!), fontWeight: 600, textTransform: "uppercase", fontSize: "11px" }}>
              {SEVERITY_LABEL[data.severity_uplifted_from!] ?? data.severity_uplifted_from}
            </span>
            {" → "}
            <span style={{ color: severityColor(data.severity), fontWeight: 600, textTransform: "uppercase", fontSize: "11px" }}>
              {SEVERITY_LABEL[data.severity] ?? data.severity}
            </span>
            {fimLinks.length > 0 && (
              <span style={{ fontWeight: 400, color: "var(--muted)", marginLeft: "4px" }}>
                — supported by{" "}
                <strong style={{ color: "var(--ink)" }}>
                  {fimLinks.length} FIM event{fimLinks.length !== 1 ? "s" : ""}
                </strong>
                {shortPath ? (
                  <>
                    {" on "}
                    <code
                      style={{
                        fontSize: "10.5px",
                        background: "rgba(19, 32, 27, 0.05)",
                        padding: "1px 4px",
                        borderRadius: "3px",
                      }}
                    >
                      {shortPath}
                    </code>
                  </>
                ) : null}
              </span>
            )}
          </span>
        </div>
      )}

      {/* Correlated events list */}
      {totalLinks > 0 && (
        <div>
          <div
            style={{
              display: "flex",
              alignItems: "center",
              gap: "5px",
              marginBottom: "6px",
            }}
          >
            <GitMerge size={11} style={{ color: "var(--muted)" }} />
            <span
              style={{
                fontSize: "10.5px",
                fontWeight: 700,
                color: "var(--muted)",
                textTransform: "uppercase",
                letterSpacing: "0.05em",
              }}
            >
              Correlated Events ({totalLinks})
            </span>
          </div>

          <div style={{ display: "flex", flexDirection: "column", gap: "4px" }}>
            {data.correlations.slice(0, 5).map((link) => {
              const evPath = link.evidence?.file_path as string | undefined;
              const evShort = evPath
                ? evPath.replace(/\\/g, "/").split("/").slice(-2).join("/")
                : null;
              return (
                <div
                  key={link.id}
                  style={{
                    display: "flex",
                    justifyContent: "space-between",
                    alignItems: "center",
                    padding: "5px 8px",
                    background: "rgba(11, 107, 87, 0.03)",
                    border: "1px solid var(--line)",
                    borderRadius: "5px",
                    fontSize: "11px",
                    gap: "8px",
                  }}
                >
                  <div style={{ display: "flex", flexDirection: "column", gap: "2px", minWidth: 0 }}>
                    <span style={{ fontWeight: 600, color: "var(--ink)", textTransform: "capitalize" }}>
                      {link.related_kind.replace(/_/g, " ")}
                    </span>
                    <span
                      style={{
                        color: "var(--muted)",
                        fontFamily: "monospace",
                        fontSize: "10px",
                        overflow: "hidden",
                        textOverflow: "ellipsis",
                        whiteSpace: "nowrap",
                      }}
                    >
                      {link.correlation_type.replace(/_/g, " ")}
                      {evShort ? ` · ${evShort}` : ""}
                    </span>
                  </div>
                  <div style={{ display: "flex", alignItems: "center", gap: "6px", flexShrink: 0 }}>
                    <span style={{ color: "var(--muted)", fontSize: "10px" }}>
                      {Math.round(link.window_seconds / 60)}m window
                    </span>
                    <span
                      style={{
                        fontSize: "10px",
                        fontWeight: 700,
                        padding: "1px 5px",
                        borderRadius: "4px",
                        background:
                          link.score >= 0.8
                            ? "rgba(180, 80, 24, 0.1)"
                            : "rgba(96, 112, 104, 0.08)",
                        color: link.score >= 0.8 ? "var(--warning)" : "var(--muted)",
                      }}
                    >
                      {Math.round(link.score * 100)}
                    </span>
                  </div>
                </div>
              );
            })}
            {totalLinks > 5 && (
              <span style={{ fontSize: "10px", color: "var(--muted)", paddingLeft: "2px" }}>
                +{totalLinks - 5} more correlated event{totalLinks - 5 !== 1 ? "s" : ""}
              </span>
            )}
          </div>
        </div>
      )}
    </div>
  );
}

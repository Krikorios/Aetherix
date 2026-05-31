import React from "react";
import { ShieldOff, AlertTriangle, CheckCircle2, FileX2, Ban } from "lucide-react";

/**
 * RollbackRefusalEvidence
 *
 * Renders the richer rollback refusal/decision evidence emitted by the
 * SimulationRollbackProvider behavior (Agent 1). Given a response-action
 * `result` object, it surfaces — in plain operator language — why a rollback
 * was refused or only partially applied:
 *
 *   - status === "not_applicable"        → provider refused the whole action
 *   - provider_refusal / refusal_reason_code → top-level refusal narrative
 *   - recovery_point_verified === false  → no verified recovery point in scope
 *   - skipped_paths[ outcome=refused_out_of_scope ] → per-path refusals
 *   - failed_paths / restored_paths      → partial-application breakdown
 *
 * The component is intentionally defensive: the rollback evidence may arrive
 * either flat on `result` or nested under `result.rollback_evidence`, and any
 * field may be absent. It returns null when there is nothing rollback-related
 * to show, so it is safe to drop into any action result panel.
 */

type AnyRecord = Record<string, unknown>;

interface PathDecision {
  path?: string;
  outcome?: string;
  reason?: string;
  refusal_reason_code?: string;
  bytes_affected?: number;
}

interface RollbackEvidenceShape {
  status?: string;
  provider?: string;
  provider_refusal?: string | null;
  refusal_reason_code?: string | null;
  recovery_point_id?: string;
  recovery_point_verified?: boolean;
  restored_paths?: PathDecision[];
  failed_paths?: PathDecision[];
  skipped_paths?: PathDecision[];
  decision_trace?: string[];
}

interface Props {
  result: AnyRecord | null | undefined;
  /** When true, render the collapsible decision trace (defaults to false). */
  showTrace?: boolean;
}

/** Map known refusal_reason_code values to operator-friendly wording. */
const REFUSAL_CODE_LABEL: Record<string, string> = {
  provider_unavailable: "Rollback provider unavailable on endpoint",
  no_verified_recovery_point: "No matching verified recovery point found",
  point_expired: "Recovery point expired before restore",
  not_in_protected_root: "Path is outside the protected recovery root",
  max_paths_exceeded: "Too many paths in restore scope",
  max_bytes_exceeded: "Restore size exceeds policy limit",
  max_depth_exceeded: "Path depth exceeds policy limit",
  endpoint_binding_mismatch: "Action was not issued for this endpoint",
  tenant_binding_mismatch: "Action was issued for a different tenant",
  failed: "Restore failed during execution",
};

function humanizeCode(code: string | null | undefined): string | null {
  if (!code) return null;
  const known = REFUSAL_CODE_LABEL[code];
  if (known) return known;
  return code.replace(/_/g, " ").replace(/\b\w/g, (c) => c.toUpperCase());
}

function shortPath(p: string | undefined | null): string {
  if (!p) return "unknown path";
  return p.replace(/\\/g, "/").split("/").slice(-2).join("/") || p;
}

function asEvidence(result: AnyRecord | null | undefined): RollbackEvidenceShape | null {
  if (!result || typeof result !== "object") return null;
  const nested = (result as AnyRecord).rollback_evidence;
  const ev = (nested && typeof nested === "object" ? nested : result) as RollbackEvidenceShape;
  return ev;
}

function hasRollbackSignal(ev: RollbackEvidenceShape): boolean {
  return (
    typeof ev.provider_refusal === "string" ||
    typeof ev.refusal_reason_code === "string" ||
    typeof ev.recovery_point_verified === "boolean" ||
    (Array.isArray(ev.skipped_paths) && ev.skipped_paths.length > 0) ||
    (Array.isArray(ev.failed_paths) && ev.failed_paths.length > 0) ||
    (Array.isArray(ev.restored_paths) && ev.restored_paths.length > 0) ||
    ev.status === "not_applicable"
  );
}

export function RollbackRefusalEvidence({ result, showTrace = false }: Props) {
  const ev = asEvidence(result);
  if (!ev || !hasRollbackSignal(ev)) return null;

  const skipped = (ev.skipped_paths ?? []).filter(
    (d) => d.outcome === "refused_out_of_scope" || d.outcome === "skipped",
  );
  const failed = ev.failed_paths ?? [];
  const restored = ev.restored_paths ?? [];

  const isRefused =
    ev.status === "not_applicable" ||
    typeof ev.provider_refusal === "string" ||
    typeof ev.refusal_reason_code === "string";
  const recoveryUnverified = ev.recovery_point_verified === false;

  const topRefusal =
    (typeof ev.provider_refusal === "string" && ev.provider_refusal) ||
    humanizeCode(ev.refusal_reason_code) ||
    "Rollback was refused by the provider";

  const accent = isRefused || failed.length > 0 ? "var(--warning)" : "var(--healthy)";
  const accentBg =
    isRefused || failed.length > 0 ? "rgba(180, 80, 24, 0.05)" : "rgba(11, 107, 87, 0.04)";
  const accentBorder =
    isRefused || failed.length > 0 ? "rgba(180, 80, 24, 0.3)" : "var(--line)";

  return (
    <div
      style={{
        padding: "10px 12px",
        borderRadius: "8px",
        border: `1px solid ${accentBorder}`,
        background: accentBg,
        display: "flex",
        flexDirection: "column",
        gap: "8px",
      }}
    >
      {/* Headline */}
      <div style={{ display: "flex", alignItems: "flex-start", gap: "7px" }}>
        {isRefused ? (
          <ShieldOff size={14} style={{ color: accent, flexShrink: 0, marginTop: "1px" }} />
        ) : (
          <CheckCircle2 size={14} style={{ color: accent, flexShrink: 0, marginTop: "1px" }} />
        )}
        <span style={{ fontSize: "12px", lineHeight: 1.45, color: "var(--ink)" }}>
          {isRefused ? (
            <>
              <strong style={{ color: accent }}>Rollback refused</strong>
              {" — "}
              {topRefusal}
              {ev.refusal_reason_code ? (
                <code
                  style={{
                    marginLeft: "6px",
                    fontSize: "10px",
                    background: "rgba(19, 32, 27, 0.06)",
                    padding: "1px 5px",
                    borderRadius: "3px",
                  }}
                >
                  {ev.refusal_reason_code}
                </code>
              ) : null}
            </>
          ) : (
            <>
              <strong style={{ color: accent }}>Rollback applied</strong>
              {" — "}
              {restored.length} file{restored.length !== 1 ? "s" : ""} restored
            </>
          )}
        </span>
      </div>

      {/* Recovery point verification */}
      <div style={{ display: "flex", alignItems: "center", gap: "6px", fontSize: "11px" }}>
        {recoveryUnverified ? (
          <AlertTriangle size={12} style={{ color: "var(--warning)" }} />
        ) : (
          <CheckCircle2 size={12} style={{ color: "var(--healthy)" }} />
        )}
        <span style={{ color: "var(--muted)" }}>Recovery point</span>
        {ev.recovery_point_id ? (
          <code
            style={{
              fontSize: "10px",
              background: "rgba(19, 32, 27, 0.05)",
              padding: "1px 4px",
              borderRadius: "3px",
            }}
          >
            {ev.recovery_point_id}
          </code>
        ) : null}
        <span
          style={{
            fontWeight: 700,
            color: recoveryUnverified ? "var(--warning)" : "var(--healthy)",
          }}
        >
          {recoveryUnverified ? "unverified / out of scope" : "verified"}
        </span>
        {ev.provider ? <span style={{ color: "var(--muted)" }}>· {ev.provider}</span> : null}
      </div>

      {/* Per-path refusals */}
      {skipped.length > 0 && (
        <div>
          <div
            style={{
              display: "flex",
              alignItems: "center",
              gap: "5px",
              marginBottom: "6px",
            }}
          >
            <Ban size={11} style={{ color: "var(--warning)" }} />
            <span
              style={{
                fontSize: "10.5px",
                fontWeight: 700,
                color: "var(--muted)",
                textTransform: "uppercase",
                letterSpacing: "0.05em",
              }}
            >
              Refused Paths ({skipped.length})
            </span>
          </div>
          <div style={{ display: "flex", flexDirection: "column", gap: "4px" }}>
            {skipped.slice(0, 6).map((d, i) => (
              <div
                key={`${d.path ?? i}-${i}`}
                style={{
                  padding: "5px 8px",
                  background: "rgba(180, 80, 24, 0.04)",
                  border: "1px solid var(--line)",
                  borderRadius: "5px",
                  fontSize: "11px",
                  display: "flex",
                  flexDirection: "column",
                  gap: "2px",
                }}
              >
                <code
                  title={d.path}
                  style={{ fontSize: "10.5px", color: "var(--ink)", wordBreak: "break-all" }}
                >
                  {shortPath(d.path)}
                </code>
                <span style={{ color: "var(--muted)", fontSize: "10.5px" }}>
                  {d.reason || humanizeCode(d.refusal_reason_code) || "Refused out of scope"}
                  {d.refusal_reason_code ? ` · ${d.refusal_reason_code}` : ""}
                </span>
              </div>
            ))}
            {skipped.length > 6 && (
              <span style={{ fontSize: "10px", color: "var(--muted)", paddingLeft: "2px" }}>
                +{skipped.length - 6} more refused path{skipped.length - 6 !== 1 ? "s" : ""}
              </span>
            )}
          </div>
        </div>
      )}

      {/* Failed paths summary */}
      {failed.length > 0 && (
        <div style={{ display: "flex", alignItems: "center", gap: "6px", fontSize: "11px" }}>
          <FileX2 size={12} style={{ color: "var(--danger)" }} />
          <span style={{ color: "var(--danger)", fontWeight: 600 }}>
            {failed.length} path{failed.length !== 1 ? "s" : ""} failed integrity during restore
          </span>
        </div>
      )}

      {/* Optional decision trace */}
      {showTrace && Array.isArray(ev.decision_trace) && ev.decision_trace.length > 0 && (
        <details style={{ fontSize: "10.5px", color: "var(--muted)" }}>
          <summary style={{ cursor: "pointer", fontWeight: 600 }}>Decision trace</summary>
          <ul style={{ margin: "4px 0 0 0", paddingLeft: "16px" }}>
            {ev.decision_trace.map((line, i) => (
              <li key={i} style={{ wordBreak: "break-word" }}>
                {line}
              </li>
            ))}
          </ul>
        </details>
      )}
    </div>
  );
}

/** Lightweight predicate so call sites can decide whether to render the panel. */
export function hasRollbackRefusalEvidence(result: AnyRecord | null | undefined): boolean {
  const ev = asEvidence(result);
  return !!ev && hasRollbackSignal(ev);
}

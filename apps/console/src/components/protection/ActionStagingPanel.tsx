import React from "react";
import { PlayCircle, ShieldCheck } from "lucide-react";
import { Detection, StagedAction, SimulationPreview } from "./types";
import { StagedActionBadge } from "./StagedActionBadge";
import { EmptyState } from "./EmptyState";

interface ActionStagingPanelProps {
  detection: Detection | null;
  selectedAction: string;
  simulation: SimulationPreview | null;
  stagedActions: StagedAction[];
  isWorking: boolean;
  availableActions: Array<{ value: string; label: string; destructive: boolean }>;
  onActionChange: (action: string) => void;
  onSimulate: () => void;
  onStage: () => void;
}

export function ActionStagingPanel({
  detection,
  selectedAction,
  simulation,
  stagedActions,
  isWorking,
  availableActions,
  onActionChange,
  onSimulate,
  onStage,
}: ActionStagingPanelProps) {
  if (!detection) {
    return (
      <article className="panel" style={{ flex: 1, display: "flex", flexDirection: "column", minWidth: "300px" }}>
        <div className="panelHeader" style={{ paddingBottom: "12px", borderBottom: "1px solid var(--line)" }}>
          <div>
            <h2 style={{ fontSize: "16px", margin: 0 }}>Response Action Hub</h2>
            <span style={{ fontSize: "12px", color: "var(--muted)" }}>Formulate mitigation steps</span>
          </div>
        </div>
        <div style={{ flex: 1, display: "flex", alignItems: "center", justifyContent: "center", padding: "16px" }}>
          <EmptyState message="Select a warning list item to prepare simulation runs, test impact analysis, and stage protective responses." />
        </div>
      </article>
    );
  }

  // Find the selected action metadata
  const currentActionMeta = availableActions.find((a) => a.value === selectedAction);
  const isDestructive = currentActionMeta?.destructive ?? false;

  // Filter staged actions belonging to the current detection
  const historicalActions = stagedActions.filter((v) => v.detection_id === detection.id);

  return (
    <article className="panel" style={{ flex: 1, display: "flex", flexDirection: "column", minWidth: "300px" }}>
      <div className="panelHeader" style={{ paddingBottom: "12px", borderBottom: "1px solid var(--line)", marginBottom: "16px" }}>
        <div>
          <h2 style={{ fontSize: "16px", margin: 0 }}>Response Action Hub</h2>
          <span style={{ fontSize: "12px", color: "var(--muted)" }}>Active target: {detection.endpoint_name}</span>
        </div>
      </div>

      <div style={{ flex: 1, overflowY: "auto", display: "flex", flexDirection: "column", gap: "20px" }}>
        {/* Step 1: Select Response Action */}
        <div>
          <h3 style={{ margin: "0 0 8px 0", fontSize: "12px", fontWeight: 600, textTransform: "uppercase", color: "var(--muted)" }}>
            1. Select Protective Response
          </h3>
          <div style={{ display: "flex", flexDirection: "column", gap: "10px" }}>
            <select
              value={selectedAction}
              onChange={(e) => onActionChange(e.target.value)}
              disabled={isWorking}
              style={{
                width: "100%",
                height: "38px",
                borderRadius: "8px",
                border: "1px solid var(--line)",
                padding: "0 10px",
                fontSize: "13px",
                background: "#fffef9",
              }}
            >
              {availableActions.map((act) => (
                <option key={act.value} value={act.value}>
                  {act.label} {act.destructive ? " (High Impact)" : ""}
                </option>
              ))}
            </select>
            {isDestructive && (
              <div
                style={{
                  fontSize: "11px",
                  color: "var(--warning)",
                  background: "rgba(180, 80, 24, 0.06)",
                  padding: "8px",
                  borderRadius: "6px",
                  border: "1px solid rgba(180, 80, 24, 0.2)",
                }}
              >
                <strong>Warning:</strong> This is a destructive response action. Policy simulation is recommended before dispatching to the host.
              </div>
            )}
          </div>
        </div>

        {/* Step 2: Policy Simulation */}
        <div>
          <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: "8px" }}>
            <h3 style={{ margin: 0, fontSize: "12px", fontWeight: 600, textTransform: "uppercase", color: "var(--muted)" }}>
              2. Policy Simulation
            </h3>
            <button
              type="button"
              onClick={onSimulate}
              disabled={isWorking}
              className="btnSecondary"
              style={{
                padding: "4px 10px",
                fontSize: "11px",
                height: "auto",
                display: "inline-flex",
                alignItems: "center",
                gap: "4px",
                cursor: "pointer",
              }}
            >
              <PlayCircle size={12} />
              Run Dry Preview
            </button>
          </div>

          {simulation ? (
            <div
              style={{
                background: "rgba(11, 107, 87, 0.03)",
                border: "1px solid var(--line)",
                borderRadius: "8px",
                padding: "10px",
              }}
            >
              <div style={{ display: "flex", justifyContent: "space-between", fontSize: "12px", borderBottom: "1px dashed var(--line)", paddingBottom: "6px", marginBottom: "6px" }}>
                <span>Impacted Processes: <strong>{simulation.affected_systems}</strong></span>
                <span>Approval Required: <strong>{simulation.approval_required ? "Yes" : "Auto"}</strong></span>
              </div>
              <ul style={{ margin: 0, paddingLeft: "16px", fontSize: "11px", color: "var(--muted)", display: "flex", flexDirection: "column", gap: "4px" }}>
                {simulation.estimated_impact.map((imp, idx) => (
                  <li key={idx}>{imp}</li>
                ))}
              </ul>
              {simulation.evidence_controls && simulation.evidence_controls.length > 0 && (
                <div style={{ marginTop: "8px", display: "flex", flexWrap: "wrap", gap: "4px" }}>
                  {simulation.evidence_controls.map((ctrl) => (
                    <span key={ctrl} style={{ fontSize: "10px", background: "var(--panel)", border: "1px solid var(--line)", padding: "1px 4px", borderRadius: "3px" }}>
                      {ctrl}
                    </span>
                  ))}
                </div>
              )}
            </div>
          ) : (
            <div style={{ fontSize: "12px", color: "var(--muted)", background: "rgba(19, 32, 27, 0.02)", padding: "12px", textAlign: "center", borderRadius: "8px", border: "1.5px dashed var(--line)" }}>
              No Dry Preview simulation logs run yet for this item.
            </div>
          )}
        </div>

        {/* Step 3: Stage Action */}
        <div>
          <h3 style={{ margin: "0 0 8px 0", fontSize: "12px", fontWeight: 600, textTransform: "uppercase", color: "var(--muted)" }}>
            3. Apply Decisions
          </h3>
          <button
            type="button"
            className="btnPrimary"
            onClick={onStage}
            disabled={isWorking || (isDestructive && !simulation)}
            style={{
              width: "100%",
              display: "flex",
              alignItems: "center",
              justifyContent: "center",
              gap: "8px",
              cursor: "pointer",
            }}
          >
            <ShieldCheck size={16} />
            Stage Mitigation Action
          </button>
          {isDestructive && !simulation && (
            <span style={{ fontSize: "11px", color: "var(--warning)", marginTop: "4px", display: "block", textAlign: "center" }}>
              Please generate a dry preview before staging this high-impact action.
            </span>
          )}
        </div>

        {/* Action Audit Log */}
        <div style={{ borderTop: "1px solid var(--line)", paddingTop: "16px", marginTop: "8px" }}>
          <h3 style={{ margin: "0 0 8px 0", fontSize: "12px", fontWeight: 600, textTransform: "uppercase", color: "var(--muted)" }}>
            Action Audit Log ({historicalActions.length})
          </h3>
          <div style={{ display: "flex", flexDirection: "column", gap: "8px" }}>
            {historicalActions.length === 0 ? (
              <div style={{ fontSize: "12px", color: "var(--muted)", fontStyle: "italic" }}>No action decisions staged for this detection yet.</div>
            ) : (
              historicalActions.map((hi) => (
                <div
                  key={hi.id}
                  style={{
                    display: "flex",
                    justifyContent: "space-between",
                    alignItems: "center",
                    padding: "8px",
                    background: "rgba(251, 252, 247, 0.95)",
                    border: "1px solid var(--line)",
                    borderRadius: "6px",
                  }}
                >
                  <div>
                    <span style={{ fontSize: "11px", fontWeight: 600, color: "var(--ink)", display: "block" }}>
                      {hi.action.replaceAll("_", " ").toUpperCase()}
                    </span>
                    <span style={{ fontSize: "10px", color: "var(--muted)" }}>
                      Requested by {hi.requested_by}
                    </span>
                  </div>
                  <div style={{ display: "flex", alignItems: "center", gap: "4px" }}>
                    <StagedActionBadge status={hi.status} />
                  </div>
                </div>
              ))
            )}
          </div>
        </div>
      </div>
    </article>
  );
}

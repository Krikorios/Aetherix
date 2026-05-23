import { CheckCircle2, FlaskConical, LockKeyhole, Send } from "lucide-react";
import { EmptyState, LoadingRow } from "../components";
import { timeAgo } from "../utils";
import { isDestructiveBehaviorAction, type BehaviorAction, type BehaviorDetection, type BehaviorSimulationResponse, type StagedBehaviorAction } from "./antimalwareTypes";

const ACTIONS: { value: BehaviorAction; label: string; destructive: boolean }[] = [
  { value: "quarantine", label: "Quarantine", destructive: false },
  { value: "kill_process", label: "Kill Process", destructive: true },
  { value: "isolate_endpoint", label: "Isolate Endpoint", destructive: true },
  { value: "rollback", label: "Rollback", destructive: true },
  { value: "allow", label: "Allow / Close", destructive: false },
];

type ResponseStagingPanelProps = {
  detection: BehaviorDetection | null;
  selectedAction: BehaviorAction;
  simulation: BehaviorSimulationResponse | null;
  stagedActions: StagedBehaviorAction[];
  isWorking: boolean;
  onActionChange: (action: BehaviorAction) => void;
  onSimulate: () => void;
  onStage: () => void;
};

export function ResponseStagingPanel({
  detection,
  selectedAction,
  simulation,
  stagedActions,
  isWorking,
  onActionChange,
  onSimulate,
  onStage,
}: ResponseStagingPanelProps) {
  return (
    <section className="panel behaviorPanel behaviorResponsePanel">
      <div className="panelHeader">
        <div>
          <h2>Response Staging</h2>
          <span>{detection ? detection.recommended_action_label : "Select a detection"}</span>
        </div>
        <LockKeyhole size={18} aria-hidden="true" />
      </div>

      {!detection ? <EmptyState>Select a detection before staging a response.</EmptyState> : null}

      {detection ? (
        <>
          <label className="stageField">
            <span>Manual override</span>
            <select value={selectedAction} onChange={(event) => onActionChange(event.target.value as BehaviorAction)}>
              {ACTIONS.map((action) => (
                <option key={action.value} value={action.value}>{action.label}</option>
              ))}
            </select>
          </label>

          <div className="stageActionStack">
            <button type="button" className="btnSecondary" onClick={onSimulate} disabled={isWorking}>
              <FlaskConical size={16} aria-hidden="true" />
              Simulate
            </button>
            <button
              type="button"
              className="btnPrimary"
              onClick={onStage}
              disabled={isWorking || (isDestructiveBehaviorAction(selectedAction) && !simulation)}
            >
              <Send size={16} aria-hidden="true" />
              Stage Action
            </button>
          </div>

          {isWorking ? <LoadingRow label="Preparing response" /> : null}

          {simulation ? (
            <article className="simulationCard">
              <header>
                <CheckCircle2 size={16} aria-hidden="true" />
                <strong>Simulation complete</strong>
              </header>
              <div className="simulationStats">
                <span>{simulation.affected_processes} processes</span>
                <span>{simulation.affected_connections} connections</span>
                <span>{simulation.approval_required ? "Approval required" : "No approval gate"}</span>
              </div>
              <ul>
                {simulation.estimated_impact.map((impact) => <li key={impact}>{impact}</li>)}
              </ul>
            </article>
          ) : (
            <p className="stageHint">Destructive actions require a completed policy simulation before staging.</p>
          )}
        </>
      ) : null}

      <div className="stageQueue">
        <h3>Staged Queue</h3>
        {stagedActions.length ? stagedActions.map((action) => (
          <article key={action.id} className={`queueItem queue-${action.status}`}>
            <strong>{action.action.replaceAll("_", " ")}</strong>
            <span>{action.status.replaceAll("_", " ")} · {timeAgo(action.created_at)}</span>
          </article>
        )) : <p className="muted">No staged actions yet.</p>}
      </div>
    </section>
  );
}
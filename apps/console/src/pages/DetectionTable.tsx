import { ShieldAlert } from "lucide-react";
import { EmptyState, LoadingRow } from "../components";
import { timeAgo } from "../utils";
import type { BehaviorDetection } from "./antimalwareTypes";

type DetectionTableProps = {
  detections: BehaviorDetection[];
  selectedId: string | null;
  loading: boolean;
  onSelect: (detection: BehaviorDetection) => void;
};

export function DetectionTable({ detections, selectedId, loading, onSelect }: DetectionTableProps) {
  return (
    <section className="panel behaviorPanel behaviorTriagePanel">
      <div className="panelHeader">
        <div>
          <h2>High-Confidence Triage</h2>
          <span>{detections.length} recent detections</span>
        </div>
        <ShieldAlert size={18} aria-hidden="true" />
      </div>

      <div className="behaviorTableHead" role="row">
        <span>Process</span>
        <span>Risk</span>
        <span>Confidence</span>
        <span>Action</span>
        <span>Time</span>
      </div>

      {detections.map((detection) => (
        <button
          type="button"
          key={detection.id}
          className={`behaviorDetectionRow${selectedId === detection.id ? " selected" : ""}`}
          onClick={() => onSelect(detection)}
          aria-pressed={selectedId === detection.id}
        >
          <span className="behaviorProcessCell">
            <strong>{detection.process}</strong>
            <small>{detection.endpoint_name}</small>
          </span>
          <span className={`behaviorScore score-${detection.risk_band}`}>{detection.risk_score}</span>
          <span>{detection.confidence}%</span>
          <span>{detection.recommended_action_label}</span>
          <span>{timeAgo(detection.created_at)}</span>
        </button>
      ))}

      {loading ? <LoadingRow label="Loading behavior detections" /> : null}
      {!loading && detections.length === 0 ? (
        <EmptyState>No high-confidence behavior detections are waiting for review.</EmptyState>
      ) : null}
    </section>
  );
}
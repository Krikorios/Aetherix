import type { RiskBand } from "../../api";

export type ModuleStatus = "protected" | "review_needed" | "disabled" | "planned";

export type DetectionStatus = "new" | "investigating" | "staged" | "resolved";

export type ActionStatus =
  | "queued"
  | "awaiting_approval"
  | "approved"
  | "executed"
  | "failed"
  | "denied";

export interface Detection {
  id: string;
  customer_id?: string | null;
  endpoint_id: string | null;
  endpoint_name: string;
  title: string;
  source: string;
  description: string;
  risk_score: number;
  risk_band: RiskBand;
  confidence: number;
  recommended_action: string;
  status: DetectionStatus;
  created_at: string;
  context?: Record<string, any>;
  /** Populated when the backend uplifted severity due to cross-module correlation. */
  severity_uplifted_from?: string | null;
}

export interface StagedAction {
  id: string;
  detection_id: string;
  action: string;
  status: ActionStatus;
  approval_required: boolean;
  requested_by: string;
  created_at: string;
  note?: string | null;
}

export interface SimulationPreview {
  id: string;
  detection_id: string;
  action: string;
  destructive: boolean;
  approval_required: boolean;
  estimated_impact: string[];
  affected_systems: number;
  evidence_controls?: string[];
  created_at: string;
}

export interface EffectivePolicy {
  policy_version: string;
  last_updated: string;
  status: ModuleStatus;
  approval_required: boolean;
  controls: Record<string, boolean>;
}

export interface ExclusionsList {
  id: string;
  pattern: string;
  type: string;
  reason: string;
}

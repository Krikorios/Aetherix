//! Ransomware rollback provider trait and Phase 1–3 scaffolding.
//!
//! Defined in `docs/edr-ransomware-rollback-interface.md` §Provider Boundary.
//!
//! ## Module structure
//!
//! - [`types`](./types.rs) — Data types (RollbackCapabilities, RecoveryPoint, RollbackEvidence, …)
//! - [`provider`](./provider.rs) — `RollbackProvider` trait + `NoopRollbackProvider` + `SimulationRollbackProvider`
//! - [`intent`](./intent.rs) — `RollbackIntent`, parsing, validation, evidence conversion
//! - [`evidence`](./evidence.rs) — Heartbeat readiness, event enrichment, endpoint.rollback.* event builders
//! - [`persistence`](./persistence.rs) — Idempotency guard with atomic persistence
//!
//! ## Public surface
//!
//! All public types and functions are re-exported from this module root so
//! callers use `aetherix_agent::edr::rollback::*` regardless of which
//! submodule defines the item.

pub mod types;
pub mod provider;
pub mod intent;
pub mod evidence;
pub mod persistence;

#[cfg(windows)]
pub mod vss;

#[cfg(windows)]
pub use vss::VssRollbackProvider;


// --- Re-exports from `types` ---
pub use types::{
    ProbeResult, RecoveryPoint, RecoveryPointHint, RecoveryPointSummary, RollbackCandidateSet,
    RollbackCapabilities, RollbackEvidence, RollbackPathDecision, RollbackPathOutcome, RollbackReadiness,
    RollbackRefusal, RollbackScope, RollbackSimulation,
};

// --- Re-exports from `provider` ---
pub use provider::{NoopRollbackProvider, RollbackProvider, SimulationRollbackProvider};

// --- Re-exports from `intent` ---
pub use intent::{
    convert_rollback_evidence_to_response, intent_to_candidate_set, parse_rollback_intent,
    validate_intent_expiry, RollbackIntent,
};

// --- Re-exports from `evidence` ---
pub use evidence::{
    build_rollback_executed_event, build_rollback_failed_event, build_rollback_refused_event,
    build_rollback_requested_event, compute_rollback_readiness, enrich_events_with_recovery_hints,
};

// --- Re-exports from `persistence` ---
pub use persistence::{
    consumed_count, evict_old_evidence, is_action_consumed, load_consumed_ids, load_evidence,
    mark_action_consumed, store_evidence,
};

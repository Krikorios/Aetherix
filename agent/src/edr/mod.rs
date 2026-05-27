//! Native EDR v0 — deterministic-only.
//!
//! This module is the skeleton for P0-3 in `docs/roadmap-2026.md` and
//! priority 4 in `docs/native-security-gap-review.md` "Native
//! Development Priorities".
//!
//! Hard rules carried from `docs/architecture.md` §1 and §3.1:
//!
//! 1. Deterministic before probabilistic — every detector here is
//!    rule/signature/IOC-based. ML scoring is a separate, later layer
//!    and must never be the sole decision input.
//! 2. Default monitor, opt-in enforce — new detectors emit evidence
//!    in `monitor` mode until simulation + operator approval promotes
//!    them via Policy Engine v2.
//! 3. Evidence by construction — every detection produced by these
//!    submodules must carry `evidence_controls` tags when forwarded to
//!    the control plane (see `apps/api/app/services/compliance.py`).
//! 4. No outbound calls except to the configured control plane.
//!
//! Submodules are intentionally stubbed; each one ships its
//! deterministic detector first and only later gains an AI-assisted
//! layer through the control-plane semantic gateway.

#![allow(dead_code)]

pub mod ioc;
pub mod process_tree;
pub mod ransomware;
pub mod response;
pub mod yara_scan;

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Kind of detection emitted by EDR submodules.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum EdrDetectionKind {
    YaraMatch,
    IocMatch,
    RansomwareCanary,
    SuspiciousProcessChain,
    ResponseAction,
}

/// Policy-gated response action. Mirrors `DlpAction` in shape so the
/// agent can serialize a unified policy outcome to the backend.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum EdrAction {
    Monitor,
    Review,
    Quarantine,
    QuarantineList,
    QuarantineRestore,
    Kill,
    Isolate,
}

/// KDF parameters required to recover a quarantined artifact after agent
/// secret rotation or KDF tuning. New quarantines use Argon2id; manifests
/// without this block are treated as legacy raw-key/SHA-256 artifacts.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct QuarantineKdf {
    pub algorithm: String,
    pub salt_b64: String,
    pub memory_cost_kib: u32,
    pub time_cost: u32,
    pub parallelism: u32,
    pub output_len: u32,
}

/// A matched string within a YARA rule — includes the string identifier,
/// the matched data (hex-encoded), and the offset in the scanned data.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct YaraStringMatch {
    pub identifier: String,
    pub matched_data: Option<String>,
    pub offset: Option<u64>,
    pub length: Option<u64>,
}

/// Auditable result of a policy-gated EDR response attempt.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ResponseStatus {
    Staged,
    Executed,
    Failed,
    NotApplicable,
}

/// Quarantine manifest details returned in EDR evidence. The manifest is
/// stored next to the encrypted artifact and chained to prior manifests.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct QuarantineManifest {
    pub quarantine_id: String,
    pub original_path: String,
    pub original_modified_at: Option<String>,
    pub original_permissions: Option<String>,
    pub quarantined_path: String,
    pub metadata_path: String,
    pub quarantined_at: String,
    pub sha256_hash: String,
    pub rule_id: String,
    pub file_size: u64,
    pub encrypted: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kdf: Option<QuarantineKdf>,
    pub previous_manifest_hash: Option<String>,
    pub manifest_hash: String,
}

/// Evidence payload that lets the control plane and console distinguish a
/// staged recommendation from an attempted/executed response action.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct ResponseEvidence {
    pub action: EdrAction,
    pub status: ResponseStatus,
    pub attempted_at: String,
    pub policy_version: String,
    pub rule_id: String,
    pub target_pid: Option<u32>,
    pub target_path: Option<String>,
    pub file_sha256: Option<String>,
    pub platform: String,
    pub platform_api: String,
    pub decision_trace: Vec<String>,
    pub error: Option<String>,
    pub quarantine: Option<QuarantineManifest>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub evidence_controls: Vec<String>,
}

/// Normalized EDR event sent to the control plane via the existing
/// evidence pipeline. The `evidence_controls` mapping is attached on
/// the backend by `app/services/compliance.py`; the agent only emits
/// the raw facts.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct EdrEvent {
    pub kind: EdrDetectionKind,
    pub rule_id: String,
    pub action: EdrAction,
    pub process_path: Option<String>,
    pub process_pid: Option<u32>,
    pub parent_pid: Option<u32>,
    pub file_path: Option<String>,
    pub file_sha256: Option<String>,
    pub matched_indicator: Option<String>,
    pub policy_version: String,
    pub collected_at: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub tags: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub matched_strings: Vec<YaraStringMatch>,
    #[serde(default, skip_serializing_if = "HashMap::is_empty")]
    pub rule_metadata: HashMap<String, String>,
    #[serde(default)]
    pub scan_duration_ms: Option<u64>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub matched_rules: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub evidence_controls: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub response: Option<ResponseEvidence>,
}

impl EdrEvent {
    pub fn new(kind: EdrDetectionKind, rule_id: &str, action: EdrAction, policy_version: &str) -> Self {
        Self {
            kind,
            rule_id: rule_id.to_string(),
            action,
            process_path: None,
            process_pid: None,
            parent_pid: None,
            file_path: None,
            file_sha256: None,
            matched_indicator: None,
            policy_version: policy_version.to_string(),
            collected_at: chrono::Utc::now().to_rfc3339(),
            tags: Vec::new(),
            matched_strings: Vec::new(),
            rule_metadata: HashMap::new(),
            scan_duration_ms: None,
            matched_rules: Vec::new(),
            evidence_controls: Vec::new(),
            response: None,
        }
    }
}

use anyhow::{Context, Result};
use crate::edr::EdrAction;
use reqwest::blocking::Client;
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

pub const DEFAULT_SENSITIVITY_LABELS: &[&str] = &["public", "internal", "confidential", "restricted"];
pub const DEFAULT_GENAI_DESTINATIONS: &[&str] = &["copilot", "claude", "gemini", "chatgpt"];

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum DlpAction {
    Allow,
    Review,
    Block,
    Redact,
}

impl Default for DlpAction {
    fn default() -> Self {
        Self::Allow
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, Default)]
pub struct DetectorConfig {
    #[serde(default = "default_true")]
    pub presidio: bool,
    #[serde(default = "default_true")]
    pub llm_semantic: bool,
    #[serde(default)]
    pub custom_classifiers: Vec<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize, Default)]
pub struct SemanticActions {
    #[serde(default = "default_review")]
    pub paste_sensitive: DlpAction,
    #[serde(default = "default_block")]
    pub upload_restricted: DlpAction,
    #[serde(default = "default_review")]
    pub copy_to_genai: DlpAction,
}

#[derive(Clone, Debug, Serialize, Deserialize, Default)]
pub struct SemanticDlpPolicy {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default = "default_labels")]
    pub sensitivity_labels: Vec<String>,
    #[serde(default = "default_destinations")]
    pub genai_destinations: Vec<String>,
    #[serde(default)]
    pub actions: SemanticActions,
    #[serde(default)]
    pub detectors: DetectorConfig,
}

#[derive(Clone, Debug, Serialize, Deserialize, Default)]
pub struct GenaiGuardrailsPolicy {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default)]
    pub destinations: Vec<String>,
    #[serde(default = "default_true")]
    pub browser_enforcement: bool,
    #[serde(default = "default_true")]
    pub endpoint_enforcement: bool,
    #[serde(default)]
    pub actions: SemanticActions,
}

#[derive(Clone, Debug, Serialize, Deserialize, Default)]
pub struct AntimalwarePolicy {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default)]
    pub response_action: Option<String>,
    #[serde(default)]
    pub response: Option<AntimalwareResponsePolicy>,
}

#[derive(Clone, Debug, Serialize, Deserialize, Default)]
pub struct AntimalwareResponsePolicy {
    #[serde(default)]
    pub action: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize, Default)]
pub struct BehaviorMonitoringPolicy {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default)]
    pub high_confidence_action: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize, Default)]
pub struct RansomwareMitigationPolicy {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default)]
    pub response_action: Option<String>,
    #[serde(default)]
    pub high_confidence_action: Option<String>,
    #[serde(default)]
    pub auto_isolate_on_high_confidence: bool,
    #[serde(default)]
    pub rollback_approval: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize, Default)]
pub struct ResolvedPolicy {
    #[serde(default)]
    pub semantic_dlp: SemanticDlpPolicy,
    #[serde(default)]
    pub genai_guardrails: GenaiGuardrailsPolicy,
    #[serde(default)]
    pub antimalware: AntimalwarePolicy,
    #[serde(default)]
    pub behavior_monitoring: BehaviorMonitoringPolicy,
    #[serde(default)]
    pub ransomware_mitigation: RansomwareMitigationPolicy,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AgentPolicyResponse {
    pub endpoint_id: String,
    pub policy_version_hash: String,
    pub resolved_policy: AgentPolicyDocument,
    #[serde(default)]
    pub evidence_controls: Vec<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize, Default)]
pub struct AgentPolicyDocument {
    #[serde(default)]
    pub modules: serde_json::Value,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RuntimePolicy {
    pub endpoint_id: String,
    pub policy_version_hash: String,
    pub evidence_controls: Vec<String>,
    pub resolved: ResolvedPolicy,
}

pub fn fetch_effective_policy(client: &Client, api_url: &str, endpoint_id: &str, token: &str) -> Result<RuntimePolicy> {
    let endpoint = format!(
        "{}/agent/policy?endpoint_id={}",
        api_url.trim_end_matches('/'),
        endpoint_id,
    );
    let response = client
        .get(endpoint)
        .header("Authorization", format!("Bearer {token}"))
        .send()
        .context("unable to fetch effective policy")?;
    if !response.status().is_success() {
        anyhow::bail!("policy fetch rejected with status {}", response.status());
    }

    let payload: AgentPolicyResponse = response
        .json()
        .context("invalid agent effective policy payload")?;
    runtime_from_response(payload)
}

pub fn runtime_from_response(payload: AgentPolicyResponse) -> Result<RuntimePolicy> {
    let modules = payload
        .resolved_policy
        .modules
        .as_object()
        .cloned()
        .unwrap_or_default();

    let semantic_value = modules
        .get("semantic_dlp")
        .cloned()
        .unwrap_or_else(|| serde_json::json!({}));
    let mut semantic: SemanticDlpPolicy = serde_json::from_value(semantic_value)
        .context("invalid semantic_dlp module")?;

    let guardrails_value = modules
        .get("genai_guardrails")
        .cloned()
        .unwrap_or_else(|| serde_json::json!({}));
    let mut guardrails: GenaiGuardrailsPolicy = serde_json::from_value(guardrails_value)
        .context("invalid genai_guardrails module")?;

    let antimalware: AntimalwarePolicy = serde_json::from_value(
        modules
            .get("antimalware")
            .cloned()
            .unwrap_or_else(|| serde_json::json!({})),
    )
    .context("invalid antimalware module")?;
    let behavior_monitoring: BehaviorMonitoringPolicy = serde_json::from_value(
        modules
            .get("behavior_monitoring")
            .cloned()
            .unwrap_or_else(|| serde_json::json!({})),
    )
    .context("invalid behavior_monitoring module")?;
    let ransomware_mitigation: RansomwareMitigationPolicy = serde_json::from_value(
        modules
            .get("ransomware_mitigation")
            .cloned()
            .unwrap_or_else(|| serde_json::json!({})),
    )
    .context("invalid ransomware_mitigation module")?;

    if guardrails.destinations.is_empty() {
        guardrails.destinations = semantic.genai_destinations.clone();
    }
    if semantic.genai_destinations.is_empty() {
        semantic.genai_destinations = guardrails.destinations.clone();
    }

    Ok(RuntimePolicy {
        endpoint_id: payload.endpoint_id,
        policy_version_hash: payload.policy_version_hash,
        evidence_controls: payload.evidence_controls,
        resolved: ResolvedPolicy {
            semantic_dlp: semantic,
            genai_guardrails: guardrails,
            antimalware,
            behavior_monitoring,
            ransomware_mitigation,
        },
    })
}

impl RuntimePolicy {
    /// Resolve an EDR detector into an enforceable action. Unknown and legacy
    /// UI values intentionally fall back to review/monitor rather than enforce.
    pub fn edr_action_for_kind(&self, kind: &crate::edr::EdrDetectionKind) -> EdrAction {
        match kind {
            crate::edr::EdrDetectionKind::YaraMatch | crate::edr::EdrDetectionKind::IocMatch => {
                if !self.resolved.antimalware.enabled {
                    return EdrAction::Monitor;
                }
                parse_edr_action(
                    self.resolved
                        .antimalware
                        .response
                        .as_ref()
                        .and_then(|response| response.action.as_deref())
                        .or(self.resolved.antimalware.response_action.as_deref()),
                )
            }
            crate::edr::EdrDetectionKind::RansomwareCanary => {
                if !self.resolved.ransomware_mitigation.enabled {
                    return EdrAction::Monitor;
                }
                let configured = self
                    .resolved
                    .ransomware_mitigation
                    .response_action
                    .as_deref()
                    .or(self.resolved.ransomware_mitigation.high_confidence_action.as_deref());
                if configured.is_none()
                    && self
                        .resolved
                        .ransomware_mitigation
                        .auto_isolate_on_high_confidence
                {
                    return EdrAction::Isolate;
                }
                parse_edr_action(configured)
            }
            crate::edr::EdrDetectionKind::SuspiciousProcessChain => {
                if !self.resolved.behavior_monitoring.enabled {
                    return EdrAction::Monitor;
                }
                parse_edr_action(
                    self.resolved
                        .behavior_monitoring
                        .high_confidence_action
                        .as_deref(),
                )
            }
            crate::edr::EdrDetectionKind::RansomwareRollback => {
                if !self.resolved.ransomware_mitigation.enabled {
                    return EdrAction::Monitor;
                }
                parse_edr_action(
                    self.resolved
                        .ransomware_mitigation
                        .response_action
                        .as_deref(),
                )
            }
            crate::edr::EdrDetectionKind::ResponseAction => EdrAction::Monitor,
        }
    }
}

fn parse_edr_action(value: Option<&str>) -> EdrAction {
    match value.unwrap_or("review").trim().to_ascii_lowercase().as_str() {
        "quarantine" | "remediate" => EdrAction::Quarantine,
        "quarantine_list" | "list_quarantine" | "list_quarantines" => EdrAction::QuarantineList,
        "quarantine_restore" | "restore_quarantine" | "release_from_quarantine" => EdrAction::QuarantineRestore,
        "kill" | "kill_process" => EdrAction::Kill,
        "isolate" | "isolate_endpoint" => EdrAction::Isolate,
        "monitor" | "allow" => EdrAction::Monitor,
        _ => EdrAction::Review,
    }
}

pub fn load_policy_cache(path: &Path) -> Result<Option<RuntimePolicy>> {
    if !path.exists() {
        return Ok(None);
    }
    let content = fs::read_to_string(path).context("unable to read policy cache")?;
    let cached: RuntimePolicy = serde_json::from_str(&content).context("invalid policy cache json")?;
    Ok(Some(cached))
}

pub fn save_policy_cache(path: &Path, policy: &RuntimePolicy) -> Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).context("unable to create policy cache directory")?;
    }
    fs::write(path, serde_json::to_string_pretty(policy)?).context("unable to write policy cache")?;
    Ok(())
}

fn default_true() -> bool {
    true
}

fn default_labels() -> Vec<String> {
    DEFAULT_SENSITIVITY_LABELS.iter().map(|v| (*v).to_string()).collect()
}

fn default_destinations() -> Vec<String> {
    DEFAULT_GENAI_DESTINATIONS
        .iter()
        .map(|v| (*v).to_string())
        .collect()
}

fn default_review() -> DlpAction {
    DlpAction::Review
}

fn default_block() -> DlpAction {
    DlpAction::Block
}

/// Default policy hot-reload poll interval (30 s) per the agent
/// hot-reload contract. Overridable via
/// `AETHERIX_POLICY_REFRESH_SECONDS`.
pub const DEFAULT_POLICY_REFRESH_SECONDS: u64 = 30;
/// Lower bound for the poll interval so a misconfigured env-var can't
/// hammer the control plane. Tests can opt into zero via
/// [`PolicyHotReloader::with_refresh_interval`].
pub const MIN_POLICY_REFRESH_SECONDS: u64 = 5;

/// Live policy hot-reloader.
///
/// Owns the credentials and refresh cadence for `GET /agent/policy`,
/// transparently falls back to the on-disk last-known-good cache
/// when the control plane is unreachable, and exposes a single
/// `tick()` entrypoint the main DLP loop calls on every iteration.
/// A swap only occurs when the freshly-fetched policy carries a new
/// `policy_version_hash`; otherwise `tick` returns `None` and the
/// caller keeps using its existing policy.
pub struct PolicyHotReloader {
    client: Client,
    api_url: String,
    agent_id: String,
    agent_secret: String,
    cache_path: PathBuf,
    refresh_interval: Duration,
    last_refresh: Option<Instant>,
    current_hash: Option<String>,
}

impl PolicyHotReloader {
    pub fn new(
        client: Client,
        api_url: String,
        agent_id: String,
        agent_secret: String,
        cache_path: PathBuf,
        refresh_interval: Duration,
    ) -> Self {
        Self {
            client,
            api_url,
            agent_id,
            agent_secret,
            cache_path,
            refresh_interval,
            last_refresh: None,
            current_hash: None,
        }
    }

    /// Builds a reloader that honours the `AETHERIX_POLICY_REFRESH_SECONDS`
    /// env-var (defaulted to 30 s, floored at 5 s).
    pub fn from_env(
        client: Client,
        api_url: String,
        agent_id: String,
        agent_secret: String,
        cache_path: PathBuf,
    ) -> Self {
        let secs = std::env::var("AETHERIX_POLICY_REFRESH_SECONDS")
            .ok()
            .and_then(|v| v.parse::<u64>().ok())
            .unwrap_or(DEFAULT_POLICY_REFRESH_SECONDS)
            .max(MIN_POLICY_REFRESH_SECONDS);
        Self::new(
            client,
            api_url,
            agent_id,
            agent_secret,
            cache_path,
            Duration::from_secs(secs),
        )
    }

    /// Test-only escape hatch: allow setting the refresh interval to
    /// anything (including zero) so integration tests can simulate
    /// a hot-reload without sleeping.
    pub fn with_refresh_interval(mut self, interval: Duration) -> Self {
        self.refresh_interval = interval;
        self
    }

    pub fn refresh_interval(&self) -> Duration {
        self.refresh_interval
    }

    /// Initial fetch + cache seeding. The agent cannot run without a
    /// policy, so this returns an error only when both the control
    /// plane is unreachable AND no cached policy exists on disk.
    pub fn bootstrap(&mut self) -> Result<RuntimePolicy> {
        let policy = match fetch_effective_policy(
            &self.client,
            &self.api_url,
            &self.agent_id,
            &self.agent_secret,
        ) {
            Ok(fetched) => {
                let _ = save_policy_cache(&self.cache_path, &fetched);
                fetched
            }
            Err(fetch_error) => load_policy_cache(&self.cache_path)
                .context("unable to load cached policy after fetch failure")?
                .ok_or_else(|| {
                    anyhow::anyhow!(
                        "no policy from api and no last-known-good cache: {fetch_error}"
                    )
                })?,
        };
        self.current_hash = Some(policy.policy_version_hash.clone());
        self.last_refresh = Some(Instant::now());
        println!(
            "aetherix-agent: policy hot-reloader bootstrapped at version {} (refresh every {}s)",
            policy.policy_version_hash,
            self.refresh_interval.as_secs()
        );
        Ok(policy)
    }

    /// Poll the control plane if the refresh interval has elapsed.
    ///
    /// * Returns `Some(new_policy)` only when the fetched policy
    ///   carries a different `policy_version_hash` than the one
    ///   currently active — atomic swap is the caller's
    ///   responsibility.
    /// * Returns `None` when the interval has not yet elapsed, when
    ///   the policy is unchanged, or when the control plane is
    ///   unreachable. In the unreachable case the last-known-good
    ///   policy stays in force — the agent keeps enforcing.
    pub fn tick(&mut self) -> Option<RuntimePolicy> {
        let due = match self.last_refresh {
            Some(at) => at.elapsed() >= self.refresh_interval,
            None => true,
        };
        if !due {
            return None;
        }
        self.last_refresh = Some(Instant::now());

        let fetched = match fetch_effective_policy(
            &self.client,
            &self.api_url,
            &self.agent_id,
            &self.agent_secret,
        ) {
            Ok(p) => p,
            Err(err) => {
                eprintln!(
                    "aetherix-agent: policy refresh failed, continuing on last-known-good ({err})"
                );
                return None;
            }
        };

        let changed = self
            .current_hash
            .as_ref()
            .map(|h| h != &fetched.policy_version_hash)
            .unwrap_or(true);

        if !changed {
            return None;
        }

        let previous = self.current_hash.clone().unwrap_or_else(|| "<none>".into());
        self.current_hash = Some(fetched.policy_version_hash.clone());
        if let Err(err) = save_policy_cache(&self.cache_path, &fetched) {
            eprintln!("aetherix-agent: failed to persist policy cache: {err}");
        }
        println!(
            "aetherix-agent: policy hot-reload applied {} -> {}",
            previous, fetched.policy_version_hash
        );
        Some(fetched)
    }
}

#[cfg(test)]
mod tests {
    use super::{runtime_from_response, AgentPolicyResponse, DlpAction};

    #[test]
    fn normalizes_semantic_and_guardrail_modules() {
        let response = AgentPolicyResponse {
            endpoint_id: "agent-1".to_string(),
            policy_version_hash: "hash-1".to_string(),
            evidence_controls: vec!["iso27001-2022:A.5.12".to_string()],
            resolved_policy: super::AgentPolicyDocument {
                modules: serde_json::json!({
                    "semantic_dlp": {
                        "enabled": true,
                        "sensitivity_labels": ["restricted"],
                        "genai_destinations": ["claude", "chatgpt"],
                        "actions": {
                            "paste_sensitive": "block",
                            "upload_restricted": "review",
                            "copy_to_genai": "block"
                        },
                        "detectors": {
                            "presidio": true,
                            "llm_semantic": false,
                            "custom_classifiers": ["finance"]
                        }
                    },
                    "genai_guardrails": {
                        "enabled": true,
                        "browser_enforcement": true,
                        "endpoint_enforcement": true,
                        "actions": {
                            "paste_sensitive": "block",
                            "upload_restricted": "block",
                            "copy_to_genai": "review"
                        }
                    }
                }),
            },
        };

        let runtime = runtime_from_response(response).expect("policy parse");
        assert!(runtime.resolved.semantic_dlp.enabled);
        assert_eq!(runtime.resolved.semantic_dlp.actions.paste_sensitive, DlpAction::Block);
        assert_eq!(runtime.resolved.genai_guardrails.destinations, vec!["claude", "chatgpt"]);
    }
}

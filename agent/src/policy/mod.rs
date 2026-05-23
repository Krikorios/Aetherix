use anyhow::{Context, Result};
use reqwest::blocking::Client;
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::Path;

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
pub struct ResolvedPolicy {
    #[serde(default)]
    pub semantic_dlp: SemanticDlpPolicy,
    #[serde(default)]
    pub genai_guardrails: GenaiGuardrailsPolicy,
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
        "{}/agent/policy?endpoint_id={}&token={}",
        api_url.trim_end_matches('/'),
        endpoint_id,
        token
    );
    let response = client
        .get(endpoint)
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
        },
    })
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

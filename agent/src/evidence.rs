use crate::dlp::{DlpEvent, EnforcementDecision};
use crate::policy::DlpAction;
use anyhow::{Context, Result};
use reqwest::blocking::Client;
use serde::Serialize;
use sha2::{Digest, Sha256};

#[derive(Serialize)]
pub struct AgentDlpEvidenceRequest {
    pub action_type: String,
    pub decision: String,
    pub destination: Option<String>,
    pub label_detected: Option<String>,
    pub content_hash: String,
    pub policy_version: String,
    pub endpoint_id: String,
    pub event_type: String,
    pub policy_action_field: String,
    pub process_name: Option<String>,
}

pub fn emit_dlp_evidence(
    client: &Client,
    api_url: &str,
    endpoint_id: &str,
    token: &str,
    policy_version: &str,
    event: &DlpEvent,
    decision: &EnforcementDecision,
) -> Result<()> {
    let endpoint = format!(
        "{}/agent/dlp-evidence?endpoint_id={}&token={}",
        api_url.trim_end_matches('/'),
        endpoint_id,
        token
    );

    let payload = AgentDlpEvidenceRequest {
        action_type: decision.action_type.clone(),
        decision: action_to_string(&decision.action).to_string(),
        destination: decision.destination.clone(),
        label_detected: decision.label_detected.clone(),
        content_hash: redact_hash(&event.content),
        policy_version: policy_version.to_string(),
        endpoint_id: endpoint_id.to_string(),
        event_type: format!("{:?}", event.event_type).to_lowercase(),
        policy_action_field: decision.policy_field.to_string(),
        process_name: event.process_name.clone(),
    };

    let response = client
        .post(endpoint)
        .json(&payload)
        .send()
        .context("failed to post DLP evidence")?;

    if !response.status().is_success() {
        anyhow::bail!("DLP evidence rejected with status {}", response.status());
    }

    Ok(())
}

fn redact_hash(content: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(content.as_bytes());
    format!("sha256:{:x}", hasher.finalize())
}

fn action_to_string(action: &DlpAction) -> &'static str {
    match action {
        DlpAction::Allow => "allow",
        DlpAction::Review => "review",
        DlpAction::Block => "block",
        DlpAction::Redact => "redact",
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn content_hash_has_prefix() {
        let hash = super::redact_hash("sensitive-text");
        assert!(hash.starts_with("sha256:"));
        assert!(hash.len() > 20);
    }
}

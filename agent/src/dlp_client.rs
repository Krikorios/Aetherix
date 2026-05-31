//! Thin DLP client facade.
//!
//! All interceptors (clipboard, browser bridge) route through
//! `DlpClient::evaluate` so policy resolution and evidence emission
//! happen in exactly one place. Evidence delivery degrades gracefully:
//! if the control-plane API is unreachable the payload is appended to
//! the local NDJSON queue and replayed by `bridge.rs` on the next
//! successful round-trip.
//!
//! This intentionally re-exports the existing `dlp::evaluate_event`
//! logic rather than duplicating it — there is one source of truth
//! for "what would the policy do".

use std::fs::OpenOptions;
use std::io::Write;
use std::path::PathBuf;

use anyhow::Result;
use reqwest::blocking::Client;
use serde_json::json;

use crate::dlp::{evaluate_event, DlpEvent, EnforcementDecision};
use crate::evidence::emit_dlp_evidence;
use crate::policy::RuntimePolicy;

#[derive(Clone)]
pub struct DlpClient {
    client: Client,
    api_url: String,
    agent_id: String,
    agent_secret: String,
    fallback_queue: PathBuf,
}

impl DlpClient {
    pub fn new(
        client: Client,
        api_url: String,
        agent_id: String,
        agent_secret: String,
        fallback_queue: PathBuf,
    ) -> Self {
        Self {
            client,
            api_url,
            agent_id,
            agent_secret,
            fallback_queue,
        }
    }

    /// Resolve the policy decision for an intercepted event. Returns
    /// `None` when the policy does not apply (e.g. no labelled content)
    /// — in which case the interceptor must allow the action through
    /// unchanged.
    pub fn evaluate(
        &self,
        policy: &RuntimePolicy,
        event: &DlpEvent,
    ) -> Option<EnforcementDecision> {
        evaluate_event(policy, event)
    }

    /// Emit compliance evidence (review + attestation) for an
    /// intercepted action. On transport failure the payload is queued
    /// locally so the action is still enforced and never silently
    /// dropped.
    pub fn emit(
        &self,
        policy_version: &str,
        event: &DlpEvent,
        decision: &EnforcementDecision,
    ) -> Result<()> {
        let ev_res = emit_dlp_evidence(
            &self.client,
            &self.api_url,
            &self.agent_id,
            &self.agent_secret,
            policy_version,
            event,
            decision,
        );

        let rev_res = self.create_compliance_review(policy_version, event, decision);
        
        let att_res = if matches!(decision.action, crate::policy::DlpAction::Block) {
            self.create_attestation(policy_version, event)
        } else {
            Ok(())
        };

        if ev_res.is_err() || rev_res.is_err() || att_res.is_err() {
            eprintln!(
                "aetherix-agent: evidence/compliance post failed; enqueueing for retry"
            );
            self.enqueue_fallback(policy_version, event, decision)?;
            Ok(())
        } else {
            Ok(())
        }
    }

    pub fn create_compliance_review(
        &self,
        _policy_version: &str,
        _event: &DlpEvent,
        decision: &EnforcementDecision,
    ) -> Result<()> {
        let payload = json!({
            "source_table": "evidence_events",
            "source_id": uuid::Uuid::new_v4().to_string(),
            "framework": "iso27001-2022",
            "control_id": "A.5.12",
            "decision": match decision.action {
                crate::policy::DlpAction::Block => "rejected",
                _ => "approved"
            },
            "note": "Agent automatic review",
            "reviewed_by_role": "auto-attested",
            "reviewed_by_name": self.agent_id,
        });

        let endpoint = format!("{}/compliance/reviews", self.api_url.trim_end_matches('/'));
        let response = self.client.post(&endpoint)
            .header("Authorization", format!("Bearer {}", self.agent_secret))
            .json(&payload)
            .send()?;

        if !response.status().is_success() {
            anyhow::bail!("Compliance review rejected with status {}", response.status());
        }
        Ok(())
    }

    pub fn create_attestation(
        &self,
        policy_version: &str,
        event: &DlpEvent,
    ) -> Result<()> {
        use sha2::{Digest, Sha256};
        use hmac::{Hmac, Mac};
        
        let content_hash = format!("{:x}", Sha256::digest(format!("{}:{}", event.content, policy_version).as_bytes()));
        
        let mut mac = Hmac::<Sha256>::new_from_slice(self.agent_secret.as_bytes())
            .map_err(|e| anyhow::anyhow!("hmac init failed: {}", e))?;
        mac.update(content_hash.as_bytes());
        let signature = format!("{:x}", mac.finalize().into_bytes());

        let now = chrono::Utc::now().format("%Y-%m-%d").to_string();

        let payload = json!({
            "framework": "iso27001-2022",
            "period_start": now,
            "period_end": now,
            "attested_role": "auto-attested",
            "attested_name": self.agent_id,
            "statement": "Auto-attested block",
            "bundle_sha256": content_hash,
            "signature": signature,
            "signature_algo": "hmac-sha256"
        });

        let endpoint = format!("{}/compliance/attestations", self.api_url.trim_end_matches('/'));
        let response = self.client.post(&endpoint)
            .header("Authorization", format!("Bearer {}", self.agent_secret))
            .json(&payload)
            .send()?;

        if !response.status().is_success() {
            anyhow::bail!("Compliance attestation rejected with status {}", response.status());
        }
        Ok(())
    }

    fn enqueue_fallback(
        &self,
        policy_version: &str,
        event: &DlpEvent,
        decision: &EnforcementDecision,
    ) -> Result<()> {
        if let Some(parent) = self.fallback_queue.parent() {
            std::fs::create_dir_all(parent).ok();
        }
        let line = serde_json::to_string(&json!({
            "kind": "endpoint_evidence",
            "policy_version": policy_version,
            "event": event,
            "decision": decision,
            "enqueued_at": chrono::Utc::now().to_rfc3339(),
        }))?;
        let mut file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.fallback_queue)?;
        file.write_all(line.as_bytes())?;
        file.write_all(b"\n")?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dlp::{DlpEvent, DlpEventType, EnforcementDecision, EventSource};
    use crate::policy::DlpAction;
    use mockito::Server;
    use reqwest::blocking::Client;
    use tempfile::tempdir;

    #[test]
    fn test_compliance_review_and_attestation_on_block() {
        let mut server = Server::new();
        
        let review_mock = server.mock("POST", "/compliance/reviews")
            .with_status(200)
            .create();
            
        let attestation_mock = server.mock("POST", "/compliance/attestations")
            .with_status(201)
            .create();

        let dir = tempdir().unwrap();
        let queue = dir.path().join("q.ndjson");
        
        let client = DlpClient::new(
            Client::new(),
            server.url(),
            "agent-123".to_string(),
            "secret-abc".to_string(),
            queue,
        );

        let event = DlpEvent {
            event_type: DlpEventType::Paste,
            source: EventSource::Endpoint,
            content: "sensitive string".to_string(),
            destination: None,
            process_name: None,
            sha256_hash: None,
        };

        let decision = EnforcementDecision {
            action: DlpAction::Block,
            action_type: "dlp.paste_block".to_string(),
            policy_field: "paste_sensitive",
            label_detected: Some("pii.ssn".to_string()),
            destination: None,
        };

        client.create_compliance_review("v1", &event, &decision).unwrap();
        client.create_attestation("v1", &event).unwrap();

        review_mock.assert();
        attestation_mock.assert();
    }
}

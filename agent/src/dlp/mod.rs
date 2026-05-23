use crate::dlp::genai::destination_allowed;
use crate::dlp::semantic::detect_label;
use crate::policy::{DlpAction, RuntimePolicy};
use serde::{Deserialize, Serialize};

pub mod genai;
pub mod semantic;

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum DlpEventType {
    Paste,
    Upload,
    Copy,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum EventSource {
    Endpoint,
    BrowserExtension,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DlpEvent {
    pub event_type: DlpEventType,
    pub source: EventSource,
    pub content: String,
    pub destination: Option<String>,
    pub process_name: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct EnforcementDecision {
    pub action: DlpAction,
    pub action_type: String,
    pub destination: Option<String>,
    pub label_detected: Option<String>,
    pub policy_field: &'static str,
}

pub fn evaluate_event(policy: &RuntimePolicy, event: &DlpEvent) -> Option<EnforcementDecision> {
    let semantic = &policy.resolved.semantic_dlp;
    let guardrails = &policy.resolved.genai_guardrails;

    if !semantic.enabled && !guardrails.enabled {
        return None;
    }

    if matches!(event.source, EventSource::BrowserExtension) && !guardrails.browser_enforcement {
        return None;
    }
    if matches!(event.source, EventSource::Endpoint) && !guardrails.endpoint_enforcement {
        return None;
    }

    let label = detect_label(&event.content, semantic);
    if label.is_none() {
        return None;
    }

    let destination_ok = event
        .destination
        .as_ref()
        .map(|dest| destination_allowed(dest, &semantic.genai_destinations) || destination_allowed(dest, &guardrails.destinations))
        .unwrap_or(true);

    if !destination_ok {
        return None;
    }

    let (action, action_type, policy_field) = match event.event_type {
        DlpEventType::Paste => (
            guardrails.actions.paste_sensitive.clone(),
            "paste_blocked",
            "paste_sensitive",
        ),
        DlpEventType::Upload => (
            guardrails.actions.upload_restricted.clone(),
            "upload_reviewed",
            "upload_restricted",
        ),
        DlpEventType::Copy => (
            guardrails.actions.copy_to_genai.clone(),
            "genai_copy_detected",
            "copy_to_genai",
        ),
    };

    Some(EnforcementDecision {
        action,
        action_type: action_type.to_string(),
        destination: event.destination.clone(),
        label_detected: label,
        policy_field,
    })
}

#[cfg(test)]
mod tests {
    use crate::dlp::{evaluate_event, DlpEvent, DlpEventType, EventSource};
    use crate::policy::{
        DlpAction, GenaiGuardrailsPolicy, ResolvedPolicy, RuntimePolicy, SemanticActions, SemanticDlpPolicy,
    };

    #[test]
    fn blocks_sensitive_paste_to_allowed_destination() {
        let policy = RuntimePolicy {
            endpoint_id: "agent-1".to_string(),
            policy_version_hash: "v1".to_string(),
            evidence_controls: vec![],
            resolved: ResolvedPolicy {
                semantic_dlp: SemanticDlpPolicy {
                    enabled: true,
                    sensitivity_labels: vec!["restricted".to_string()],
                    genai_destinations: vec!["chatgpt".to_string()],
                    actions: SemanticActions::default(),
                    detectors: Default::default(),
                },
                genai_guardrails: GenaiGuardrailsPolicy {
                    enabled: true,
                    destinations: vec!["chatgpt".to_string()],
                    browser_enforcement: true,
                    endpoint_enforcement: true,
                    actions: SemanticActions {
                        paste_sensitive: DlpAction::Block,
                        upload_restricted: DlpAction::Review,
                        copy_to_genai: DlpAction::Review,
                    },
                },
            },
        };

        let event = DlpEvent {
            event_type: DlpEventType::Paste,
            source: EventSource::BrowserExtension,
            content: "[restricted] quarterly mrr and customer pii".to_string(),
            destination: Some("https://chatgpt.com".to_string()),
            process_name: Some("chrome".to_string()),
        };

        let decision = evaluate_event(&policy, &event).expect("decision expected");
        assert_eq!(decision.action, DlpAction::Block);
        assert_eq!(decision.label_detected.as_deref(), Some("restricted"));
    }
}

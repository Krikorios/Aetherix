use crate::dlp::genai::destination_allowed;
use crate::dlp::semantic::detect_label;
use crate::policy::{DlpAction, RuntimePolicy, SemanticDlpPolicy};
use serde::{Deserialize, Serialize};

pub mod genai;
pub mod semantic;

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum DlpEventType {
    Paste,
    Upload,
    Copy,
    UsbMounted,
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

/// Selects the appropriate action source for a decision.
///
/// Priority order (semantic > guardrails):
/// 1. If semantic DLP is enabled and detected a label → use `semantic.actions`
/// 2. Otherwise → use `guardrails.actions`
fn select_actions<'a>(
    semantic: &'a SemanticDlpPolicy,
    guardrails_actions: &'a crate::policy::SemanticActions,
    label_is_some: bool,
) -> &'a crate::policy::SemanticActions {
    if semantic.enabled && label_is_some {
        eprintln!("[dlp] using semantic.actions (semantic DLP triggered)");
        &semantic.actions
    } else {
        eprintln!("[dlp] using guardrails.actions (fallback)");
        guardrails_actions
    }
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

    let actions = select_actions(semantic, &guardrails.actions, label.is_some());

    let (action, action_type, policy_field) = match event.event_type {
        DlpEventType::Paste => (
            actions.paste_sensitive.clone(),
            "paste_blocked",
            "paste_sensitive",
        ),
        DlpEventType::Upload => (
            actions.upload_restricted.clone(),
            "upload_reviewed",
            "upload_restricted",
        ),
        DlpEventType::Copy => (
            actions.copy_to_genai.clone(),
            "genai_copy_detected",
            "copy_to_genai",
        ),
        DlpEventType::UsbMounted => (
            DlpAction::Block, // Hardcoded block for POC, would come from policy in prod
            "usb_mounted",
            "usb_control",
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

    fn make_policy(
        semantic_enabled: bool,
        semantic_actions: SemanticActions,
        guardrails_enabled: bool,
        guardrails_actions: SemanticActions,
    ) -> RuntimePolicy {
        RuntimePolicy {
            endpoint_id: "agent-1".to_string(),
            policy_version_hash: "v1".to_string(),
            evidence_controls: vec![],
            resolved: ResolvedPolicy {
                semantic_dlp: SemanticDlpPolicy {
                    enabled: semantic_enabled,
                    sensitivity_labels: vec!["restricted".to_string()],
                    genai_destinations: vec!["chatgpt".to_string()],
                    actions: semantic_actions,
                    detectors: Default::default(),
                },
                genai_guardrails: GenaiGuardrailsPolicy {
                    enabled: guardrails_enabled,
                    destinations: vec!["chatgpt".to_string()],
                    browser_enforcement: true,
                    endpoint_enforcement: true,
                    actions: guardrails_actions,
                },
                ..Default::default()
            },
        }
    }

    fn paste_event() -> DlpEvent {
        DlpEvent {
            event_type: DlpEventType::Paste,
            source: EventSource::BrowserExtension,
            content: "[restricted] quarterly mrr and customer pii".to_string(),
            destination: Some("https://chatgpt.com".to_string()),
            process_name: Some("chrome".to_string()),
        }
    }

    // ── Semantic enabled + Guardrails enabled ──────────────────────────

    #[test]
    fn semantic_actions_take_priority_when_both_enabled() {
        let policy = make_policy(
            true,
            SemanticActions {
                paste_sensitive: DlpAction::Review,
                upload_restricted: DlpAction::Block,
                copy_to_genai: DlpAction::Review,
            },
            true,
            SemanticActions {
                paste_sensitive: DlpAction::Block,
                upload_restricted: DlpAction::Block,
                copy_to_genai: DlpAction::Block,
            },
        );

        let decision = evaluate_event(&policy, &paste_event()).expect("decision expected");
        // Semantic is enabled and matched → use semantic.actions (Review), NOT guardrails.actions (Block)
        assert_eq!(decision.action, DlpAction::Review);
        assert_eq!(decision.label_detected.as_deref(), Some("restricted"));
        assert_eq!(decision.policy_field, "paste_sensitive");
    }

    #[test]
    fn semantic_actions_with_block_take_priority() {
        let policy = make_policy(
            true,
            SemanticActions {
                paste_sensitive: DlpAction::Block,
                upload_restricted: DlpAction::Block,
                copy_to_genai: DlpAction::Block,
            },
            true,
            SemanticActions {
                paste_sensitive: DlpAction::Allow,
                upload_restricted: DlpAction::Allow,
                copy_to_genai: DlpAction::Allow,
            },
        );

        let decision = evaluate_event(&policy, &paste_event()).expect("decision expected");
        assert_eq!(decision.action, DlpAction::Block);
    }

    // ── Only Semantic DLP enabled ──────────────────────────────────────

    #[test]
    fn uses_semantic_actions_when_only_semantic_enabled() {
        let policy = make_policy(
            true,
            SemanticActions {
                paste_sensitive: DlpAction::Block,
                upload_restricted: DlpAction::Block,
                copy_to_genai: DlpAction::Review,
            },
            false,
            SemanticActions::default(),
        );

        let decision = evaluate_event(&policy, &paste_event()).expect("decision expected");
        assert_eq!(decision.action, DlpAction::Block);
    }

    #[test]
    fn returns_none_when_neither_module_enabled() {
        let policy = make_policy(false, SemanticActions::default(), false, SemanticActions::default());
        assert!(evaluate_event(&policy, &paste_event()).is_none());
    }

    // ── Source enforcement gates ───────────────────────────────────────

    #[test]
    fn respects_browser_enforcement_gate() {
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
                    browser_enforcement: false,
                    endpoint_enforcement: true,
                    actions: SemanticActions {
                        paste_sensitive: DlpAction::Block,
                        ..SemanticActions::default()
                    },
                },
                ..Default::default()
            },
        };

        let event = DlpEvent {
            event_type: DlpEventType::Paste,
            source: EventSource::BrowserExtension,
            content: "[restricted] secret".to_string(),
            destination: Some("https://chatgpt.com".to_string()),
            process_name: Some("chrome".to_string()),
        };

        // browser_enforcement is false → should return None even with label match
        assert!(evaluate_event(&policy, &event).is_none());
    }
}

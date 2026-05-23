use crate::policy::{DetectorConfig, SemanticDlpPolicy};

pub fn detect_label(content: &str, policy: &SemanticDlpPolicy) -> Option<String> {
    if !policy.enabled {
        return None;
    }
    let lowered = content.to_lowercase();

    for label in &policy.sensitivity_labels {
        if lowered.contains(&format!("[{label}]")) || lowered.contains(label) {
            return Some(label.clone());
        }
    }

    if policy.detectors.presidio && looks_like_structured_pii(&lowered) {
        return Some("restricted".to_string());
    }

    if policy.detectors.llm_semantic && looks_like_semantic_secret(&lowered) {
        return Some("confidential".to_string());
    }

    if has_custom_classifier_hit(&lowered, &policy.detectors) {
        return Some("restricted".to_string());
    }

    None
}

fn looks_like_structured_pii(content: &str) -> bool {
    let has_ssn = content
        .split_whitespace()
        .any(|token| token.len() == 11 && token.chars().filter(|c| *c == '-').count() == 2);
    let has_card = content
        .chars()
        .filter(|c| c.is_ascii_digit())
        .count()
        >= 15;
    has_ssn || has_card || content.contains("passport") || content.contains("tax id")
}

fn looks_like_semantic_secret(content: &str) -> bool {
    content.contains("api key")
        || content.contains("private key")
        || content.contains("access token")
        || content.contains("customer pii")
        || content.contains("patient record")
}

fn has_custom_classifier_hit(content: &str, detectors: &DetectorConfig) -> bool {
    detectors
        .custom_classifiers
        .iter()
        .map(|c| c.to_lowercase())
        .any(|needle| !needle.is_empty() && content.contains(&needle))
}

#[cfg(test)]
mod tests {
    use crate::policy::{DetectorConfig, SemanticActions, SemanticDlpPolicy};

    #[test]
    fn finds_sensitive_label_from_content() {
        let policy = SemanticDlpPolicy {
            enabled: true,
            sensitivity_labels: vec!["restricted".to_string()],
            genai_destinations: vec!["chatgpt".to_string()],
            actions: SemanticActions::default(),
            detectors: DetectorConfig::default(),
        };

        let label = super::detect_label("[restricted] customer report", &policy);
        assert_eq!(label.as_deref(), Some("restricted"));
    }
}

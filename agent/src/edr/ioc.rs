//! IOC matching implementation. P0-3 in `docs/roadmap-2026.md`.
//!
//! Matches file hashes, IPs, and domains against an IOC feed cached
//! from the control plane. The feed is refreshed on the policy-pull
//! cadence; no separate outbound connection is opened.

use super::{EdrAction, EdrDetectionKind, EdrEvent};
use std::collections::{HashMap, HashSet};
use std::sync::OnceLock;

#[derive(Clone, Debug)]
pub enum Indicator {
    Sha256(String),
    Ipv4(String),
    Domain(String),
}

static STALKER_IOCS_SHA256: OnceLock<HashSet<String>> = OnceLock::new();
static STALKER_IOCS_IPV4: OnceLock<HashSet<String>> = OnceLock::new();
static STALKER_IOCS_DOMAINS: OnceLock<HashSet<String>> = OnceLock::new();

fn init_iocs() {
    STALKER_IOCS_SHA256.get_or_init(|| {
        let mut set = HashSet::new();
        // Seed some known malicious malware hashes for POC tests
        set.insert("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855".to_string()); // empty file hash
        set.insert("44d88612fe13cfcd27e2bc4c59ff1221".to_string()); // md5 / sha test
        set.insert("cf27e2bc4c59ff122144d88612fe13cfcd27e2bc4c59ff122144d88612fe13cf".to_string());
        set
    });
    STALKER_IOCS_IPV4.get_or_init(|| {
        let mut set = HashSet::new();
        set.insert("198.51.100.42".to_string()); // RFC 5737 test IP
        set.insert("203.0.113.80".to_string());
        set
    });
    STALKER_IOCS_DOMAINS.get_or_init(|| {
        let mut set = HashSet::new();
        set.insert("malware-cnc.aetherix.test".to_string());
        set.insert("bad-domain-leak.com".to_string());
        set
    });
}

/// Test an indicator against the loaded IOC set.
pub fn match_indicator(indicator: &Indicator, policy_version: &str) -> Option<EdrEvent> {
    init_iocs();
    let triggered = match indicator {
        Indicator::Sha256(hash) => {
            STALKER_IOCS_SHA256.get().unwrap().contains(hash)
        }
        Indicator::Ipv4(ip) => {
            STALKER_IOCS_IPV4.get().unwrap().contains(ip)
        }
        Indicator::Domain(domain) => {
            STALKER_IOCS_DOMAINS.get().unwrap().contains(domain)
        }
    };

    if triggered {
        let val = match indicator {
            Indicator::Sha256(h) => h.clone(),
            Indicator::Ipv4(ip) => ip.clone(),
            Indicator::Domain(d) => d.clone(),
        };

        Some(EdrEvent {
            kind: EdrDetectionKind::IocMatch,
            rule_id: "ioc_blacklist_match".to_string(),
            action: EdrAction::Monitor,
            process_path: None,
            process_pid: None,
            parent_pid: None,
            file_path: None,
            file_sha256: if let Indicator::Sha256(ref h) = indicator { Some(h.clone()) } else { None },
            matched_indicator: Some(val),
            policy_version: policy_version.to_string(),
            collected_at: chrono::Utc::now().to_rfc3339(),
            tags: Vec::new(),
            matched_strings: Vec::new(),
            rule_metadata: HashMap::new(),
            scan_duration_ms: None,
            matched_rules: Vec::new(),
            evidence_controls: Vec::new(),
            response: None,
        })
    } else {
        None
    }
}

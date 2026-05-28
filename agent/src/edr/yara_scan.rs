use super::{EdrAction, EdrDetectionKind, EdrEvent, YaraStringMatch};
use anyhow::Result;
use sha2::{Digest, Sha256};
use std::collections::{HashMap, VecDeque};
use std::sync::Mutex;
use std::time::Instant;
use std::{fs, time::Duration};
use yara_x::{Compiler, Rules, Scanner};

const DEFAULT_MAX_SCAN_SIZE: u64 = 256 * 1024 * 1024;
const DEFAULT_SCAN_TIMEOUT_SECS: u64 = 30;
const DEFAULT_MAX_MATCHES_PER_PATTERN: usize = 10;
const DEFAULT_CACHE_CAPACITY: usize = 10000;

#[derive(Clone, Debug)]
pub struct YaraScanConfig {
    pub max_scan_size: u64,
    pub scan_timeout: Duration,
    pub max_matches_per_pattern: usize,
    pub excluded_paths: Vec<String>,
    pub scan_cache_capacity: usize,
    pub enabled: bool,
}

impl Default for YaraScanConfig {
    fn default() -> Self {
        Self {
            max_scan_size: DEFAULT_MAX_SCAN_SIZE,
            scan_timeout: Duration::from_secs(DEFAULT_SCAN_TIMEOUT_SECS),
            max_matches_per_pattern: DEFAULT_MAX_MATCHES_PER_PATTERN,
            excluded_paths: Vec::new(),
            scan_cache_capacity: DEFAULT_CACHE_CAPACITY,
            enabled: true,
        }
    }
}

impl YaraScanConfig {
    pub fn with_max_scan_size(mut self, size: u64) -> Self {
        self.max_scan_size = size;
        self
    }

    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.scan_timeout = timeout;
        self
    }

    pub fn with_excluded_paths(mut self, paths: Vec<String>) -> Self {
        self.excluded_paths = paths;
        self
    }
}

struct ScanCacheEntry {
    sha256: String,
    matched: bool,
    rule_ids: Vec<String>,
}

pub struct ScanCache {
    entries: HashMap<String, ScanCacheEntry>,
    eviction_order: VecDeque<String>,
    capacity: usize,
}

impl ScanCache {
    pub fn new(capacity: usize) -> Self {
        Self {
            entries: HashMap::new(),
            eviction_order: VecDeque::new(),
            capacity,
        }
    }

    pub fn get(&self, sha256: &str) -> Option<&ScanCacheEntry> {
        self.entries.get(sha256)
    }

    pub fn insert(&mut self, entry: ScanCacheEntry) {
        if self.entries.len() >= self.capacity {
            if let Some(oldest) = self.eviction_order.pop_front() {
                self.entries.remove(&oldest);
            }
        }
        self.eviction_order.push_back(entry.sha256.clone());
        self.entries.insert(entry.sha256.clone(), entry);
    }

    pub fn clear(&mut self) {
        self.entries.clear();
        self.eviction_order.clear();
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }
}

pub struct YaraRuleStore {
    rules: Option<Rules>,
    namespaces: HashMap<String, String>,
    raw_sources: Vec<String>,
    config: YaraScanConfig,
    cache: Mutex<ScanCache>,
}

impl YaraRuleStore {
    pub fn new() -> Self {
        Self::with_config(YaraScanConfig::default())
    }

    pub fn with_config(config: YaraScanConfig) -> Self {
        let cap = config.scan_cache_capacity;
        Self {
            rules: None,
            namespaces: HashMap::new(),
            raw_sources: Vec::new(),
            config,
            cache: Mutex::new(ScanCache::new(cap)),
        }
    }

    pub fn load(&mut self, source: &str) -> Result<()> {
        let mut compiler = Compiler::new();
        compiler.add_source(source)?;
        self.rules = Some(compiler.build());
        self.raw_sources = vec![source.to_string()];
        self.clear_cache();
        Ok(())
    }

    pub fn load_with_namespace(&mut self, source: &str, namespace: &str) -> Result<()> {
        let mut compiler = Compiler::new();
        compiler.new_namespace(namespace);
        compiler.add_source(source)?;
        self.rules = Some(compiler.build());
        self.namespaces.insert(namespace.to_string(), source.to_string());
        self.clear_cache();
        Ok(())
    }

    pub fn append(&mut self, source: &str) -> Result<()> {
        let existing = self.serialize_current_rules();
        let combined = if existing.is_empty() {
            source.to_string()
        } else {
            format!("{existing}\n{source}")
        };
        self.load(&combined)
    }

    pub fn append_with_namespace(&mut self, source: &str, namespace: &str) -> Result<()> {
        let existing_source = self.namespaces.get(namespace);
        let combined = match existing_source {
            Some(prev) => format!("{prev}\n{source}"),
            None => source.to_string(),
        };
        self.load_with_namespace(&combined, namespace)
    }

    pub fn load_from_payload(payload: &serde_json::Value) -> Result<Self> {
        let mut store = Self::new();
        if let Some(yara_value) = payload.get("yara_rules") {
            if let Some(source) = yara_value.as_str() {
                store.load(source)?;
            }
        }
        if let Some(namespaces) = payload.get("yara_namespaces").and_then(|v| v.as_object()) {
            for (ns, source_val) in namespaces {
                if let Some(source) = source_val.as_str() {
                    store.load_with_namespace(source, ns)?;
                }
            }
        }
        if let Some(config_val) = payload.get("yara_config") {
            if let Some(max_size) = config_val.get("max_scan_size").and_then(|v| v.as_u64()) {
                store.config.max_scan_size = max_size;
            }
            if let Some(timeout_secs) = config_val.get("scan_timeout_secs").and_then(|v| v.as_u64()) {
                store.config.scan_timeout = Duration::from_secs(timeout_secs);
            }
            if let Some(excluded) = config_val.get("excluded_paths").and_then(|v| v.as_array()) {
                store.config.excluded_paths = excluded
                    .iter()
                    .filter_map(|v| v.as_str().map(String::from))
                    .collect();
            }
            if let Some(enabled) = config_val.get("enabled").and_then(|v| v.as_bool()) {
                store.config.enabled = enabled;
            }
        }
        Ok(store)
    }

    pub fn reload(&mut self) -> Result<()> {
        if self.namespaces.is_empty() {
            return Ok(());
        }
        let mut compiler = Compiler::new();
        for (ns, source) in &self.namespaces {
            compiler.new_namespace(ns);
            compiler.add_source(source.as_str())?;
        }
        self.rules = Some(compiler.build());
        self.clear_cache();
        Ok(())
    }

    pub fn rules(&self) -> Option<&Rules> {
        self.rules.as_ref()
    }

    pub fn is_loaded(&self) -> bool {
        self.rules.is_some()
    }

    pub fn config(&self) -> &YaraScanConfig {
        &self.config
    }

    pub fn config_mut(&mut self) -> &mut YaraScanConfig {
        &mut self.config
    }

    pub fn cache(&self) -> &Mutex<ScanCache> {
        &self.cache
    }

    pub fn clear_cache(&self) {
        if let Ok(mut c) = self.cache.lock() {
            c.clear();
        }
    }

    pub fn validate_source(source: &str) -> std::result::Result<(), Vec<String>> {
        let mut compiler = Compiler::new();
        match compiler.add_source(source) {
            Ok(_) => {
                let _ = compiler.build();
                Ok(())
            }
            Err(e) => Err(vec![format!("{e}")]),
        }
    }

    fn serialize_current_rules(&self) -> String {
        self.raw_sources.join("\n")
    }
}

fn extract_metadata(rule: &yara_x::Rule) -> HashMap<String, String> {
    let mut meta = HashMap::new();
    for (ident, value) in rule.metadata() {
        let str_val = match value {
            yara_x::MetaValue::String(s) => s.to_string(),
            yara_x::MetaValue::Integer(i) => i.to_string(),
            yara_x::MetaValue::Float(f) => f.to_string(),
            yara_x::MetaValue::Bool(b) => b.to_string(),
            yara_x::MetaValue::Bytes(b) => hex_encode(b),
        };
        meta.insert(ident.to_string(), str_val);
    }
    meta
}

fn extract_tags(rule: &yara_x::Rule) -> Vec<String> {
    rule.tags().map(|t| t.identifier().to_string()).collect()
}

fn extract_matched_strings(rule: &yara_x::Rule, max_matches: usize) -> Vec<YaraStringMatch> {
    let mut strings = Vec::new();
    for pattern in rule.patterns() {
        let ident = pattern.identifier().to_string();
        let mut match_count = 0;
        for m in pattern.matches() {
            if match_count >= max_matches {
                break;
            }
            let range = m.range();
            let offset = range.start as u64;
            let length = range.end.saturating_sub(range.start) as u64;
            let data = m.data();
            let matched_data = if data.len() <= 64 {
                Some(hex_encode(data))
            } else {
                let truncated = hex_encode(&data[..64]);
                Some(format!("{truncated}..."))
            };
            strings.push(YaraStringMatch {
                identifier: ident.clone(),
                matched_data,
                offset: Some(offset),
                length: Some(length),
            });
            match_count += 1;
        }
    }
    strings
}

fn hex_encode(bytes: &[u8]) -> String {
    bytes.iter().fold(String::new(), |mut acc, b| {
        acc.push_str(&format!("{b:02x}"));
        acc
    })
}

fn compute_sha256_bytes(data: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(data);
    format!("{:x}", hasher.finalize())
}

pub fn compute_sha256_path(path: &str) -> Option<String> {
    let data = fs::read(path).ok()?;
    Some(compute_sha256_bytes(&data))
}

pub fn compute_sha256_for_path(path: &str) -> Option<String> {
    compute_sha256_path(path)
}

fn is_excluded(path: &str, config: &YaraScanConfig) -> bool {
    config.excluded_paths.iter().any(|excluded| path.starts_with(excluded) || path.contains(excluded))
}

fn exceeds_max_size(path: &str, max_size: u64) -> bool {
    fs::metadata(path).map(|m| m.len() > max_size).unwrap_or(true)
}

pub fn scan_path(path: &str, store: &YaraRuleStore, policy_version: &str) -> Vec<EdrEvent> {
    if !store.config.enabled {
        return Vec::new();
    }
    let rules = match store.rules() {
        Some(r) => r,
        None => return Vec::new(),
    };

    if is_excluded(path, &store.config) {
        return Vec::new();
    }

    if exceeds_max_size(path, store.config.max_scan_size) {
        return Vec::new();
    }

    let sha256 = match compute_sha256_path(path) {
        Some(h) => h,
        None => return Vec::new(),
    };

    if let Ok(cache) = store.cache.lock() {
        if let Some(entry) = cache.get(&sha256) {
            if entry.matched {
                return entry
                    .rule_ids
                    .iter()
                    .map(|rule_id| {
                        let mut event = create_minimal_event(rule_id, path, &sha256, policy_version);
                        event.scan_duration_ms = Some(0);
                        event
                    })
                    .collect();
            }
            return Vec::new();
        }
    }

    let start = Instant::now();
    let data = match fs::read(path) {
        Ok(d) => d,
        Err(_) => return Vec::new(),
    };

    let events = scan_data(&data, rules, &store.config, path, &sha256, policy_version, start);

    if let Ok(mut cache) = store.cache.lock() {
        let matched = !events.is_empty();
        let rule_ids: Vec<String> = events.iter().map(|e| e.rule_id.clone()).collect();
        cache.insert(ScanCacheEntry { sha256, matched, rule_ids });
    }

    events
}

pub fn scan_bytes(data: &[u8], store: &YaraRuleStore, source: &str, policy_version: &str) -> Vec<EdrEvent> {
    if !store.config.enabled {
        return Vec::new();
    }
    let rules = match store.rules() {
        Some(r) => r,
        None => return Vec::new(),
    };

    let sha256 = compute_sha256_bytes(data);
    let start = Instant::now();

    if let Ok(cache) = store.cache.lock() {
        if let Some(entry) = cache.get(&sha256) {
            if entry.matched {
                return entry
                    .rule_ids
                    .iter()
                    .map(|rule_id| create_minimal_event(rule_id, source, &sha256, policy_version))
                    .collect();
            }
            return Vec::new();
        }
    }

    let events = scan_data(data, rules, &store.config, source, &sha256, policy_version, start);

    if let Ok(mut cache) = store.cache.lock() {
        let matched = !events.is_empty();
        let rule_ids: Vec<String> = events.iter().map(|e| e.rule_id.clone()).collect();
        cache.insert(ScanCacheEntry { sha256, matched, rule_ids });
    }

    events
}

fn scan_data(
    data: &[u8],
    rules: &Rules,
    config: &YaraScanConfig,
    source: &str,
    sha256: &str,
    policy_version: &str,
    start: Instant,
) -> Vec<EdrEvent> {
    if data.is_empty() {
        return Vec::new();
    }

    let mut scanner = Scanner::new(rules);
    scanner
        .set_timeout(config.scan_timeout)
        .max_scan_size(data.len().min(config.max_scan_size as usize))
        .max_matches_per_pattern(config.max_matches_per_pattern);

    let scan_data = if data.len() > config.max_scan_size as usize {
        &data[..config.max_scan_size as usize]
    } else {
        data
    };

    let scan_results = match scanner.scan(scan_data) {
        Ok(r) => r,
        Err(_) => return Vec::new(),
    };

    let scan_duration_ms = start.elapsed().as_millis() as u64;
    let now = chrono::Utc::now().to_rfc3339();

    let matching_rules: Vec<_> = scan_results.matching_rules().collect();
    let all_rule_ids: Vec<String> = matching_rules.iter().map(|r| r.identifier().to_string()).collect();

    let mut events = Vec::new();
    for rule in &matching_rules {
        let rule_id = rule.identifier().to_string();
        let tags = extract_tags(rule);
        let metadata = extract_metadata(rule);
        let matched_strings = extract_matched_strings(rule, config.max_matches_per_pattern);

        events.push(EdrEvent {
            kind: EdrDetectionKind::YaraMatch,
            rule_id,
            action: EdrAction::Monitor,
            process_path: None,
            process_pid: None,
            parent_pid: None,
            file_path: Some(source.to_string()),
            file_sha256: Some(sha256.to_string()),
            matched_indicator: matched_strings.first().map(|s| s.identifier.clone()),
            policy_version: policy_version.to_string(),
            collected_at: now.clone(),
            tags,
            matched_strings,
            rule_metadata: metadata,
            scan_duration_ms: Some(scan_duration_ms),
            matched_rules: all_rule_ids.clone(),
            evidence_controls: Vec::new(),
            response: None,
            recovery_hints: None,
            rollback_evidence: None,
        });
    }

    events
}

fn create_minimal_event(rule_id: &str, source: &str, sha256: &str, policy_version: &str) -> EdrEvent {
    EdrEvent {
        kind: EdrDetectionKind::YaraMatch,
        rule_id: rule_id.to_string(),
        action: EdrAction::Monitor,
        process_path: None,
        process_pid: None,
        parent_pid: None,
        file_path: Some(source.to_string()),
        file_sha256: Some(sha256.to_string()),
        matched_indicator: None,
        policy_version: policy_version.to_string(),
        collected_at: chrono::Utc::now().to_rfc3339(),
        tags: Vec::new(),
        matched_strings: Vec::new(),
        rule_metadata: HashMap::new(),
        scan_duration_ms: None,
        matched_rules: vec![rule_id.to_string()],
        evidence_controls: Vec::new(),
        response: None,
        recovery_hints: None,
        rollback_evidence: None,
    }
}

pub fn validate_rules(source: &str) -> std::result::Result<(), Vec<String>> {
    YaraRuleStore::validate_source(source)
}

pub fn scan_paths(paths: &[String], store: &YaraRuleStore, policy_version: &str) -> Vec<EdrEvent> {
    let mut all = Vec::new();
    for path in paths {
        all.extend(scan_path(path, store, policy_version));
    }
    all
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::tempdir;

    #[test]
    fn test_rule_store_empty_by_default() {
        let store = YaraRuleStore::new();
        assert!(!store.is_loaded());
        assert!(store.rules().is_none());
    }

    #[test]
    fn test_rule_store_load_from_source() {
        let mut store = YaraRuleStore::new();
        store
            .load(r#"rule test { strings: $a = "MALWARE" condition: $a }"#)
            .expect("should compile valid rules");
        assert!(store.is_loaded());
        assert!(store.rules().is_some());
    }

    #[test]
    fn test_rule_store_load_invalid_source() {
        let mut store = YaraRuleStore::new();
        assert!(store.load("invalid rule syntax {").is_err());
        assert!(!store.is_loaded());
    }

    #[test]
    fn test_load_with_namespace() {
        let mut store = YaraRuleStore::new();
        store
            .load_with_namespace(
                r#"rule NsTest { strings: $a = "NS" condition: $a }"#,
                "custom_ns",
            )
            .expect("should compile with namespace");
        assert!(store.is_loaded());
    }

    #[test]
    fn test_append_rules() {
        let mut store = YaraRuleStore::new();
        store.load(r#"rule A { strings: $a = "AAA" condition: $a }"#).expect("load A");
        store.append(r#"rule B { strings: $a = "BBB" condition: $a }"#).expect("append B");
        assert!(store.is_loaded());

        let dir = tempdir().unwrap();
        let fa = dir.path().join("aaa.txt");
        let fb = dir.path().join("bbb.txt");
        fs::write(&fa, "AAA").unwrap();
        fs::write(&fb, "BBB").unwrap();

        let events_a = scan_path(fa.to_str().unwrap(), &store, "v1");
        let events_b = scan_path(fb.to_str().unwrap(), &store, "v1");
        assert!(!events_a.is_empty(), "rule A should match");
        assert!(!events_b.is_empty(), "rule B should match");
    }

    #[test]
    fn test_scan_path_no_rules() {
        let store = YaraRuleStore::new();
        let result = scan_path("/nonexistent", &store, "test-v1");
        assert!(result.is_empty(), "no rules loaded = no match");
    }

    #[test]
    fn test_scan_path_matches() {
        let mut store = YaraRuleStore::new();
        store
            .load(r#"rule EicarTest { strings: $a = "AETHERIX_TEST_EICAR" condition: $a }"#)
            .expect("compile");

        let dir = tempdir().unwrap();
        let file_path = dir.path().join("test_file.txt");
        fs::write(&file_path, "AETHERIX_TEST_EICAR").unwrap();

        let result = scan_path(file_path.to_str().unwrap(), &store, "test-v1");
        assert_eq!(result.len(), 1, "should match EICAR");
        assert_eq!(result[0].rule_id, "EicarTest");
        assert_eq!(result[0].kind, EdrDetectionKind::YaraMatch);
    }

    #[test]
    fn test_scan_path_no_match() {
        let mut store = YaraRuleStore::new();
        store
            .load(r#"rule EicarTest { strings: $a = "AETHERIX_TEST_EICAR" condition: $a }"#)
            .expect("compile");

        let dir = tempdir().unwrap();
        let file_path = dir.path().join("clean.txt");
        fs::write(&file_path, "clean data with no match").unwrap();

        let result = scan_path(file_path.to_str().unwrap(), &store, "test-v1");
        assert!(result.is_empty(), "clean data should not match");
    }

    #[test]
    fn test_multiple_rule_matches() {
        let mut store = YaraRuleStore::new();
        store
            .load(
                r#"
                rule RuleA { strings: $a = "ALPHA" condition: $a }
                rule RuleB { strings: $a = "BETA" condition: $a }
                "#,
            )
            .expect("compile multi-rule");

        let dir = tempdir().unwrap();
        let file_path = dir.path().join("multi_match.txt");
        fs::write(&file_path, "ALPHA BETA").unwrap();

        let result = scan_path(file_path.to_str().unwrap(), &store, "v1");
        assert_eq!(result.len(), 2, "both rules should match");
        let ids: Vec<&str> = result.iter().map(|e| e.rule_id.as_str()).collect();
        assert!(ids.contains(&"RuleA"));
        assert!(ids.contains(&"RuleB"));
    }

    #[test]
    fn test_rule_tags_extracted() {
        let mut store = YaraRuleStore::new();
        store
            .load(r#"rule TaggedRule : tag1 tag2 { strings: $a = "TAGGED" condition: $a }"#)
            .expect("compile");

        let dir = tempdir().unwrap();
        let file_path = dir.path().join("tagged.txt");
        fs::write(&file_path, "TAGGED").unwrap();

        let result = scan_path(file_path.to_str().unwrap(), &store, "v1");
        assert_eq!(result.len(), 1);
        let mut tags = result[0].tags.clone();
        tags.sort();
        assert_eq!(tags, vec!["tag1", "tag2"]);
    }

    #[test]
    fn test_rule_metadata_extracted() {
        let mut store = YaraRuleStore::new();
        store
            .load(
                r#"
                rule MetaRule {
                    meta:
                        description = "test rule"
                        severity = 5
                        active = true
                    strings:
                        $a = "METADATA"
                    condition:
                        $a
                }
                "#,
            )
            .expect("compile");

        let dir = tempdir().unwrap();
        let file_path = dir.path().join("meta.txt");
        fs::write(&file_path, "METADATA").unwrap();

        let result = scan_path(file_path.to_str().unwrap(), &store, "v1");
        assert_eq!(result.len(), 1);
        let meta = &result[0].rule_metadata;
        assert_eq!(meta.get("description").map(|s| s.as_str()), Some("test rule"));
        assert_eq!(meta.get("severity").map(|s| s.as_str()), Some("5"));
        assert_eq!(meta.get("active").map(|s| s.as_str()), Some("true"));
    }

    #[test]
    fn test_matched_strings_extracted() {
        let mut store = YaraRuleStore::new();
        store
            .load(r#"rule StrRule { strings: $a = "HELLO" $b = "WORLD" condition: $a and $b }"#)
            .expect("compile");

        let dir = tempdir().unwrap();
        let file_path = dir.path().join("strings.txt");
        fs::write(&file_path, "HELLO WORLD").unwrap();

        let result = scan_path(file_path.to_str().unwrap(), &store, "v1");
        assert_eq!(result.len(), 1);
        let matched = &result[0].matched_strings;
        assert!(!matched.is_empty(), "should have matched strings");
        let idents: Vec<&str> = matched.iter().map(|s| s.identifier.as_str()).collect();
        assert!(idents.contains(&"$a"), "should contain $a");
        assert!(idents.contains(&"$b"), "should contain $b");
    }

    #[test]
    fn test_scan_cache_avoids_redundant_scans() {
        let mut store = YaraRuleStore::new();
        store
            .load(r#"rule CachedRule { strings: $a = "CACHED" condition: $a }"#)
            .expect("compile");

        let dir = tempdir().unwrap();
        let file_path = dir.path().join("cached.txt");
        fs::write(&file_path, "CACHED").unwrap();

        let r1 = scan_path(file_path.to_str().unwrap(), &store, "v1");
        assert_eq!(r1.len(), 1);

        let r2 = scan_path(file_path.to_str().unwrap(), &store, "v1");
        assert_eq!(r2.len(), 1);
    }

    #[test]
    fn test_cache_cleared_on_reload() {
        let mut store = YaraRuleStore::new();
        store
            .load(r#"rule CachedRule { strings: $a = "CACHED" condition: $a }"#)
            .expect("compile");

        let dir = tempdir().unwrap();
        let file_path = dir.path().join("cached.txt");
        fs::write(&file_path, "CACHED").unwrap();

        scan_path(file_path.to_str().unwrap(), &store, "v1");
        assert_eq!(store.cache.lock().unwrap().len(), 1);
        store.clear_cache();
        assert_eq!(store.cache.lock().unwrap().len(), 0);
    }

    #[test]
    fn test_scan_bytes_matches() {
        let mut store = YaraRuleStore::new();
        store
            .load(r#"rule ByteRule { strings: $a = "BYTE_SCAN" condition: $a }"#)
            .expect("compile");

        let result = scan_bytes(b"BYTE_SCAN_DATA", &store, "bytes", "v1");
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].rule_id, "ByteRule");
    }

    #[test]
    fn test_scan_bytes_no_match() {
        let mut store = YaraRuleStore::new();
        store
            .load(r#"rule ByteRule { strings: $a = "MALWARE" condition: $a }"#)
            .expect("compile");

        let result = scan_bytes(b"CLEAN DATA", &store, "bytes", "v1");
        assert!(result.is_empty());
    }

    #[test]
    fn test_excluded_paths_skipped() {
        let config = YaraScanConfig::default().with_excluded_paths(vec!["/excluded".to_string()]);
        let mut store = YaraRuleStore::with_config(config);
        store
            .load(r#"rule Test { strings: $a = "X" condition: $a }"#)
            .expect("compile");

        let result = scan_path("/excluded/file.txt", &store, "v1");
        assert!(result.is_empty(), "excluded paths should not be scanned");
    }

    #[test]
    fn test_disabled_config_returns_no_matches() {
        let config = YaraScanConfig { enabled: false, ..Default::default() };
        let mut store = YaraRuleStore::with_config(config);
        store
            .load(r#"rule Test { strings: $a = "ANY" condition: $a }"#)
            .expect("compile");

        let dir = tempdir().unwrap();
        let file_path = dir.path().join("any.txt");
        fs::write(&file_path, "ANY").unwrap();

        let result = scan_path(file_path.to_str().unwrap(), &store, "v1");
        assert!(result.is_empty(), "disabled config should not scan");
    }

    #[test]
    fn test_validate_rules_valid() {
        assert!(validate_rules(r#"rule T { strings: $a = "ok" condition: $a }"#).is_ok());
    }

    #[test]
    fn test_validate_rules_invalid() {
        assert!(validate_rules("this is not valid yara").is_err());
    }

    #[test]
    fn test_load_from_payload_with_rules() {
        let payload = serde_json::json!({
            "yara_rules": r#"rule TestRule { strings: $a = "test" condition: $a }"#
        });
        let store = YaraRuleStore::load_from_payload(&payload).expect("load from payload");
        assert!(store.is_loaded());
    }

    #[test]
    fn test_load_from_payload_missing_field() {
        let payload = serde_json::json!({});
        let store = YaraRuleStore::load_from_payload(&payload).expect("load from payload");
        assert!(!store.is_loaded(), "no rules when payload field absent");
    }

    #[test]
    fn test_load_from_payload_with_namespaces() {
        let payload = serde_json::json!({
            "yara_namespaces": {
                "ns1": r#"rule A { strings: $a = "ALPHA" condition: $a }"#,
                "ns2": r#"rule B { strings: $a = "BETA" condition: $a }"#
            }
        });
        let store = YaraRuleStore::load_from_payload(&payload).expect("load from payload");
        assert!(store.is_loaded());
    }

    #[test]
    fn test_load_from_payload_with_config() {
        let payload = serde_json::json!({
            "yara_rules": r#"rule T { strings: $a = "test" condition: $a }"#,
            "yara_config": {
                "max_scan_size": 1024,
                "scan_timeout_secs": 5,
                "enabled": true,
                "excluded_paths": ["/tmp", "/dev"]
            }
        });
        let store = YaraRuleStore::load_from_payload(&payload).expect("load");
        assert!(store.is_loaded());
        assert_eq!(store.config.max_scan_size, 1024);
        assert_eq!(store.config.scan_timeout, Duration::from_secs(5));
        assert_eq!(store.config.excluded_paths.len(), 2);
    }

    #[test]
    fn test_scan_duration_recorded() {
        let mut store = YaraRuleStore::new();
        store
            .load(r#"rule Timed { strings: $a = "TIMED" condition: $a }"#)
            .expect("compile");

        let dir = tempdir().unwrap();
        let file_path = dir.path().join("timed.txt");
        fs::write(&file_path, "TIMED").unwrap();

        let result = scan_path(file_path.to_str().unwrap(), &store, "v1");
        assert!(result[0].scan_duration_ms.is_some());
    }

    #[test]
    fn test_scan_paths_multiple_files() {
        let mut store = YaraRuleStore::new();
        store
            .load(r#"rule Multi { strings: $a = "SCAN" condition: $a }"#)
            .expect("compile");

        let dir = tempdir().unwrap();
        let f1 = dir.path().join("f1.txt");
        let f2 = dir.path().join("f2.txt");
        fs::write(&f1, "SCAN_1").unwrap();
        fs::write(&f2, "SCAN_2").unwrap();

        let paths = vec![f1.to_str().unwrap().to_string(), f2.to_str().unwrap().to_string()];
        let results = scan_paths(&paths, &store, "v1");
        assert_eq!(results.len(), 2);
    }

    #[test]
    fn test_matched_string_offsets() {
        let mut store = YaraRuleStore::new();
        store
            .load(r#"rule OffsetTest { strings: $a = "findme" condition: $a }"#)
            .expect("compile");

        let dir = tempdir().unwrap();
        let file_path = dir.path().join("offsets.txt");
        fs::write(&file_path, "prefix_findme_suffix").unwrap();

        let result = scan_path(file_path.to_str().unwrap(), &store, "v1");
        assert_eq!(result.len(), 1);
        let ms = &result[0].matched_strings;
        assert!(!ms.is_empty());
        assert_eq!(ms[0].identifier, "$a");
        assert!(ms[0].offset.is_some());
        assert!(ms[0].length.is_some());
    }

    #[test]
    fn test_matched_rules_field() {
        let mut store = YaraRuleStore::new();
        store
            .load(r#"rule R1 { strings: $a = "R1" condition: $a } rule R2 { strings: $a = "R2" condition: $a }"#)
            .expect("compile");

        let dir = tempdir().unwrap();
        let file_path = dir.path().join("both.txt");
        fs::write(&file_path, "R1 R2").unwrap();

        let result = scan_path(file_path.to_str().unwrap(), &store, "v1");
        assert_eq!(result.len(), 2);
        for event in &result {
            assert_eq!(event.matched_rules.len(), 2);
            assert!(event.matched_rules.contains(&"R1".to_string()));
            assert!(event.matched_rules.contains(&"R2".to_string()));
        }
    }

    #[test]
    fn test_scanner_timeout_applied() {
        let mut store = YaraRuleStore::new();
        store.config.scan_timeout = Duration::from_millis(100);
        store
            .load(r#"rule Quick { strings: $a = "DATA" condition: $a }"#)
            .expect("compile");

        let dir = tempdir().unwrap();
        let file_path = dir.path().join("quick.txt");
        fs::write(&file_path, "DATA").unwrap();

        let result = scan_path(file_path.to_str().unwrap(), &store, "v1");
        assert_eq!(result.len(), 1);
    }
}

#[test]
fn test_debug_multi_rule() {
    let rules = yara_x::compile(
        r#"rule R1 { strings: $a = "R1" condition: $a } rule R2 { strings: $a = "R2" condition: $a }"#
    ).unwrap();
    let mut scanner = yara_x::Scanner::new(&rules);
    let results = scanner.scan(b"R1 R2").unwrap();
    eprintln!("debug multi-rule count: {}", results.matching_rules().count());
    // second pass since iterator is consumed
    let results = scanner.scan(b"R1 R2").unwrap();
    for r in results.matching_rules() {
        eprintln!("  matched: {}", r.identifier());
    }
    assert_eq!(results.matching_rules().count(), 2);
}

#[test]
fn test_debug_scan_data_multi() {
    let rules = yara_x::compile(
        r#"rule R1 { strings: $a = "R1" condition: $a } rule R2 { strings: $a = "R2" condition: $a }"#
    ).unwrap();
    let config = YaraScanConfig::default();
    let results = scan_data(b"R1 R2", &rules, &config, "test", "abc123", "v1", std::time::Instant::now());
    eprintln!("scan_data events count: {}", results.len());
    for e in &results {
        eprintln!("  event rule_id: {}, matched_rules: {:?}", e.rule_id, e.matched_rules);
    }
    assert_eq!(results.len(), 2, "should get 2 events from scan_data");
}

#[test]
fn test_debug_scan_path_multi() {
    let mut store = YaraRuleStore::new();
    store
        .load(r#"rule R1 { strings: $a = "R1" condition: $a } rule R2 { strings: $a = "R2" condition: $a }"#)
        .expect("compile");

    let dir = tempfile::tempdir().unwrap();
    let file_path = dir.path().join("both.txt");
    fs::write(&file_path, "R1 R2").unwrap();
    let path_str = file_path.to_str().unwrap().to_string();

    let result = scan_path(&path_str, &store, "v1");
    eprintln!("scan_path multi result count: {}", result.len());
    for e in &result {
        eprintln!("  rule_id: {}, matched_rules: {:?}", e.rule_id, e.matched_rules);
    }
    assert_eq!(result.len(), 2, "scan_path should return 2 events");
}

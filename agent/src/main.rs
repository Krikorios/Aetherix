use aetherix_agent::edr::ioc;
use aetherix_agent::edr::response as edr_response;
use aetherix_agent::{bridge, cis, dlp, dlp_client, fim, interceptors, inventory, policy};

use anyhow::Context;
use chrono::Utc;
use dlp_client::DlpClient;
use interceptors::{ClipboardInterceptor, FileUploadInterceptor, SystemClipboard, UsbInterceptor};
use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::{Arc, Mutex, RwLock};
use std::thread;
use std::time::{Duration, Instant};
use sysinfo::System;

const DEFAULT_AGENT_VERSION: &str = env!("CARGO_PKG_VERSION");
type HmacSha256 = Hmac<Sha256>;

#[derive(Serialize)]
struct Heartbeat {
    agent_id: String,
    hostname: String,
    os: String,
    collected_at: String,
    policy_version: String,
    agent_version: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    signature: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    nonce: Option<u64>,
    signals: AgentSignals,
    #[serde(skip_serializing_if = "Option::is_none")]
    inventory: Option<inventory::SystemInventory>,
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    fim_events: Vec<fim::FimEvent>,
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    edr_events: Vec<aetherix_agent::edr::EdrEvent>,
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    cis_results: Vec<cis::CisCheckResult>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    rollback_readiness: Option<aetherix_agent::edr::rollback::RollbackReadiness>,
}

struct HeartbeatContext<'a> {
    client: &'a reqwest::blocking::Client,
    api_url: &'a str,
    credentials: &'a AgentCredentials,
    hostname: &'a str,
    os: &'a str,
    rollback_provider: &'a dyn aetherix_agent::edr::rollback::RollbackProvider,
}

#[derive(Serialize)]
struct AgentSignals {
    blocked_events: u64,
    dlp_events: u64,
    pending_updates: u64,
    cpu_percent: f32,
    memory_percent: f32,
}

#[derive(Serialize)]
struct EnrollmentRequest {
    enrollment_token: String,
    hostname: String,
    os: String,
    agent_version: String,
}

#[derive(Deserialize)]
struct EnrollmentResponse {
    agent_id: String,
    agent_secret: String,
    #[serde(default)]
    customer_id: Option<String>,
    #[serde(default)]
    group_id: Option<String>,
    #[serde(default)]
    policy_package_id: Option<String>,
}

#[derive(Deserialize, Serialize, Clone)]
struct AgentCredentials {
    agent_id: String,
    agent_secret: String,
    last_nonce: u64,
    #[serde(default)]
    customer_id: Option<String>,
    #[serde(default)]
    group_id: Option<String>,
    #[serde(default)]
    policy_package_id: Option<String>,
}

#[derive(Deserialize, Debug)]
struct ModuleAction {
    id: String,
    #[serde(rename = "target_id")]
    #[allow(dead_code)]
    target_id: String,
    action: String,
    #[serde(default)]
    payload: Option<serde_json::Value>,
    #[allow(dead_code)]
    status: String,
    #[allow(dead_code)]
    approval_required: bool,
    #[serde(default)]
    evidence_controls: Option<Vec<String>>,
}

#[derive(Deserialize)]
struct InstallProfile {
    control_plane_url: String,
    enrollment_token: String,
    #[serde(default)]
    customer_id: Option<String>,
    #[serde(default)]
    group_id: Option<String>,
    #[serde(default)]
    policy_package_id: Option<String>,
    #[serde(default)]
    profile_signature: Option<String>,
}

#[derive(Deserialize, Serialize)]
struct PolicyPackage {
    id: String,
    name: String,
    version: u64,
    payload: serde_json::Value,
    signature: String,
}

fn main() {
    if let Err(error) = run() {
        eprintln!("aetherix-agent: {error}");
        std::process::exit(1);
    }
}

fn run() -> Result<(), Box<dyn std::error::Error>> {
    let hostname = hostname();
    let collected_at = Utc::now().format("%Y-%m-%dT%H:%M:%S+00:00").to_string();
    let os = std::env::consts::OS.to_string();
    let install_profile = load_install_profile(&install_profile_path())?;
    let api_url = std::env::var("AETHERIX_API_URL")
        .ok()
        .or_else(|| install_profile.as_ref().map(|profile| profile.control_plane_url.clone()));
    let client = reqwest::blocking::Client::new();
    let credentials_path = credentials_path();
    let mut credentials = load_credentials(&credentials_path)?;

    if credentials.is_none() {
        let enrollment_token = std::env::var("AETHERIX_ENROLLMENT_TOKEN")
            .ok()
            .or_else(|| install_profile.as_ref().map(|profile| profile.enrollment_token.clone()));
        if let Some(enrollment_token) = enrollment_token {
            let api_url = api_url
                .as_deref()
                .ok_or("AETHERIX_API_URL or install profile control_plane_url is required for enrollment")?;
            let enrolled = enroll_agent(&client, api_url, enrollment_token, &hostname, &os)?;
            credentials = Some(AgentCredentials {
                agent_id: enrolled.agent_id,
                agent_secret: enrolled.agent_secret,
                last_nonce: 0,
                customer_id: enrolled.customer_id.or_else(|| install_profile.as_ref().and_then(|profile| profile.customer_id.clone())),
                group_id: enrolled.group_id.or_else(|| install_profile.as_ref().and_then(|profile| profile.group_id.clone())),
                policy_package_id: enrolled.policy_package_id.or_else(|| install_profile.as_ref().and_then(|profile| profile.policy_package_id.clone())),
            });
        }
    }

    let active_edr_policy = if let (Some(api_url), Some(credentials)) = (api_url.as_deref(), credentials.as_ref()) {
        policy::fetch_effective_policy(&client, api_url, &credentials.agent_id, &credentials.agent_secret).ok()
    } else {
        None
    };

    let (policy_version, mut yara_rule_store) = if let (Some(api_url), Some(credentials)) = (api_url.as_deref(), credentials.as_ref()) {
        let policy = fetch_policy_package(&client, api_url, &credentials.agent_id)?;
        save_policy_package(&policy_path(), &policy)?;
        let store = aetherix_agent::edr::yara_scan::YaraRuleStore::load_from_payload(&policy.payload)?;
        (format!("{}-v{}", policy.id, policy.version), store)
    } else {
        (env_or("AETHERIX_POLICY_VERSION", "policy-local"), aetherix_agent::edr::yara_scan::YaraRuleStore::new())
    };

    // Seed built-in EICAR test rule if policy provided no YARA rules
    if !yara_rule_store.is_loaded() {
        let eicar_source = r#"rule EICAR_test {
            meta:
                description = "Aetherix built-in EICAR test detection"
                severity = "high"
            strings:
                $eicar = "X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"
            condition:
                $eicar
        }"#;
        if let Err(e) = yara_rule_store.load(eicar_source) {
            eprintln!("aetherix-agent: failed to load built-in EICAR rule: {e}");
        } else {
            println!("aetherix-agent: loaded built-in EICAR test rule (no policy YARA rules)");
        }
    }

    let (agent_id, signature, nonce) = if let Some(credentials) = credentials.as_mut() {
        let nonce = reserve_next_nonce(credentials, &credentials_path)?;
        let signature = enrolled_signature(
            &credentials.agent_secret,
            &credentials.agent_id,
            &hostname,
            &os,
            &collected_at,
            &policy_version,
            nonce,
        );
        (credentials.agent_id.clone(), Some(signature), Some(nonce))
    } else {
        let agent_id = std::env::var("AETHERIX_AGENT_ID").unwrap_or_else(|_| derived_agent_id(&hostname));
        (
            agent_id.clone(),
            legacy_signature(&agent_id, &hostname, &collected_at, &policy_version),
            None,
        )
    };

    // Collect System Inventory
    let mut system_for_inventory = System::new_all();
    let inventory = Some(inventory::collect_inventory(&mut system_for_inventory));

    // Run FIM baseline scan (uses real-time notify watcher for ongoing events)
    let watched_dirs = vec![
        PathBuf::from("/etc/aetherix"),
        PathBuf::from("/var/aetherix"),
        PathBuf::from("C:\\ProgramData\\Aetherix"),
    ];
    let mut fim_monitor = fim::FileIntegrityMonitor::new(watched_dirs.clone());
    let fim_events = fim_monitor.baseline_scan();

    // Initialize ransomware canary files in watched directories
    for dir in &watched_dirs {
        if dir.exists() && dir.is_dir() {
            let canary_path = dir.join("aetherix_canary.txt");
            if !canary_path.exists() {
                if let Err(e) = std::fs::write(&canary_path, "Aetherix Ransomware Canary - DO NOT DELETE") {
                    eprintln!("aetherix-agent: failed to write canary in {:?}: {e}", dir);
                }
            }
        }
    }

    // Trigger YARA scan on baseline-detected files
    let mut edr_events = Vec::new();
    for event in &fim_events {
        if event.event_type == fim::FimEventType::Added || event.event_type == fim::FimEventType::Modified {
            let mut yara_events = aetherix_agent::edr::yara_scan::scan_path(&event.file_path, &yara_rule_store, &policy_version);
            apply_policy_to_edr_events(&mut yara_events, active_edr_policy.as_ref());
            for yara_event in &yara_events {
                println!("YARA Match! File: {} matched rule: {}", event.file_path, yara_event.rule_id);
            }
            edr_events.extend(yara_events);
        }
    }

    // Run IOC matching on baseline FIM file hashes
    for event in &fim_events {
        if let Some(ref sha256) = event.sha256_hash {
            if let Some(mut ioc_event) = ioc::match_indicator(&ioc::Indicator::Sha256(sha256.clone()), &policy_version) {
                apply_policy_to_edr_events(std::slice::from_mut(&mut ioc_event), active_edr_policy.as_ref());
                println!("IOC Match! File: {} matched hash: {}", event.file_path, sha256);
                edr_events.push(ioc_event);
            }
        }
    }

    // Run EDR Process Tree (spawns a real-time watcher thread)
    let mut process_monitor = aetherix_agent::edr::process_tree::ProcessMonitor::new();
    let proc_events = process_monitor.scan(&policy_version);

    // Run IOC matching on newly detected process executables
    for proc_event in &proc_events {
        if let Some(ref proc_path) = proc_event.process_path {
            if let Some(hash) = aetherix_agent::edr::yara_scan::compute_sha256_for_path(proc_path) {
                if let Some(mut ioc_event) = ioc::match_indicator(&ioc::Indicator::Sha256(hash), &policy_version) {
                    apply_policy_to_edr_events(std::slice::from_mut(&mut ioc_event), active_edr_policy.as_ref());
                    println!("IOC Match! Process: {} matched hash", proc_path);
                    edr_events.push(ioc_event);
                }
            }
        }
    }

    let mut proc_events = proc_events;
    apply_policy_to_edr_events(&mut proc_events, active_edr_policy.as_ref());
    edr_events.extend(proc_events);

    let quarantine_secret = credentials.as_ref().map(|creds| creds.agent_secret.as_bytes()).unwrap_or(b"default-agent-key");
    execute_edr_response_actions(&mut edr_events, quarantine_secret);

    // Run CIS Benchmarking Scan
    let cis_scanner = cis::CisScanner::new();
    let cis_results = cis_scanner.scan();

    // Platform-aware provider selection (Windows VSS provider or NoopRollbackProvider fallback)
    let rollback_provider: Arc<dyn aetherix_agent::edr::rollback::RollbackProvider + Send + Sync> = {
        #[cfg(windows)]
        {
            let vss = aetherix_agent::edr::rollback::VssRollbackProvider::new();
            let probe = vss.probe();
            if probe.functional {
                println!(
                    "aetherix-agent: VSS rollback provider ready — {} volume(s), {} recovery point(s)",
                    probe.volume_capabilities.len(),
                    probe.recovery_point_count
                );
                Arc::new(vss)
            } else {
                println!(
                    "aetherix-agent: VSS rollback provider not functional ({}), falling back to noop",
                    probe.diagnosis
                );
                Arc::new(aetherix_agent::edr::rollback::NoopRollbackProvider)
            }
        }
        #[cfg(not(windows))]
        {
            Arc::new(aetherix_agent::edr::rollback::NoopRollbackProvider)
        }
    };


    // Enrich ransomware EDR events with recovery point hints from the provider.
    aetherix_agent::edr::rollback::enrich_events_with_recovery_hints(
        &mut edr_events,
        &*rollback_provider,
    );

    let fim_paths_for_readiness: Vec<String> = fim_events
        .iter()
        .map(|e| e.file_path.clone())
        .collect();
    let rollback_readiness =
        Some(aetherix_agent::edr::rollback::compute_rollback_readiness(
            &*rollback_provider,
            &fim_paths_for_readiness,
        ));

    let heartbeat = Heartbeat {
        signature,
        nonce,
        signals: collect_signals(),
        inventory,
        fim_events,
        edr_events,
        cis_results,
        agent_id: agent_id.clone(),
        hostname: hostname.clone(),
        os: os.clone(),
        collected_at,
        policy_version: policy_version.clone(),
        agent_version: DEFAULT_AGENT_VERSION.to_string(),
        rollback_readiness,
    };

    if let Some(ref api_url) = api_url {
        let endpoint = format!("{}/agent/heartbeat", api_url.trim_end_matches('/'));
        let response = client.post(endpoint).json(&heartbeat).send()?;

        if !response.status().is_success() {
            return Err(format!("heartbeat rejected with status {}", response.status()).into());
        }
    }

    println!("{}", serde_json::to_string_pretty(&heartbeat)?);

    // Spawn EDR/FIM real-time monitoring and heartbeat reporting thread
    let fim_monitor_arc = Arc::new(Mutex::new(fim_monitor));
    let process_monitor_arc = Arc::new(Mutex::new(process_monitor));
    let yara_rule_store_arc = Arc::new(yara_rule_store);
    
    let credentials_clone = credentials.clone();
    let api_url_clone = api_url.clone();
    let client_clone = client.clone();
    let active_edr_policy_for_shared = active_edr_policy.clone();
    let agent_id_clone = agent_id.clone();
    let hostname_clone = hostname.clone();
    let os_clone = os.clone();
    let rollback_provider_loop = rollback_provider.clone();
    let shared_policy: Arc<RwLock<Option<policy::RuntimePolicy>>> =
        Arc::new(RwLock::new(None));
    if let Some(policy) = active_edr_policy_for_shared.as_ref() {
        if let Ok(mut guard) = shared_policy.write() {
            *guard = Some(policy.clone());
        }
    }

    let shared_policy_heartbeat = shared_policy.clone();

    thread::Builder::new()
        .name("aetherix-edr-heartbeat-loop".to_string())
        .spawn(move || {
            let delay = Duration::from_secs(5);
            loop {
                thread::sleep(delay);

                let mut fim_events = Vec::new();
                if let Ok(mut fim) = fim_monitor_arc.lock() {
                    fim_events = fim.drain_events();
                }

                let mut edr_events = Vec::new();

                let policy_guard = shared_policy_heartbeat.read().ok().and_then(|guard| guard.clone());
                let current_policy_version = policy_guard
                    .as_ref()
                    .map(|p| p.policy_version_hash.clone())
                    .unwrap_or_else(|| "default-policy-v1".to_string());

                // 1. Run YARA scan and ransomware canary/entropy/mass-write checks on FIM events
                for event in &fim_events {
                    if event.event_type == fim::FimEventType::Added || event.event_type == fim::FimEventType::Modified {
                        // Dynamic YARA scan
                        let mut yara_matches = aetherix_agent::edr::yara_scan::scan_path(&event.file_path, &yara_rule_store_arc, &current_policy_version);
                        apply_policy_to_edr_events(&mut yara_matches, policy_guard.as_ref());
                        for y_match in yara_matches {
                            println!("Dynamic YARA Match! File: {} matched rule: {}", event.file_path, y_match.rule_id);
                            edr_events.push(y_match);
                        }
                    }

                    // Dynamic Ransomware checks
                    if let Some(mut r_event) = aetherix_agent::edr::ransomware::on_file_change(&event.file_path, &current_policy_version) {
                        apply_policy_to_edr_events(std::slice::from_mut(&mut r_event), policy_guard.as_ref());
                        println!("Dynamic Ransomware alert! File: {}, rule: {}", event.file_path, r_event.rule_id);
                        edr_events.push(r_event);
                    }
                }

                // 2. Run Process Tree checks
                if let Ok(mut pm) = process_monitor_arc.lock() {
                    let mut proc_events = pm.scan(&current_policy_version);
                    apply_policy_to_edr_events(&mut proc_events, policy_guard.as_ref());
                    edr_events.extend(proc_events);
                }

                // 3. Enrich ransomware events with recovery point hints
                aetherix_agent::edr::rollback::enrich_events_with_recovery_hints(
                    &mut edr_events,
                    &*rollback_provider_loop,
                );

                // 4. Apply active response actions locally
                let quarantine_secret = credentials_clone.as_ref().map(|creds| creds.agent_secret.as_bytes()).unwrap_or(b"default-agent-key");
                execute_edr_response_actions(&mut edr_events, quarantine_secret);

                // 5. Send heartbeat with dynamic EDR and FIM events
                if !fim_events.is_empty() || !edr_events.is_empty() {
                    if let Some(ref url) = api_url_clone {
                        let endpoint = format!("{}/agent/heartbeat", url.trim_end_matches('/'));
                        let collected_at = Utc::now().format("%Y-%m-%dT%H:%M:%S+00:00").to_string();
                        let fim_paths_for_readiness: Vec<String> = fim_events
                            .iter()
                            .map(|e| e.file_path.clone())
                            .collect();
                        let rollback_readiness = Some(
                            aetherix_agent::edr::rollback::compute_rollback_readiness(
                                &*rollback_provider_loop,
                                &fim_paths_for_readiness,
                            ),
                        );
                        let hb = Heartbeat {
                            agent_id: agent_id_clone.clone(),
                            hostname: hostname_clone.clone(),
                            os: os_clone.clone(),
                            collected_at,
                            policy_version: current_policy_version.clone(),
                            agent_version: DEFAULT_AGENT_VERSION.to_string(),
                            signature: None,
                            nonce: None,
                            signals: collect_signals(),
                            inventory: None,
                            fim_events,
                            edr_events,
                            cis_results: Vec::new(),
                            rollback_readiness,
                        };

                        if let Err(e) = client_clone.post(&endpoint).json(&hb).send() {
                            eprintln!("aetherix-agent: failed to send dynamic heartbeat: {e}");
                        }
                    }
                }
            }
        })
        .expect("spawn EDR heartbeat loop thread");

    // Shared policy state used by both the DLP enforcement loop (writer)
    // and the local browser bridge (reader). Wrapped in an Arc<RwLock<...>>
    // so refreshes from the loop become visible to the bridge instantly.

    let bridge_enabled = env_bool("AETHERIX_ENABLE_LOCAL_BRIDGE");
    let native_bridge_enabled = env_bool("AETHERIX_ENABLE_NATIVE_BRIDGE");
    if bridge_enabled || native_bridge_enabled {
        if let (Some(api_url), Some(credentials)) = (api_url.as_deref(), credentials.as_ref()) {
            // Best-effort initial population so the extension gets a real
            // policy on its very first poll.
            if let Ok(fetched) = policy::fetch_effective_policy(
                &client,
                api_url,
                &credentials.agent_id,
                &credentials.agent_secret,
            ) {
                if let Ok(mut guard) = shared_policy.write() {
                    *guard = Some(fetched);
                }
            } else if let Ok(Some(cached)) = policy::load_policy_cache(&effective_policy_path()) {
                if let Ok(mut guard) = shared_policy.write() {
                    *guard = Some(cached);
                }
            }

            let bridge_state = build_bridge_state(api_url, credentials, shared_policy.clone())?;

            if bridge_enabled {
                let config = bridge::BridgeConfig::from_env();
                let addr = bridge::spawn(bridge_state.clone(), config.port)
                    .context("spawn local HTTP bridge")?;
                println!("aetherix-agent: local bridge listening on http://{addr}");
            }

            if native_bridge_enabled {
                aetherix_agent::native_bridge::spawn(bridge_state)
                    .context("spawn native messaging bridge")?;
                println!("aetherix-agent: native messaging bridge active");
            }
        } else {
            eprintln!(
                "aetherix-agent: bridge enabled but no credentials or API URL; bridges disabled"
            );
        }
    }

    if env_bool("AETHERIX_ENABLE_DLP_ENFORCEMENT") {
        if let (Some(api_url), Some(credentials)) = (api_url.as_deref(), credentials.as_ref()) {
            run_dlp_enforcement_loop(&client, api_url, credentials, &hostname, &os, shared_policy.clone(), &*rollback_provider)
                .map_err(|err| format!("dlp enforcement failed: {err}"))?;
        }
    }

    // Keep the main thread alive and send periodic status heartbeats so the
    // control plane's last_seen stays fresh (OFFLINE_AFTER = 15 min).
    // This also keeps bridge/EDR threads alive when DLP enforcement is off.
    let heartbeat_interval = Duration::from_secs(
        std::env::var("AETHERIX_HEARTBEAT_INTERVAL_SECONDS")
            .ok()
            .and_then(|s| s.parse::<u64>().ok())
            .unwrap_or(60),
    );
    // Clone credentials once for use inside the keep-alive loop.
    let mut keepalive_creds = credentials.clone();
    loop {
        thread::sleep(heartbeat_interval);
        if let Some(ref url) = api_url {
            let (sig, hb_nonce) = if let Some(ref mut creds) = keepalive_creds {
                let nonce = reserve_next_nonce(creds, &credentials_path).unwrap_or(0);
                let collected_at = Utc::now().format("%Y-%m-%dT%H:%M:%S+00:00").to_string();
                let s = enrolled_signature(
                    &creds.agent_secret,
                    &creds.agent_id,
                    &hostname,
                    &os,
                    &collected_at,
                    &policy_version,
                    nonce,
                );
                (Some((s, collected_at)), Some(nonce))
            } else {
                (None, None)
            };
            let collected_at = sig
                .as_ref()
                .map(|(_, t)| t.clone())
                .unwrap_or_else(|| Utc::now().format("%Y-%m-%dT%H:%M:%S+00:00").to_string());
            let rollback_readiness = Some(
                aetherix_agent::edr::rollback::compute_rollback_readiness(
                    &*rollback_provider,
                    &[],
                ),
            );
            let hb = Heartbeat {
                agent_id: agent_id.clone(),
                hostname: hostname.clone(),
                os: os.clone(),
                collected_at,
                policy_version: policy_version.clone(),
                agent_version: DEFAULT_AGENT_VERSION.to_string(),
                signature: sig.map(|(s, _)| s),
                nonce: hb_nonce,
                signals: collect_signals(),
                inventory: None,
                fim_events: Vec::new(),
                edr_events: Vec::new(),
                cis_results: Vec::new(),
                rollback_readiness,
            };
            let endpoint = format!("{}/agent/heartbeat", url.trim_end_matches('/'));
            if let Err(e) = client.post(&endpoint).json(&hb).send() {
                eprintln!("aetherix-agent: status heartbeat failed: {e}");
            }
        }
    }
}

fn build_bridge_state(
    api_url: &str,
    credentials: &AgentCredentials,
    shared_policy: Arc<RwLock<Option<policy::RuntimePolicy>>>,
) -> anyhow::Result<Arc<bridge::BridgeState>> {
    let config = bridge::BridgeConfig::from_env();
    Ok(Arc::new(bridge::BridgeState::new(
        shared_policy,
        credentials.agent_id.clone(),
        credentials.agent_secret.clone(),
        api_url.to_string(),
        reqwest::blocking::Client::builder()
            .timeout(Duration::from_secs(5))
            .build()
            .context("build bridge http client")?,
        dlp_queue_path(),
        config.allowed_origins,
    )))
}

struct DlpRuntimeState {
    clipboard: Option<ClipboardInterceptor<SystemClipboard>>,
    files: Option<FileUploadInterceptor>,
    usb: UsbInterceptor,
    queue_lines_read: usize,
}

fn run_dlp_enforcement_loop(
    client: &reqwest::blocking::Client,
    api_url: &str,
    credentials: &AgentCredentials,
    hostname: &str,
    os: &str,
    shared_policy: Arc<RwLock<Option<policy::RuntimePolicy>>>,
    rollback_provider: &dyn aetherix_agent::edr::rollback::RollbackProvider,
) -> anyhow::Result<()> {
    let poll_interval = env_u64("AETHERIX_DLP_POLL_INTERVAL_SECONDS").max(1);
    let run_seconds = env_u64("AETHERIX_DLP_RUN_SECONDS");
    let started = Instant::now();

    let cache_path = effective_policy_path();
    let mut reloader = policy::PolicyHotReloader::from_env(
        client.clone(),
        api_url.to_string(),
        credentials.agent_id.clone(),
        credentials.agent_secret.clone(),
        cache_path.clone(),
    );
    let mut active_policy = reloader.bootstrap()?;
    if let Ok(mut guard) = shared_policy.write() {
        *guard = Some(active_policy.clone());
    }

    let queue_path = dlp_queue_path();
    let dlp_client = DlpClient::new(
        client.clone(),
        api_url.to_string(),
        credentials.agent_id.clone(),
        credentials.agent_secret.clone(),
        queue_path.clone(),
    );
    let mut state = DlpRuntimeState {
        clipboard: SystemClipboard::new()
            .map(ClipboardInterceptor::new)
            .ok(),
        files: FileUploadInterceptor::from_env(),
        usb: UsbInterceptor::new(),
        queue_lines_read: 0,
    };
    if let Some(files) = state.files.as_ref() {
        println!(
            "aetherix-agent: file upload interceptor watching {} dir(s)",
            files.watched_dirs().len()
        );
    }
    let mut last_refresh = Instant::now();

    loop {
        if last_refresh.elapsed() >= reloader.refresh_interval() {
            if let Some(new_policy) = reloader.tick() {
                // Atomic swap of the active policy. The DLP loop reads
                // `active_policy` by reference on every interceptor
                // pass, so the next clipboard/file scan immediately
                // sees the new rules — no restart required.
                active_policy = new_policy;
                if let Ok(mut guard) = shared_policy.write() {
                    *guard = Some(active_policy.clone());
                }
            }
            last_refresh = Instant::now();
        }

        // Clipboard interceptor: every changed clipboard value is
        // routed through `DlpClient::evaluate` and, on Block, the
        // clipboard is actively overwritten so the user's paste cannot
        // succeed.
        if let Some(interceptor) = state.clipboard.as_mut() {
            handle_clipboard_paste(interceptor, &active_policy, &dlp_client);
        }

        // File upload interceptor: every new/changed file in a watched
        // directory is read (capped) and routed through DlpClient. On a
        // Block decision the file is deleted in place — equivalent to
        // cancelling the user's save / pre-upload staging.
        if let Some(files) = state.files.as_mut() {
            for candidate in files.scan() {
                if let Some(decision) = dlp_client.evaluate(&active_policy, &candidate.event) {
                    if matches!(decision.action, policy::DlpAction::Block) {
                        match files.enforce_block(&candidate.path) {
                            Ok(()) => println!(
                                "Aetherix DLP blocked upload {} (label={:?}); file deleted",
                                candidate.path.display(),
                                decision.label_detected
                            ),
                            Err(err) => eprintln!(
                                "aetherix-agent: file deletion failed for {}: {err}",
                                candidate.path.display()
                            ),
                        }
                    }
                    if let Err(err) = dlp_client.emit(
                        &active_policy.policy_version_hash,
                        &candidate.event,
                        &decision,
                    ) {
                        eprintln!("aetherix-agent: failed to emit upload evidence: {err}");
                    }
                }
            }
        }

        // USB interceptor: polls for newly mounted removable devices
        for event in state.usb.poll() {
            if let Some(decision) = dlp_client.evaluate(&active_policy, &event) {
                if let Err(err) =
                    dlp_client.emit(&active_policy.policy_version_hash, &event, &decision)
                {
                    eprintln!("aetherix-agent: failed to emit USB evidence: {err}");
                }
                if matches!(decision.action, policy::DlpAction::Block) {
                    println!(
                        "Aetherix DLP blocked USB mount to {:?}",
                        decision.destination,
                    );
                    // In a full implementation we would unmount or reject the device here
                }
            }
        }

        // File-queue events (legacy + browser bridge replay) — evaluated
        // through the same DlpClient so behaviour is identical to the
        // clipboard path. These cannot mutate the clipboard, so block
        // enforcement is delegated to the originating interceptor.
        for event in collect_queued_events(&mut state, &queue_path) {
            if let Some(decision) = dlp_client.evaluate(&active_policy, &event) {
                if let Err(err) =
                    dlp_client.emit(&active_policy.policy_version_hash, &event, &decision)
                {
                    eprintln!("aetherix-agent: failed to emit DLP evidence: {err}");
                }
                if matches!(decision.action, policy::DlpAction::Block) {
                    println!(
                        "Aetherix DLP blocked {:?} to {:?} (label={:?})",
                        event.event_type,
                        decision.destination,
                        decision.label_detected
                    );
                }
            }
        }

        // Poll control-plane for any queued module actions and execute them.
        let heartbeat_context = HeartbeatContext {
            client,
            api_url,
            credentials,
            hostname,
            os,
            rollback_provider,
        };
        if let Err(err) = poll_and_execute_actions(&heartbeat_context, &mut active_policy, &shared_policy) {
            eprintln!("aetherix-agent: action poller error: {err}");
        }

        if run_seconds > 0 && started.elapsed().as_secs() >= run_seconds {
            break;
        }

        thread::sleep(Duration::from_secs(poll_interval));
    }

    Ok(())
}

fn handle_clipboard_paste(
    interceptor: &mut ClipboardInterceptor<SystemClipboard>,
    active_policy: &policy::RuntimePolicy,
    dlp_client: &DlpClient,
) {
    if let Some(event) = interceptor.poll() {
        if let Some(decision) = dlp_client.evaluate(active_policy, &event) {
            if matches!(decision.action, policy::DlpAction::Block) {
                match interceptor.enforce_block() {
                    Ok(placeholder) => println!(
                        "Aetherix DLP blocked clipboard paste (label={:?}); clipboard overwritten with: {placeholder}",
                        decision.label_detected
                    ),
                    Err(err) => eprintln!(
                        "aetherix-agent: clipboard overwrite failed: {err}"
                    ),
                }
            }
            if let Err(err) =
                dlp_client.emit(&active_policy.policy_version_hash, &event, &decision)
            {
                eprintln!("aetherix-agent: failed to emit DLP evidence: {err}");
            }
        }
    }
}

fn apply_policy_to_edr_events(
    events: &mut [aetherix_agent::edr::EdrEvent],
    active_policy: Option<&policy::RuntimePolicy>,
) {
    for event in events {
        if let Some(policy) = active_policy {
            event.action = policy.edr_action_for_kind(&event.kind);
            event.policy_version = policy.policy_version_hash.clone();
            event.evidence_controls = policy.evidence_controls.clone();
        } else {
            event.action = aetherix_agent::edr::EdrAction::Monitor;
        }
    }
}

fn execute_edr_response_actions(
    events: &mut [aetherix_agent::edr::EdrEvent],
    quarantine_secret: &[u8],
) {
    for event in events {
        let evidence = edr_response::apply_to_event_with_secret(event, quarantine_secret);
        if !matches!(
            evidence.status,
            aetherix_agent::edr::ResponseStatus::Staged
        ) {
            println!(
                "Aetherix EDR response {:?} for rule {} -> {:?}",
                evidence.action, evidence.rule_id, evidence.status
            );
        }
    }
}

fn collect_queued_events(state: &mut DlpRuntimeState, queue_path: &Path) -> Vec<dlp::DlpEvent> {
    let mut events = Vec::new();
    if let Ok(content) = fs::read_to_string(queue_path) {
        let lines: Vec<&str> = content.lines().collect();
        for line in lines.iter().skip(state.queue_lines_read) {
            if line.trim().is_empty() {
                continue;
            }
            if let Ok(event) = serde_json::from_str::<dlp::DlpEvent>(line) {
                events.push(event);
            }
        }
        state.queue_lines_read = lines.len();
    }
    events
}

fn hostname() -> String {
    std::env::var("AETHERIX_HOSTNAME")
        .or_else(|_| std::env::var("HOSTNAME"))
        .ok()
        .filter(|value| !value.trim().is_empty())
        .unwrap_or_else(|| {
            Command::new("hostname")
                .output()
                .ok()
                .and_then(|output| String::from_utf8(output.stdout).ok())
                .map(|value| value.trim().to_string())
                .filter(|value| !value.is_empty())
                .unwrap_or_else(|| "unknown".to_string())
        })
}

fn collect_signals() -> AgentSignals {
    let mut system = System::new_all();
    system.refresh_all();

    let memory_percent = if system.total_memory() == 0 {
        0.0
    } else {
        (system.used_memory() as f32 / system.total_memory() as f32) * 100.0
    };

    AgentSignals {
        blocked_events: env_u64("AETHERIX_BLOCKED_EVENTS"),
        dlp_events: env_u64("AETHERIX_DLP_EVENTS"),
        pending_updates: env_u64("AETHERIX_PENDING_UPDATES"),
        cpu_percent: system.global_cpu_usage(),
        memory_percent,
    }
}

fn enroll_agent(
    client: &reqwest::blocking::Client,
    api_url: &str,
    enrollment_token: String,
    hostname: &str,
    os: &str,
) -> Result<EnrollmentResponse, Box<dyn std::error::Error>> {
    let endpoint = format!("{}/agent/enroll", api_url.trim_end_matches('/'));
    let request = EnrollmentRequest {
        enrollment_token,
        hostname: hostname.to_string(),
        os: os.to_string(),
        agent_version: DEFAULT_AGENT_VERSION.to_string(),
    };
    let response = client.post(endpoint).json(&request).send()?;

    if !response.status().is_success() {
        return Err(format!("enrollment rejected with status {}", response.status()).into());
    }

    Ok(response.json()?)
}

fn fetch_policy_package(
    client: &reqwest::blocking::Client,
    api_url: &str,
    agent_id: &str,
) -> Result<PolicyPackage, Box<dyn std::error::Error>> {
    let endpoint = format!("{}/agent/{}/policy", api_url.trim_end_matches('/'), agent_id);
    let response = client.get(endpoint).send()?;

    if !response.status().is_success() {
        return Err(format!("policy fetch rejected with status {}", response.status()).into());
    }

    Ok(response.json()?)
}

fn load_credentials(path: &Path) -> Result<Option<AgentCredentials>, Box<dyn std::error::Error>> {
    if !path.exists() {
        return Ok(None);
    }

    Ok(Some(serde_json::from_str(&fs::read_to_string(path)?)?))
}

fn load_install_profile(path: &Path) -> Result<Option<InstallProfile>, Box<dyn std::error::Error>> {
    if !path.exists() {
        return Ok(None);
    }

    let profile: InstallProfile = serde_json::from_str(&fs::read_to_string(path)?)?;
    if profile.enrollment_token.trim().is_empty() || profile.control_plane_url.trim().is_empty() {
        return Err("install profile is missing control_plane_url or enrollment_token".into());
    }
    if profile
        .profile_signature
        .as_deref()
        .is_some_and(|signature| signature.trim().is_empty())
    {
        return Err("install profile signature is empty".into());
    }
    Ok(Some(profile))
}

fn reserve_next_nonce(
    credentials: &mut AgentCredentials,
    path: &Path,
) -> Result<u64, Box<dyn std::error::Error>> {
    credentials.last_nonce += 1;
    save_credentials(path, credentials)?;
    Ok(credentials.last_nonce)
}

fn save_credentials(path: &Path, credentials: &AgentCredentials) -> Result<(), Box<dyn std::error::Error>> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    write_credentials_file(path, &serde_json::to_string_pretty(credentials)?)?;
    Ok(())
}

fn save_policy_package(path: &Path, policy: &PolicyPackage) -> Result<(), Box<dyn std::error::Error>> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    write_credentials_file(path, &serde_json::to_string_pretty(policy)?)?;
    Ok(())
}

fn poll_and_execute_actions(
    context: &HeartbeatContext,
    active_policy: &mut policy::RuntimePolicy,
    shared_policy: &Arc<RwLock<Option<policy::RuntimePolicy>>>,
) -> Result<(), Box<dyn std::error::Error>> {
    let endpoint = format!("{}/agent/actions?endpoint_id={}", context.api_url.trim_end_matches('/'), context.credentials.agent_id);
    let resp = context.client
        .get(&endpoint)
        .bearer_auth(&context.credentials.agent_secret)
        .send()?;

    if !resp.status().is_success() {
        // nothing to do if control-plane doesn't respond with actions
        return Ok(());
    }

    let actions: Vec<ModuleAction> = resp.json()?;
    for action in actions {
        println!("aetherix-agent: action received: {} -> {}", action.id, action.action);
        match action.action.as_str() {
            "push_policy_update" => {
                if let Ok(fetched) = policy::fetch_effective_policy(context.client, context.api_url, &context.credentials.agent_id, &context.credentials.agent_secret) {
                    *active_policy = fetched.clone();
                    if let Ok(mut guard) = shared_policy.write() {
                        *guard = Some(fetched);
                    }
                }
                ack_action(context, &action.id);
            }
            "quarantine" | "kill_process" | "isolate_endpoint" | "quarantine_list"
            | "list_quarantine" | "quarantine_restore" | "restore_quarantine"
            | "release_from_quarantine" => {
                let event = remote_action_event(&action, active_policy, &context.credentials.agent_secret);
                emit_remote_action_evidence(context, event);
                ack_action(context, &action.id);
            }
            "rollback" | "rollback_restore" => {
                let event = handle_remote_rollback_action(
                    &action,
                    active_policy,
                    context,
                );
                emit_remote_action_evidence(context, event);
                ack_action(context, &action.id);
            }
            "rollback_simulate" => {
                let event = handle_remote_rollback_simulation(
                    &action,
                    active_policy,
                    context,
                );
                emit_remote_action_evidence(context, event);
                ack_action(context, &action.id);
            }
            other => {
                eprintln!("aetherix-agent: unsupported action {other}");
                ack_action(context, &action.id);
            }
        }
    }

    Ok(())
}

fn ack_action(context: &HeartbeatContext, action_id: &str) {
    let ack_url = format!(
        "{}/agent/actions/{}/ack?endpoint_id={}",
        context.api_url.trim_end_matches('/'),
        action_id,
        context.credentials.agent_id
    );
    let _ = context
        .client
        .post(&ack_url)
        .bearer_auth(&context.credentials.agent_secret)
        .send();
}

fn remote_action_event(
    action: &ModuleAction,
    active_policy: &policy::RuntimePolicy,
    quarantine_secret: &str,
) -> aetherix_agent::edr::EdrEvent {
    let payload = action.payload.as_ref();
    let requested_action = normalize_remote_edr_action(&action.action);
    let remote_request_id = payload
        .and_then(|value| value.get("request_id").or_else(|| value.get("restore_request_id")))
        .and_then(|value| value.as_str());
    let policy_denial_reason = payload
        .and_then(|value| {
            value
                .get("policy_denial_reason")
                .or_else(|| value.get("denial_reason"))
        })
        .and_then(|value| value.as_str());
    let rate_limit_state = payload
        .and_then(|value| value.get("rate_limit_state").or_else(|| value.get("rate_limited")));
    let approval_state = payload
        .and_then(|value| {
            value
                .get("approval_state")
                .or_else(|| value.get("approval_status"))
        })
        .and_then(|value| value.as_str())
        .or_else(|| action.approval_required.then_some("required"));
    let mut event = aetherix_agent::edr::EdrEvent::new(
        aetherix_agent::edr::EdrDetectionKind::ResponseAction,
        payload
            .and_then(|value| value.get("rule_id"))
            .and_then(|value| value.as_str())
            .unwrap_or(action.action.as_str()),
        requested_action.clone(),
        &active_policy.policy_version_hash,
    );
    event.evidence_controls = action
        .evidence_controls
        .clone()
        .unwrap_or_else(|| active_policy.evidence_controls.clone());
    event.tags.push("remote_response_action".to_string());
    event.tags.push(format!("remote_action:{}", action.action));
    event.matched_indicator = Some(action.id.clone());
    event.process_pid = payload
        .and_then(|value| value.get("target_pid"))
        .and_then(|value| value.as_u64())
        .and_then(|pid| u32::try_from(pid).ok());
    event.file_path = payload
        .and_then(|value| value.get("target_path").or_else(|| value.get("file_path")))
        .and_then(|value| value.as_str())
        .map(str::to_string);

    let allowed = remote_action_is_policy_promoted(&requested_action, payload, active_policy);
    if !allowed && dangerous_remote_action(&requested_action) {
        event.action = aetherix_agent::edr::EdrAction::Review;
        let mut evidence = edr_response::execute(
            &event.action,
            event.process_pid,
            event.file_path.as_deref(),
            None,
            &event.rule_id,
            &event.policy_version,
            &event.evidence_controls,
            quarantine_secret.as_bytes(),
        );
        evidence.status = aetherix_agent::edr::ResponseStatus::Staged;
        evidence.decision_trace.push(format!(
            "remote action {:?} denied: current policy has not promoted matching detector action",
            requested_action
        ));
        evidence
            .decision_trace
            .push(format!("action_queue_id={}", action.id));
        if let Some(remote_request_id) = remote_request_id {
            evidence
                .decision_trace
                .push(format!("remote_request_id={remote_request_id}"));
        }
        append_remote_restore_context(
            &mut evidence,
            &requested_action,
            approval_state,
            policy_denial_reason,
            rate_limit_state,
        );
        event.response = Some(evidence);
        return event;
    }

    if matches!(
        requested_action,
        aetherix_agent::edr::EdrAction::QuarantineRestore
    ) {
        event.file_path = payload
            .and_then(|value| value.get("quarantine_id").or_else(|| value.get("target_path")))
            .and_then(|value| value.as_str())
            .map(str::to_string);
    }

    if requires_target_path(&requested_action) && event.file_path.is_none() {
        let mut evidence = edr_response::execute(
            &requested_action,
            event.process_pid,
            event.file_path.as_deref(),
            None,
            &event.rule_id,
            &event.policy_version,
            &event.evidence_controls,
            quarantine_secret.as_bytes(),
        );
        evidence.status = aetherix_agent::edr::ResponseStatus::Failed;
        evidence
            .decision_trace
            .push(format!("action_queue_id={}", action.id));
        if let Some(remote_request_id) = remote_request_id {
            evidence
                .decision_trace
                .push(format!("remote_request_id={remote_request_id}"));
        }
        append_remote_restore_context(
            &mut evidence,
            &requested_action,
            approval_state,
            policy_denial_reason,
            rate_limit_state,
        );
        event.action = requested_action;
        event.response = Some(evidence);
        return event;
    }

    let mut evidence =
        edr_response::apply_to_event_with_secret(&mut event, quarantine_secret.as_bytes());
    evidence
        .decision_trace
        .push(format!("action_queue_id={}", action.id));
    if let Some(remote_request_id) = remote_request_id {
        evidence
            .decision_trace
            .push(format!("remote_request_id={remote_request_id}"));
    }
    append_remote_restore_context(
        &mut evidence,
        &requested_action,
        approval_state,
        policy_denial_reason,
        rate_limit_state,
    );
    evidence.decision_trace.push(
        "remote response evidence emitted via heartbeat response_action event".to_string(),
    );
    if matches!(evidence.status, aetherix_agent::edr::ResponseStatus::Failed) {
        eprintln!(
            "aetherix-agent: remote action {} failed: {}",
            action.id,
            evidence.error.clone().unwrap_or_else(|| "unknown error".to_string())
        );
    }
    event.response = Some(evidence);
    event
}

fn append_remote_restore_context(
    evidence: &mut aetherix_agent::edr::ResponseEvidence,
    requested_action: &aetherix_agent::edr::EdrAction,
    approval_state: Option<&str>,
    policy_denial_reason: Option<&str>,
    rate_limit_state: Option<&serde_json::Value>,
) {
    if !matches!(
        requested_action,
        aetherix_agent::edr::EdrAction::QuarantineRestore
    ) {
        return;
    }
    evidence.decision_trace.push(
        "restore request accepted only after control-plane approval gates queue the action"
            .to_string(),
    );
    if let Some(approval_state) = approval_state {
        evidence
            .decision_trace
            .push(format!("restore_approval_state={approval_state}"));
    }
    if let Some(reason) = policy_denial_reason {
        evidence
            .decision_trace
            .push(format!("restore_policy_denial_reason={reason}"));
    }
    if let Some(state) = rate_limit_state {
        evidence
            .decision_trace
            .push(format!("restore_rate_limit_state={state}"));
    }
}

fn requires_target_path(action: &aetherix_agent::edr::EdrAction) -> bool {
    matches!(
        action,
        aetherix_agent::edr::EdrAction::Quarantine
            | aetherix_agent::edr::EdrAction::QuarantineRestore
    )
}

fn normalize_remote_edr_action(action: &str) -> aetherix_agent::edr::EdrAction {
    match action {
        "quarantine" => aetherix_agent::edr::EdrAction::Quarantine,
        "kill_process" | "kill" => aetherix_agent::edr::EdrAction::Kill,
        "isolate_endpoint" | "isolate" => aetherix_agent::edr::EdrAction::Isolate,
        "quarantine_list" | "list_quarantine" => aetherix_agent::edr::EdrAction::QuarantineList,
        "quarantine_restore" | "restore_quarantine" | "release_from_quarantine" => {
            aetherix_agent::edr::EdrAction::QuarantineRestore
        }
        "rollback" | "rollback_restore" => aetherix_agent::edr::EdrAction::Rollback,
        _ => aetherix_agent::edr::EdrAction::Review,
    }
}

fn dangerous_remote_action(action: &aetherix_agent::edr::EdrAction) -> bool {
    matches!(
        action,
        aetherix_agent::edr::EdrAction::Quarantine
            | aetherix_agent::edr::EdrAction::Kill
            | aetherix_agent::edr::EdrAction::Isolate
            | aetherix_agent::edr::EdrAction::Rollback
    )
}

fn remote_action_is_policy_promoted(
    action: &aetherix_agent::edr::EdrAction,
    payload: Option<&serde_json::Value>,
    active_policy: &policy::RuntimePolicy,
) -> bool {
    if !dangerous_remote_action(action) {
        return true;
    }
    let kind = payload
        .and_then(|value| value.get("kind").or_else(|| value.get("detection_kind")))
        .and_then(|value| value.as_str())
        .and_then(parse_remote_detection_kind)
        .unwrap_or(match action {
            aetherix_agent::edr::EdrAction::Quarantine => {
                aetherix_agent::edr::EdrDetectionKind::YaraMatch
            }
            aetherix_agent::edr::EdrAction::Kill => {
                aetherix_agent::edr::EdrDetectionKind::SuspiciousProcessChain
            }
            aetherix_agent::edr::EdrAction::Isolate => {
                aetherix_agent::edr::EdrDetectionKind::RansomwareCanary
            }
            aetherix_agent::edr::EdrAction::Rollback => {
                aetherix_agent::edr::EdrDetectionKind::RansomwareRollback
            }
            _ => aetherix_agent::edr::EdrDetectionKind::ResponseAction,
        });
    active_policy.edr_action_for_kind(&kind) == *action
}

fn parse_remote_detection_kind(value: &str) -> Option<aetherix_agent::edr::EdrDetectionKind> {
    match value {
        "yara_match" => Some(aetherix_agent::edr::EdrDetectionKind::YaraMatch),
        "ioc_match" => Some(aetherix_agent::edr::EdrDetectionKind::IocMatch),
        "ransomware_canary" => Some(aetherix_agent::edr::EdrDetectionKind::RansomwareCanary),
        "ransomware_rollback" => Some(aetherix_agent::edr::EdrDetectionKind::RansomwareRollback),
        "suspicious_process_chain" => Some(
            aetherix_agent::edr::EdrDetectionKind::SuspiciousProcessChain,
        ),
        _ => None,
    }
}

fn emit_remote_action_evidence(context: &HeartbeatContext, event: aetherix_agent::edr::EdrEvent) {
    let endpoint = format!("{}/agent/heartbeat", context.api_url.trim_end_matches('/'));
    let rollback_readiness = Some(
        aetherix_agent::edr::rollback::compute_rollback_readiness(
            context.rollback_provider,
            &[],
        ),
    );
    let hb = Heartbeat {
        agent_id: context.credentials.agent_id.clone(),
        hostname: context.hostname.to_string(),
        os: context.os.to_string(),
        collected_at: Utc::now().format("%Y-%m-%dT%H:%M:%S+00:00").to_string(),
        policy_version: event.policy_version.clone(),
        agent_version: DEFAULT_AGENT_VERSION.to_string(),
        signature: None,
        nonce: None,
        signals: collect_signals(),
        inventory: None,
        fim_events: Vec::new(),
        edr_events: vec![event],
        cis_results: Vec::new(),
        rollback_readiness,
    };
    if let Err(err) = context.client.post(endpoint).json(&hb).send() {
        eprintln!("aetherix-agent: failed to emit remote response evidence: {err}");
    }
}

/// Handle a `rollback` action from the control-plane action queue.
///
/// Validates the approved intent (expiry, required fields), checks policy
/// promotion, calls `RollbackProvider::restore()`, and returns an `EdrEvent`
/// carrying both `ResponseEvidence` (for compatibility) and `RollbackEvidence`
/// (for the full rollback-specific schema).
///
/// Every code path (including refusal and error) produces both evidence types
/// so the control plane always has a complete audit record.
fn handle_remote_rollback_action(
    action: &ModuleAction,
    active_policy: &policy::RuntimePolicy,
    context: &HeartbeatContext,
) -> aetherix_agent::edr::EdrEvent {
    use aetherix_agent::edr::rollback;
    use aetherix_agent::edr::{EdrAction, EdrDetectionKind, EdrEvent, ResponseStatus};

    let action_name = action.action.as_str();
    let evidence_controls = action
        .evidence_controls
        .clone()
        .unwrap_or_else(|| active_policy.evidence_controls.clone());

    // --- Endpoint / tenant binding verification ---
    if action.target_id != context.credentials.agent_id {
        return build_rollback_refusal_event(
            &action.id,
            action_name,
            active_policy,
            evidence_controls,
            ResponseStatus::NotApplicable,
            &[
                "endpoint binding mismatch: action target_id does not match this agent".to_string(),
                format!("action.target_id={}, agent_id={}", action.target_id, context.credentials.agent_id),
                format!("action_queue_id={}", action.id),
            ],
            "endpoint_binding_mismatch",
            "not_applicable",
            Some("this action was not issued for this endpoint"),
        );
    }
    if let Some(payload) = action.payload.as_ref() {
        if let Some(action_customer) = payload.get("customer_id").and_then(|v| v.as_str()) {
            let my_customer = context.credentials.customer_id.as_deref().unwrap_or("");
            if !action_customer.is_empty() && action_customer != my_customer {
                return build_rollback_refusal_event(
                    &action.id,
                    action_name,
                    active_policy,
                    evidence_controls,
                    ResponseStatus::NotApplicable,
                    &[
                        "tenant binding mismatch: action customer_id does not match this agent".to_string(),
                        format!("action.customer_id={action_customer}, agent.customer_id={my_customer}"),
                        format!("action_queue_id={}", action.id),
                    ],
                    "tenant_binding_mismatch",
                    "not_applicable",
                    Some("this action was issued for a different tenant"),
                );
            }
        }
    }

    // --- Idempotency guard + cached-evidence return ---
    if rollback::is_action_consumed(&action.id) {
        if let Some(cached) = rollback::load_evidence(&action.id) {
            let mut cached = cached;
            cached
                .decision_trace
                .push(format!("cached_re_report: approved_action_id={}", action.id));
            cached.evidence_controls = evidence_controls.clone();

            let mut response = rollback::convert_rollback_evidence_to_response(&cached);
            response
                .decision_trace
                .push(format!("cached_re_report: approved_action_id={}", action.id));
            response.evidence_controls = evidence_controls.clone();

            let mut event = EdrEvent::new(
                EdrDetectionKind::ResponseAction,
                &cached.simulation_id,
                EdrAction::Rollback,
                &active_policy.policy_version_hash,
            );
            event.evidence_controls = evidence_controls.clone();
            event.tags.push("remote_response_action".to_string());
            event.tags.push(format!("remote_action:{action_name}"));
            event.tags.push("rollback_cached".to_string());
            event.matched_indicator = cached
                .decision_trace
                .iter()
                .find_map(|entry| entry.strip_prefix("original_alert_id=").map(str::to_string))
                .or_else(|| Some(action.id.clone()));
            event.rollback_file_paths = cached
                .restored_paths
                .iter()
                .map(|path| path.path.clone())
                .collect();
            event.response = Some(response);
            event.rollback_evidence = Some(cached);
            return event;
        }
        return build_rollback_refusal_event(
            &action.id,
            action_name,
            active_policy,
            evidence_controls,
            ResponseStatus::NotApplicable,
            &[
                format!(
                    "rollback action {} already consumed on this endpoint",
                    action.id
                ),
                format!("action_queue_id={}", action.id),
            ],
            "action_already_consumed",
            "not_applicable",
            Some("duplicate intent: action already consumed — cached evidence unavailable"),
        );
    }

    // --- Parse payload ---
    let payload = match action.payload.as_ref() {
        Some(p) => p,
        None => {
            return build_rollback_refusal_event(
                &action.id,
                action_name,
                active_policy,
                evidence_controls,
                ResponseStatus::Failed,
                &[
                    "rollback intent missing payload".to_string(),
                    format!("action_queue_id={}", action.id),
                ],
                "rollback intent payload is empty",
                "failed",
                None,
            );
        }
    };

    // --- Parse the approved rollback intent ---
    let intent = match rollback::parse_rollback_intent(&action.id, payload) {
        Some(i) => i,
        None => {
            return build_rollback_refusal_event(
                &action.id,
                action_name,
                active_policy,
                evidence_controls,
                ResponseStatus::Failed,
                &[
                    "rollback intent missing required fields (simulation_id, candidate_set_hash, recovery_point_id, valid_until)".to_string(),
                    format!("action_queue_id={}", action.id),
                ],
                "malformed rollback intent",
                "failed",
                None,
            );
        }
    };

    // --- Validate intent expiry ---
    if let Err(err) = rollback::validate_intent_expiry(&intent) {
        return build_rollback_refusal_event(
            &action.id,
            action_name,
            active_policy,
            evidence_controls,
            ResponseStatus::NotApplicable,
            &[
                format!("rollback intent expired: {err}"),
                format!("action_queue_id={}", action.id),
                format!("simulation_id={}", intent.simulation_id),
            ],
            "intent_expired",
            "not_applicable",
            Some(&format!("intent expired: {err}")),
        );
    }

    // --- Policy check: rollback is destructive and must be policy-promoted ---
    if !remote_action_is_policy_promoted(&EdrAction::Rollback, Some(payload), active_policy) {
        return build_rollback_refusal_event(
            &action.id,
            action_name,
            active_policy,
            evidence_controls,
            ResponseStatus::Staged,
            &[
                "rollback action denied: current policy has not promoted rollback for this detection kind".to_string(),
                format!("action_queue_id={}", action.id),
                format!("simulation_id={}", intent.simulation_id),
            ],
            "policy_not_promoted",
            "staged",
            Some("current policy has not promoted rollback for this detection kind"),
        );
    }

    // --- Correlation link entries from payload (if present) ---
    let mut correlation_links: Vec<String> = Vec::new();
    if let Some(corr_ids) = payload.get("correlation_link_ids").and_then(|v| v.as_array()) {
        for v in corr_ids {
            if let Some(id) = v.as_str() {
                correlation_links.push(format!("corroborated_by_correlation_link:{id}"));
            }
        }
    }
    // Also support a single link
    if correlation_links.is_empty() {
        if let Some(id) = payload.get("correlation_link_id").and_then(|v| v.as_str()) {
            correlation_links.push(format!("corroborated_by_correlation_link:{id}"));
        }
    }

    // --- Execute via provider ---
    let candidates = rollback::intent_to_candidate_set(&intent);
    let rollback_evidence = match context.rollback_provider.restore(&candidates, &action.id) {
        Ok(mut ev) => {
            ev.endpoint_id = context.credentials.agent_id.clone();
            ev.customer_id = context.credentials.customer_id.clone();
            ev.policy_version = active_policy.policy_version_hash.clone();
            ev.evidence_controls = evidence_controls.clone();
            if ev.requester_id.is_empty() {
                ev.requester_id = payload
                    .get("requester_id")
                    .or_else(|| payload.get("requested_by"))
                    .and_then(|value| value.as_str())
                    .unwrap_or("control-plane")
                    .to_string();
            }
            if ev.approver_ids.is_empty() {
                ev.approver_ids = payload
                    .get("approver_ids")
                    .and_then(|value| value.as_array())
                    .map(|values| {
                        values
                            .iter()
                            .filter_map(|value| value.as_str().map(str::to_string))
                            .collect()
                    })
                    .unwrap_or_default();
            }
            append_rollback_correlation_hints(&mut ev.decision_trace, payload);
            ev.decision_trace.extend(correlation_links.clone());
            ev
        }
        Err(err) => {
            rollback::mark_action_consumed(&action.id);
            let refusal = build_rollback_refusal_event(
                &action.id,
                action_name,
                active_policy,
                evidence_controls,
                ResponseStatus::Failed,
                &[
                    "rollback provider returned error".to_string(),
                    format!("provider_error={err}"),
                    format!("action_queue_id={}", action.id),
                    format!("simulation_id={}", intent.simulation_id),
                ],
                &format!("rollback_provider_error: {err}"),
                "failed",
                Some(&format!("provider error: {err}")),
            );
            if let Some(ref ev) = refusal.rollback_evidence {
                rollback::store_evidence(&action.id, ev);
                rollback::evict_old_evidence();
            }
            return refusal;
        }
    };

    // --- Mark as consumed (idempotency) and persist evidence ---
    rollback::mark_action_consumed(&action.id);
    rollback::store_evidence(&action.id, &rollback_evidence);
    rollback::evict_old_evidence();

    // --- Result: convert and attach both evidence types ---
    let rollback_status = rollback_evidence.status.clone();
    let response = rollback::convert_rollback_evidence_to_response(&rollback_evidence);
    let mut event = EdrEvent::new(
        EdrDetectionKind::ResponseAction,
        &intent.simulation_id,
        EdrAction::Rollback,
        &active_policy.policy_version_hash,
    );
    event.evidence_controls = evidence_controls;
    event.tags.push("remote_response_action".to_string());
    event.tags.push(format!("remote_action:{action_name}"));
    if rollback_status == "executed" {
        event.tags.push("rollback_executed".to_string());
    } else {
        event.tags.push("rollback_failed".to_string());
    }
    event.matched_indicator = rollback_original_alert_id(payload).or_else(|| Some(action.id.clone()));
    event.rollback_file_paths = rollback_evidence
        .restored_paths
        .iter()
        .map(|path| path.path.clone())
        .collect();
    event.response = Some(response);
    event.rollback_evidence = Some(rollback_evidence);
    event
}

fn rollback_original_alert_id(payload: &serde_json::Value) -> Option<String> {
    payload
        .get("original_alert_id")
        .or_else(|| payload.get("security_alert_id"))
        .or_else(|| payload.get("alert_id"))
        .and_then(|value| value.as_str())
        .map(str::to_string)
}

fn append_rollback_correlation_hints(decision_trace: &mut Vec<String>, payload: &serde_json::Value) {
    let path_values = payload
        .get("affected_paths")
        .and_then(|value| value.as_array())
        .into_iter()
        .flatten()
        .filter_map(|value| value.as_str());
    for path in path_values {
        decision_trace.push(format!("correlation_hint:fim_path={path}"));
        decision_trace.push(format!("correlation_hint:dlp_path={path}"));
    }
    if let Some(event_id) = payload.get("fim_event_id").and_then(|value| value.as_str()) {
        decision_trace.push(format!("correlation_hint:fim_event_id={event_id}"));
    }
    if let Some(event_id) = payload.get("dlp_event_id").and_then(|value| value.as_str()) {
        decision_trace.push(format!("correlation_hint:dlp_event_id={event_id}"));
    }
    if let Some(alert_id) = rollback_original_alert_id(payload) {
        decision_trace.push(format!("original_alert_id={alert_id}"));
    }
}

/// Build an `EdrEvent` for a rollback refusal or error, attaching both
/// `ResponseEvidence` and `RollbackEvidence` so the evidence pipeline always
/// sees a complete record.
///
/// `action_name` — the original module action string (e.g. `"rollback"`,
/// `"rollback_restore"`, `"rollback_simulate"`) used for evidence tags so the
/// control plane can distinguish the action variant that was refused.
#[allow(clippy::too_many_arguments)]
fn build_rollback_refusal_event(
    action_id: &str,
    action_name: &str,
    active_policy: &policy::RuntimePolicy,
    evidence_controls: Vec<String>,
    response_status: aetherix_agent::edr::ResponseStatus,
    decision_trace: &[String],
    error_message: &str,
    rollback_status: &str,
    provider_refusal: Option<&str>,
) -> aetherix_agent::edr::EdrEvent {
    let mut event = aetherix_agent::edr::EdrEvent::new(
        aetherix_agent::edr::EdrDetectionKind::ResponseAction,
        "rollback",
        aetherix_agent::edr::EdrAction::Review,
        &active_policy.policy_version_hash,
    );
    event.evidence_controls = evidence_controls.clone();
    event.tags.push("remote_response_action".to_string());
    event.tags.push(format!("remote_action:{action_name}"));
    event.tags.push(format!("rollback_{rollback_status}"));
    event.matched_indicator = Some(action_id.to_string());

    let resp = aetherix_agent::edr::ResponseEvidence {
        action: aetherix_agent::edr::EdrAction::Review,
        status: response_status,
        attempted_at: chrono::Utc::now().to_rfc3339(),
        policy_version: active_policy.policy_version_hash.clone(),
        rule_id: "rollback".to_string(),
        target_pid: None,
        target_path: None,
        file_sha256: None,
        platform: std::env::consts::OS.to_string(),
        platform_api: "rollback-provider".to_string(),
        decision_trace: decision_trace.to_vec(),
        error: Some(error_message.to_string()),
        quarantine: None,
        quarantine_items: vec![],
        evidence_controls: evidence_controls.clone(),
    };
    event.response = Some(resp);

    // Attach a minimal RollbackEvidence so the field is always populated.
    event.rollback_evidence = Some(aetherix_agent::edr::rollback::RollbackEvidence {
        status: rollback_status.to_string(),
        decision_trace: decision_trace.to_vec(),
        evidence_controls: evidence_controls.clone(),
        endpoint_id: String::new(),
        customer_id: None,
        policy_version: active_policy.policy_version_hash.clone(),
        requester_id: String::new(),
        approver_ids: vec![],
        simulation_id: String::new(),
        candidate_set_hash: String::new(),
        approved_action_id: action_id.to_string(),
        provider: "noop".to_string(),
        recovery_point_id: String::new(),
        recovery_point_created_at: String::new(),
        recovery_point_expires_at: None,
        recovery_point_verified: false,
        metadata_preserved: None,
        provider_refusal: provider_refusal.map(str::to_string),
        refusal_reason_code: provider_refusal.map(|r| r.to_string()),
        restored_paths: vec![],
        failed_paths: vec![],
        skipped_paths: vec![],
        provider_version: "0.1.0".to_string(),
        os_platform: std::env::consts::OS.to_string(),
        privilege_context: "none".to_string(),
    });

    event
}

/// Handle a `rollback_simulate` action — calls `RollbackProvider::simulate_restore`
/// and returns results as response evidence. Does NOT mutate the host.
fn handle_remote_rollback_simulation(
    action: &ModuleAction,
    active_policy: &policy::RuntimePolicy,
    context: &HeartbeatContext,
) -> aetherix_agent::edr::EdrEvent {
    use aetherix_agent::edr::rollback;
    use aetherix_agent::edr::{EdrAction, EdrDetectionKind, EdrEvent, ResponseStatus};

    let action_name = action.action.as_str();
    let evidence_controls = action
        .evidence_controls
        .clone()
        .unwrap_or_else(|| active_policy.evidence_controls.clone());

    let payload = match action.payload.as_ref() {
        Some(p) => p,
        None => {
            return build_rollback_refusal_event(
                &action.id,
                "rollback_simulate",
                active_policy,
                evidence_controls,
                ResponseStatus::Failed,
                &[
                    "rollback simulation missing payload".to_string(),
                    format!("action_queue_id={}", action.id),
                ],
                "rollback simulation payload is empty",
                "failed",
                None,
            );
        }
    };

    // Parse simulation fields (subset of the restore intent)
    let simulation_id = payload
        .get("simulation_id")
        .and_then(|v| v.as_str())
        .unwrap_or("sim");
    let candidate_set_hash = payload
        .get("candidate_set_hash")
        .and_then(|v| v.as_str())
        .unwrap_or("");
    let recovery_point_id = payload
        .get("recovery_point_id")
        .and_then(|v| v.as_str())
        .unwrap_or("");
    let affected_paths: Vec<String> = payload
        .get("affected_paths")
        .and_then(|v| v.as_array())
        .map(|arr| arr.iter().filter_map(|v| v.as_str().map(String::from)).collect())
        .unwrap_or_default();
    let max_depth = payload
        .get("max_depth")
        .and_then(|v| v.as_u64())
        .map(|d| d as u8)
        .unwrap_or(8);

    let scope = rollback::RollbackScope {
        incident_id: action.id.clone(),
        detector_rule_id: simulation_id.to_string(),
        affected_paths: affected_paths.clone(),
        observed_at: chrono::Utc::now().to_rfc3339(),
    };

    let candidates = rollback::RollbackCandidateSet {
        scope,
        recovery_point_id: recovery_point_id.to_string(),
        paths: affected_paths,
        total_bytes_estimate: payload
            .get("total_bytes_estimate")
            .and_then(|v| v.as_u64())
            .unwrap_or(0),
        max_depth,
        candidate_set_hash: candidate_set_hash.to_string(),
    };

    let sim_result = match context.rollback_provider.simulate_restore(&candidates) {
        Ok(sim) => sim,
        Err(err) => {
            return build_rollback_refusal_event(
                &action.id,
                action_name,
                active_policy,
                evidence_controls,
                ResponseStatus::Failed,
                &[
                    "rollback simulation provider error".to_string(),
                    format!("provider_error={err}"),
                    format!("action_queue_id={}", action.id),
                ],
                &format!("simulation_provider_error: {err}"),
                "failed",
                Some(&format!("simulation error: {err}")),
            );
        }
    };

    // Build event with simulation result in decision trace and response
    let mut decision_trace = vec![
        format!("simulation_result: {} candidate(s), {} restorable, {} skipped",
            sim_result.candidate_count,
            sim_result.restorable_count,
            sim_result.skipped_paths.len(),
        ),
        format!("simulation_id={}", sim_result.simulation_id),
        format!("candidate_set_hash={}", sim_result.candidate_set_hash),
        format!("destructive={}", sim_result.destructive),
        format!("valid_until={}", sim_result.valid_until),
    ];

    // Add correlation link entries from payload
    if let Some(corr_ids) = payload.get("correlation_link_ids").and_then(|v| v.as_array()) {
        for v in corr_ids {
            if let Some(id) = v.as_str() {
                decision_trace.push(format!("corroborated_by_correlation_link:{id}"));
            }
        }
    }
    if let Some(id) = payload.get("correlation_link_id").and_then(|v| v.as_str()) {
        decision_trace.push(format!("corroborated_by_correlation_link:{id}"));
    }

    decision_trace.extend(sim_result.decision_trace);

    let response = aetherix_agent::edr::ResponseEvidence {
        action: EdrAction::Review,
        status: ResponseStatus::Executed,
        attempted_at: chrono::Utc::now().to_rfc3339(),
        policy_version: active_policy.policy_version_hash.clone(),
        rule_id: simulation_id.to_string(),
        target_pid: None,
        target_path: None,
        file_sha256: None,
        platform: std::env::consts::OS.to_string(),
        platform_api: "rollback:simulation".to_string(),
        decision_trace,
        error: None,
        quarantine: None,
        quarantine_items: vec![],
        evidence_controls: evidence_controls.clone(),
    };

    let mut event = EdrEvent::new(
        EdrDetectionKind::ResponseAction,
        simulation_id,
        EdrAction::Review,
        &active_policy.policy_version_hash,
    );
    event.evidence_controls = evidence_controls;
    event.tags.push("remote_response_action".to_string());
    event.tags.push("remote_action:rollback_simulate".to_string());
    event.tags.push("rollback_simulation".to_string());
    event.matched_indicator = Some(action.id.clone());
    event.response = Some(response);
    event
}

#[cfg(unix)]
fn write_credentials_file(path: &Path, contents: &str) -> Result<(), Box<dyn std::error::Error>> {
    use std::os::unix::fs::OpenOptionsExt;

    let mut file = fs::OpenOptions::new()
        .create(true)
        .write(true)
        .truncate(true)
        .mode(0o600)
        .open(path)?;
    file.write_all(contents.as_bytes())?;
    Ok(())
}

#[cfg(not(unix))]
fn write_credentials_file(path: &Path, contents: &str) -> Result<(), Box<dyn std::error::Error>> {
    fs::write(path, contents)?;
    Ok(())
}

fn credentials_path() -> PathBuf {
    std::env::var("AETHERIX_AGENT_CREDENTIALS_PATH")
        .map(PathBuf::from)
        .unwrap_or_else(|_| {
            home_dir()
                .unwrap_or_else(|| PathBuf::from("."))
                .join(".aetherix")
                .join("agent-credentials.json")
        })
}

fn install_profile_path() -> PathBuf {
    std::env::var("AETHERIX_INSTALL_PROFILE_PATH")
        .map(PathBuf::from)
        .unwrap_or_else(|_| {
            if cfg!(windows) {
                PathBuf::from(r"C:\ProgramData\Aetherix\install-profile.json")
            } else {
                PathBuf::from("/etc/aetherix/install-profile.json")
            }
        })
}

fn policy_path() -> PathBuf {
    std::env::var("AETHERIX_POLICY_PATH")
        .map(PathBuf::from)
        .unwrap_or_else(|_| {
            home_dir()
                .unwrap_or_else(|| PathBuf::from("."))
                .join(".aetherix")
                .join("policy-package.json")
        })
}

fn effective_policy_path() -> PathBuf {
    std::env::var("AETHERIX_EFFECTIVE_POLICY_PATH")
        .map(PathBuf::from)
        .unwrap_or_else(|_| {
            home_dir()
                .unwrap_or_else(|| PathBuf::from("."))
                .join(".aetherix")
                .join("effective-policy.json")
        })
}

fn dlp_queue_path() -> PathBuf {
    std::env::var("AETHERIX_DLP_EVENT_QUEUE")
        .map(PathBuf::from)
        .unwrap_or_else(|_| {
            home_dir()
                .unwrap_or_else(|| PathBuf::from("."))
                .join(".aetherix")
                .join("dlp-events.ndjson")
        })
}

fn home_dir() -> Option<PathBuf> {
    std::env::var("HOME")
        .or_else(|_| std::env::var("USERPROFILE"))
        .ok()
        .filter(|value| !value.trim().is_empty())
        .map(PathBuf::from)
}

fn legacy_signature(agent_id: &str, hostname: &str, collected_at: &str, policy_version: &str) -> Option<String> {
    let secret = std::env::var("AETHERIX_AGENT_SHARED_SECRET").ok()?;
    let message = format!("{agent_id}:{hostname}:{collected_at}:{policy_version}:{secret}");
    Some(format!("{:x}", Sha256::digest(message.as_bytes())))
}

fn enrolled_signature(
    secret: &str,
    agent_id: &str,
    hostname: &str,
    os: &str,
    collected_at: &str,
    policy_version: &str,
    nonce: u64,
) -> String {
    let message = format!("{agent_id}|{hostname}|{os}|{collected_at}|{policy_version}|{nonce}");
    let mut mac = HmacSha256::new_from_slice(secret.as_bytes()).expect("HMAC accepts any key length");
    mac.update(message.as_bytes());
    hex_encode(&mac.finalize().into_bytes())
}

fn derived_agent_id(hostname: &str) -> String {
    let digest = Sha256::digest(format!("{hostname}:{}", std::env::consts::OS).as_bytes());
    format!("agent-{}", hex_prefix(&digest, 8))
}

fn hex_prefix(bytes: &[u8], length: usize) -> String {
    bytes.iter().take(length).fold(String::new(), |mut value, byte| {
        value.push_str(&format!("{byte:02x}"));
        value
    })
}

fn hex_encode(bytes: &[u8]) -> String {
    bytes.iter().fold(String::new(), |mut value, byte| {
        value.push_str(&format!("{byte:02x}"));
        value
    })
}

fn env_or(name: &str, default_value: &str) -> String {
    std::env::var(name).unwrap_or_else(|_| default_value.to_string())
}

fn env_u64(name: &str) -> u64 {
    std::env::var(name)
        .ok()
        .and_then(|value| value.parse::<u64>().ok())
        .unwrap_or(0)
}

fn env_bool(name: &str) -> bool {
    std::env::var(name)
        .ok()
        .map(|value| {
            let normalized = value.trim().to_ascii_lowercase();
            matches!(normalized.as_str(), "1" | "true" | "yes" | "on")
        })
        .unwrap_or(false)
}

#[cfg(test)]
mod tests {
    use super::{enrolled_signature, load_install_profile};
    use std::fs;

    #[test]
    fn enrolled_signature_matches_server_contract() {
        let signature = enrolled_signature(
            "secret-123",
            "agent-abc",
            "lab-host-1",
            "macos",
            "2026-05-17T12:00:00+00:00",
            "policy-local",
            42,
        );

        assert_eq!(
            signature,
            "6fb43acb884a7d49cb7baf35a31b19a47a0223f9a5df87dd1dc271478b28ef1e"
        );
    }

    #[test]
    fn install_profile_loads_bootstrap_context() {
        let path = std::env::temp_dir().join(format!(
            "aetherix-install-profile-{}.json",
            std::process::id()
        ));
        fs::write(
            &path,
            r#"{
                "control_plane_url": "https://api.example.test",
                "enrollment_token": "token-123",
                "customer_id": "customer-1",
                "policy_package_id": "policy-1"
            }"#,
        )
        .expect("write profile");

        let profile = load_install_profile(&path)
            .expect("profile parse")
            .expect("profile exists");

        assert_eq!(profile.control_plane_url, "https://api.example.test");
        assert_eq!(profile.enrollment_token, "token-123");
        assert_eq!(profile.customer_id.as_deref(), Some("customer-1"));
        fs::remove_file(path).ok();
    }
}

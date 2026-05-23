mod bridge;
mod dlp;
mod evidence;
mod policy;

use anyhow::Context;
use arboard::Clipboard;
use chrono::Utc;
use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::{Arc, RwLock};
use std::thread;
use std::time::{Duration, Instant};
use std::process::Command;
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

#[derive(Deserialize, Serialize)]
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

    let policy_version = if let (Some(api_url), Some(credentials)) = (api_url.as_deref(), credentials.as_ref()) {
        let policy = fetch_policy_package(&client, api_url, &credentials.agent_id)?;
        save_policy_package(&policy_path(), &policy)?;
        format!("{}-v{}", policy.id, policy.version)
    } else {
        env_or("AETHERIX_POLICY_VERSION", "policy-local")
    };

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

    let heartbeat = Heartbeat {
        signature,
        nonce,
        signals: collect_signals(),
        agent_id,
        hostname,
        os,
        collected_at,
        policy_version,
        agent_version: DEFAULT_AGENT_VERSION.to_string(),
    };

    if let Some(ref api_url) = api_url {
        let endpoint = format!("{}/agent/heartbeat", api_url.trim_end_matches('/'));
        let response = client.post(endpoint).json(&heartbeat).send()?;

        if !response.status().is_success() {
            return Err(format!("heartbeat rejected with status {}", response.status()).into());
        }
    }

    println!("{}", serde_json::to_string_pretty(&heartbeat)?);

    // Shared policy state used by both the DLP enforcement loop (writer)
    // and the local browser bridge (reader). Wrapped in an Arc<RwLock<...>>
    // so refreshes from the loop become visible to the bridge instantly.
    let shared_policy: Arc<RwLock<Option<policy::RuntimePolicy>>> =
        Arc::new(RwLock::new(None));

    let bridge_enabled = env_bool("AETHERIX_ENABLE_LOCAL_BRIDGE");
    if bridge_enabled {
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

            if let Err(err) =
                start_local_bridge(api_url, credentials, shared_policy.clone())
            {
                eprintln!("aetherix-agent: local bridge failed to start: {err}");
            }
        } else {
            eprintln!(
                "aetherix-agent: AETHERIX_ENABLE_LOCAL_BRIDGE=1 but no credentials or API URL; bridge disabled"
            );
        }
    }

    if env_bool("AETHERIX_ENABLE_DLP_ENFORCEMENT") {
        if let (Some(api_url), Some(credentials)) = (api_url.as_deref(), credentials.as_ref()) {
            run_dlp_enforcement_loop(&client, api_url, credentials, shared_policy.clone())
                .map_err(|err| format!("dlp enforcement failed: {err}"))?;
        }
    } else if bridge_enabled {
        // Bridge is up but the enforcement loop isn't; block the main
        // thread so the bridge thread stays alive. The user can stop the
        // agent via SIGINT/Ctrl-C as usual.
        loop {
            thread::sleep(Duration::from_secs(60));
        }
    }

    Ok(())
}

fn start_local_bridge(
    api_url: &str,
    credentials: &AgentCredentials,
    shared_policy: Arc<RwLock<Option<policy::RuntimePolicy>>>,
) -> anyhow::Result<()> {
    let config = bridge::BridgeConfig::from_env();
    let state = Arc::new(bridge::BridgeState::new(
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
    ));
    let addr = bridge::spawn(state, config.port)
        .context("spawn local bridge")?;
    println!("aetherix-agent: local bridge listening on http://{addr}");
    Ok(())
}

struct DlpRuntimeState {
    clipboard: Option<Clipboard>,
    last_clipboard: Option<String>,
    queue_lines_read: usize,
}

fn run_dlp_enforcement_loop(
    client: &reqwest::blocking::Client,
    api_url: &str,
    credentials: &AgentCredentials,
    shared_policy: Arc<RwLock<Option<policy::RuntimePolicy>>>,
) -> anyhow::Result<()> {
    let poll_interval = env_u64("AETHERIX_DLP_POLL_INTERVAL_SECONDS").max(1);
    let refresh_interval = env_u64("AETHERIX_POLICY_REFRESH_SECONDS").max(5);
    let run_seconds = env_u64("AETHERIX_DLP_RUN_SECONDS");
    let started = Instant::now();

    let cache_path = effective_policy_path();
    let mut active_policy = match policy::fetch_effective_policy(client, api_url, &credentials.agent_id, &credentials.agent_secret) {
        Ok(fetched) => {
            let _ = policy::save_policy_cache(&cache_path, &fetched);
            fetched
        }
        Err(fetch_error) => policy::load_policy_cache(&cache_path)
            .context("unable to load cached policy after fetch failure")?
            .ok_or_else(|| anyhow::anyhow!("no policy from api and no last-known-good cache: {fetch_error}"))?,
    };
    if let Ok(mut guard) = shared_policy.write() {
        *guard = Some(active_policy.clone());
    }

    let queue_path = dlp_queue_path();
    let mut state = DlpRuntimeState {
        clipboard: Clipboard::new().ok(),
        last_clipboard: None,
        queue_lines_read: 0,
    };
    let mut last_refresh = Instant::now();

    loop {
        if last_refresh.elapsed().as_secs() >= refresh_interval {
            if let Ok(fetched) = policy::fetch_effective_policy(client, api_url, &credentials.agent_id, &credentials.agent_secret) {
                let changed = fetched.policy_version_hash != active_policy.policy_version_hash;
                if changed {
                    active_policy = fetched;
                    let _ = policy::save_policy_cache(&cache_path, &active_policy);
                    if let Ok(mut guard) = shared_policy.write() {
                        *guard = Some(active_policy.clone());
                    }
                }
            }
            last_refresh = Instant::now();
        }

        let events = collect_dlp_events(&mut state, &queue_path);
        for event in events {
            if let Some(decision) = dlp::evaluate_event(&active_policy, &event) {
                if let Err(err) = evidence::emit_dlp_evidence(
                    client,
                    api_url,
                    &credentials.agent_id,
                    &credentials.agent_secret,
                    &active_policy.policy_version_hash,
                    &event,
                    &decision,
                ) {
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

        if run_seconds > 0 && started.elapsed().as_secs() >= run_seconds {
            break;
        }

        thread::sleep(Duration::from_secs(poll_interval));
    }

    Ok(())
}

fn collect_dlp_events(state: &mut DlpRuntimeState, queue_path: &Path) -> Vec<dlp::DlpEvent> {
    let mut events = Vec::new();

    if let Some(clipboard) = state.clipboard.as_mut() {
        if let Ok(text) = clipboard.get_text() {
            let trimmed = text.trim();
            if !trimmed.is_empty() && state.last_clipboard.as_deref() != Some(trimmed) {
                state.last_clipboard = Some(trimmed.to_string());
                events.push(dlp::DlpEvent {
                    event_type: dlp::DlpEventType::Paste,
                    source: dlp::EventSource::Endpoint,
                    content: trimmed.to_string(),
                    destination: None,
                    process_name: None,
                });
            }
        }
    }

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

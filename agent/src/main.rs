use chrono::Utc;
use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
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

    if let Some(api_url) = api_url {
        let endpoint = format!("{}/agent/heartbeat", api_url.trim_end_matches('/'));
        let response = client.post(endpoint).json(&heartbeat).send()?;

        if !response.status().is_success() {
            return Err(format!("heartbeat rejected with status {}", response.status()).into());
        }
    }

    println!("{}", serde_json::to_string_pretty(&heartbeat)?);
    Ok(())
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

use chrono::Utc;
use serde::Serialize;
use sha2::{Digest, Sha256};

#[derive(Serialize)]
struct Heartbeat {
    agent_id: String,
    hostname: String,
    os: String,
    collected_at: String,
    policy_version: String,
    signature: String,
}

fn main() {
    let hostname = std::env::var("HOSTNAME").unwrap_or_else(|_| "unknown-endpoint".to_string());
    let unsigned = format!("aetherix-dev:{hostname}:policy-default");
    let signature = format!("{:x}", Sha256::digest(unsigned.as_bytes()));

    let heartbeat = Heartbeat {
        agent_id: "agent-dev-001".to_string(),
        hostname,
        os: std::env::consts::OS.to_string(),
        collected_at: Utc::now().to_rfc3339(),
        policy_version: "policy-default".to_string(),
        signature,
    };

    println!("{}", serde_json::to_string_pretty(&heartbeat).expect("heartbeat serializes"));
}

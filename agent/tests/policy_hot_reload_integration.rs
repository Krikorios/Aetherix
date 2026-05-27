//! Integration test: a policy hot-reload from the control plane is
//! picked up and applied in-place within one poll cycle, with no agent
//! restart. The mock control plane serves policy v1 (Review on paste)
//! first, then switches to policy v2 (Block on paste); after one
//! `tick()` the reloader returns the new policy and the running
//! `DlpClient::evaluate` flow immediately enforces the new action.

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

use aetherix_agent::dlp_client::DlpClient;
use aetherix_agent::dlp::{DlpEvent, DlpEventType, EventSource};
use aetherix_agent::policy::{DlpAction, PolicyHotReloader};

// ---------- mock control plane with switchable policy ----------

struct MockPolicyApi {
    url: String,
    version: Arc<Mutex<u32>>,
    policy_hits: Arc<AtomicUsize>,
}

fn start_mock(endpoint_id: &str) -> MockPolicyApi {
    let server = tiny_http::Server::http("127.0.0.1:0").expect("bind mock api");
    let addr = server.server_addr().to_ip().unwrap();
    let url = format!("http://{addr}");
    let version = Arc::new(Mutex::new(1u32));
    let policy_hits = Arc::new(AtomicUsize::new(0));

    let version_clone = version.clone();
    let hits_clone = policy_hits.clone();
    let endpoint_id = endpoint_id.to_string();

    thread::spawn(move || {
        for req in server.incoming_requests() {
            let url = req.url().to_string();
            if url.starts_with("/agent/policy") {
                hits_clone.fetch_add(1, Ordering::SeqCst);
                let v = *version_clone.lock().unwrap();
                let body = policy_payload(&endpoint_id, v);
                let resp = tiny_http::Response::from_string(body)
                    .with_status_code(tiny_http::StatusCode(200))
                    .with_header(
                        "content-type: application/json"
                            .parse::<tiny_http::Header>()
                            .unwrap(),
                    );
                let _ = req.respond(resp);
            } else {
                // Evidence emits etc. — just 200 OK them.
                let resp = tiny_http::Response::from_string(r#"{"id":"evt"}"#)
                    .with_status_code(tiny_http::StatusCode(200));
                let _ = req.respond(resp);
            }
        }
    });

    MockPolicyApi {
        url,
        version,
        policy_hits,
    }
}

/// Two policy versions wired to the same endpoint.
///   v1: paste_sensitive = "review"   (allow-with-attestation)
///   v2: paste_sensitive = "block"    (hard block)
fn policy_payload(endpoint_id: &str, version: u32) -> String {
    let (hash, paste_action) = match version {
        1 => ("policy-v1", "review"),
        _ => ("policy-v2", "block"),
    };
    serde_json::json!({
        "endpoint_id": endpoint_id,
        "policy_version_hash": hash,
        "evidence_controls": ["iso27001-2022:A.5.12"],
        "resolved_policy": {
            "modules": {
                "semantic_dlp": {
                    "enabled": true,
                    "sensitivity_labels": ["restricted"],
                    "genai_destinations": ["chatgpt"],
                    "actions": {
                        "paste_sensitive": paste_action,
                        "upload_restricted": "block",
                        "copy_to_genai": "block"
                    }
                },
                "genai_guardrails": {
                    "enabled": true,
                    "destinations": ["chatgpt"],
                    "browser_enforcement": true,
                    "endpoint_enforcement": true,
                    "actions": {
                        "paste_sensitive": paste_action,
                        "upload_restricted": "block",
                        "copy_to_genai": "block"
                    }
                }
            }
        }
    })
    .to_string()
}

fn restricted_paste_event() -> DlpEvent {
    DlpEvent {
        event_type: DlpEventType::Paste,
        source: EventSource::BrowserExtension,
        content: "[restricted] customer ssn 111-22-3333".to_string(),
        destination: Some("https://chatgpt.com".to_string()),
        process_name: None,
    }
}

#[test]
fn policy_change_is_applied_within_one_poll_cycle() {
    let agent_id = "agent-hot-1";
    let api = start_mock(agent_id);

    let cache_dir = tempfile::tempdir().unwrap();
    let cache_path = cache_dir.path().join("effective-policy.json");
    let queue_dir = tempfile::tempdir().unwrap();
    let queue_path = queue_dir.path().join("fallback.ndjson");

    let http = reqwest::blocking::Client::new();
    // Zero-second refresh interval so every `tick()` actually polls —
    // the production default is 30 s and is exercised by `from_env`,
    // which is unit-tested elsewhere. This integration test cares
    // about the swap semantics, not the wall-clock cadence.
    let mut reloader = PolicyHotReloader::new(
        http.clone(),
        api.url.clone(),
        agent_id.to_string(),
        "secret-hot-1".to_string(),
        cache_path.clone(),
        Duration::from_secs(30),
    )
    .with_refresh_interval(Duration::ZERO);

    // ----- Phase 1: bootstrap on v1 (Review) -----
    let mut active = reloader.bootstrap().expect("bootstrap policy");
    assert_eq!(active.policy_version_hash, "policy-v1");
    assert_eq!(
        active.resolved.semantic_dlp.actions.paste_sensitive,
        DlpAction::Review
    );
    assert!(cache_path.exists(), "bootstrap must persist last-known-good");

    let dlp_client = DlpClient::new(
        http.clone(),
        api.url.clone(),
        agent_id.to_string(),
        "secret-hot-1".to_string(),
        queue_path.clone(),
    );

    // Under v1 a restricted paste is Review, not Block.
    let event = restricted_paste_event();
    let decision_v1 = dlp_client.evaluate(&active, &event).expect("v1 decision");
    assert_eq!(
        decision_v1.action,
        DlpAction::Review,
        "v1 must resolve to review, not block"
    );

    // ----- Phase 2: control plane swaps the policy -----
    *api.version.lock().unwrap() = 2;

    // A single tick polls (interval = 0) and returns the new policy.
    let swapped = reloader.tick().expect("hot reload must surface v2");
    assert_eq!(swapped.policy_version_hash, "policy-v2");
    // Atomic swap into the loop's active policy.
    active = swapped;

    // ----- Phase 3: the SAME running enforcement path now blocks -----
    let decision_v2 = dlp_client.evaluate(&active, &event).expect("v2 decision");
    assert_eq!(
        decision_v2.action,
        DlpAction::Block,
        "after hot-reload the agent must enforce the new Block action immediately"
    );

    // Subsequent tick with no upstream change must NOT report a swap.
    let no_change = reloader.tick();
    assert!(no_change.is_none(), "unchanged hash must not re-swap");

    // Cache on disk must now reflect v2 (last-known-good is current).
    let cached = std::fs::read_to_string(&cache_path).unwrap();
    assert!(cached.contains("policy-v2"));

    // We hit the policy endpoint at least three times:
    //   bootstrap, swap-tick, and no-change-tick.
    assert!(
        api.policy_hits.load(Ordering::SeqCst) >= 3,
        "reloader must actually poll the control plane"
    );
}

#[test]
fn unreachable_control_plane_keeps_last_known_good_policy() {
    // Bootstrap against a live mock, then point a *new* reloader at an
    // unroutable URL while keeping the same on-disk cache. The agent
    // must continue to operate on the cached policy without error.
    let agent_id = "agent-hot-2";
    let api = start_mock(agent_id);
    let cache_dir = tempfile::tempdir().unwrap();
    let cache_path = cache_dir.path().join("effective-policy.json");
    let http = reqwest::blocking::Client::builder()
        .timeout(Duration::from_millis(250))
        .build()
        .unwrap();

    // Seed the cache from the live mock.
    let mut warm = PolicyHotReloader::new(
        http.clone(),
        api.url.clone(),
        agent_id.to_string(),
        "secret-hot-2".to_string(),
        cache_path.clone(),
        Duration::from_secs(30),
    );
    warm.bootstrap().expect("seed last-known-good cache");

    // Now simulate a control-plane outage.
    let mut offline = PolicyHotReloader::new(
        http,
        "http://127.0.0.1:1".to_string(),
        agent_id.to_string(),
        "secret-hot-2".to_string(),
        cache_path.clone(),
        Duration::from_secs(30),
    )
    .with_refresh_interval(Duration::ZERO);

    let cached_policy = offline
        .bootstrap()
        .expect("offline bootstrap must succeed via cache");
    assert_eq!(cached_policy.policy_version_hash, "policy-v1");

    // A tick against the unroutable URL must NOT surface a change and
    // must NOT panic — the agent keeps using the cached policy.
    let attempt = offline.tick();
    assert!(
        attempt.is_none(),
        "offline tick must return None and preserve the active policy"
    );
}

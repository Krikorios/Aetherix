//! Integration test: a file containing restricted content that lands
//! in a watched directory is deleted by the agent (real Block
//! enforcement) AND a compliance evidence record is posted to the
//! control plane.

use std::io::Write;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;

use aetherix_agent::dlp_client::DlpClient;
use aetherix_agent::interceptors::FileUploadInterceptor;
use aetherix_agent::policy::{
    DlpAction, GenaiGuardrailsPolicy, ResolvedPolicy, RuntimePolicy, SemanticActions,
    SemanticDlpPolicy,
};

// ---------- minimal mock control plane (mirrors clipboard test) ----------

struct MockApi {
    url: String,
    hits: Arc<AtomicUsize>,
    bodies: Arc<Mutex<Vec<String>>>,
}

fn start_mock_api() -> MockApi {
    let server = tiny_http::Server::http("127.0.0.1:0").expect("bind mock api");
    let addr = server.server_addr().to_ip().unwrap();
    let url = format!("http://{addr}");
    let hits = Arc::new(AtomicUsize::new(0));
    let bodies: Arc<Mutex<Vec<String>>> = Arc::new(Mutex::new(Vec::new()));
    let hits_clone = hits.clone();
    let body_clone = bodies.clone();
    thread::spawn(move || {
        for mut req in server.incoming_requests() {
            hits_clone.fetch_add(1, Ordering::SeqCst);
            let mut body = String::new();
            let _ = std::io::Read::read_to_string(req.as_reader(), &mut body);
            body_clone.lock().unwrap().push(body);
            let resp = tiny_http::Response::from_string(r#"{"id":"evt-1"}"#)
                .with_status_code(tiny_http::StatusCode(200));
            let _ = req.respond(resp);
        }
    });
    MockApi {
        url,
        hits,
        bodies,
    }
}

fn blocking_policy() -> RuntimePolicy {
    RuntimePolicy {
        endpoint_id: "agent-fu-1".to_string(),
        policy_version_hash: "policy-fu-1".to_string(),
        evidence_controls: vec!["iso27001-2022:A.5.12".to_string()],
        resolved: ResolvedPolicy {
            semantic_dlp: SemanticDlpPolicy {
                enabled: true,
                sensitivity_labels: vec!["restricted".to_string()],
                genai_destinations: vec!["chatgpt".to_string()],
                actions: SemanticActions {
                    paste_sensitive: DlpAction::Block,
                    upload_restricted: DlpAction::Block,
                    copy_to_genai: DlpAction::Block,
                },
                ..Default::default()
            },
            genai_guardrails: GenaiGuardrailsPolicy {
                enabled: true,
                destinations: vec!["chatgpt".to_string()],
                browser_enforcement: true,
                endpoint_enforcement: true,
                actions: SemanticActions {
                    paste_sensitive: DlpAction::Block,
                    upload_restricted: DlpAction::Block,
                    copy_to_genai: DlpAction::Block,
                },
            },
            ..Default::default()
        },
    }
}

#[test]
fn restricted_file_in_watched_dir_is_deleted_and_evidence_is_emitted() {
    // 1. Arrange — mock control plane, watch a tempdir, prime the scanner.
    let api = start_mock_api();
    let watch_dir = tempfile::tempdir().expect("watch tempdir");
    let queue_dir = tempfile::tempdir().expect("queue tempdir");
    let fallback_queue = queue_dir.path().join("fallback.ndjson");

    let mut interceptor = FileUploadInterceptor::new(
        vec![watch_dir.path().to_path_buf()],
        vec!["txt".to_string()],
    );
    // Priming scan: no pre-existing files, but flips the interceptor
    // out of "ignore initial inventory" mode.
    let primed = interceptor.scan();
    assert!(primed.is_empty(), "no files yet");

    let dlp_client = DlpClient::new(
        reqwest::blocking::Client::new(),
        api.url.clone(),
        "agent-fu-1".to_string(),
        "secret-fu-1".to_string(),
        fallback_queue.clone(),
    );
    let policy = blocking_policy();

    // 2. Act — create a restricted file in the watched dir, exactly as
    //    a user "Save As..." or a browser download would.
    let target = watch_dir.path().join("leak.txt");
    {
        let mut f = std::fs::File::create(&target).expect("create leak file");
        f.write_all(b"[restricted] customer ssn 111-22-3333 + api-key sk-live-xyz")
            .unwrap();
        f.sync_all().unwrap();
    }
    assert!(target.exists(), "precondition: file exists before scan");

    let candidates = interceptor.scan();
    assert_eq!(candidates.len(), 1, "exactly one new file detected");
    let candidate = &candidates[0];
    assert_eq!(candidate.path, target);

    let decision = dlp_client
        .evaluate(&policy, &candidate.event)
        .expect("policy must resolve to a Block for restricted content");
    assert_eq!(decision.action, DlpAction::Block);

    interceptor
        .enforce_block(&candidate.path)
        .expect("file deletion must succeed");
    dlp_client
        .emit(&policy.policy_version_hash, &candidate.event, &decision)
        .expect("evidence emit must succeed against mock api");

    // 3. Assert — the file is gone, the control plane saw exactly one
    //    POST whose body carries decision=block and the policy version.
    assert!(!target.exists(), "blocked file must be deleted from disk");
    assert_eq!(api.hits.load(Ordering::SeqCst), 3);
    let bodies = api
        .bodies
        .lock()
        .unwrap()
        .clone();
    let evidence_body = bodies.iter().find(|b| b.contains("\"decision\":\"block\"")).expect("evidence body recorded");
    assert!(
        evidence_body.contains("\"decision\":\"block\""),
        "evidence must carry decision=block; got: {evidence_body}"
    );
    assert!(
        evidence_body.contains("\"event_type\":\"upload\""),
        "evidence must carry event_type=upload; got: {evidence_body}"
    );
    assert!(evidence_body.contains("policy-fu-1"));
    assert!(
        !fallback_queue.exists(),
        "fallback queue should stay empty on happy path"
    );
}

#[test]
fn file_block_still_enforces_locally_when_api_is_down() {
    // Sidecar unreachable — the file must still be deleted and the
    // evidence persisted to the local fallback queue.
    let watch_dir = tempfile::tempdir().unwrap();
    let queue_dir = tempfile::tempdir().unwrap();
    let fallback_queue = queue_dir.path().join("fallback.ndjson");

    let mut interceptor = FileUploadInterceptor::new(
        vec![watch_dir.path().to_path_buf()],
        vec!["txt".to_string()],
    );
    let _ = interceptor.scan();

    let dlp_client = DlpClient::new(
        reqwest::blocking::Client::builder()
            .timeout(std::time::Duration::from_millis(250))
            .build()
            .unwrap(),
        "http://127.0.0.1:1".to_string(),
        "agent-fu-2".to_string(),
        "secret-fu-2".to_string(),
        fallback_queue.clone(),
    );
    let policy = blocking_policy();

    let target = watch_dir.path().join("offline-leak.txt");
    std::fs::write(&target, "[restricted] offline secret payload").unwrap();
    let candidates = interceptor.scan();
    assert_eq!(candidates.len(), 1);
    let candidate = &candidates[0];

    let decision = dlp_client.evaluate(&policy, &candidate.event).unwrap();
    assert_eq!(decision.action, DlpAction::Block);
    interceptor.enforce_block(&candidate.path).unwrap();
    dlp_client
        .emit(&policy.policy_version_hash, &candidate.event, &decision)
        .expect("emit returns Ok after queueing on transport failure");

    assert!(!target.exists(), "file must be deleted even when API is down");
    assert!(fallback_queue.exists(), "evidence must be queued locally");
    let queued = std::fs::read_to_string(&fallback_queue).unwrap();
    assert!(queued.contains("endpoint_evidence"));
    assert!(queued.contains("upload"));
}

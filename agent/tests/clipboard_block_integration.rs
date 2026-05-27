//! Integration test: real `Block` decision actually prevents the paste
//! (clipboard is overwritten) AND a compliance review/attestation
//! evidence record is posted to the control plane.
//!
//! This is the production-contract test for the endpoint agent.
//! It wires the real `ClipboardInterceptor` to a fake backend and the
//! real `DlpClient` to an in-process `tiny_http` server that
//! impersonates the FastAPI control plane.

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;

use aetherix_agent::dlp_client::DlpClient;
use aetherix_agent::interceptors::{ClipboardBackend, ClipboardInterceptor, BLOCKED_PLACEHOLDER};
use aetherix_agent::policy::{
    DlpAction, GenaiGuardrailsPolicy, ResolvedPolicy, RuntimePolicy, SemanticActions,
    SemanticDlpPolicy,
};

// ---------- shared in-memory clipboard ----------

#[derive(Clone)]
struct FakeClipboard {
    inner: Arc<Mutex<String>>,
}

impl FakeClipboard {
    fn with_text(text: &str) -> Self {
        Self {
            inner: Arc::new(Mutex::new(text.to_string())),
        }
    }
    fn read(&self) -> String {
        self.inner.lock().unwrap().clone()
    }
}

impl ClipboardBackend for FakeClipboard {
    fn get_text(&mut self) -> anyhow::Result<String> {
        Ok(self.inner.lock().unwrap().clone())
    }
    fn set_text(&mut self, value: &str) -> anyhow::Result<()> {
        *self.inner.lock().unwrap() = value.to_string();
        Ok(())
    }
}

// ---------- minimal mock control plane ----------

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

// ---------- test policy: BLOCK on restricted paste ----------

fn blocking_policy() -> RuntimePolicy {
    RuntimePolicy {
        endpoint_id: "agent-it-1".to_string(),
        policy_version_hash: "policy-vit-1".to_string(),
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

// ---------- the contract test ----------

#[test]
fn block_decision_overwrites_clipboard_and_emits_evidence() {
    // 1. Arrange — start a mock control plane and seed the clipboard
    //    with restricted content.
    let api = start_mock_api();
    let queue_dir = tempfile::tempdir().expect("tempdir");
    let fallback_queue = queue_dir.path().join("fallback.ndjson");

    let backend = FakeClipboard::with_text("[restricted] quarterly mrr 4.2M and ssn 111-22-3333");
    let probe = backend.clone();
    let mut interceptor = ClipboardInterceptor::new(backend);

    let policy = blocking_policy();
    let dlp_client = DlpClient::new(
        reqwest::blocking::Client::new(),
        api.url.clone(),
        "agent-it-1".to_string(),
        "secret-it-1".to_string(),
        fallback_queue.clone(),
    );

    // 2. Act — pull the changed clipboard through the interceptor and
    //    route it through `dlp_client.evaluate()` exactly as the
    //    production loop does.
    let event = interceptor.poll().expect("clipboard event expected");
    let decision = dlp_client
        .evaluate(&policy, &event)
        .expect("policy should resolve to a decision for restricted content");

    assert_eq!(decision.action, DlpAction::Block, "policy must Block");

    // Real enforcement: overwrite the clipboard so the user's paste cannot succeed.
    interceptor
        .enforce_block()
        .expect("clipboard overwrite must succeed");

    // Compliance evidence: review + attestation are posted to the API.
    dlp_client
        .emit(&policy.policy_version_hash, &event, &decision)
        .expect("evidence emit must succeed against mock api");

    // 3. Assert — the actual clipboard contents are the redaction
    //    placeholder, the mock API received exactly one evidence POST,
    //    and the body carries decision=block.
    assert_eq!(
        probe.read(),
        BLOCKED_PLACEHOLDER,
        "clipboard must be overwritten with the block placeholder"
    );
    assert_eq!(
        api.hits.load(Ordering::SeqCst),
        3,
        "exactly 3 POSTs (evidence, review, attestation) must reach the control plane"
    );
    let bodies = api
        .bodies
        .lock()
        .unwrap()
        .clone();
        
    let evidence_body = bodies.iter().find(|b| b.contains("\"decision\":\"block\"")).expect("evidence body recorded");
    assert!(
        evidence_body.contains("policy-vit-1"),
        "evidence body must carry the policy version hash"
    );

    // Fallback queue is unused on the happy path.
    assert!(
        !fallback_queue.exists(),
        "fallback queue should be empty when the API accepts the post"
    );
}

#[test]
fn block_still_enforces_locally_when_api_is_down() {
    // Sidecar/API unreachable — agent must still overwrite the
    // clipboard and persist the evidence to the local NDJSON queue.
    let queue_dir = tempfile::tempdir().expect("tempdir");
    let fallback_queue = queue_dir.path().join("fallback.ndjson");

    let backend = FakeClipboard::with_text("[restricted] api-key=sk-live-secret");
    let probe = backend.clone();
    let mut interceptor = ClipboardInterceptor::new(backend);
    let policy = blocking_policy();
    let dlp_client = DlpClient::new(
        reqwest::blocking::Client::builder()
            .timeout(std::time::Duration::from_millis(250))
            .build()
            .unwrap(),
        // Unrouteable port — guaranteed connect failure.
        "http://127.0.0.1:1".to_string(),
        "agent-it-2".to_string(),
        "secret-it-2".to_string(),
        fallback_queue.clone(),
    );

    let event = interceptor.poll().expect("clipboard event expected");
    let decision = dlp_client
        .evaluate(&policy, &event)
        .expect("policy decision present");
    interceptor.enforce_block().expect("block enforced");
    dlp_client
        .emit(&policy.policy_version_hash, &event, &decision)
        .expect("emit returns Ok after queueing on transport failure");

    assert_eq!(probe.read(), BLOCKED_PLACEHOLDER);
    assert!(
        fallback_queue.exists(),
        "fallback queue must exist after transport failure"
    );
    let queued = std::fs::read_to_string(&fallback_queue).unwrap();
    assert!(queued.contains("endpoint_evidence"));
    assert!(queued.contains("policy-vit-1"));
}

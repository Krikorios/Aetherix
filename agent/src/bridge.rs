//! Local-loopback HTTP bridge for the Aetherix browser extension (Phase 2).
//!
//! The browser extension cannot speak directly to the FastAPI control plane
//! because it does not hold the enrolled `agent_secret`. Instead, the agent
//! exposes a tiny HTTP server on `127.0.0.1` that:
//!
//!   * serves the most recent effective policy (`GET /policy`), and
//!   * accepts evidence payloads (`POST /dlp-event`) and forwards them to
//!     `POST /agent/dlp-evidence` using the existing enrolled credentials.
//!
//! Design notes:
//!
//!   * The bridge is intentionally synchronous (`tiny_http`) so it slots into
//!     the agent's existing `reqwest::blocking` model without pulling tokio
//!     into the whole codebase.
//!   * Bind is hard-coded to `127.0.0.1`. Every accepted connection's peer
//!     address is re-validated to be in the loopback range before any
//!     handler runs.
//!   * A simple per-IP token bucket protects against runaway extensions or
//!     malicious local processes. The bucket is generous (60 rps burst,
//!     30 rps sustained) because we expect only a single browser to talk
//!     to us.
//!   * `Origin` is validated against a configurable allow-list of
//!     `chrome-extension://` / `moz-extension://` URIs (default: any
//!     extension origin). CORS preflight is handled in-line.

use crate::policy::RuntimePolicy;
use anyhow::{anyhow, Context, Result};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::fs::OpenOptions;
use std::io::Write;
use std::net::{IpAddr, SocketAddr};
use std::path::PathBuf;
use std::sync::{Arc, Mutex, RwLock};
use std::thread;
use std::time::{Duration, Instant};
use tiny_http::{Header, Method, Request, Response, Server, StatusCode};

const DEFAULT_PORT: u16 = 8787;
const MAX_BODY_BYTES: usize = 256 * 1024; // 256 KiB cap on POST bodies
const FORWARD_TIMEOUT: Duration = Duration::from_secs(5);

/// Public configuration for the bridge. Built from env vars by `main.rs`.
#[derive(Clone)]
pub struct BridgeConfig {
    pub port: u16,
    pub allowed_origins: Vec<String>,
}

impl BridgeConfig {
    pub fn from_env() -> Self {
        let port = std::env::var("AETHERIX_LOCAL_BRIDGE_PORT")
            .ok()
            .and_then(|v| v.parse::<u16>().ok())
            .unwrap_or(DEFAULT_PORT);

        let allowed_origins = std::env::var("AETHERIX_LOCAL_BRIDGE_ORIGIN")
            .ok()
            .map(|raw| {
                raw.split(',')
                    .map(|s| s.trim().to_string())
                    .filter(|s| !s.is_empty())
                    .collect::<Vec<_>>()
            })
            .unwrap_or_default();

        Self {
            port,
            allowed_origins,
        }
    }
}

/// Shared state passed to the bridge handler thread.
pub struct BridgeState {
    pub policy: Arc<RwLock<Option<RuntimePolicy>>>,
    pub agent_id: String,
    pub agent_secret: String,
    pub api_url: String,
    pub client: reqwest::blocking::Client,
    pub queue_path: PathBuf,
    pub allowed_origins: Vec<String>,
    rate_limiter: Mutex<RateLimiter>,
}

impl BridgeState {
    pub fn new(
        policy: Arc<RwLock<Option<RuntimePolicy>>>,
        agent_id: String,
        agent_secret: String,
        api_url: String,
        client: reqwest::blocking::Client,
        queue_path: PathBuf,
        allowed_origins: Vec<String>,
    ) -> Self {
        Self {
            policy,
            agent_id,
            agent_secret,
            api_url,
            client,
            queue_path,
            allowed_origins,
            rate_limiter: Mutex::new(RateLimiter::default()),
        }
    }
}

/// Spawn the bridge on a background thread. Returns the bound address so
/// callers (and tests) can log / connect to the actual port (useful when
/// `port` is `0` for ephemeral binding).
pub fn spawn(state: Arc<BridgeState>, port: u16) -> Result<SocketAddr> {
    let server = Server::http(("127.0.0.1", port))
        .map_err(|e| anyhow!("failed to bind local bridge on 127.0.0.1:{port}: {e}"))?;
    let addr = server
        .server_addr()
        .to_ip()
        .ok_or_else(|| anyhow!("tiny_http server bound to non-ip address"))?;

    thread::Builder::new()
        .name("aetherix-bridge".to_string())
        .spawn(move || serve_loop(server, state))
        .context("failed to spawn aetherix-bridge thread")?;

    Ok(addr)
}

fn serve_loop(server: Server, state: Arc<BridgeState>) {
    for request in server.incoming_requests() {
        // Defense in depth: tiny_http only binds the requested interface but
        // verify the peer is loopback anyway. Any other address gets a
        // hard close.
        if let Some(addr) = request.remote_addr() {
            if !is_loopback(addr.ip()) {
                let _ = request.respond(text_response(StatusCode(403), "forbidden"));
                continue;
            }
        }
        if let Err(err) = handle_request(request, &state) {
            eprintln!("aetherix-bridge: handler error: {err}");
        }
    }
}

fn handle_request(mut request: Request, state: &Arc<BridgeState>) -> Result<()> {
    // Rate limit first so abusive callers can't spend resources reading
    // request bodies.
    let peer = request
        .remote_addr()
        .map(|a| a.ip())
        .unwrap_or(IpAddr::from([127, 0, 0, 1]));
    {
        let mut rl = state.rate_limiter.lock().expect("rate limiter poisoned");
        if !rl.allow(peer) {
            return request
                .respond(text_response(StatusCode(429), "rate limited"))
                .map_err(Into::into);
        }
    }

    let method = request.method().clone();
    let url = request.url().to_string();
    let path = url.split('?').next().unwrap_or("/").to_string();
    let origin = header_value(&request, "Origin");

    // CORS preflight short-circuits every route.
    if method == Method::Options {
        if origin
            .as_deref()
            .is_some_and(|o| pick_allowed_origin(o, &state.allowed_origins).is_none())
        {
            return request
                .respond(text_response(StatusCode(403), "origin forbidden"))
                .map_err(Into::into);
        }
        return request
            .respond(cors_preflight(&state.allowed_origins, origin.as_deref()))
            .map_err(Into::into);
    }

    if origin
        .as_deref()
        .is_some_and(|o| pick_allowed_origin(o, &state.allowed_origins).is_none())
    {
        return request
            .respond(text_response(StatusCode(403), "origin forbidden"))
            .map_err(Into::into);
    }

    match (method, path.as_str()) {
        (Method::Get, "/health") => respond(
            request,
            &state.allowed_origins,
            origin.as_deref(),
            StatusCode(200),
            &health_payload(state),
        ),
        (Method::Get, "/policy") => respond(
            request,
            &state.allowed_origins,
            origin.as_deref(),
            StatusCode(200),
            &policy_payload(state),
        ),
        (Method::Post, "/dlp-event") => {
            let body = read_body_capped(&mut request, MAX_BODY_BYTES)?;
            let payload: Value = match serde_json::from_slice(&body) {
                Ok(v) => v,
                Err(err) => {
                    return request
                        .respond(json_response(
                            &state.allowed_origins,
                            origin.as_deref(),
                            StatusCode(400),
                            &serde_json::json!({"ok": false, "error": format!("invalid json: {err}")}),
                        ))
                        .map_err(Into::into);
                }
            };
            let (status, body) = forward_evidence(state, payload);
            request
                .respond(json_response(
                    &state.allowed_origins,
                    origin.as_deref(),
                    status,
                    &body,
                ))
                .map_err(Into::into)
        }
        _ => request
            .respond(text_response(StatusCode(404), "not found"))
            .map_err(Into::into),
    }
}

// ---------- responses ----------

fn health_payload(state: &BridgeState) -> Value {
    let policy = state.policy.read().ok().and_then(|g| g.clone());
    serde_json::json!({
        "ok": true,
        "agent_id": state.agent_id,
        "policy_version_hash": policy.as_ref().map(|p| p.policy_version_hash.clone()),
        "has_policy": policy.is_some(),
    })
}

fn policy_payload(state: &BridgeState) -> Value {
    match state.policy.read().ok().and_then(|g| g.clone()) {
        Some(policy) => serde_json::to_value(policy)
            .unwrap_or_else(|_| serde_json::json!({"error": "policy serialization failed"})),
        None => serde_json::json!({"error": "policy not available"}),
    }
}

fn respond(
    request: Request,
    allowed_origins: &[String],
    origin: Option<&str>,
    status: StatusCode,
    body: &Value,
) -> Result<()> {
    request
        .respond(json_response(allowed_origins, origin, status, body))
        .map_err(Into::into)
}

fn json_response(
    allowed_origins: &[String],
    origin: Option<&str>,
    status: StatusCode,
    body: &Value,
) -> Response<std::io::Cursor<Vec<u8>>> {
    let bytes = serde_json::to_vec(body).unwrap_or_else(|_| b"{}".to_vec());
    let mut resp = Response::from_data(bytes).with_status_code(status);
    resp.add_header(Header::from_bytes(&b"content-type"[..], &b"application/json"[..]).unwrap());
    apply_cors(&mut resp, allowed_origins, origin);
    resp
}

fn text_response(status: StatusCode, body: &str) -> Response<std::io::Cursor<Vec<u8>>> {
    let mut resp = Response::from_string(body.to_string()).with_status_code(status);
    resp.add_header(Header::from_bytes(&b"content-type"[..], &b"text/plain; charset=utf-8"[..]).unwrap());
    resp
}

fn cors_preflight(
    allowed_origins: &[String],
    origin: Option<&str>,
) -> Response<std::io::Cursor<Vec<u8>>> {
    let mut resp = Response::from_string(String::new()).with_status_code(StatusCode(204));
    apply_cors(&mut resp, allowed_origins, origin);
    resp
}

fn apply_cors(
    resp: &mut Response<std::io::Cursor<Vec<u8>>>,
    allowed_origins: &[String],
    origin: Option<&str>,
) {
    if let Some(o) = origin.and_then(|o| pick_allowed_origin(o, allowed_origins)) {
        resp.add_header(Header::from_bytes(&b"access-control-allow-origin"[..], o.as_bytes()).unwrap());
        resp.add_header(
            Header::from_bytes(&b"vary"[..], &b"Origin"[..]).unwrap(),
        );
        resp.add_header(
            Header::from_bytes(&b"access-control-allow-methods"[..], &b"GET, POST, OPTIONS"[..])
                .unwrap(),
        );
        resp.add_header(
            Header::from_bytes(&b"access-control-allow-headers"[..], &b"content-type"[..]).unwrap(),
        );
        resp.add_header(
            Header::from_bytes(&b"access-control-max-age"[..], &b"600"[..]).unwrap(),
        );
    }
}

/// Decide whether to echo the given origin back as the
/// `Access-Control-Allow-Origin` value. Browser extensions always have
/// `chrome-extension://<id>` / `moz-extension://<id>` origins, and we
/// default to accepting any extension origin when no explicit allow-list
/// is configured.
fn pick_allowed_origin(origin: &str, allowed_origins: &[String]) -> Option<String> {
    if allowed_origins.is_empty() {
        if origin.starts_with("chrome-extension://") || origin.starts_with("moz-extension://") {
            return Some(origin.to_string());
        }
        // Local dev tools sometimes use null origin; reject silently.
        return None;
    }
    if allowed_origins.iter().any(|allowed| allowed == origin) {
        return Some(origin.to_string());
    }
    None
}

// ---------- evidence forwarding ----------

#[derive(Serialize)]
struct ForwardEnvelope<'a> {
    action_type: &'a str,
    decision: &'a str,
    destination: Option<&'a str>,
    label_detected: Option<&'a str>,
    content_hash: String,
    policy_version: String,
    endpoint_id: &'a str,
    event_type: &'a str,
    policy_action_field: &'a str,
    process_name: Option<&'a str>,
}

#[derive(Deserialize)]
struct BrowserEvidence {
    #[serde(default)]
    event_type: Option<String>,
    #[serde(default)]
    destination: Option<String>,
    #[serde(default)]
    label_detected: Option<String>,
    #[serde(default)]
    content_hash: Option<String>,
    #[serde(default)]
    policy_action_field: Option<String>,
    #[serde(default)]
    decision: Option<String>,
    #[serde(default)]
    process_name: Option<String>,
    #[serde(default)]
    action: Option<String>,
}

fn forward_evidence(state: &BridgeState, payload: Value) -> (StatusCode, Value) {
    let parsed: BrowserEvidence = match serde_json::from_value(payload.clone()) {
        Ok(p) => p,
        Err(err) => {
            return (
                StatusCode(400),
                serde_json::json!({"ok": false, "error": format!("invalid evidence: {err}")}),
            );
        }
    };

    let event_type = match parsed.event_type.as_deref().filter(|s| !s.trim().is_empty()) {
        Some(value) => value,
        None => {
            return (
                StatusCode(400),
                serde_json::json!({"ok": false, "error": "event_type is required"}),
            );
        }
    };
    let decision = parsed.decision.as_deref().unwrap_or("review");
    let action_type = parsed
        .action
        .as_deref()
        .map(|s| s.to_string())
        .unwrap_or_else(|| format!("dlp.{}_{}", event_type, decision));
    let policy_version = state
        .policy
        .read()
        .ok()
        .and_then(|g| g.as_ref().map(|p| p.policy_version_hash.clone()))
        .unwrap_or_else(|| "unknown".to_string());

    // Content hash from the browser is already SHA-256; if missing,
    // synthesize a deterministic hash from the JSON body so the backend
    // still gets a non-empty identifier.
    let content_hash = parsed.content_hash.clone().unwrap_or_else(|| {
        let mut hasher = Sha256::new();
        hasher.update(serde_json::to_vec(&payload).unwrap_or_default());
        format!("sha256:{:x}", hasher.finalize())
    });

    let envelope = ForwardEnvelope {
        action_type: &action_type,
        decision,
        destination: parsed.destination.as_deref(),
        label_detected: parsed.label_detected.as_deref(),
        content_hash,
        policy_version,
        endpoint_id: &state.agent_id,
        event_type,
        policy_action_field: parsed
            .policy_action_field
            .as_deref()
            .unwrap_or("paste_sensitive"),
        process_name: parsed.process_name.as_deref(),
    };

    let endpoint = format!(
        "{}/agent/dlp-evidence?endpoint_id={}&token={}",
        state.api_url.trim_end_matches('/'),
        state.agent_id,
        state.agent_secret
    );

    let send_result = state
        .client
        .post(&endpoint)
        .timeout(FORWARD_TIMEOUT)
        .json(&envelope)
        .send();

    match send_result {
        Ok(resp) if resp.status().is_success() => (
            StatusCode(202),
            serde_json::json!({"ok": true, "forwarded": true}),
        ),
        Ok(resp) => {
            // 4xx from the backend means the payload itself is wrong —
            // queueing won't help. Anything else, queue for retry.
            let status = resp.status();
            if status.is_client_error() {
                (
                    StatusCode(status.as_u16()),
                    serde_json::json!({
                        "ok": false,
                        "forwarded": false,
                        "backend_status": status.as_u16(),
                        "queued": false,
                    }),
                )
            } else {
                let _ = enqueue_for_retry(&state.queue_path, &payload);
                (
                    StatusCode(202),
                    serde_json::json!({
                        "ok": true,
                        "forwarded": false,
                        "backend_status": status.as_u16(),
                        "queued": true,
                    }),
                )
            }
        }
        Err(_) => {
            let _ = enqueue_for_retry(&state.queue_path, &payload);
            (
                StatusCode(202),
                serde_json::json!({
                    "ok": true,
                    "forwarded": false,
                    "queued": true,
                }),
            )
        }
    }
}

fn enqueue_for_retry(queue_path: &PathBuf, payload: &Value) -> Result<()> {
    if let Some(parent) = queue_path.parent() {
        std::fs::create_dir_all(parent).ok();
    }
    let line = serde_json::to_string(&serde_json::json!({
        "kind": "browser_evidence",
        "payload": payload,
        "enqueued_at": chrono::Utc::now().to_rfc3339(),
    }))?;
    let mut file = OpenOptions::new()
        .create(true)
        .append(true)
        .open(queue_path)
        .context("opening dlp event queue")?;
    file.write_all(line.as_bytes())?;
    file.write_all(b"\n")?;
    Ok(())
}

// ---------- HTTP helpers ----------

fn header_value(request: &Request, name: &str) -> Option<String> {
    request
        .headers()
        .iter()
        .find(|h| h.field.as_str().as_str().eq_ignore_ascii_case(name))
        .map(|h| h.value.as_str().to_string())
}

fn read_body_capped(request: &mut Request, max: usize) -> Result<Vec<u8>> {
    let mut buf = Vec::new();
    let reader = request.as_reader();
    let mut chunk = [0u8; 4096];
    loop {
        let n = std::io::Read::read(reader, &mut chunk)?;
        if n == 0 {
            break;
        }
        if buf.len() + n > max {
            return Err(anyhow!("request body exceeded {max} bytes"));
        }
        buf.extend_from_slice(&chunk[..n]);
    }
    Ok(buf)
}

fn is_loopback(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => v4.is_loopback(),
        IpAddr::V6(v6) => v6.is_loopback(),
    }
}

// ---------- rate limiting ----------

struct RateLimiter {
    buckets: HashMap<IpAddr, TokenBucket>,
    capacity: f64,
    refill_per_sec: f64,
}

impl Default for RateLimiter {
    fn default() -> Self {
        Self {
            buckets: HashMap::new(),
            capacity: 60.0,
            refill_per_sec: 30.0,
        }
    }
}

impl RateLimiter {
    fn allow(&mut self, ip: IpAddr) -> bool {
        let bucket = self.buckets.entry(ip).or_insert_with(|| TokenBucket {
            tokens: self.capacity,
            last: Instant::now(),
        });
        let now = Instant::now();
        let elapsed = now.duration_since(bucket.last).as_secs_f64();
        bucket.tokens = (bucket.tokens + elapsed * self.refill_per_sec).min(self.capacity);
        bucket.last = now;
        if bucket.tokens >= 1.0 {
            bucket.tokens -= 1.0;
            true
        } else {
            false
        }
    }
}

struct TokenBucket {
    tokens: f64,
    last: Instant,
}

// ---------- tests ----------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::policy::{
        DlpAction, GenaiGuardrailsPolicy, ResolvedPolicy, RuntimePolicy, SemanticActions,
        SemanticDlpPolicy,
    };
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;
    use tempfile::tempdir;

    fn sample_policy() -> RuntimePolicy {
        RuntimePolicy {
            endpoint_id: "agent-test".to_string(),
            policy_version_hash: "hash-test".to_string(),
            evidence_controls: vec!["iso27001-2022:A.5.12".to_string()],
            resolved: ResolvedPolicy {
                semantic_dlp: SemanticDlpPolicy {
                    enabled: true,
                    sensitivity_labels: vec!["public".into(), "restricted".into()],
                    genai_destinations: vec!["claude".into()],
                    actions: SemanticActions {
                        paste_sensitive: DlpAction::Review,
                        upload_restricted: DlpAction::Block,
                        copy_to_genai: DlpAction::Review,
                    },
                    ..Default::default()
                },
                genai_guardrails: GenaiGuardrailsPolicy {
                    enabled: true,
                    destinations: vec!["claude".into()],
                    browser_enforcement: true,
                    endpoint_enforcement: true,
                    actions: SemanticActions {
                        paste_sensitive: DlpAction::Block,
                        upload_restricted: DlpAction::Block,
                        copy_to_genai: DlpAction::Review,
                    },
                },
            },
        }
    }

    /// In-process mock backend that records hits and returns 200.
    fn start_mock_backend() -> (String, Arc<AtomicUsize>) {
        let server = Server::http("127.0.0.1:0").expect("mock backend bind");
        let addr = server.server_addr().to_ip().unwrap();
        let hits = Arc::new(AtomicUsize::new(0));
        let counter = hits.clone();
        thread::spawn(move || {
            for req in server.incoming_requests() {
                counter.fetch_add(1, Ordering::SeqCst);
                let _ = req.respond(Response::from_string("{\"id\":\"evt\"}").with_status_code(StatusCode(200)));
            }
        });
        (format!("http://{addr}"), hits)
    }

    fn start_bridge(policy: Option<RuntimePolicy>, api_url: String, queue: PathBuf) -> SocketAddr {
        let state = Arc::new(BridgeState::new(
            Arc::new(RwLock::new(policy)),
            "agent-test".to_string(),
            "secret-test".to_string(),
            api_url,
            reqwest::blocking::Client::new(),
            queue,
            Vec::new(),
        ));
        spawn(state, 0).expect("bridge spawn")
    }

    #[test]
    fn get_health_returns_ok_even_without_policy() {
        let dir = tempdir().unwrap();
        let addr = start_bridge(None, "http://127.0.0.1:1".to_string(), dir.path().join("q.ndjson"));
        let resp = reqwest::blocking::get(format!("http://{addr}/health")).unwrap();
        assert!(resp.status().is_success());
        let body: Value = resp.json().unwrap();
        assert_eq!(body["ok"], serde_json::json!(true));
        assert_eq!(body["has_policy"], serde_json::json!(false));
    }

    #[test]
    fn get_policy_returns_runtime_policy_json() {
        let dir = tempdir().unwrap();
        let addr = start_bridge(
            Some(sample_policy()),
            "http://127.0.0.1:1".to_string(),
            dir.path().join("q.ndjson"),
        );
        let resp = reqwest::blocking::get(format!("http://{addr}/policy")).unwrap();
        assert!(resp.status().is_success());
        let body: Value = resp.json().unwrap();
        assert_eq!(body["policy_version_hash"], serde_json::json!("hash-test"));
        assert_eq!(body["resolved"]["semantic_dlp"]["enabled"], serde_json::json!(true));
        assert_eq!(
            body["resolved"]["genai_guardrails"]["actions"]["paste_sensitive"],
            serde_json::json!("block")
        );
    }

    #[test]
    fn post_dlp_event_forwards_to_backend() {
        let dir = tempdir().unwrap();
        let (backend_url, hits) = start_mock_backend();
        let addr = start_bridge(
            Some(sample_policy()),
            backend_url,
            dir.path().join("q.ndjson"),
        );

        let evidence = serde_json::json!({
            "action": "dlp.paste_block",
            "event_type": "paste",
            "destination": "claude",
            "label_detected": "restricted",
            "content_hash": "sha256:deadbeef",
            "policy_action_field": "paste_sensitive",
            "decision": "block",
        });

        let client = reqwest::blocking::Client::new();
        let resp = client
            .post(format!("http://{addr}/dlp-event"))
            .json(&evidence)
            .send()
            .unwrap();
        let status = resp.status();
        let body: Value = resp.json().unwrap();
        assert!(status.is_success(), "got status {status} body {body}");
        assert_eq!(body["ok"], serde_json::json!(true));
        assert_eq!(body["forwarded"], serde_json::json!(true));
        assert_eq!(hits.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn post_dlp_event_queues_when_backend_down() {
        let dir = tempdir().unwrap();
        let queue = dir.path().join("q.ndjson");
        // Point at an unrouteable port so the request fails fast.
        let addr = start_bridge(
            Some(sample_policy()),
            "http://127.0.0.1:1".to_string(),
            queue.clone(),
        );
        let client = reqwest::blocking::Client::new();
        let resp = client
            .post(format!("http://{addr}/dlp-event"))
            .json(&serde_json::json!({
                "event_type": "paste",
                "decision": "review",
                "content_hash": "sha256:abc",
            }))
            .send()
            .unwrap();
        assert!(resp.status().is_success());
        let body: Value = resp.json().unwrap();
        assert_eq!(body["queued"], serde_json::json!(true));
        assert!(queue.exists(), "queue file should be created");
        let queued = std::fs::read_to_string(&queue).unwrap();
        assert!(queued.contains("browser_evidence"));
    }

    #[test]
    fn rejects_disallowed_origin_on_http_routes() {
        let dir = tempdir().unwrap();
        let addr = start_bridge(
            Some(sample_policy()),
            "http://127.0.0.1:1".to_string(),
            dir.path().join("q.ndjson"),
        );

        let client = reqwest::blocking::Client::new();
        let resp = client
            .get(format!("http://{addr}/policy"))
            .header("Origin", "https://evil.example.com")
            .send()
            .unwrap();

        assert_eq!(resp.status(), reqwest::StatusCode::FORBIDDEN);
    }

    #[test]
    fn post_dlp_event_rejects_missing_event_type() {
        let dir = tempdir().unwrap();
        let (backend_url, hits) = start_mock_backend();
        let addr = start_bridge(
            Some(sample_policy()),
            backend_url,
            dir.path().join("q.ndjson"),
        );

        let client = reqwest::blocking::Client::new();
        let resp = client
            .post(format!("http://{addr}/dlp-event"))
            .json(&serde_json::json!({
                "decision": "review",
                "content_hash": "sha256:abc",
            }))
            .send()
            .unwrap();

        assert_eq!(resp.status(), reqwest::StatusCode::BAD_REQUEST);
        assert_eq!(hits.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn rejects_non_loopback_origin_in_cors() {
        // Pure unit on the helper — we cannot easily forge a non-loopback
        // peer in tiny_http without raw sockets.
        let allowed: Vec<String> = vec![];
        assert!(pick_allowed_origin("chrome-extension://abc", &allowed).is_some());
        assert!(pick_allowed_origin("https://evil.example.com", &allowed).is_none());
        let allowed = vec!["chrome-extension://known".to_string()];
        assert!(pick_allowed_origin("chrome-extension://known", &allowed).is_some());
        assert!(pick_allowed_origin("chrome-extension://other", &allowed).is_none());
    }

    #[test]
    fn rate_limiter_blocks_after_burst() {
        let mut rl = RateLimiter::default();
        let ip = IpAddr::from([127, 0, 0, 1]);
        let mut allowed = 0;
        for _ in 0..200 {
            if rl.allow(ip) {
                allowed += 1;
            }
        }
        // Burst capacity is 60 with effectively no time passing.
        assert!(allowed >= 50 && allowed <= 65, "got {allowed}");
    }
}

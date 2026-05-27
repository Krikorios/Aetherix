use crate::bridge::BridgeState;
use anyhow::Result;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::io::{self, Read, Write};
use std::sync::Arc;
use std::thread;

const READ_BUF_SIZE: usize = 1_048_576;

#[derive(Serialize, Deserialize)]
struct NativeRequest {
    request_id: u64,
    op: String,
    #[serde(default)]
    payload: Option<Value>,
}

#[derive(Serialize, Deserialize)]
struct NativeResponse {
    request_id: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    payload: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<String>,
}

pub fn spawn(state: Arc<BridgeState>) -> Result<()> {
    thread::Builder::new()
        .name("aetherix-native-bridge".to_string())
        .spawn(move || native_messaging_loop(state))
        .map_err(|e| anyhow::anyhow!("failed to spawn native bridge thread: {e}"))?;
    Ok(())
}

fn native_messaging_loop(state: Arc<BridgeState>) {
    let mut stdin = io::stdin().lock();
    let mut stdout = io::stdout().lock();
    let mut length_buf = [0u8; 4];

    loop {
        match stdin.read_exact(&mut length_buf) {
            Ok(()) => {}
            Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => {
                break;
            }
            Err(e) => {
                eprintln!("aetherix-native-bridge: read length: {e}");
                break;
            }
        }

        let length = u32::from_le_bytes(length_buf) as usize;
        if length == 0 || length > READ_BUF_SIZE {
            let err = NativeResponse {
                request_id: 0,
                payload: None,
                error: Some(format!("message length {length} out of range")),
            };
            let _ = write_message(&mut stdout, &err);
            if length == 0 {
                break;
            }
            continue;
        }

        let mut buf = vec![0u8; length];
        if let Err(e) = stdin.read_exact(&mut buf) {
            eprintln!("aetherix-native-bridge: read body: {e}");
            break;
        }

        let request: NativeRequest = match serde_json::from_slice(&buf) {
            Ok(r) => r,
            Err(e) => {
                let err = NativeResponse {
                    request_id: 0,
                    payload: None,
                    error: Some(format!("invalid json: {e}")),
                };
                let _ = write_message(&mut stdout, &err);
                continue;
            }
        };

        let response = handle_request(&state, &request);
        if let Err(e) = write_message(&mut stdout, &response) {
            eprintln!("aetherix-native-bridge: write response: {e}");
            break;
        }
    }
}

fn handle_request(state: &BridgeState, request: &NativeRequest) -> NativeResponse {
    match request.op.as_str() {
        "ping" => NativeResponse {
            request_id: request.request_id,
            payload: Some(serde_json::json!({"pong": true})),
            error: None,
        },
        "get_policy" => {
            let policy = state.policy.read().ok().and_then(|g| g.clone());
            NativeResponse {
                request_id: request.request_id,
                payload: policy.map(|p| serde_json::to_value(p).unwrap_or_default()),
                error: None,
            }
        }
        "emit_evidence" => {
            let payload = request.payload.clone().unwrap_or_default();
            let body = crate::bridge::forward_evidence_raw(state, payload);
            let has_error = body.get("ok").and_then(|v| v.as_bool()) != Some(true);
            NativeResponse {
                request_id: request.request_id,
                payload: Some(body),
                error: if has_error {
                    Some("forward failed".to_string())
                } else {
                    None
                },
            }
        }
        other => NativeResponse {
            request_id: request.request_id,
            payload: None,
            error: Some(format!("unknown op: {other}")),
        },
    }
}

fn write_message<W: Write>(writer: &mut W, msg: &impl Serialize) -> Result<()> {
    let json = serde_json::to_vec(msg)?;
    let len = json.len() as u32;
    writer.write_all(&len.to_le_bytes())?;
    writer.write_all(&json)?;
    writer.flush()?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bridge::BridgeState;
    use crate::policy::{
        DlpAction, GenaiGuardrailsPolicy, ResolvedPolicy, RuntimePolicy, SemanticActions,
        SemanticDlpPolicy,
    };
    use std::io::Cursor;
    use std::sync::{Arc, RwLock};
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
                ..Default::default()
            },
        }
    }

    fn test_state(queue_path: std::path::PathBuf) -> Arc<BridgeState> {
        Arc::new(BridgeState::new(
            Arc::new(RwLock::new(Some(sample_policy()))),
            "agent-test".to_string(),
            "secret-test".to_string(),
            "http://127.0.0.1:1".to_string(),
            reqwest::blocking::Client::new(),
            queue_path,
            Vec::new(),
        ))
    }

    /// Simulate sending a request over native messaging and reading the response.
    fn roundtrip(state: &Arc<BridgeState>, request: &NativeRequest) -> NativeResponse {
        let mut output = Vec::new();
        let mut input = Vec::new();

        // Serialize the request and write it as a native message
        {
            let json = serde_json::to_vec(request).unwrap();
            let len = json.len() as u32;
            input.extend_from_slice(&len.to_le_bytes());
            input.extend_from_slice(&json);
        }

        // Feed the input through the handler
        let mut reader = Cursor::new(&input);
        let mut writer = Cursor::new(&mut output);
        let mut length_buf = [0u8; 4];
        reader.read_exact(&mut length_buf).unwrap();
        let length = u32::from_le_bytes(length_buf) as usize;
        let mut buf = vec![0u8; length];
        reader.read_exact(&mut buf).unwrap();

        let req: NativeRequest = serde_json::from_slice(&buf).unwrap();
        let resp = handle_request(state, &req);
        write_message(&mut writer, &resp).unwrap();

        // Parse the output as a native message
        let mut out_reader = Cursor::new(&output);
        out_reader.read_exact(&mut length_buf).unwrap();
        let out_len = u32::from_le_bytes(length_buf) as usize;
        let mut out_buf = vec![0u8; out_len];
        out_reader.read_exact(&mut out_buf).unwrap();
        serde_json::from_slice(&out_buf).unwrap()
    }

    #[test]
    fn ping_returns_pong() {
        let dir = tempdir().unwrap();
        let state = test_state(dir.path().join("q.ndjson"));
        let resp = roundtrip(&state, &NativeRequest {
            request_id: 1,
            op: "ping".to_string(),
            payload: None,
        });
        assert_eq!(resp.request_id, 1);
        assert!(resp.error.is_none());
        assert_eq!(resp.payload.unwrap().get("pong").and_then(|v| v.as_bool()), Some(true));
    }

    #[test]
    fn get_policy_returns_policy() {
        let dir = tempdir().unwrap();
        let state = test_state(dir.path().join("q.ndjson"));
        let resp = roundtrip(&state, &NativeRequest {
            request_id: 2,
            op: "get_policy".to_string(),
            payload: None,
        });
        assert_eq!(resp.request_id, 2);
        assert!(resp.error.is_none());
        let payload = resp.payload.unwrap();
        assert_eq!(payload.get("policy_version_hash").and_then(|v| v.as_str()), Some("hash-test"));
    }

    #[test]
    fn unknown_op_returns_error() {
        let dir = tempdir().unwrap();
        let state = test_state(dir.path().join("q.ndjson"));
        let resp = roundtrip(&state, &NativeRequest {
            request_id: 3,
            op: "nonexistent".to_string(),
            payload: None,
        });
        assert_eq!(resp.request_id, 3);
        assert!(resp.error.is_some());
        assert!(resp.error.unwrap().contains("unknown op"));
    }

    #[test]
    fn emit_evidence_forwards_event() {
        let dir = tempdir().unwrap();
        let state = test_state(dir.path().join("q.ndjson"));
        let resp = roundtrip(&state, &NativeRequest {
            request_id: 4,
            op: "emit_evidence".to_string(),
            payload: Some(serde_json::json!({
                "event_type": "paste",
                "decision": "block",
                "destination": "claude",
                "content_hash": "sha256:deadbeef",
            })),
        });
        assert_eq!(resp.request_id, 4);
        // Even though backend is down, we accept and queue
        assert!(resp.error.is_none(), "error: {:?}", resp.error);
        let body = resp.payload.unwrap();
        // Should show queued=true since the mock backend at 127.0.0.1:1 is down
        assert_eq!(body.get("queued").and_then(|v| v.as_bool()), Some(true));
    }

    #[test]
    fn rejects_malformed_json_input() {
        let mut input = Vec::new();
        let len = 10u32;
        input.extend_from_slice(&len.to_le_bytes());
        input.extend_from_slice(b"not-valid-json");

        let mut reader = Cursor::new(&input);
        let mut length_buf = [0u8; 4];
        reader.read_exact(&mut length_buf).unwrap();
        let length = u32::from_le_bytes(length_buf) as usize;
        let mut buf = vec![0u8; length];
        reader.read_exact(&mut buf).unwrap();

        let result: Result<NativeRequest, _> = serde_json::from_slice(&buf);
        assert!(result.is_err());
    }
}

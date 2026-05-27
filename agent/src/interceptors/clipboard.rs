//! Cross-platform clipboard interceptor.
//!
//! Polls the OS clipboard via `arboard`, emits a `DlpEvent` whenever the
//! clipboard content changes, and — when the central policy evaluation
//! returns `DlpAction::Block` — overwrites the clipboard with a
//! redaction marker so the user's next paste cannot leak the original
//! payload. This is the production enforcement primitive that replaces
//! the previous evidence-only flow.
//!
//! Testability: the interceptor is generic over a `ClipboardBackend`
//! trait so integration tests can drive it with an in-memory fake
//! without requiring an X server / display.

use anyhow::{Context, Result};
use arboard::Clipboard;

use crate::dlp::{DlpEvent, DlpEventType, EventSource};

/// Marker written to the clipboard when a `Block` decision fires. The
/// constant is part of the agent's public behavioural contract: the
/// integration test asserts the exact value, and the MSP console
/// surfaces it verbatim in evidence cards.
pub const BLOCKED_PLACEHOLDER: &str =
    "[blocked by Aetherix DLP — restricted content cannot be pasted]";

/// Minimal abstraction over the system clipboard so the interceptor
/// can be unit / integration tested without a real display.
pub trait ClipboardBackend: Send {
    fn get_text(&mut self) -> Result<String>;
    fn set_text(&mut self, value: &str) -> Result<()>;
}

/// Production backend: thin wrapper over `arboard::Clipboard`.
pub struct SystemClipboard {
    inner: Clipboard,
}

impl SystemClipboard {
    pub fn new() -> Result<Self> {
        let inner = Clipboard::new().context("opening system clipboard")?;
        Ok(Self { inner })
    }
}

impl ClipboardBackend for SystemClipboard {
    fn get_text(&mut self) -> Result<String> {
        self.inner.get_text().context("reading clipboard text")
    }

    fn set_text(&mut self, value: &str) -> Result<()> {
        self.inner
            .set_text(value.to_string())
            .context("writing clipboard text")
    }
}

/// Polls a `ClipboardBackend` and emits one `DlpEvent` per genuine
/// change. After a `Block` enforcement the interceptor records the
/// placeholder as the last-seen value so the redaction itself is not
/// re-emitted.
pub struct ClipboardInterceptor<B: ClipboardBackend> {
    backend: B,
    last_seen: Option<String>,
}

impl<B: ClipboardBackend> ClipboardInterceptor<B> {
    pub fn new(backend: B) -> Self {
        Self {
            backend,
            last_seen: None,
        }
    }

    /// Read the current clipboard. Returns `Some(event)` only when the
    /// content is non-empty and differs from the previously emitted
    /// value, which means each paste-attempt produces at most one
    /// event.
    pub fn poll(&mut self) -> Option<DlpEvent> {
        let text = self.backend.get_text().ok()?;
        let trimmed = text.trim();
        if trimmed.is_empty() {
            return None;
        }
        if self.last_seen.as_deref() == Some(trimmed) {
            return None;
        }
        if trimmed == BLOCKED_PLACEHOLDER {
            // We wrote this ourselves on the previous tick; don't
            // re-emit it as a new event.
            self.last_seen = Some(trimmed.to_string());
            return None;
        }
        self.last_seen = Some(trimmed.to_string());
        Some(DlpEvent {
            event_type: DlpEventType::Paste,
            source: EventSource::Endpoint,
            content: trimmed.to_string(),
            destination: None,
            process_name: None,
        })
    }

    /// Actively prevent the paste by overwriting the clipboard.
    /// Returns the placeholder that was written so callers can log it.
    pub fn enforce_block(&mut self) -> Result<&'static str> {
        self.backend.set_text(BLOCKED_PLACEHOLDER)?;
        self.last_seen = Some(BLOCKED_PLACEHOLDER.to_string());
        Ok(BLOCKED_PLACEHOLDER)
    }

    /// Test accessor — used by integration tests to assert the
    /// post-enforcement clipboard state without going through `poll`.
    #[cfg(test)]
    #[allow(dead_code)]
    pub fn backend_mut(&mut self) -> &mut B {
        &mut self.backend
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Arc, Mutex};

    /// Shared in-memory clipboard so tests can both drive the interceptor
    /// and inspect the resulting state.
    #[derive(Clone, Default)]
    pub struct FakeClipboard {
        inner: Arc<Mutex<String>>,
    }

    impl FakeClipboard {
        pub fn with_text(text: &str) -> Self {
            Self {
                inner: Arc::new(Mutex::new(text.to_string())),
            }
        }
        pub fn read(&self) -> String {
            self.inner.lock().unwrap().clone()
        }
    }

    impl ClipboardBackend for FakeClipboard {
        fn get_text(&mut self) -> Result<String> {
            Ok(self.inner.lock().unwrap().clone())
        }
        fn set_text(&mut self, value: &str) -> Result<()> {
            *self.inner.lock().unwrap() = value.to_string();
            Ok(())
        }
    }

    #[test]
    fn poll_emits_event_only_on_change() {
        let backend = FakeClipboard::with_text("hello world");
        let mut interceptor = ClipboardInterceptor::new(backend);

        let first = interceptor.poll().expect("first poll yields event");
        assert_eq!(first.content, "hello world");
        assert!(interceptor.poll().is_none(), "same content must not re-emit");
    }

    #[test]
    fn enforce_block_overwrites_clipboard_with_placeholder() {
        let backend = FakeClipboard::with_text("[restricted] customer ssn 111-22-3333");
        let probe = backend.clone();
        let mut interceptor = ClipboardInterceptor::new(backend);

        let _event = interceptor.poll().expect("event for restricted text");
        interceptor.enforce_block().expect("enforcement succeeds");

        assert_eq!(probe.read(), BLOCKED_PLACEHOLDER);
        assert!(
            interceptor.poll().is_none(),
            "placeholder must not be re-emitted as a new event"
        );
    }
}

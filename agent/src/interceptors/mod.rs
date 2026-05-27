//! Real OS-level interceptors for Aetherix endpoint enforcement.
//!
//! Each interceptor produces `dlp::DlpEvent`s that are evaluated through
//! the central `dlp_client::DlpClient` and, when the resolved decision
//! is `Block`, actively prevents the user action (e.g. overwrites the
//! system clipboard, or returns a block verdict to the browser
//! extension).
//!
//! The browser-side interceptor lives in `crate::bridge` (HTTP loopback
//! on 127.0.0.1) which the MV3 extension calls before allowing a paste
//! or upload — see `POST /evaluate`. This module owns the clipboard
//! interceptor and the `Interceptor` trait shared between them.

pub mod clipboard;
pub mod file_upload;
pub mod usb;

#[allow(unused_imports)]
pub use clipboard::{ClipboardBackend, ClipboardInterceptor, SystemClipboard, BLOCKED_PLACEHOLDER};
#[allow(unused_imports)]
pub use file_upload::{FileUploadInterceptor, UploadCandidate};
#[allow(unused_imports)]
pub use usb::UsbInterceptor;

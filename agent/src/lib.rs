//! Library facade for the Aetherix endpoint agent.
//!
//! The binary entrypoint lives in `main.rs` and re-exports nothing on
//! its own; integration tests under `tests/` consume the agent's
//! internals through this library crate.

pub mod bridge;
pub mod dlp;
pub mod dlp_client;
pub mod edr;
pub mod evidence;
pub mod interceptors;
pub mod inventory;
pub mod fim;
pub mod cis;
pub mod native_bridge;
pub mod policy;

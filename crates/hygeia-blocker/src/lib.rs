//! Browser extension engine.
//!
//! [`Engine`] is plain Rust (unit-tested natively); `wasm.rs` exposes it to
//! JavaScript through wasm-bindgen on `wasm32`. The extension never trusts the
//! network: a bundle is verified against a pinned ed25519 key BEFORE decoding,
//! and a bundle older than the one already installed is refused (rollback
//! protection).

mod engine;
pub use engine::{DnrPlan, DnrRule, Engine, EngineError, url_host};

#[cfg(target_arch = "wasm32")]
mod wasm;

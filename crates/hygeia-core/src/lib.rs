//! Hygeia core: sans-I/O building blocks shared by DNS, proxy and blocker.
//!
//! No async runtime, no filesystem, no network: bytes in, [`Verdict`] out.
//! This keeps the crate compilable to `wasm32` for the browser extension.

pub mod bundle;
pub mod cosmetic;
pub mod cosmetic_list;
pub mod domain;
pub mod list;
pub mod policy;
pub mod tenant;

pub use bundle::{Bundle, Meta, ParsedSource, SignedBundle, SourceMeta};
pub use cosmetic_list::{CosmeticOptions, ParsedCosmetic, parse_cosmetic};
pub use domain::{DomainTrie, normalize};
pub use list::{ListFormat, ParsedList, parse_list};
pub use policy::{Action, ListData, Reason, Ruleset, RulesetData, Verdict};

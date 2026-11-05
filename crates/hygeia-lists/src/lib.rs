//! Catalogue, download and parsing of third-party filter lists.
//!
//! Lists are fetched at runtime and never vendored in this repository. Every
//! source carries its license and attribution, which travel in the signed
//! bundle metadata. **Check each license before enabling a source** and before
//! redistributing derived data to third parties (e.g. GPL-3.0 lists require the
//! license text to accompany redistribution).

pub mod catalog;
pub mod fetch;
pub mod manager;

pub use catalog::{Source, builtin};
pub use fetch::{Fetch, FetchError, Fetched, HttpFetcher, Validators};
pub use manager::{Manager, RefreshResult, SourceStatus};

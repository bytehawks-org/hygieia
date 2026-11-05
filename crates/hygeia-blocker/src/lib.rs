//! Browser extension engine — SKELETON.
//!
//! Compiles to `wasm32` (hygeia-core is I/O free). Planned: wasm-bindgen
//! exports, DNR subset compiler for Chrome MV3 (rules ordered by hit
//! frequency), full engine for Firefox `webRequest`, cosmetic filtering and
//! packaged scriptlets (MV3 forbids remote code: bundles carry only data),
//! enrollment + signed-bundle pull with ETag, per-tenant fail-open/closed.

use hygeia_core::{Ruleset, Verdict};

/// Extract the host from an absolute `http(s)` URL (no userinfo/port/path).
pub fn url_host(url: &str) -> Option<&str> {
    let rest = url
        .strip_prefix("https://")
        .or_else(|| url.strip_prefix("http://"))?;
    let auth = rest.split(['/', '?', '#']).next()?;
    let auth = auth.rsplit_once('@').map_or(auth, |(_, h)| h);
    if let Some(v6) = auth.strip_prefix('[') {
        return v6.split(']').next();
    }
    Some(auth.rsplit_once(':').map_or(auth, |(h, _)| h))
}

pub fn check_url(rs: &Ruleset, url: &str) -> Option<Verdict> {
    Some(rs.evaluate(url_host(url)?))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hosts() {
        assert_eq!(
            url_host("https://u:p@Ads.Example.com:8443/a?b#c"),
            Some("Ads.Example.com")
        );
        assert_eq!(url_host("http://a.test"), Some("a.test"));
        assert_eq!(url_host("ftp://a.test"), None);
    }
}

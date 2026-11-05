//! HTTP(S) proxy data plane — SKELETON.
//!
//! Implemented: host-level decision for `CONNECT host:port` (what a proxy can
//! see without TLS interception). Planned: hyper + rustls listener, PAC
//! endpoint, ruleset feed for the blocker, optional selective MITM behind the
//! `mitm` cargo feature (not compiled by default).

use hygeia_core::{Ruleset, Verdict};

/// Split `host:port` / `[v6]:port` and evaluate the host.
pub fn check_connect(rs: &Ruleset, authority: &str) -> Option<Verdict> {
    let host = if let Some(rest) = authority.strip_prefix('[') {
        rest.split(']').next()?
    } else {
        authority.rsplit_once(':').map_or(authority, |(h, _)| h)
    };
    Some(rs.evaluate(host))
}

#[cfg(test)]
mod tests {
    use super::*;
    use hygeia_core::RulesetData;

    #[test]
    fn connect_authority() {
        let rs = Ruleset::from_data(&RulesetData {
            custom_block: vec!["bad.test".into()],
            ..Default::default()
        });
        assert!(check_connect(&rs, "x.bad.test:443").unwrap().is_block());
        assert!(!check_connect(&rs, "good.test:443").unwrap().is_block());
    }
}

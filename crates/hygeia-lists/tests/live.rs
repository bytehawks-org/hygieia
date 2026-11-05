//! Network test against the real upstream lists (not run by default):
//!   cargo test -p hygeia-lists --test live -- --ignored --nocapture

use std::sync::Arc;

use hygeia_lists::{HttpFetcher, Manager, builtin};

#[tokio::test]
#[ignore = "downloads real lists"]
async fn live_catalog() {
    let f = Arc::new(HttpFetcher::new(64 * 1024 * 1024, false).unwrap());
    let m = Manager::new(builtin(), f, false);
    let r = m.refresh().await;
    for s in &r.status {
        println!(
            "{:<26} ok={:<5} block={:<7} allow={:<5} generic={:<6} hosts={:<6} js={:<5} skipped={:<6} trusted_dropped={} err={:?}",
            s.id,
            s.last_ok.is_some(),
            s.block_domains,
            s.allow_domains,
            s.generic_selectors,
            s.host_rule_sets,
            s.scriptlet_calls,
            s.skipped_lines,
            s.dropped_trusted_scriptlets,
            s.last_error
        );
    }
    assert!(
        r.status.iter().any(|s| s.last_ok.is_some()),
        "no source reachable"
    );
}

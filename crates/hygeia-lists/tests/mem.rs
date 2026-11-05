//! Rough cost of loading a large real list into the matcher:
//!   cargo test -p hygeia-lists --test mem --release -- --ignored --nocapture

use hygeia_core::cosmetic::CosmeticRules;
use hygeia_core::{Bundle, ListData, Meta, Ruleset, RulesetData, SignedBundle};
use hygeia_lists::{HttpFetcher, Manager, builtin};
use std::sync::Arc;

fn rss_mb() -> u64 {
    std::fs::read_to_string("/proc/self/status")
        .ok()
        .and_then(|s| {
            s.lines()
                .find(|l| l.starts_with("VmRSS"))
                .and_then(|l| l.split_whitespace().nth(1)?.parse::<u64>().ok())
        })
        .unwrap_or(0)
        / 1024
}

#[tokio::test]
#[ignore = "downloads real lists"]
async fn hagezi_pro_footprint() {
    let src: Vec<_> = builtin()
        .into_iter()
        .filter(|s| s.id == "hagezi-pro" || s.id == "ublock-filters")
        .collect();
    let m = Manager::new(
        src,
        Arc::new(HttpFetcher::new(64 << 20, false).unwrap()),
        false,
    );
    let r = m.refresh().await;
    let base = rss_mb();
    let data = RulesetData {
        custom_allow: vec![],
        custom_block: vec![],
        lists: r
            .sources
            .iter()
            .map(|s| ListData {
                id: s.meta.id.clone(),
                allow: s.allow.clone(),
                block: s.block.clone(),
            })
            .collect(),
    };
    let t = std::time::Instant::now();
    let rs = Ruleset::from_data(&data);
    println!(
        "trie build: {:?}, RSS +{} MB",
        t.elapsed(),
        rss_mb().saturating_sub(base)
    );
    let t = std::time::Instant::now();
    let mut blocked = 0;
    for i in 0..200_000 {
        if rs
            .evaluate(&format!("sub{i}.example{}.com", i % 50))
            .is_block()
        {
            blocked += 1;
        }
    }
    println!("200k lookups: {:?} (blocked {blocked})", t.elapsed());
    let mut cos = CosmeticRules::default();
    for s in &r.sources {
        cos.merge(s.cosmetic.clone());
    }
    let b = Bundle {
        meta: Meta {
            version: 1,
            tenant_id: "t".into(),
            group_id: "g".into(),
            created_at: 0,
            sources: vec![],
        },
        network: data,
        cosmetic: cos,
    };
    let sb = SignedBundle::sign(&b, &ed25519_dalek::SigningKey::from_bytes(&[1; 32]));
    println!("signed bundle: {} KB", sb.0.len() / 1024);
}

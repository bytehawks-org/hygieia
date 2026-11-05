//! Footprint and speed of the matcher at realistic list sizes. Ignored by default (timings are only
//! meaningful in release); prints a small report:
//!
//!   cargo test -p hygeia-core --release --test scale -- --ignored --nocapture
//!
//! The assertions are deliberately loose (order-of-magnitude regressions only).

use std::time::Instant;

use hygeia_core::cosmetic::CosmeticRules;
use hygeia_core::{Action, Bundle, ListData, Meta, Ruleset, RulesetData, SignedBundle};

fn domains(n: usize) -> Vec<String> {
    // varied shapes: second-level, third-level, long labels, shared suffixes
    (0..n)
        .map(|i| match i % 4 {
            0 => format!("ad{i}.tracker{}.example.com", i % 997),
            1 => format!("cdn-{i}.metrics.example.net"),
            2 => format!("x{i}.example.org"),
            _ => format!("a-rather-long-label-number-{i}.telemetry.example.io"),
        })
        .collect()
}

#[test]
#[ignore = "benchmark-style: run with --release -- --ignored --nocapture"]
fn matcher_and_bundle_at_240k_domains() {
    let n = 240_000;
    let block = domains(n);
    let data = RulesetData {
        custom_allow: vec!["allowed.example.com".into()],
        custom_block: vec!["custom.example.com".into()],
        lists: vec![ListData {
            id: "synthetic".into(),
            allow: vec![],
            block: block.clone(),
        }],
    };

    let t = Instant::now();
    let rs = Ruleset::from_data(&data);
    let build = t.elapsed();

    // correctness at scale
    assert!(rs.evaluate("ad0.tracker0.example.com").is_block());
    assert!(
        rs.evaluate("deep.sub.x2.example.org").is_block(),
        "subdomains of a listed domain"
    );
    assert!(!rs.evaluate("example.com").is_block());
    assert!(!rs.evaluate("allowed.example.com").is_block());
    assert_eq!(rs.evaluate("custom.example.com").action, Action::Block);

    // lookup latency: half hits, half misses
    let probes: Vec<String> = (0..200_000)
        .map(|i| {
            if i % 2 == 0 {
                format!("www.{}", block[i % n])
            } else {
                format!("clean{i}.example.dev")
            }
        })
        .collect();
    let t = Instant::now();
    let mut blocked = 0usize;
    for p in &probes {
        if rs.evaluate(p).is_block() {
            blocked += 1;
        }
    }
    let per = t.elapsed().as_nanos() as f64 / probes.len() as f64;
    assert_eq!(blocked, probes.len() / 2);

    // signed bundle size and sign/verify time
    let key = ed25519_dalek::SigningKey::from_bytes(&[9u8; 32]);
    let bundle = Bundle {
        meta: Meta {
            version: 1,
            tenant_id: "t".into(),
            group_id: "g".into(),
            created_at: 0,
            sources: vec![],
        },
        network: data,
        cosmetic: CosmeticRules::default(),
    };
    let t = Instant::now();
    let signed = SignedBundle::sign(&bundle, &key);
    let sign = t.elapsed();
    let t = Instant::now();
    SignedBundle::open(&signed.0, &key.verifying_key()).expect("verifies");
    let open = t.elapsed();

    println!("---- hygeia-core scale report ({n} domains) ----");
    println!("ruleset build        : {build:?}");
    println!("lookup (hit+miss)    : {per:.0} ns/query");
    println!(
        "signed bundle        : {:.1} MiB",
        signed.0.len() as f64 / (1 << 20) as f64
    );
    println!("sign / verify+decode : {sign:?} / {open:?}");

    assert!(build.as_secs_f64() < 10.0, "build took {build:?}");
    assert!(per < 50_000.0, "lookup took {per} ns");
}

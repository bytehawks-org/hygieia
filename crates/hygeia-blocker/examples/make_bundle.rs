//! Writes a small signed bundle + its public key for extension tests:
//!   cargo run -p hygeia-blocker --example make_bundle -- <out_dir> [version]
use hygeia_core::cosmetic::{CosmeticRules, HostRules, ScriptletCall};
use hygeia_core::{Bundle, ListData, Meta, RulesetData, SignedBundle, SourceMeta};

fn main() {
    let mut args = std::env::args().skip(1);
    let dir = args.next().expect("out dir");
    let version: u64 = args.next().map_or(1, |v| v.parse().expect("version"));
    let key = ed25519_dalek::SigningKey::from_bytes(&[42u8; 32]);

    let mut cosmetic = CosmeticRules {
        generic: vec![".ad-banner".into()],
        ..Default::default()
    };
    cosmetic.by_host.insert(
        "site.test".into(),
        HostRules {
            selectors: vec!["#promo".into()],
            exceptions: vec![],
            scriptlets: vec![ScriptletCall {
                name: "set-constant".into(),
                args: vec!["adsEnabled".into(), "false".into()],
            }],
        },
    );
    let bundle = Bundle {
        meta: Meta {
            version,
            tenant_id: "t".into(),
            group_id: "g".into(),
            created_at: 0,
            sources: vec![SourceMeta {
                id: "fixture".into(),
                name: "fixture".into(),
                url: "https://example.com".into(),
                license: "CC0-1.0".into(),
                attribution: "test".into(),
            }],
        },
        network: RulesetData {
            custom_allow: vec!["ok.ads.test".into()],
            custom_block: vec!["blocked.test".into()],
            lists: vec![ListData {
                id: "l".into(),
                allow: vec![],
                block: vec!["ads.test".into()],
            }],
        },
        cosmetic,
    };
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(
        format!("{dir}/bundle.bin"),
        SignedBundle::sign(&bundle, &key).0,
    )
    .unwrap();
    let hex: String = key
        .verifying_key()
        .to_bytes()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();
    std::fs::write(format!("{dir}/pubkey.hex"), hex).unwrap();
}

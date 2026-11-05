//! Compile rules + lists into a signed bundle.

use hygeia_core::cosmetic::CosmeticRules;
use hygeia_core::{
    Bundle, ListData, ListFormat, Meta, RulesetData, SignedBundle, SourceMeta, normalize,
    parse_list,
};
use hygeia_store::{Rule, RuleAction};

/// A downloaded list plus its provenance (license/attribution travel in the bundle).
#[derive(Debug, Clone)]
pub struct ListInput {
    pub meta: SourceMeta,
    pub format: ListFormat,
    pub text: String,
}

pub fn compile(
    tenant_id: &str,
    group_id: &str,
    version: u64,
    now: i64,
    rules: &[Rule],
    lists: &[ListInput],
    key: &ed25519_dalek::SigningKey,
) -> SignedBundle {
    let mut data = RulesetData::default();
    for r in rules {
        let Some(p) = normalize(&r.pattern) else {
            continue;
        };
        match r.action {
            RuleAction::Allow => data.custom_allow.push(p),
            RuleAction::Block => data.custom_block.push(p),
        }
    }
    for l in lists {
        let p = parse_list(l.format, &l.text);
        data.lists.push(ListData {
            id: l.meta.id.clone(),
            allow: p.allow,
            block: p.block,
        });
    }
    let bundle = Bundle {
        meta: Meta {
            version,
            tenant_id: tenant_id.into(),
            group_id: group_id.into(),
            created_at: now,
            sources: lists.iter().map(|l| l.meta.clone()).collect(),
        },
        network: data,
        cosmetic: CosmeticRules::default(),
    };
    SignedBundle::sign(&bundle, key)
}

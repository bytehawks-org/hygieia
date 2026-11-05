//! Compile rules + lists into a signed bundle.

use std::sync::Arc;

use hygeia_core::cosmetic::CosmeticRules;
use hygeia_core::{Bundle, ListData, Meta, ParsedSource, RulesetData, SignedBundle, normalize};
use hygeia_store::{Rule, RuleAction};

pub fn compile(
    tenant_id: &str,
    group_id: &str,
    version: u64,
    now: i64,
    rules: &[Rule],
    lists: &[Arc<ParsedSource>],
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
    let mut cosmetic = CosmeticRules::default();
    for l in lists {
        data.lists.push(ListData {
            id: l.meta.id.clone(),
            allow: l.allow.clone(),
            block: l.block.clone(),
        });
        cosmetic.merge(l.cosmetic.clone());
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
        cosmetic,
    };
    SignedBundle::sign(&bundle, key)
}

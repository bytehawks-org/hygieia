//! Policy evaluation. Precedence (first match wins):
//! custom allow > custom block > list allow > list block > default.

use serde::{Deserialize, Serialize};

use crate::domain::DomainTrie;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Action {
    Allow,
    Block,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum Reason {
    CustomAllow { rule: String },
    CustomBlock { rule: String },
    ListAllow { list: String, rule: String },
    ListBlock { list: String, rule: String },
    Default,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Verdict {
    pub action: Action,
    pub reason: Reason,
}

impl Verdict {
    pub fn is_block(&self) -> bool {
        self.action == Action::Block
    }
}

/// Serialisable form (what travels inside a bundle).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ListData {
    pub id: String,
    pub allow: Vec<String>,
    pub block: Vec<String>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct RulesetData {
    pub custom_allow: Vec<String>,
    pub custom_block: Vec<String>,
    pub lists: Vec<ListData>,
}

struct ListLayer {
    id: String,
    allow: DomainTrie,
    block: DomainTrie,
}

/// Immutable, query-ready ruleset. Share behind `Arc`/`ArcSwap` in data planes.
pub struct Ruleset {
    custom_allow: DomainTrie,
    custom_block: DomainTrie,
    lists: Vec<ListLayer>,
}

impl Ruleset {
    pub fn from_data(d: &RulesetData) -> Self {
        let t = |v: &Vec<String>| -> DomainTrie { v.iter().map(String::as_str).collect() };
        Self {
            custom_allow: t(&d.custom_allow),
            custom_block: t(&d.custom_block),
            lists: d
                .lists
                .iter()
                .map(|l| ListLayer {
                    id: l.id.clone(),
                    allow: t(&l.allow),
                    block: t(&l.block),
                })
                .collect(),
        }
    }

    pub fn evaluate(&self, host: &str) -> Verdict {
        if let Some(rule) = self.custom_allow.find(host) {
            return Verdict {
                action: Action::Allow,
                reason: Reason::CustomAllow { rule },
            };
        }
        if let Some(rule) = self.custom_block.find(host) {
            return Verdict {
                action: Action::Block,
                reason: Reason::CustomBlock { rule },
            };
        }
        for l in &self.lists {
            if let Some(rule) = l.allow.find(host) {
                return Verdict {
                    action: Action::Allow,
                    reason: Reason::ListAllow {
                        list: l.id.clone(),
                        rule,
                    },
                };
            }
        }
        for l in &self.lists {
            if let Some(rule) = l.block.find(host) {
                return Verdict {
                    action: Action::Block,
                    reason: Reason::ListBlock {
                        list: l.id.clone(),
                        rule,
                    },
                };
            }
        }
        Verdict {
            action: Action::Allow,
            reason: Reason::Default,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rs() -> Ruleset {
        Ruleset::from_data(&RulesetData {
            custom_allow: vec!["safe.ads.example.com".into()],
            custom_block: vec!["blocked.test".into(), "ads.example.com".into()],
            lists: vec![
                ListData {
                    id: "a".into(),
                    allow: vec!["cdn.tracker.test".into()],
                    block: vec!["tracker.test".into()],
                },
                ListData {
                    id: "b".into(),
                    allow: vec![],
                    block: vec!["other.test".into()],
                },
            ],
        })
    }

    #[test]
    fn precedence() {
        let r = rs();
        assert!(matches!(
            r.evaluate("safe.ads.example.com").reason,
            Reason::CustomAllow { .. }
        ));
        assert!(matches!(
            r.evaluate("x.ads.example.com").reason,
            Reason::CustomBlock { .. }
        ));
        assert!(matches!(
            r.evaluate("cdn.tracker.test").reason,
            Reason::ListAllow { .. }
        ));
        let v = r.evaluate("t.tracker.test");
        assert_eq!(
            v.reason,
            Reason::ListBlock {
                list: "a".into(),
                rule: "tracker.test".into()
            }
        );
        assert_eq!(r.evaluate("example.org").reason, Reason::Default);
        assert!(!r.evaluate("example.org").is_block());
    }
}

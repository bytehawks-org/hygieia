//! Cosmetic rules (element hiding + scriptlet calls) consumed by the blocker.
//! MV3 forbids remote code: only *data* (scriptlet name + args) is shipped.

use std::collections::HashMap;

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ScriptletCall {
    pub name: String,
    pub args: Vec<String>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct HostRules {
    pub selectors: Vec<String>,
    /// Generic selectors that must NOT apply on this host.
    pub exceptions: Vec<String>,
    pub scriptlets: Vec<ScriptletCall>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct CosmeticRules {
    pub generic: Vec<String>,
    pub by_host: HashMap<String, HostRules>,
}

/// Effective cosmetic payload for one page.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct PageCosmetics {
    pub selectors: Vec<String>,
    pub scriptlets: Vec<ScriptletCall>,
}

impl CosmeticRules {
    /// Merge generic + host-specific rules, walking up parent domains.
    pub fn for_host(&self, host: &str) -> PageCosmetics {
        let Some(host) = crate::domain::normalize(host) else {
            return PageCosmetics::default();
        };
        let mut exceptions: Vec<&str> = Vec::new();
        let mut selectors: Vec<String> = Vec::new();
        let mut scriptlets = Vec::new();
        let mut cur: &str = &host;
        loop {
            if let Some(h) = self.by_host.get(cur) {
                selectors.extend(h.selectors.iter().cloned());
                scriptlets.extend(h.scriptlets.iter().cloned());
                exceptions.extend(h.exceptions.iter().map(String::as_str));
            }
            match cur.split_once('.') {
                Some((_, rest)) if rest.contains('.') || self.by_host.contains_key(rest) => {
                    cur = rest
                }
                _ => break,
            }
        }
        let mut all: Vec<String> = self
            .generic
            .iter()
            .filter(|s| !exceptions.contains(&s.as_str()))
            .cloned()
            .collect();
        all.extend(selectors);
        PageCosmetics {
            selectors: all,
            scriptlets,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn merge_and_exceptions() {
        let mut c = CosmeticRules {
            generic: vec![".ad".into(), ".banner".into()],
            ..Default::default()
        };
        c.by_host.insert(
            "example.com".into(),
            HostRules {
                selectors: vec!["#promo".into()],
                exceptions: vec![".banner".into()],
                scriptlets: vec![ScriptletCall {
                    name: "set-constant".into(),
                    args: vec!["a".into(), "b".into()],
                }],
            },
        );
        let p = c.for_host("www.example.com");
        assert_eq!(p.selectors, vec![".ad", "#promo"]);
        assert_eq!(p.scriptlets.len(), 1);
        assert_eq!(c.for_host("other.org").selectors, vec![".ad", ".banner"]);
    }
}

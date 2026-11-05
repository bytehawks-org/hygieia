use ed25519_dalek::VerifyingKey;
use hygeia_core::bundle::BundleError;
use hygeia_core::cosmetic::{CosmeticRules, PageCosmetics, ScriptletCall};
use hygeia_core::{DomainTrie, Meta, Ruleset, RulesetData, SignedBundle, Verdict};
use serde::Serialize;

#[derive(Debug, thiserror::Error)]
pub enum EngineError {
    #[error("invalid public key: {0}")]
    BadKey(String),
    #[error(transparent)]
    Bundle(#[from] BundleError),
    #[error("bundle version {got} is older than installed version {have} (rollback refused)")]
    Rollback { got: u64, have: u64 },
}

pub struct Engine {
    ruleset: Ruleset,
    network: RulesetData,
    cosmetic: CosmeticRules,
    meta: Meta,
}

/// One declarativeNetRequest rule group: `action` over many `domains`
/// (`requestDomains` matches the domain and all its subdomains, like the trie).
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct DnrRule {
    pub priority: u32,
    /// `"allow"` or `"block"`
    pub action: &'static str,
    pub domains: Vec<String>,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct DnrPlan {
    pub rules: Vec<DnrRule>,
    /// Domains that did not fit in the budget (lowest priority first dropped).
    pub truncated: usize,
}

const DNR_CHUNK: usize = 1000;

pub fn parse_pubkey(hex: &str) -> Result<VerifyingKey, EngineError> {
    let hex = hex.trim();
    if hex.len() != 64 || !hex.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(EngineError::BadKey("expected 64 hex characters".into()));
    }
    let mut raw = [0u8; 32];
    for (i, c) in hex.as_bytes().chunks(2).enumerate() {
        raw[i] = u8::from_str_radix(std::str::from_utf8(c).unwrap(), 16).unwrap();
    }
    VerifyingKey::from_bytes(&raw).map_err(|e| EngineError::BadKey(e.to_string()))
}

/// Drop domains already covered by a shorter suffix in the same set.
fn minimize(domains: &[String]) -> Vec<String> {
    let trie: DomainTrie = domains.iter().map(String::as_str).collect();
    trie.to_sorted_vec()
        .into_iter()
        .filter(|d| trie.find(d).as_deref() == Some(d.as_str()))
        .collect()
}

impl Engine {
    /// Verify signature, refuse rollbacks, then decode.
    /// `installed_version` is the version currently in use (0 = none).
    pub fn load(
        bytes: &[u8],
        pubkey_hex: &str,
        installed_version: u64,
    ) -> Result<Self, EngineError> {
        let key = parse_pubkey(pubkey_hex)?;
        let b = SignedBundle::open(bytes, &key)?;
        if b.meta.version < installed_version {
            return Err(EngineError::Rollback {
                got: b.meta.version,
                have: installed_version,
            });
        }
        Ok(Self {
            ruleset: Ruleset::from_data(&b.network),
            network: b.network,
            cosmetic: b.cosmetic,
            meta: b.meta,
        })
    }

    pub fn meta(&self) -> &Meta {
        &self.meta
    }

    pub fn check_host(&self, host: &str) -> Verdict {
        self.ruleset.evaluate(host)
    }

    pub fn check_url(&self, url: &str) -> Option<Verdict> {
        Some(self.ruleset.evaluate(url_host(url)?))
    }

    pub fn cosmetics_for(&self, host: &str) -> PageCosmetics {
        self.cosmetic.for_host(host)
    }

    /// Translate the network rules into DNR groups within a domain budget.
    /// Priorities mirror policy precedence: custom allow (4), custom block (3),
    /// list allow (2), list block (1). Higher-precedence groups are kept first
    /// when the domain budget forces truncation.
    pub fn dnr_plan(&self, max_domains: usize) -> DnrPlan {
        let mut layers: Vec<(u32, &'static str, Vec<String>)> = vec![
            (4, "allow", minimize(&self.network.custom_allow)),
            (3, "block", minimize(&self.network.custom_block)),
            (
                2,
                "allow",
                minimize(
                    &self
                        .network
                        .lists
                        .iter()
                        .flat_map(|l| l.allow.iter().cloned())
                        .collect::<Vec<_>>(),
                ),
            ),
            (
                1,
                "block",
                minimize(
                    &self
                        .network
                        .lists
                        .iter()
                        .flat_map(|l| l.block.iter().cloned())
                        .collect::<Vec<_>>(),
                ),
            ),
        ];
        let mut budget = max_domains;
        let mut truncated = 0;
        let mut rules = Vec::new();
        for (priority, action, domains) in layers.drain(..) {
            let take = domains.len().min(budget);
            truncated += domains.len() - take;
            budget -= take;
            for chunk in domains[..take].chunks(DNR_CHUNK) {
                rules.push(DnrRule {
                    priority,
                    action,
                    domains: chunk.to_vec(),
                });
            }
        }
        DnrPlan { rules, truncated }
    }

    pub fn scriptlets_for(&self, host: &str) -> Vec<ScriptletCall> {
        self.cosmetic.for_host(host).scriptlets
    }
}

/// Extract the host from an absolute `http(s)` URL.
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

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::SigningKey;
    use hygeia_core::cosmetic::HostRules;
    use hygeia_core::{Bundle, ListData};

    fn key() -> SigningKey {
        SigningKey::from_bytes(&[9u8; 32])
    }
    fn hex(k: &SigningKey) -> String {
        k.verifying_key()
            .to_bytes()
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect()
    }

    fn bundle(version: u64) -> Vec<u8> {
        let mut cos = CosmeticRules {
            generic: vec![".ad".into()],
            ..Default::default()
        };
        cos.by_host.insert(
            "a.com".into(),
            HostRules {
                selectors: vec!["#promo".into()],
                scriptlets: vec![ScriptletCall {
                    name: "set-constant".into(),
                    args: vec!["x".into(), "1".into()],
                }],
                ..Default::default()
            },
        );
        let b = Bundle {
            meta: Meta {
                version,
                tenant_id: "t".into(),
                group_id: "g".into(),
                created_at: 0,
                sources: vec![],
            },
            network: RulesetData {
                custom_allow: vec!["ok.ads.test".into()],
                custom_block: vec!["evil.test".into()],
                lists: vec![ListData {
                    id: "l".into(),
                    allow: vec![],
                    block: vec![
                        "ads.test".into(),
                        "x.ads.test".into(),
                        "tracker.test".into(),
                    ],
                }],
            },
            cosmetic: cos,
        };
        SignedBundle::sign(&b, &key()).0
    }

    #[test]
    fn load_verifies_signature_pin_and_rollback() {
        let k = hex(&key());
        let e = Engine::load(&bundle(5), &k, 0).unwrap();
        assert_eq!(e.meta().version, 5);
        assert!(
            Engine::load(&bundle(5), &k, 5).is_ok(),
            "same version is fine"
        );
        assert!(matches!(
            Engine::load(&bundle(4), &k, 5),
            Err(EngineError::Rollback { got: 4, have: 5 })
        ));
        let other = hex(&SigningKey::from_bytes(&[1u8; 32]));
        assert!(matches!(
            Engine::load(&bundle(5), &other, 0),
            Err(EngineError::Bundle(_))
        ));
        assert!(matches!(
            Engine::load(&bundle(5), "zz", 0),
            Err(EngineError::BadKey(_))
        ));
        let mut tampered = bundle(5);
        tampered[20] ^= 1;
        assert!(Engine::load(&tampered, &k, 0).is_err());
    }

    #[test]
    fn queries() {
        let e = Engine::load(&bundle(1), &hex(&key()), 0).unwrap();
        assert!(
            e.check_url("https://sub.ads.test/p?q=1")
                .unwrap()
                .is_block()
        );
        assert!(!e.check_url("https://ok.ads.test/").unwrap().is_block());
        assert!(e.check_url("ftp://ads.test").is_none());
        let c = e.cosmetics_for("www.a.com");
        assert_eq!(c.selectors, vec![".ad", "#promo"]);
        assert_eq!(c.scriptlets[0].name, "set-constant");
    }

    #[test]
    fn dnr_plan_priorities_minimize_and_budget() {
        let e = Engine::load(&bundle(1), &hex(&key()), 0).unwrap();
        let p = e.dnr_plan(100);
        assert_eq!(p.truncated, 0);
        let find = |prio| p.rules.iter().find(|r| r.priority == prio).unwrap();
        assert_eq!(find(4).action, "allow");
        assert_eq!(find(3).domains, vec!["evil.test"]);
        // x.ads.test is redundant under ads.test
        assert_eq!(find(1).domains, vec!["ads.test", "tracker.test"]);

        // budget 2: custom allow + custom block kept, list block dropped
        let p = e.dnr_plan(2);
        assert_eq!(p.rules.len(), 2);
        assert_eq!(p.truncated, 2);
    }

    #[test]
    fn dnr_chunks() {
        let domains: Vec<String> = (0..2500).map(|i| format!("d{i}.test")).collect();
        let b = Bundle {
            meta: Meta {
                version: 1,
                tenant_id: "t".into(),
                group_id: "g".into(),
                created_at: 0,
                sources: vec![],
            },
            network: RulesetData {
                lists: vec![ListData {
                    id: "l".into(),
                    allow: vec![],
                    block: domains,
                }],
                ..Default::default()
            },
            cosmetic: CosmeticRules::default(),
        };
        let bytes = SignedBundle::sign(&b, &key()).0;
        let e = Engine::load(&bytes, &hex(&key()), 0).unwrap();
        let p = e.dnr_plan(100_000);
        assert_eq!(p.rules.len(), 3);
        assert!(p.rules.iter().all(|r| r.domains.len() <= 1000));
    }
}

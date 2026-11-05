use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

use hygeia_core::cosmetic::CosmeticRules;
use hygeia_core::{CosmeticOptions, ParsedSource, parse_cosmetic, parse_list};
use serde::Serialize;
use sha2::{Digest, Sha256};
use tokio::sync::Semaphore;

use crate::catalog::Source;
use crate::fetch::{Fetch, Validators};

/// A refreshed list is rejected when it shrinks below this fraction of the
/// previous rule count (guards against truncated, broken or poisoned downloads).
const MIN_RETAINED: f64 = 0.5;
const SHRINK_GUARD_MIN_RULES: usize = 100;

#[derive(Debug, Clone, Default, Serialize)]
pub struct SourceStatus {
    pub id: String,
    pub name: String,
    pub url: String,
    pub license: String,
    pub attribution: String,
    pub last_ok: Option<i64>,
    pub last_error: Option<String>,
    pub block_domains: usize,
    pub allow_domains: usize,
    pub generic_selectors: usize,
    pub host_rule_sets: usize,
    pub scriptlet_calls: usize,
    /// Lines not representable by this engine (procedural selectors, options...).
    pub skipped_lines: usize,
    pub dropped_trusted_scriptlets: usize,
    pub sha256: Option<String>,
}

#[derive(Clone)]
struct Cached {
    validators: Validators,
    parsed: Arc<ParsedSource>,
    status: SourceStatus,
}

pub struct RefreshResult {
    pub sources: Vec<Arc<ParsedSource>>,
    pub status: Vec<SourceStatus>,
    /// True if any source content changed (a new bundle is needed).
    pub changed: bool,
}

pub struct Manager {
    sources: Vec<Source>,
    fetcher: Arc<dyn Fetch>,
    cache: Mutex<HashMap<String, Cached>>,
    concurrency: usize,
}

fn now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs() as i64)
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

fn parse_source(src: &Source, text: &str) -> (ParsedSource, SourceStatus) {
    let mut st = SourceStatus {
        id: src.id.clone(),
        name: src.name.clone(),
        url: src.url.clone(),
        license: src.license.clone(),
        attribution: src.attribution.clone(),
        sha256: Some(hex(&Sha256::digest(text.as_bytes()))),
        ..Default::default()
    };
    let (mut allow, mut block) = (Vec::new(), Vec::new());
    if src.network {
        let p = parse_list(src.format, text);
        st.skipped_lines += p.skipped;
        allow = p.allow;
        block = p.block;
    }
    let mut cosmetic = CosmeticRules::default();
    if src.cosmetic {
        let c = parse_cosmetic(
            text,
            CosmeticOptions {
                allow_trusted_scriptlets: src.allow_trusted_scriptlets,
            },
        );
        st.skipped_lines += c.skipped;
        st.dropped_trusted_scriptlets = c.dropped_trusted;
        cosmetic = c.rules;
    }
    st.block_domains = block.len();
    st.allow_domains = allow.len();
    st.generic_selectors = cosmetic.generic.len();
    st.host_rule_sets = cosmetic.by_host.len();
    st.scriptlet_calls = cosmetic.by_host.values().map(|h| h.scriptlets.len()).sum();
    (
        ParsedSource {
            meta: src.meta(),
            allow,
            block,
            cosmetic,
        },
        st,
    )
}

fn rule_count(s: &SourceStatus) -> usize {
    s.block_domains + s.allow_domains + s.generic_selectors + s.host_rule_sets + s.scriptlet_calls
}

impl Manager {
    /// Invalid sources (missing license, non-https...) are dropped with an error log.
    pub fn new(sources: Vec<Source>, fetcher: Arc<dyn Fetch>, allow_http: bool) -> Self {
        let sources = sources
            .into_iter()
            .filter(|s| match s.validate(allow_http) {
                Ok(()) => true,
                Err(e) => {
                    tracing::error!("{e}");
                    false
                }
            })
            .collect();
        Self {
            sources,
            fetcher,
            cache: Mutex::new(HashMap::new()),
            concurrency: 4,
        }
    }

    pub fn sources(&self) -> &[Source] {
        &self.sources
    }

    /// Fetch every source (bounded concurrency), conditional GET, atomic per source:
    /// on any failure the previous good copy stays in use.
    pub async fn refresh(&self) -> RefreshResult {
        let sem = Arc::new(Semaphore::new(self.concurrency));
        let mut tasks = tokio::task::JoinSet::new();
        for src in self.sources.iter().cloned() {
            let prev = self.cache.lock().unwrap().get(&src.id).cloned();
            let (fetcher, sem) = (self.fetcher.clone(), sem.clone());
            tasks.spawn(async move {
                let _permit = sem.acquire_owned().await.expect("semaphore open");
                let validators = prev
                    .as_ref()
                    .map(|p| p.validators.clone())
                    .unwrap_or_default();
                let outcome = match fetcher.get(&src.url, &validators).await {
                    Err(e) => Err(e.to_string()),
                    Ok(f) if f.body.is_none() => Ok((None, f.validators)),
                    Ok(f) => {
                        let body = f.body.unwrap();
                        let s2 = src.clone();
                        let parsed = tokio::task::spawn_blocking(move || parse_source(&s2, &body))
                            .await
                            .map_err(|e| e.to_string());
                        parsed.map(|p| (Some(p), f.validators))
                    }
                };
                (src, prev, outcome)
            });
        }

        let mut changed = false;
        let mut results: HashMap<String, Cached> = HashMap::new();
        while let Some(joined) = tasks.join_next().await {
            let Ok((src, prev, outcome)) = joined else {
                continue;
            };
            let keep_prev = |err: String, prev: Option<Cached>| -> Option<Cached> {
                tracing::warn!(source = %src.id, error = %err, "list refresh failed; keeping previous copy");
                prev.map(|mut p| {
                    p.status.last_error = Some(err.clone());
                    p
                })
                .or_else(|| {
                    Some(Cached {
                        validators: Validators::default(),
                        parsed: Arc::new(ParsedSource {
                            meta: src.meta(),
                            allow: vec![],
                            block: vec![],
                            cosmetic: CosmeticRules::default(),
                        }),
                        status: SourceStatus {
                            id: src.id.clone(),
                            name: src.name.clone(),
                            url: src.url.clone(),
                            license: src.license.clone(),
                            attribution: src.attribution.clone(),
                            last_error: Some(err),
                            ..Default::default()
                        },
                    })
                })
            };
            let entry = match outcome {
                Err(e) => keep_prev(e, prev),
                Ok((None, validators)) => prev.map(|mut p| {
                    p.validators = validators;
                    p.status.last_ok = Some(now());
                    p.status.last_error = None;
                    p
                }),
                Ok((Some((parsed, mut status)), validators)) => {
                    let new_n = rule_count(&status);
                    let old_n = prev.as_ref().map_or(0, |p| rule_count(&p.status));
                    if new_n == 0 {
                        keep_prev("downloaded list contains no usable rules".into(), prev)
                    } else if old_n >= SHRINK_GUARD_MIN_RULES
                        && (new_n as f64) < old_n as f64 * MIN_RETAINED
                    {
                        keep_prev(
                            format!("rule count dropped from {old_n} to {new_n}; rejected"),
                            prev,
                        )
                    } else {
                        changed |= prev
                            .as_ref()
                            .is_none_or(|p| p.status.sha256 != status.sha256);
                        status.last_ok = Some(now());
                        Some(Cached {
                            validators,
                            parsed: Arc::new(parsed),
                            status,
                        })
                    }
                }
            };
            if let Some(e) = entry {
                results.insert(src.id.clone(), e);
            }
        }

        let mut cache = self.cache.lock().unwrap();
        for (k, v) in results {
            cache.insert(k, v);
        }
        // Stable catalogue order = precedence order in the bundle.
        let mut sources = Vec::new();
        let mut status = Vec::new();
        for s in &self.sources {
            if let Some(c) = cache.get(&s.id) {
                sources.push(c.parsed.clone());
                status.push(c.status.clone());
            }
        }
        RefreshResult {
            sources,
            status,
            changed,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::catalog::builtin;
    use crate::fetch::{FetchError, Fetched};
    use async_trait::async_trait;
    use hygeia_core::ListFormat;

    #[derive(Default)]
    struct Fake {
        // url -> queue of responses
        q: Mutex<HashMap<String, Vec<Result<Fetched, FetchError>>>>,
    }
    impl Fake {
        fn push(&self, url: &str, r: Result<Fetched, FetchError>) {
            // replaces the canned response for `url`
            self.q.lock().unwrap().insert(url.into(), vec![r]);
        }
    }
    #[async_trait]
    impl Fetch for Fake {
        async fn get(&self, url: &str, _v: &Validators) -> Result<Fetched, FetchError> {
            let mut q = self.q.lock().unwrap();
            let v = q.get_mut(url).expect("unexpected url");
            v[0].clone()
        }
    }
    fn ok(body: &str) -> Result<Fetched, FetchError> {
        Ok(Fetched {
            body: Some(body.into()),
            validators: Validators {
                etag: Some("e".into()),
                last_modified: None,
            },
        })
    }

    fn two_sources() -> Vec<Source> {
        let mut dns = builtin()
            .into_iter()
            .find(|s| s.id == "stevenblack")
            .unwrap();
        dns.url = "https://t/dns".into();
        dns.format = ListFormat::Hosts;
        let mut cos = builtin()
            .into_iter()
            .find(|s| s.id == "ublock-filters")
            .unwrap();
        cos.url = "https://t/cos".into();
        vec![dns, cos]
    }

    #[tokio::test]
    async fn parses_both_kinds_and_reports_status() {
        let f = Arc::new(Fake::default());
        f.push("https://t/dns", ok("0.0.0.0 ads.test\n0.0.0.0 t.test\n"));
        f.push(
            "https://t/cos",
            ok("##.ad\na.com##+js(set-constant, x, 1)\na.com##.b:has-text(x)\n||net.test^\n"),
        );
        let m = Manager::new(two_sources(), f, false);
        let r = m.refresh().await;
        assert!(r.changed);
        assert_eq!(r.sources[0].block, vec!["ads.test", "t.test"]);
        assert_eq!(r.sources[1].cosmetic.generic, vec![".ad"]);
        assert!(
            r.sources[1].block.is_empty(),
            "cosmetic-only source must not feed DNS"
        );
        let st = &r.status[1];
        assert_eq!(
            (st.generic_selectors, st.scriptlet_calls, st.skipped_lines),
            (1, 1, 1)
        );
        assert_eq!(st.license, "GPL-3.0");
    }

    #[tokio::test]
    async fn not_modified_error_and_shrink_guard_keep_previous() {
        let f = Arc::new(Fake::default());
        let big: String = (0..300).map(|i| format!("0.0.0.0 h{i}.test\n")).collect();
        f.push("https://t/dns", ok(&big));
        f.push("https://t/cos", ok("##.ad\n"));
        let m = Manager::new(two_sources(), f.clone(), false);
        m.refresh().await;

        // 304 -> unchanged
        f.push(
            "https://t/dns",
            Ok(Fetched {
                body: None,
                validators: Validators::default(),
            }),
        );
        let r = m.refresh().await;
        assert!(!r.changed);
        assert_eq!(r.sources[0].block.len(), 300);

        // transport error -> stale copy kept, error surfaced
        f.push("https://t/dns", Err(FetchError::Status(500)));
        let r = m.refresh().await;
        assert_eq!(r.sources[0].block.len(), 300);
        assert!(r.status[0].last_error.as_deref().unwrap().contains("500"));

        // truncated download (300 -> 10) rejected
        f.push(
            "https://t/dns",
            ok(&big.lines().take(10).collect::<Vec<_>>().join("\n")),
        );
        let r = m.refresh().await;
        assert_eq!(r.sources[0].block.len(), 300);
        assert!(
            r.status[0]
                .last_error
                .as_deref()
                .unwrap()
                .contains("rejected")
        );

        // empty / garbage download rejected
        f.push("https://t/dns", ok("<html>captive portal</html>"));
        let r = m.refresh().await;
        assert_eq!(r.sources[0].block.len(), 300);
    }

    #[tokio::test]
    async fn first_fetch_failure_yields_empty_source_with_error() {
        let f = Arc::new(Fake::default());
        f.push("https://t/dns", Err(FetchError::Status(404)));
        f.push("https://t/cos", ok("##.ad\n"));
        let m = Manager::new(two_sources(), f, false);
        let r = m.refresh().await;
        assert!(r.sources[0].block.is_empty());
        assert!(r.status[0].last_error.is_some());
        assert_eq!(r.sources[1].cosmetic.generic.len(), 1);
    }
}

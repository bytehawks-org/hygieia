//! List refresh for several server replicas.
//!
//! One replica at a time holds the `list-refresh` lease and is the only one that downloads. It
//! publishes each parsed source (content-addressed) and the status report to the shared store; the
//! others load them from there. Every replica therefore compiles from byte-identical list data, so
//! equal inputs give equal bundle hashes and the replicas serve one bundle.
//!
//! The lease is short (renewed every tick); a dead leader is replaced within `LEASE_TTL`.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

use hygeia_api::{AppState, now};
use hygeia_core::ParsedSource;
use hygeia_lists::Manager;
use sha2::{Digest, Sha256};

pub const LEASE_NAME: &str = "list-refresh";
pub const LEASE_TTL: i64 = 180;
const TICK: Duration = Duration::from_secs(60);
const LIST_PREFIX: &str = "list:";
const STATUS_KEY: &str = "list-status";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Role {
    Leader,
    Follower,
}

pub struct ListCoordinator {
    state: Arc<AppState>,
    manager: Manager,
    holder: String,
    interval: Duration,
    last_refresh: Option<Instant>,
    /// key -> hash of what this replica holds
    known: HashMap<String, String>,
    parsed: HashMap<String, Arc<ParsedSource>>,
    installed: bool,
}

fn sha_hex(b: &[u8]) -> String {
    Sha256::digest(b)
        .iter()
        .map(|x| format!("{x:02x}"))
        .collect()
}

impl ListCoordinator {
    pub fn new(state: Arc<AppState>, manager: Manager, interval: Duration) -> Self {
        Self {
            state,
            manager,
            holder: format!("replica-{}", crate::rand_hex(6)),
            interval,
            last_refresh: None,
            known: HashMap::new(),
            parsed: HashMap::new(),
            installed: false,
        }
    }

    /// One scheduling step. `force` asks a leader to download now.
    pub async fn tick(&mut self, force: bool) -> Role {
        let lead = match self
            .state
            .store
            .try_lease(LEASE_NAME, &self.holder, LEASE_TTL, now())
            .await
        {
            Ok(l) => l,
            Err(e) => {
                tracing::warn!(error = %e, "list lease unavailable; acting as follower");
                false
            }
        };
        if lead {
            let due = self
                .last_refresh
                .is_none_or(|t| t.elapsed() >= self.interval);
            if due || force || !self.installed {
                self.refresh_and_publish().await;
            }
            Role::Leader
        } else {
            self.sync_from_shared().await;
            Role::Follower
        }
    }

    async fn refresh_and_publish(&mut self) {
        let r = self.manager.refresh().await;
        self.last_refresh = Some(Instant::now());
        let status = serde_json::to_value(&r.status).unwrap_or_default();
        let store = &self.state.store;
        for s in &r.sources {
            let key = format!("{LIST_PREFIX}{}", s.meta.id);
            let bytes = s.to_bytes();
            let hash = sha_hex(&bytes);
            if self.known.get(&key) != Some(&hash) {
                match store.put_shared(&key, &hash, &bytes).await {
                    Ok(()) => {
                        self.known.insert(key, hash);
                    }
                    Err(e) => tracing::error!(error = %e, "could not publish a parsed list"),
                }
            }
            self.parsed.insert(s.meta.id.clone(), s.clone());
        }
        let sbytes = status.to_string().into_bytes();
        let shash = sha_hex(&sbytes);
        if self.known.get(STATUS_KEY) != Some(&shash)
            && store.put_shared(STATUS_KEY, &shash, &sbytes).await.is_ok()
        {
            self.known.insert(STATUS_KEY.into(), shash);
        }
        if r.changed || !self.installed {
            match self.state.set_lists(r.sources, status).await {
                Ok(()) => {
                    self.installed = true;
                    tracing::info!(sources = r.status.len(), "lists updated (leader)");
                }
                Err(e) => tracing::error!(error = %e, "could not install refreshed lists"),
            }
        } else {
            self.state.set_list_status(status);
        }
    }

    async fn sync_from_shared(&mut self) {
        let store = self.state.store.clone();
        let index = match store.shared_index("").await {
            Ok(i) => i,
            Err(e) => {
                tracing::warn!(error = %e, "could not read shared lists");
                return;
            }
        };
        let mut lists_changed = false;
        for (key, hash) in &index {
            if key == STATUS_KEY || !key.starts_with(LIST_PREFIX) {
                continue;
            }
            if self.known.get(key) == Some(hash) {
                continue;
            }
            let Ok(Some((h, bytes))) = store.get_shared(key).await else {
                continue;
            };
            if sha_hex(&bytes) != h {
                tracing::error!(%key, "shared list failed its integrity check; ignored");
                continue;
            }
            match ParsedSource::from_bytes(&bytes) {
                Ok(p) => {
                    self.parsed
                        .insert(key[LIST_PREFIX.len()..].to_string(), Arc::new(p));
                    self.known.insert(key.clone(), h);
                    lists_changed = true;
                }
                Err(e) => tracing::error!(%key, error = %e, "shared list undecodable; ignored"),
            }
        }
        let status = match index.iter().find(|(k, _)| k == STATUS_KEY) {
            Some((_, h)) if self.known.get(STATUS_KEY) != Some(h) => {
                match store.get_shared(STATUS_KEY).await {
                    Ok(Some((h2, b))) if sha_hex(&b) == h2 => {
                        self.known.insert(STATUS_KEY.into(), h2);
                        serde_json::from_slice(&b).ok()
                    }
                    _ => None,
                }
            }
            _ => None,
        };
        if lists_changed || (!self.installed && !self.parsed.is_empty()) {
            // configuration order = precedence order
            let ordered: Vec<Arc<ParsedSource>> = self
                .manager
                .sources()
                .iter()
                .filter_map(|s| self.parsed.get(&s.id).cloned())
                .collect();
            let st = status.clone().unwrap_or_else(|| self.state.list_status());
            match self.state.set_lists(ordered, st).await {
                Ok(()) => {
                    self.installed = true;
                    tracing::info!("lists updated (from the shared store)");
                }
                Err(e) => tracing::error!(error = %e, "could not install shared lists"),
            }
        } else if let Some(st) = status {
            self.state.set_list_status(st);
        }
    }
}

/// Run the coordinator forever: refresh requests (`POST /v1/admin/lists/refresh`) make a leader
/// download immediately; on a follower they are a no-op (the leader's next tick is picked up).
pub fn spawn(state: Arc<AppState>, manager: Manager, interval: Duration) {
    tokio::spawn(async move {
        let notify = state.refresh_requested.clone();
        let mut c = ListCoordinator::new(state, manager, interval);
        let mut force = false;
        loop {
            c.tick(force).await;
            force = false;
            tokio::select! {
                _ = tokio::time::sleep(TICK) => {}
                _ = notify.notified() => { tracing::info!("list refresh requested"); force = true; }
            }
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;
    use async_trait::async_trait;
    use hygeia_api::AuthConfig;
    use hygeia_lists::{Fetch, FetchError, Fetched, Validators, builtin};
    use hygeia_store::{MemoryStore, Store};
    use std::sync::Mutex;

    struct Fake(Mutex<String>, bool);
    #[async_trait]
    impl Fetch for Fake {
        async fn get(&self, _url: &str, _v: &Validators) -> Result<Fetched, FetchError> {
            assert!(self.1, "a follower must never download");
            Ok(Fetched {
                body: Some(self.0.lock().unwrap().clone()),
                validators: Validators::default(),
            })
        }
    }

    fn manager(fake: Arc<Fake>) -> Manager {
        let mut s = builtin()
            .into_iter()
            .find(|s| s.id == "stevenblack")
            .unwrap();
        s.url = "https://t/dns".into();
        s.format = hygeia_core::ListFormat::Hosts;
        Manager::new(vec![s], fake, false)
    }

    fn hosts(n: usize) -> String {
        (0..n)
            .map(|i| format!("0.0.0.0 ad{i}.example.com\n"))
            .collect()
    }

    #[tokio::test]
    async fn one_replica_downloads_the_others_load_and_all_serve_the_same_bundle() {
        let store: Arc<dyn Store> = Arc::new(MemoryStore::new());
        store.bootstrap_default().await.unwrap();
        let key = ed25519_dalek::SigningKey::from_bytes(&[3u8; 32]);
        let mk = || {
            Arc::new(
                AppState::new(store.clone(), key.clone(), AuthConfig::default())
                    .with_cache_ttl(Duration::ZERO),
            )
        };
        let (sa, sb) = (mk(), mk());
        let fa = Arc::new(Fake(Mutex::new(hosts(150)), true));
        let fb = Arc::new(Fake(Mutex::new(String::new()), false));
        let mut a =
            ListCoordinator::new(sa.clone(), manager(fa.clone()), Duration::from_secs(3600));
        let mut b = ListCoordinator::new(sb.clone(), manager(fb), Duration::from_secs(3600));

        assert_eq!(a.tick(false).await, Role::Leader);
        assert_eq!(b.tick(false).await, Role::Follower, "lease is exclusive");
        assert_eq!(
            sb.available_sources().len(),
            1,
            "follower loaded the list from the store"
        );
        let (t, g) = (hygeia_api::DEFAULT_TENANT, hygeia_api::DEFAULT_GROUP);
        let b1 = sa.bundle_for(t, g).await.unwrap();
        let b2 = sb.bundle_for(t, g).await.unwrap();
        assert_eq!(b1.0, b2.0);

        // upstream changes: leader downloads and publishes, follower converges, still one bundle
        *fa.0.lock().unwrap() = hosts(200);
        a.tick(true).await;
        b.tick(false).await;
        let c1 = sa.bundle_for(t, g).await.unwrap();
        let c2 = sb.bundle_for(t, g).await.unwrap();
        assert_eq!(c1.0, c2.0);
        assert_ne!(c1.0, b1.0);
        assert!(sb.list_status().to_string().contains("stevenblack"));

        // an unchanged tick publishes nothing new and keeps the same bundle
        a.tick(true).await;
        b.tick(false).await;
        assert_eq!(sb.bundle_for(t, g).await.unwrap().0, c1.0);
    }

    #[tokio::test]
    async fn follower_takes_over_when_the_lease_lapses() {
        let store: Arc<dyn Store> = Arc::new(MemoryStore::new());
        let t0 = 1_000;
        assert!(
            store
                .try_lease(LEASE_NAME, "dead", LEASE_TTL, t0)
                .await
                .unwrap()
        );
        assert!(
            !store
                .try_lease(LEASE_NAME, "live", LEASE_TTL, t0 + 10)
                .await
                .unwrap()
        );
        assert!(
            store
                .try_lease(LEASE_NAME, "live", LEASE_TTL, t0 + LEASE_TTL + 1)
                .await
                .unwrap()
        );
    }
}

use std::collections::HashMap;
use std::sync::{Arc, Mutex, RwLock};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use ed25519_dalek::SigningKey;
use hygeia_audit::Draft;
use hygeia_core::SignedBundle;
use hygeia_store::{CatalogSource, Result as StoreResult, Rule, Selection, Store, StoredBundle};
use serde_json::Value;
use sha2::{Digest, Sha256};

use hygeia_core::ParsedSource;

use crate::auth::AuthConfig;
use crate::build::compile;

pub use hygeia_store::{DEFAULT_GROUP_ID as DEFAULT_GROUP, DEFAULT_TENANT_ID as DEFAULT_TENANT};

pub fn now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs() as i64)
}

pub struct AppState {
    pub store: Arc<dyn Store>,
    pub signing_key: SigningKey,
    pub auth: AuthConfig,
    /// Non-secret settings the UI needs before login (`GET /v1/config`).
    pub public: crate::routes::PublicConfig,
    lists: RwLock<Vec<Arc<ParsedSource>>>,
    list_status: RwLock<Value>,
    /// Notified by `POST /v1/admin/lists/refresh`; the list refresher awaits it.
    pub refresh_requested: Arc<tokio::sync::Notify>,
    /// Content fingerprint per loaded list id (part of a bundle's input hash).
    fingerprints: RwLock<HashMap<String, String>>,
    /// Short-lived per-process cache in front of the shared store (see [`CACHE_TTL`]).
    cache: Mutex<BundleCache>,
    cache_ttl: Duration,
}

type BundleCache = HashMap<(String, String), (Arc<SignedBundle>, Instant)>;

/// How long a replica serves a bundle without asking the store whether another replica published a
/// newer one (rule change, list refresh). Local changes invalidate immediately.
pub const CACHE_TTL: Duration = Duration::from_secs(5);

fn feed(h: &mut Sha256, s: &str) {
    h.update((s.len() as u64).to_be_bytes());
    h.update(s.as_bytes());
}

fn fingerprint(l: &ParsedSource) -> String {
    let mut h = Sha256::new();
    feed(&mut h, &l.meta.id);
    for v in [&l.allow, &l.block, &l.cosmetic.generic] {
        h.update((v.len() as u64).to_be_bytes());
        v.iter().for_each(|x| feed(&mut h, x));
    }
    let mut hosts: Vec<_> = l.cosmetic.by_host.iter().collect();
    hosts.sort_by(|a, b| a.0.cmp(b.0));
    for (host, r) in hosts {
        feed(&mut h, host);
        for v in [&r.selectors, &r.exceptions] {
            h.update((v.len() as u64).to_be_bytes());
            v.iter().for_each(|x| feed(&mut h, x));
        }
        for c in &r.scriptlets {
            feed(&mut h, &c.name);
            c.args.iter().for_each(|x| feed(&mut h, x));
        }
    }
    h.finalize().iter().map(|b| format!("{b:02x}")).collect()
}

impl AppState {
    pub fn new(store: Arc<dyn Store>, signing_key: SigningKey, auth: AuthConfig) -> Self {
        Self {
            store,
            signing_key,
            auth,
            public: Default::default(),
            lists: RwLock::new(Vec::new()),
            list_status: RwLock::new(Value::Array(vec![])),
            refresh_requested: Arc::new(tokio::sync::Notify::new()),
            fingerprints: RwLock::new(HashMap::new()),
            cache: Mutex::new(HashMap::new()),
            cache_ttl: CACHE_TTL,
        }
    }

    /// Override the cross-replica freshness window (tests).
    pub fn with_cache_ttl(mut self, ttl: Duration) -> Self {
        self.cache_ttl = ttl;
        self
    }

    /// Install freshly parsed sources and their status report; mirrors the catalogue into the
    /// store (so tenants can subscribe) and invalidates cached bundles.
    pub async fn set_lists(&self, lists: Vec<Arc<ParsedSource>>, status: Value) -> StoreResult<()> {
        let catalog: Vec<CatalogSource> = lists
            .iter()
            .map(|l| CatalogSource {
                id: l.meta.id.clone(),
                name: l.meta.name.clone(),
                url: l.meta.url.clone(),
                license: l.meta.license.clone(),
                attribution: l.meta.attribution.clone(),
            })
            .collect();
        self.store.sync_catalog(&catalog).await?;
        *self.fingerprints.write().unwrap() = lists
            .iter()
            .map(|l| (l.meta.id.clone(), fingerprint(l)))
            .collect();
        *self.lists.write().unwrap() = lists;
        *self.list_status.write().unwrap() = status;
        self.invalidate();
        Ok(())
    }

    /// Sources currently loaded (platform-enabled), in precedence order.
    pub fn available_sources(&self) -> Vec<hygeia_core::SourceMeta> {
        self.lists
            .read()
            .unwrap()
            .iter()
            .map(|l| l.meta.clone())
            .collect()
    }

    /// Update only the status report (content unchanged: bundles stay valid).
    pub fn set_list_status(&self, status: Value) {
        *self.list_status.write().unwrap() = status;
    }

    pub fn list_status(&self) -> Value {
        self.list_status.read().unwrap().clone()
    }

    /// Drop cached bundles; next pull recompiles with a new version.
    pub fn invalidate(&self) {
        self.cache.lock().unwrap().clear();
    }

    pub async fn bundle_for(&self, tenant: &str, group: &str) -> StoreResult<Arc<SignedBundle>> {
        let key = (tenant.to_string(), group.to_string());
        if let Some((b, at)) = self.cache.lock().unwrap().get(&key)
            && at.elapsed() < self.cache_ttl
        {
            return Ok(b.clone());
        }
        let rules = self.store.rules_for(tenant, group).await?;
        let selection = self.store.selection(tenant, group).await?;
        let lists: Vec<Arc<ParsedSource>> = self
            .lists
            .read()
            .unwrap()
            .iter()
            .filter(|l| match &selection {
                Selection::All => true,
                Selection::Only(ids) => ids.contains(&l.meta.id),
            })
            .cloned()
            .collect();

        // Everything that determines the bundle content, including the signing key: equal inputs
        // give equal hashes on every replica, so they converge on one stored bundle.
        let mut h = Sha256::new();
        feed(&mut h, tenant);
        feed(&mut h, group);
        h.update(self.signing_key.verifying_key().as_bytes());
        let mut rs: Vec<&Rule> = rules.iter().collect();
        rs.sort_by(|a, b| a.id.cmp(&b.id));
        for r in rs {
            feed(&mut h, &r.id);
            feed(&mut h, &format!("{:?}", r.action));
            feed(&mut h, &r.pattern);
        }
        {
            let fp = self.fingerprints.read().unwrap();
            for l in &lists {
                feed(&mut h, fp.get(&l.meta.id).map_or("", String::as_str));
            }
        }
        let inputs_hash: String = h.finalize().iter().map(|b| format!("{b:02x}")).collect();

        let stored = self.store.load_compiled(tenant, group).await?;
        let (bytes, fresh) = match stored {
            Some(s) if s.inputs_hash == inputs_hash => (s.bytes, None),
            _ => {
                let version = self.store.next_bundle_version(tenant, group).await?;
                let signed = compile(
                    tenant,
                    group,
                    version,
                    now(),
                    &rules,
                    &lists,
                    &self.signing_key,
                );
                let won = self
                    .store
                    .store_compiled(
                        tenant,
                        group,
                        StoredBundle {
                            inputs_hash,
                            version,
                            bytes: signed.0,
                        },
                    )
                    .await?;
                let mine = won.version == version;
                (won.bytes, mine.then_some(version))
            }
        };
        let b = Arc::new(SignedBundle(bytes));
        self.cache
            .lock()
            .unwrap()
            .insert(key, (b.clone(), Instant::now()));
        if let Some(version) = fresh {
            self.record(
                tenant,
                "system",
                "bundle.compile",
                &format!("{group}@v{version}"),
                None,
            )
            .await;
        }
        Ok(b)
    }

    /// Audit failures are logged loudly but do not abort the operation here;
    /// a deployment that requires fail-closed auditing should change this.
    pub async fn record(
        &self,
        tenant: &str,
        actor: &str,
        action: &str,
        target: &str,
        diff: Option<Value>,
    ) {
        let draft = Draft {
            ts: now(),
            tenant_id: tenant.into(),
            actor: actor.into(),
            action: action.into(),
            target: target.into(),
            diff,
        };
        if let Err(e) = self.store.append_audit(draft).await {
            tracing::error!(error = %e, action, "audit append failed");
        }
    }
}

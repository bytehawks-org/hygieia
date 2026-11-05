use std::collections::HashMap;
use std::sync::{Arc, Mutex, RwLock};
use std::time::{SystemTime, UNIX_EPOCH};

use ed25519_dalek::SigningKey;
use hygeia_audit::Draft;
use hygeia_core::SignedBundle;
use hygeia_store::{CatalogSource, Result as StoreResult, Selection, Store};
use serde_json::Value;

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
    cache: Mutex<HashMap<(String, String), Arc<SignedBundle>>>,
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
            cache: Mutex::new(HashMap::new()),
        }
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
        if let Some(b) = self.cache.lock().unwrap().get(&key) {
            return Ok(b.clone());
        }
        let version = self.store.next_bundle_version(tenant, group).await?;
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
        let b = Arc::new(compile(
            tenant,
            group,
            version,
            now(),
            &rules,
            &lists,
            &self.signing_key,
        ));
        self.cache.lock().unwrap().insert(key, b.clone());
        self.record(
            tenant,
            "system",
            "bundle.compile",
            &format!("{group}@v{version}"),
            None,
        )
        .await;
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

use std::collections::HashMap;
use std::sync::{Arc, Mutex, RwLock};
use std::time::{SystemTime, UNIX_EPOCH};

use ed25519_dalek::SigningKey;
use hygeia_audit::Draft;
use hygeia_core::SignedBundle;
use hygeia_store::{Result as StoreResult, Store};
use serde_json::Value;

use hygeia_core::ParsedSource;

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
    pub admin_token_hash: [u8; 32],
    lists: RwLock<Vec<Arc<ParsedSource>>>,
    list_status: RwLock<Value>,
    /// Notified by `POST /v1/admin/lists/refresh`; the list refresher awaits it.
    pub refresh_requested: Arc<tokio::sync::Notify>,
    cache: Mutex<HashMap<(String, String), Arc<SignedBundle>>>,
}

impl AppState {
    pub fn new(store: Arc<dyn Store>, signing_key: SigningKey, admin_token: &str) -> Self {
        Self {
            store,
            signing_key,
            admin_token_hash: hygeia_store::hash_secret(admin_token),
            lists: RwLock::new(Vec::new()),
            list_status: RwLock::new(Value::Array(vec![])),
            refresh_requested: Arc::new(tokio::sync::Notify::new()),
            cache: Mutex::new(HashMap::new()),
        }
    }

    /// Install freshly parsed sources and their status report; invalidates bundles.
    pub fn set_lists(&self, lists: Vec<Arc<ParsedSource>>, status: Value) {
        *self.lists.write().unwrap() = lists;
        *self.list_status.write().unwrap() = status;
        self.invalidate();
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
        let lists = self.lists.read().unwrap().clone();
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

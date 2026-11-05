use std::collections::HashMap;
use std::sync::{Arc, Mutex, RwLock};
use std::time::{SystemTime, UNIX_EPOCH};

use ed25519_dalek::SigningKey;
use hygeia_audit::{AuditLog, Draft};
use hygeia_core::SignedBundle;
use hygeia_store::MemoryStore;
use serde_json::Value;

use crate::build::{ListInput, compile};

pub const DEFAULT_TENANT: &str = "default";
pub const DEFAULT_GROUP: &str = "default";

pub fn now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs() as i64)
}

pub struct AppState {
    pub store: MemoryStore,
    pub audit: Mutex<AuditLog>,
    pub signing_key: SigningKey,
    pub admin_token_hash: [u8; 32],
    lists: RwLock<Vec<ListInput>>,
    cache: Mutex<HashMap<(String, String), Arc<SignedBundle>>>,
}

impl AppState {
    pub fn new(signing_key: SigningKey, admin_token: &str) -> Self {
        Self {
            store: MemoryStore::new(),
            audit: Mutex::new(AuditLog::new()),
            signing_key,
            admin_token_hash: hygeia_store::hash_secret(admin_token),
            lists: RwLock::new(Vec::new()),
            cache: Mutex::new(HashMap::new()),
        }
    }

    pub fn set_lists(&self, lists: Vec<ListInput>) {
        *self.lists.write().unwrap() = lists;
        self.invalidate();
    }

    /// Drop cached bundles; next pull recompiles with a new version.
    pub fn invalidate(&self) {
        self.cache.lock().unwrap().clear();
    }

    pub fn bundle_for(&self, tenant: &str, group: &str) -> Arc<SignedBundle> {
        let key = (tenant.to_string(), group.to_string());
        let mut cache = self.cache.lock().unwrap();
        if let Some(b) = cache.get(&key) {
            return b.clone();
        }
        let version = self.store.next_bundle_version(tenant, group);
        let rules = self.store.rules_for(tenant, group);
        let lists = self.lists.read().unwrap();
        let b = Arc::new(compile(
            tenant,
            group,
            version,
            now(),
            &rules,
            &lists,
            &self.signing_key,
        ));
        cache.insert(key, b.clone());
        drop(cache);
        self.record(
            tenant,
            "system",
            "bundle.compile",
            &format!("{group}@v{version}"),
            None,
        );
        b
    }

    pub fn record(
        &self,
        tenant: &str,
        actor: &str,
        action: &str,
        target: &str,
        diff: Option<Value>,
    ) {
        self.audit.lock().unwrap().append(Draft {
            ts: now(),
            tenant_id: tenant.into(),
            actor: actor.into(),
            action: action.into(),
            target: target.into(),
            diff,
        });
    }
}

//! File-backed store for single-machine (standalone node) deployments.
//!
//! [`FileStore`] wraps [`MemoryStore`] and persists an atomic JSON snapshot after every durable
//! mutation. It is meant for one machine and a small amount of data; the multi-tenant server uses
//! PostgreSQL.
//!
//! * Written atomically (temp file, fsync, rename) with the previous snapshot kept as `<file>.bak`;
//!   created with mode 0600 on Unix (it holds credential hashes and the audit log).
//! * Loading verifies every audit hash chain: a tampered or corrupted file is refused, never
//!   silently replaced by an empty store.
//! * `last_seen` refreshes (device pulls) are deliberately not persisted.

use std::collections::HashMap;
use std::io::Write;
use std::path::{Path, PathBuf};

use async_trait::async_trait;
use hygeia_audit::{AuditLog, Draft, Event};
use serde::{Deserialize, Serialize};

use crate::{
    ApiToken, AuditStatus, Binding, CatalogSource, Device, EnrollmentToken, Group, ListPolicy,
    MemoryStore, Result, Rule, Selection, Store, StoreError, Subscription, Tenant, User, rbac,
};

const FORMAT: u32 = 1;

mod hex32 {
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S: Serializer>(v: &[u8; 32], s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&v.iter().map(|b| format!("{b:02x}")).collect::<String>())
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<[u8; 32], D::Error> {
        let s = String::deserialize(d)?;
        if s.len() != 64 || !s.is_ascii() {
            return Err(serde::de::Error::custom("expected 64 hex characters"));
        }
        let mut out = [0u8; 32];
        for (i, c) in s.as_bytes().chunks(2).enumerate() {
            out[i] = u8::from_str_radix(std::str::from_utf8(c).unwrap(), 16)
                .map_err(serde::de::Error::custom)?;
        }
        Ok(out)
    }
}

#[derive(Serialize, Deserialize)]
struct Secret<T> {
    #[serde(flatten)]
    item: T,
    #[serde(with = "hex32")]
    secret_hash: [u8; 32],
}

#[derive(Serialize, Deserialize)]
struct Versioned {
    tenant_id: String,
    group_id: String,
    version: u64,
}

#[derive(Serialize, Deserialize)]
struct Snapshot {
    format: u32,
    tokens: Vec<Secret<EnrollmentToken>>,
    devices: Vec<Secret<Device>>,
    rules: Vec<Rule>,
    bundle_versions: Vec<Versioned>,
    audit: Vec<(String, Vec<Event>)>,
    tenants: Vec<Tenant>,
    groups: Vec<Group>,
    users: Vec<User>,
    bindings: Vec<Binding>,
    api_tokens: Vec<Secret<ApiToken>>,
    /// Added after format 1 shipped: absent in older files.
    #[serde(default)]
    dns_tokens: Vec<Secret<crate::DnsToken>>,
    #[serde(default)]
    dns_settings: Vec<(String, crate::DnsSettings)>,
    policies: Vec<(String, ListPolicy)>,
    subs: Vec<(String, Subscription)>,
}

impl MemoryStore {
    fn snapshot(&self) -> Snapshot {
        let s = self.s.lock().unwrap();
        Snapshot {
            format: FORMAT,
            tokens: s
                .tokens
                .values()
                .map(|t| Secret {
                    item: t.clone(),
                    secret_hash: t.secret_hash,
                })
                .collect(),
            devices: s
                .devices
                .values()
                .map(|d| Secret {
                    item: d.clone(),
                    secret_hash: d.secret_hash,
                })
                .collect(),
            rules: s.rules.clone(),
            bundle_versions: s
                .bundle_version
                .iter()
                .map(|((t, g), v)| Versioned {
                    tenant_id: t.clone(),
                    group_id: g.clone(),
                    version: *v,
                })
                .collect(),
            audit: s
                .audit
                .iter()
                .map(|(t, l)| (t.clone(), l.events().to_vec()))
                .collect(),
            tenants: s.tenants.clone(),
            groups: s.groups.clone(),
            users: s.users.clone(),
            bindings: s.bindings.clone(),
            api_tokens: s
                .api_tokens
                .iter()
                .map(|(t, h)| Secret {
                    item: t.clone(),
                    secret_hash: *h,
                })
                .collect(),
            dns_tokens: s
                .dns_tokens
                .iter()
                .map(|(t, h)| Secret {
                    item: t.clone(),
                    secret_hash: *h,
                })
                .collect(),
            dns_settings: s
                .dns_settings
                .iter()
                .map(|(k, v)| (k.clone(), v.clone()))
                .collect(),
            policies: s.policies.iter().map(|(k, v)| (k.clone(), *v)).collect(),
            subs: s.subs.clone(),
        }
    }

    fn from_snapshot(snap: Snapshot) -> Result<Self> {
        if snap.format != FORMAT {
            return Err(StoreError::Backend(format!(
                "unsupported state file format {}",
                snap.format
            )));
        }
        let store = MemoryStore::new();
        {
            let mut s = store.s.lock().unwrap();
            s.tokens = snap
                .tokens
                .into_iter()
                .map(|x| {
                    let mut t = x.item;
                    t.secret_hash = x.secret_hash;
                    (t.id.clone(), t)
                })
                .collect();
            s.devices = snap
                .devices
                .into_iter()
                .map(|x| {
                    let mut d = x.item;
                    d.secret_hash = x.secret_hash;
                    (d.id.clone(), d)
                })
                .collect();
            s.rules = snap.rules;
            s.bundle_version = snap
                .bundle_versions
                .into_iter()
                .map(|v| ((v.tenant_id, v.group_id), v.version))
                .collect::<HashMap<_, _>>();
            for (tenant, events) in snap.audit {
                let log = AuditLog::from_events(events).map_err(|e| {
                    StoreError::Backend(format!(
                        "audit chain of tenant {tenant} does not verify: {e}"
                    ))
                })?;
                s.audit.insert(tenant, log);
            }
            s.tenants = snap.tenants;
            s.groups = snap.groups;
            s.users = snap.users;
            s.bindings = snap.bindings;
            s.api_tokens = snap
                .api_tokens
                .into_iter()
                .map(|x| (x.item, x.secret_hash))
                .collect();
            s.dns_tokens = snap
                .dns_tokens
                .into_iter()
                .map(|x| (x.item, x.secret_hash))
                .collect();
            s.dns_settings = snap.dns_settings.into_iter().collect();
            s.policies = snap.policies.into_iter().collect();
            s.subs = snap.subs;
        }
        Ok(store)
    }
}

pub struct FileStore {
    inner: MemoryStore,
    path: PathBuf,
}

fn backend<E: std::fmt::Display>(what: &str, e: E) -> StoreError {
    StoreError::Backend(format!("{what}: {e}"))
}

fn bak(path: &Path) -> PathBuf {
    let mut s = path.as_os_str().to_owned();
    s.push(".bak");
    PathBuf::from(s)
}

fn tmp(path: &Path) -> PathBuf {
    let mut s = path.as_os_str().to_owned();
    s.push(".tmp");
    PathBuf::from(s)
}

fn write_atomic(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    let tmp = tmp(path);
    let mut opts = std::fs::OpenOptions::new();
    opts.write(true).create(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    let mut f = opts.open(&tmp)?;
    f.write_all(bytes)?;
    f.sync_all()?;
    drop(f);
    if path.exists() {
        // keep the previous snapshot as a recovery point
        let _ = std::fs::remove_file(bak(path));
        std::fs::rename(path, bak(path))?;
    }
    std::fs::rename(&tmp, path)
}

impl FileStore {
    /// Open (or create) the store at `path`. A damaged file is an error: nothing is overwritten.
    pub fn open(path: impl Into<PathBuf>) -> Result<Self> {
        let path = path.into();
        let source = if path.exists() {
            Some(path.clone())
        } else if bak(&path).exists() {
            tracing::warn!(file = %bak(&path).display(), "state file missing; recovering from the backup");
            Some(bak(&path))
        } else {
            None
        };
        let inner = match source {
            Some(p) => {
                let raw = std::fs::read(&p)
                    .map_err(|e| backend(&format!("reading {}", p.display()), e))?;
                let snap: Snapshot = serde_json::from_slice(&raw)
                    .map_err(|e| backend(&format!("{} is not a valid state file (refusing to start; restore the .bak or remove it deliberately)", p.display()), e))?;
                MemoryStore::from_snapshot(snap)?
            }
            None => MemoryStore::new(),
        };
        Ok(Self { inner, path })
    }

    /// Persist now.
    pub fn flush(&self) -> Result<()> {
        let bytes = serde_json::to_vec(&self.inner.snapshot())
            .map_err(|e| backend("serialising state", e))?;
        write_atomic(&self.path, &bytes)
            .map_err(|e| backend(&format!("writing {}", self.path.display()), e))
    }

    fn save(&self) {
        if let Err(e) = self.flush() {
            // The in-memory state stays authoritative; surface loudly so the operator can react.
            tracing::error!(error = %e, "could not persist state");
        }
    }
}

#[async_trait]
impl Store for FileStore {
    async fn bootstrap_default(&self) -> Result<()> {
        let r = self.inner.bootstrap_default().await;
        if r.is_ok() {
            self.save();
        }
        r
    }

    async fn create_enrollment_token(
        &self,
        tenant_id: &str,
        group_id: &str,
        ttl_secs: i64,
        max_uses: Option<u32>,
        now: i64,
    ) -> Result<(EnrollmentToken, String)> {
        let r = self
            .inner
            .create_enrollment_token(tenant_id, group_id, ttl_secs, max_uses, now)
            .await;
        if r.is_ok() {
            self.save();
        }
        r
    }

    async fn revoke_enrollment_token(&self, tenant_id: &str, id: &str) -> Result<()> {
        let r = self.inner.revoke_enrollment_token(tenant_id, id).await;
        if r.is_ok() {
            self.save();
        }
        r
    }

    async fn enroll(&self, secret: &str, info: &str, now: i64) -> Result<(Device, String)> {
        let r = self.inner.enroll(secret, info, now).await;
        if r.is_ok() {
            self.save();
        }
        r
    }

    async fn authenticate_device(&self, secret: &str, now: i64) -> Result<Option<Device>> {
        self.inner.authenticate_device(secret, now).await
    }

    async fn revoke_device(&self, tenant_id: &str, id: &str) -> Result<()> {
        let r = self.inner.revoke_device(tenant_id, id).await;
        if r.is_ok() {
            self.save();
        }
        r
    }

    async fn list_devices(&self, tenant_id: &str) -> Result<Vec<Device>> {
        self.inner.list_devices(tenant_id).await
    }

    async fn add_rule(&self, rule: Rule) -> Result<Rule> {
        let r = self.inner.add_rule(rule).await;
        if r.is_ok() {
            self.save();
        }
        r
    }

    async fn delete_rule(&self, tenant_id: &str, id: &str) -> Result<Rule> {
        let r = self.inner.delete_rule(tenant_id, id).await;
        if r.is_ok() {
            self.save();
        }
        r
    }

    async fn rules_for(&self, tenant_id: &str, group_id: &str) -> Result<Vec<Rule>> {
        self.inner.rules_for(tenant_id, group_id).await
    }

    async fn list_rules(&self, tenant_id: &str) -> Result<Vec<Rule>> {
        self.inner.list_rules(tenant_id).await
    }

    // Compiled bundles are a cache: not persisted, rebuilt after a restart.
    async fn load_compiled(&self, t: &str, g: &str) -> Result<Option<crate::StoredBundle>> {
        self.inner.load_compiled(t, g).await
    }

    async fn store_compiled(
        &self,
        t: &str,
        g: &str,
        c: crate::StoredBundle,
    ) -> Result<crate::StoredBundle> {
        self.inner.store_compiled(t, g, c).await
    }

    async fn create_dns_token(
        &self,
        t: &str,
        g: &str,
        n: &str,
        e: Option<i64>,
    ) -> Result<(crate::DnsToken, String)> {
        let r = self.inner.create_dns_token(t, g, n, e).await;
        if r.is_ok() {
            self.save();
        }
        r
    }

    async fn authenticate_dns_token(&self, s: &str, now: i64) -> Result<Option<crate::DnsToken>> {
        self.inner.authenticate_dns_token(s, now).await
    }

    async fn revoke_dns_token(&self, t: &str, id: &str) -> Result<()> {
        let r = self.inner.revoke_dns_token(t, id).await;
        if r.is_ok() {
            self.save();
        }
        r
    }

    async fn list_dns_tokens(&self, t: &str) -> Result<Vec<crate::DnsToken>> {
        self.inner.list_dns_tokens(t).await
    }

    async fn dns_settings(&self, t: &str) -> Result<crate::DnsSettings> {
        self.inner.dns_settings(t).await
    }

    async fn set_dns_settings(&self, t: &str, st: crate::DnsSettings) -> Result<()> {
        let r = self.inner.set_dns_settings(t, st).await;
        if r.is_ok() {
            self.save();
        }
        r
    }

    // The query log is high-volume and not persisted by the file store (the standalone node has no
    // cloud DNS); entries live in memory until restart.
    async fn append_query_log(&self, t: &str, e: &[crate::QueryLogEntry]) -> Result<()> {
        self.inner.append_query_log(t, e).await
    }

    async fn query_log(
        &self,
        t: &str,
        since: i64,
        limit: u32,
        q: Option<&str>,
        a: Option<&str>,
    ) -> Result<Vec<crate::QueryLogEntry>> {
        self.inner.query_log(t, since, limit, q, a).await
    }

    async fn purge_query_log(&self, t: &str, before: i64) -> Result<u64> {
        self.inner.purge_query_log(t, before).await
    }

    // Coordination state is ephemeral: not persisted.
    async fn try_lease(&self, n: &str, h: &str, ttl: i64, now: i64) -> Result<bool> {
        self.inner.try_lease(n, h, ttl, now).await
    }

    async fn put_shared(&self, key: &str, hash: &str, bytes: &[u8]) -> Result<()> {
        self.inner.put_shared(key, hash, bytes).await
    }

    async fn shared_index(&self, prefix: &str) -> Result<Vec<(String, String)>> {
        self.inner.shared_index(prefix).await
    }

    async fn get_shared(&self, key: &str) -> Result<Option<(String, Vec<u8>)>> {
        self.inner.get_shared(key).await
    }

    async fn ping(&self) -> Result<()> {
        Ok(())
    }

    async fn next_bundle_version(&self, tenant_id: &str, group_id: &str) -> Result<u64> {
        let r = self.inner.next_bundle_version(tenant_id, group_id).await;
        if r.is_ok() {
            self.save();
        }
        r
    }

    async fn sync_catalog(&self, sources: &[CatalogSource]) -> Result<()> {
        self.inner.sync_catalog(sources).await
    }

    async fn list_policy(&self, tenant_id: &str) -> Result<ListPolicy> {
        self.inner.list_policy(tenant_id).await
    }

    async fn set_list_policy(&self, tenant_id: &str, policy: ListPolicy) -> Result<()> {
        let r = self.inner.set_list_policy(tenant_id, policy).await;
        if r.is_ok() {
            self.save();
        }
        r
    }

    async fn subscriptions(&self, tenant_id: &str) -> Result<Vec<Subscription>> {
        self.inner.subscriptions(tenant_id).await
    }

    async fn subscribe(
        &self,
        tenant_id: &str,
        group_id: Option<&str>,
        source_id: &str,
    ) -> Result<()> {
        let r = self.inner.subscribe(tenant_id, group_id, source_id).await;
        if r.is_ok() {
            self.save();
        }
        r
    }

    async fn unsubscribe(
        &self,
        tenant_id: &str,
        group_id: Option<&str>,
        source_id: &str,
    ) -> Result<()> {
        let r = self.inner.unsubscribe(tenant_id, group_id, source_id).await;
        if r.is_ok() {
            self.save();
        }
        r
    }

    async fn selection(&self, tenant_id: &str, group_id: &str) -> Result<Selection> {
        self.inner.selection(tenant_id, group_id).await
    }

    async fn create_tenant(&self, slug: &str, name: &str) -> Result<Tenant> {
        let r = self.inner.create_tenant(slug, name).await;
        if r.is_ok() {
            self.save();
        }
        r
    }

    async fn list_tenants(&self) -> Result<Vec<Tenant>> {
        self.inner.list_tenants().await
    }

    async fn create_group(&self, tenant_id: &str, name: &str) -> Result<Group> {
        let r = self.inner.create_group(tenant_id, name).await;
        if r.is_ok() {
            self.save();
        }
        r
    }

    async fn list_groups(&self, tenant_id: &str) -> Result<Vec<Group>> {
        self.inner.list_groups(tenant_id).await
    }

    async fn upsert_user(&self, issuer: &str, subject: &str, email: Option<&str>) -> Result<User> {
        let r = self.inner.upsert_user(issuer, subject, email).await;
        if r.is_ok() {
            self.save();
        }
        r
    }

    async fn list_users(&self) -> Result<Vec<User>> {
        self.inner.list_users().await
    }

    async fn bindings_for_user(&self, user_id: &str) -> Result<Vec<Binding>> {
        self.inner.bindings_for_user(user_id).await
    }

    async fn list_bindings(&self, tenant_id: Option<&str>) -> Result<Vec<Binding>> {
        self.inner.list_bindings(tenant_id).await
    }

    async fn bind_role(
        &self,
        user_id: &str,
        tenant_id: Option<&str>,
        role: rbac::Role,
    ) -> Result<Binding> {
        let r = self.inner.bind_role(user_id, tenant_id, role).await;
        if r.is_ok() {
            self.save();
        }
        r
    }

    async fn unbind_role(&self, binding_id: &str) -> Result<()> {
        let r = self.inner.unbind_role(binding_id).await;
        if r.is_ok() {
            self.save();
        }
        r
    }

    async fn create_api_token(
        &self,
        tenant_id: &str,
        name: &str,
        role: rbac::Role,
        expires_at: Option<i64>,
    ) -> Result<(ApiToken, String)> {
        let r = self
            .inner
            .create_api_token(tenant_id, name, role, expires_at)
            .await;
        if r.is_ok() {
            self.save();
        }
        r
    }

    async fn authenticate_api_token(&self, secret: &str, now: i64) -> Result<Option<ApiToken>> {
        self.inner.authenticate_api_token(secret, now).await
    }

    async fn revoke_api_token(&self, tenant_id: &str, id: &str) -> Result<()> {
        let r = self.inner.revoke_api_token(tenant_id, id).await;
        if r.is_ok() {
            self.save();
        }
        r
    }

    async fn list_api_tokens(&self, tenant_id: &str) -> Result<Vec<ApiToken>> {
        self.inner.list_api_tokens(tenant_id).await
    }

    async fn append_audit(&self, draft: Draft) -> Result<()> {
        let r = self.inner.append_audit(draft).await;
        if r.is_ok() {
            self.save();
        }
        r
    }

    async fn list_audit(&self, tenant_id: &str, limit: u32) -> Result<Vec<Event>> {
        self.inner.list_audit(tenant_id, limit).await
    }

    async fn verify_audit(&self, tenant_id: &str) -> Result<AuditStatus> {
        self.inner.verify_audit(tenant_id).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rbac::Role;

    fn dir() -> PathBuf {
        let d = std::env::temp_dir().join(format!(
            "hygeia-fs-{}-{}",
            std::process::id(),
            crate::new_id()
        ));
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    #[tokio::test]
    async fn conformance_on_file_store() {
        let d = dir();
        let st = FileStore::open(d.join("state.json")).unwrap();
        crate::conformance::run(&st, ("t1", "g1", "g1b"), ("t2", "g2")).await;
        let st = FileStore::open(d.join("state2.json")).unwrap();
        crate::conformance::run_identity(&st).await;
        let st = FileStore::open(d.join("state3.json")).unwrap();
        crate::conformance::run_lists(&st).await;
    }

    #[tokio::test]
    async fn state_survives_restart_including_credentials_and_audit() {
        let d = dir();
        let path = d.join("state.json");
        let (dev_secret, enroll_secret, api_secret);
        {
            let st = FileStore::open(&path).unwrap();
            st.bootstrap_default().await.unwrap();
            let (_, es) = st
                .create_enrollment_token(
                    crate::DEFAULT_TENANT_ID,
                    crate::DEFAULT_GROUP_ID,
                    3600,
                    Some(2),
                    0,
                )
                .await
                .unwrap();
            enroll_secret = es.clone();
            let (_, ds) = st.enroll(&es, "browser", 10).await.unwrap();
            dev_secret = ds;
            st.add_rule(Rule {
                id: String::new(),
                tenant_id: crate::DEFAULT_TENANT_ID.into(),
                group_id: None,
                action: crate::RuleAction::Block,
                pattern: "ads.test".into(),
                comment: String::new(),
            })
            .await
            .unwrap();
            let (_, a) = st
                .create_api_token(crate::DEFAULT_TENANT_ID, "ci", Role::Viewer, None)
                .await
                .unwrap();
            api_secret = a;
            assert_eq!(
                st.next_bundle_version(crate::DEFAULT_TENANT_ID, crate::DEFAULT_GROUP_ID)
                    .await
                    .unwrap(),
                1
            );
            assert_eq!(
                st.next_bundle_version(crate::DEFAULT_TENANT_ID, crate::DEFAULT_GROUP_ID)
                    .await
                    .unwrap(),
                2
            );
            st.append_audit(Draft {
                ts: 1,
                tenant_id: crate::DEFAULT_TENANT_ID.into(),
                actor: "a".into(),
                action: "x.y".into(),
                target: "t".into(),
                diff: None,
            })
            .await
            .unwrap();
        }
        let st = FileStore::open(&path).unwrap();
        assert!(
            st.authenticate_device(&dev_secret, 20)
                .await
                .unwrap()
                .is_some(),
            "device credential survives"
        );
        assert!(
            st.authenticate_api_token(&api_secret, 0)
                .await
                .unwrap()
                .is_some(),
            "API token survives"
        );
        assert_eq!(
            st.list_rules(crate::DEFAULT_TENANT_ID).await.unwrap().len(),
            1
        );
        assert_eq!(
            st.verify_audit(crate::DEFAULT_TENANT_ID)
                .await
                .unwrap()
                .events,
            1
        );
        // monotonic versions across restarts (extension rollback guard)
        assert_eq!(
            st.next_bundle_version(crate::DEFAULT_TENANT_ID, crate::DEFAULT_GROUP_ID)
                .await
                .unwrap(),
            3
        );
        // the use counter persisted: one use left of two, then exhausted
        assert!(st.enroll(&enroll_secret, "second", 30).await.is_ok());
        assert!(st.enroll(&enroll_secret, "third", 31).await.is_err());
    }

    #[tokio::test]
    async fn damaged_or_tampered_files_are_refused_not_reset() {
        let d = dir();
        let path = d.join("state.json");
        {
            let st = FileStore::open(&path).unwrap();
            st.bootstrap_default().await.unwrap();
            for i in 0..3 {
                st.append_audit(Draft {
                    ts: i,
                    tenant_id: crate::DEFAULT_TENANT_ID.into(),
                    actor: "a".into(),
                    action: "x.y".into(),
                    target: format!("t{i}"),
                    diff: None,
                })
                .await
                .unwrap();
            }
        }
        // tamper with an audit field
        let good = std::fs::read_to_string(&path).unwrap();
        std::fs::write(
            &path,
            good.replace("\"target\":\"t1\"", "\"target\":\"evil\""),
        )
        .unwrap();
        let err = FileStore::open(&path)
            .err()
            .expect("tampered audit must be refused")
            .to_string();
        assert!(err.contains("does not verify"), "{err}");
        // garbage
        std::fs::write(&path, "{ not json").unwrap();
        assert!(FileStore::open(&path).is_err());
        assert_eq!(
            std::fs::read_to_string(&path).unwrap(),
            "{ not json",
            "a damaged file is left untouched"
        );
    }

    #[tokio::test]
    async fn backup_recovery_and_permissions() {
        let d = dir();
        let path = d.join("state.json");
        let st = FileStore::open(&path).unwrap();
        st.bootstrap_default().await.unwrap();
        st.create_tenant("acme", "Acme").await.unwrap(); // second write creates the .bak
        assert!(bak(&path).exists());
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
                0o600
            );
        }
        // crash between "move old aside" and "move new in": only the .bak exists
        std::fs::remove_file(&path).unwrap();
        let st = FileStore::open(&path).unwrap();
        assert!(!st.list_tenants().await.unwrap().is_empty());
    }
}

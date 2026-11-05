//! Persistence for the control plane behind the async [`Store`] trait.
//!
//! * [`PgStore`] — PostgreSQL via sqlx (production). Schema in `migrations/`,
//!   tenant isolation by row level security.
//! * [`MemoryStore`] — reference implementation for tests and demos.

#[doc(hidden)]
pub mod conformance;
pub mod pg;
pub mod rbac;

pub use pg::PgStore;

use async_trait::async_trait;
use hygeia_audit::{AuditLog, ChainError, Draft, Event};
use std::collections::HashMap;
use std::sync::Mutex;

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

pub const PREFIX_ENROLL: &str = "hyg_enr_";
pub const PREFIX_DEVICE: &str = "hyg_dev_";
pub const PREFIX_API: &str = "hyg_api_";

/// 256 random bits with a scanner-friendly prefix. Returns `(secret, sha256)`.
/// SHA-256 (not Argon2): input has full entropy, and a fast hash allows lookup by index.
pub fn new_secret(prefix: &str) -> (String, [u8; 32]) {
    let mut raw = [0u8; 32];
    getrandom::fill(&mut raw).expect("OS randomness unavailable");
    let secret = format!("{prefix}{}", URL_SAFE_NO_PAD.encode(raw));
    let hash = hash_secret(&secret);
    (secret, hash)
}

pub fn hash_secret(secret: &str) -> [u8; 32] {
    Sha256::digest(secret.as_bytes()).into()
}

/// Random UUID (v4 layout) in canonical dashed form.
pub fn new_id() -> String {
    let mut r = [0u8; 16];
    getrandom::fill(&mut r).expect("OS randomness unavailable");
    r[6] = (r[6] & 0x0f) | 0x40;
    r[8] = (r[8] & 0x3f) | 0x80;
    let h: String = r.iter().map(|b| format!("{b:02x}")).collect();
    format!(
        "{}-{}-{}-{}-{}",
        &h[..8],
        &h[8..12],
        &h[12..16],
        &h[16..20],
        &h[20..]
    )
}

/// Fixed ids for the zero-config / single-org deployment.
pub const DEFAULT_TENANT_ID: &str = "00000000-0000-0000-0000-000000000001";
pub const DEFAULT_GROUP_ID: &str = "00000000-0000-0000-0000-000000000002";

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum StoreError {
    #[error("invalid, expired, exhausted or revoked token")]
    InvalidToken,
    #[error("not found")]
    NotFound,
    #[error("already exists")]
    Conflict,
    #[error("audit chain broken: {0}")]
    Chain(String),
    #[error("backend error: {0}")]
    Backend(String),
}

impl From<ChainError> for StoreError {
    fn from(e: ChainError) -> Self {
        StoreError::Chain(e.to_string())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuditStatus {
    pub events: u64,
    pub head: String,
}

pub type Result<T> = std::result::Result<T, StoreError>;

/// Every operation that touches tenant data takes the tenant explicitly;
/// implementations must never let one tenant read or modify another's rows.
#[async_trait]
pub trait Store: Send + Sync {
    /// Ensure the default tenant + group exist (zero-config / single-org).
    async fn bootstrap_default(&self) -> Result<()>;

    async fn create_enrollment_token(
        &self,
        tenant_id: &str,
        group_id: &str,
        ttl_secs: i64,
        max_uses: Option<u32>,
        now: i64,
    ) -> Result<(EnrollmentToken, String)>;
    async fn revoke_enrollment_token(&self, tenant_id: &str, id: &str) -> Result<()>;
    /// Exchange an enrollment token for a device credential (atomic use count).
    async fn enroll(&self, secret: &str, info: &str, now: i64) -> Result<(Device, String)>;
    /// Authenticate a device by credential; updates `last_seen`.
    async fn authenticate_device(&self, secret: &str, now: i64) -> Result<Option<Device>>;
    async fn revoke_device(&self, tenant_id: &str, id: &str) -> Result<()>;
    async fn list_devices(&self, tenant_id: &str) -> Result<Vec<Device>>;

    async fn add_rule(&self, rule: Rule) -> Result<Rule>;
    async fn delete_rule(&self, tenant_id: &str, id: &str) -> Result<Rule>;
    /// Tenant-wide plus group-specific rules.
    async fn rules_for(&self, tenant_id: &str, group_id: &str) -> Result<Vec<Rule>>;
    async fn list_rules(&self, tenant_id: &str) -> Result<Vec<Rule>>;

    async fn next_bundle_version(&self, tenant_id: &str, group_id: &str) -> Result<u64>;

    // ---- tenants and groups ----
    async fn create_tenant(&self, slug: &str, name: &str) -> Result<Tenant>;
    async fn list_tenants(&self) -> Result<Vec<Tenant>>;
    async fn create_group(&self, tenant_id: &str, name: &str) -> Result<Group>;
    async fn list_groups(&self, tenant_id: &str) -> Result<Vec<Group>>;

    // ---- identity, roles, API tokens ----
    /// Create on first sight (OIDC login); never grants any role by itself.
    async fn upsert_user(&self, issuer: &str, subject: &str, email: Option<&str>) -> Result<User>;
    async fn list_users(&self) -> Result<Vec<User>>;
    async fn bindings_for_user(&self, user_id: &str) -> Result<Vec<Binding>>;
    /// Bindings of one tenant (`Some`) or the platform-wide ones (`None`).
    async fn list_bindings(&self, tenant_id: Option<&str>) -> Result<Vec<Binding>>;
    async fn bind_role(
        &self,
        user_id: &str,
        tenant_id: Option<&str>,
        role: rbac::Role,
    ) -> Result<Binding>;
    async fn unbind_role(&self, binding_id: &str) -> Result<()>;

    async fn create_api_token(
        &self,
        tenant_id: &str,
        name: &str,
        role: rbac::Role,
        expires_at: Option<i64>,
    ) -> Result<(ApiToken, String)>;
    async fn authenticate_api_token(&self, secret: &str, now: i64) -> Result<Option<ApiToken>>;
    async fn revoke_api_token(&self, tenant_id: &str, id: &str) -> Result<()>;
    async fn list_api_tokens(&self, tenant_id: &str) -> Result<Vec<ApiToken>>;

    /// Append to the tenant's hash chain.
    async fn append_audit(&self, draft: Draft) -> Result<()>;
    /// Last `limit` events of the tenant, oldest first.
    async fn list_audit(&self, tenant_id: &str, limit: u32) -> Result<Vec<Event>>;
    async fn verify_audit(&self, tenant_id: &str) -> Result<AuditStatus>;
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EnrollmentToken {
    pub id: String,
    pub tenant_id: String,
    pub group_id: String,
    #[serde(skip)]
    pub secret_hash: [u8; 32],
    pub expires_at: i64,
    pub max_uses: Option<u32>,
    pub used: u32,
    pub revoked: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Device {
    pub id: String,
    pub tenant_id: String,
    pub group_id: String,
    #[serde(skip)]
    pub secret_hash: [u8; 32],
    pub info: String,
    pub last_seen: i64,
    pub revoked: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Tenant {
    pub id: String,
    pub slug: String,
    pub name: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Group {
    pub id: String,
    pub tenant_id: String,
    pub name: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct User {
    pub id: String,
    pub issuer: String,
    pub subject: String,
    pub email: Option<String>,
    pub disabled: bool,
}

/// `tenant_id == None` is a platform-wide binding (MSP operator).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Binding {
    pub id: String,
    pub user_id: String,
    pub tenant_id: Option<String>,
    pub role: rbac::Role,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ApiToken {
    pub id: String,
    pub tenant_id: String,
    pub name: String,
    pub role: rbac::Role,
    pub expires_at: Option<i64>,
    pub revoked: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum RuleAction {
    Allow,
    Block,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Rule {
    pub id: String,
    pub tenant_id: String,
    /// `None` = applies to the whole tenant.
    pub group_id: Option<String>,
    pub action: RuleAction,
    pub pattern: String,
    pub comment: String,
}

#[derive(Default)]
struct State {
    tokens: HashMap<String, EnrollmentToken>,
    devices: HashMap<String, Device>,
    rules: Vec<Rule>,
    bundle_version: HashMap<(String, String), u64>,
    audit: HashMap<String, AuditLog>,
    tenants: Vec<Tenant>,
    groups: Vec<Group>,
    users: Vec<User>,
    bindings: Vec<Binding>,
    api_tokens: Vec<(ApiToken, [u8; 32])>,
}

#[derive(Default)]
pub struct MemoryStore {
    s: Mutex<State>,
}

impl MemoryStore {
    pub fn new() -> Self {
        Self::default()
    }
}

#[async_trait]
impl Store for MemoryStore {
    async fn bootstrap_default(&self) -> Result<()> {
        Ok(())
    }

    async fn create_enrollment_token(
        &self,
        tenant_id: &str,
        group_id: &str,
        ttl_secs: i64,
        max_uses: Option<u32>,
        now: i64,
    ) -> Result<(EnrollmentToken, String)> {
        let (secret, hash) = new_secret(PREFIX_ENROLL);
        let t = EnrollmentToken {
            id: new_id(),
            tenant_id: tenant_id.into(),
            group_id: group_id.into(),
            secret_hash: hash,
            expires_at: now.saturating_add(ttl_secs),
            max_uses,
            used: 0,
            revoked: false,
        };
        self.s
            .lock()
            .unwrap()
            .tokens
            .insert(t.id.clone(), t.clone());
        Ok((t, secret))
    }

    async fn revoke_enrollment_token(&self, tenant_id: &str, id: &str) -> Result<()> {
        let mut s = self.s.lock().unwrap();
        let t = s
            .tokens
            .get_mut(id)
            .filter(|t| t.tenant_id == tenant_id)
            .ok_or(StoreError::NotFound)?;
        t.revoked = true;
        Ok(())
    }

    async fn enroll(&self, secret: &str, info: &str, now: i64) -> Result<(Device, String)> {
        if !secret.starts_with(PREFIX_ENROLL) {
            return Err(StoreError::InvalidToken);
        }
        let h = hash_secret(secret);
        let mut s = self.s.lock().unwrap();
        let t = s
            .tokens
            .values_mut()
            .find(|t| t.secret_hash == h)
            .ok_or(StoreError::InvalidToken)?;
        if t.revoked || now >= t.expires_at || t.max_uses.is_some_and(|m| t.used >= m) {
            return Err(StoreError::InvalidToken);
        }
        t.used += 1;
        let (dev_secret, dev_hash) = new_secret(PREFIX_DEVICE);
        let d = Device {
            id: new_id(),
            tenant_id: t.tenant_id.clone(),
            group_id: t.group_id.clone(),
            secret_hash: dev_hash,
            info: info.chars().take(256).collect(),
            last_seen: now,
            revoked: false,
        };
        s.devices.insert(d.id.clone(), d.clone());
        Ok((d, dev_secret))
    }

    async fn authenticate_device(&self, secret: &str, now: i64) -> Result<Option<Device>> {
        if !secret.starts_with(PREFIX_DEVICE) {
            return Ok(None);
        }
        let h = hash_secret(secret);
        let mut s = self.s.lock().unwrap();
        Ok(s.devices
            .values_mut()
            .find(|d| d.secret_hash == h && !d.revoked)
            .map(|d| {
                d.last_seen = now;
                d.clone()
            }))
    }

    async fn revoke_device(&self, tenant_id: &str, id: &str) -> Result<()> {
        let mut s = self.s.lock().unwrap();
        let d = s
            .devices
            .get_mut(id)
            .filter(|d| d.tenant_id == tenant_id)
            .ok_or(StoreError::NotFound)?;
        d.revoked = true;
        Ok(())
    }

    async fn list_devices(&self, tenant_id: &str) -> Result<Vec<Device>> {
        let s = self.s.lock().unwrap();
        Ok(s.devices
            .values()
            .filter(|d| d.tenant_id == tenant_id)
            .cloned()
            .collect())
    }

    async fn add_rule(&self, mut r: Rule) -> Result<Rule> {
        r.id = new_id();
        self.s.lock().unwrap().rules.push(r.clone());
        Ok(r)
    }

    async fn delete_rule(&self, tenant_id: &str, id: &str) -> Result<Rule> {
        let mut s = self.s.lock().unwrap();
        let i = s
            .rules
            .iter()
            .position(|r| r.id == id && r.tenant_id == tenant_id)
            .ok_or(StoreError::NotFound)?;
        Ok(s.rules.remove(i))
    }

    async fn rules_for(&self, tenant_id: &str, group_id: &str) -> Result<Vec<Rule>> {
        let s = self.s.lock().unwrap();
        Ok(s.rules
            .iter()
            .filter(|r| {
                r.tenant_id == tenant_id && r.group_id.as_deref().is_none_or(|g| g == group_id)
            })
            .cloned()
            .collect())
    }

    async fn list_rules(&self, tenant_id: &str) -> Result<Vec<Rule>> {
        let s = self.s.lock().unwrap();
        Ok(s.rules
            .iter()
            .filter(|r| r.tenant_id == tenant_id)
            .cloned()
            .collect())
    }

    async fn next_bundle_version(&self, tenant_id: &str, group_id: &str) -> Result<u64> {
        let mut s = self.s.lock().unwrap();
        let v = s
            .bundle_version
            .entry((tenant_id.into(), group_id.into()))
            .or_insert(0);
        *v += 1;
        Ok(*v)
    }

    async fn create_tenant(&self, slug: &str, name: &str) -> Result<Tenant> {
        let mut s = self.s.lock().unwrap();
        if s.tenants.iter().any(|t| t.slug == slug) {
            return Err(StoreError::Conflict);
        }
        let t = Tenant {
            id: new_id(),
            slug: slug.into(),
            name: name.into(),
        };
        s.tenants.push(t.clone());
        Ok(t)
    }

    async fn list_tenants(&self) -> Result<Vec<Tenant>> {
        Ok(self.s.lock().unwrap().tenants.clone())
    }

    async fn create_group(&self, tenant_id: &str, name: &str) -> Result<Group> {
        let mut s = self.s.lock().unwrap();
        if !s.tenants.iter().any(|t| t.id == tenant_id) {
            return Err(StoreError::NotFound);
        }
        if s.groups
            .iter()
            .any(|g| g.tenant_id == tenant_id && g.name == name)
        {
            return Err(StoreError::Conflict);
        }
        let g = Group {
            id: new_id(),
            tenant_id: tenant_id.into(),
            name: name.into(),
        };
        s.groups.push(g.clone());
        Ok(g)
    }

    async fn list_groups(&self, tenant_id: &str) -> Result<Vec<Group>> {
        Ok(self
            .s
            .lock()
            .unwrap()
            .groups
            .iter()
            .filter(|g| g.tenant_id == tenant_id)
            .cloned()
            .collect())
    }

    async fn upsert_user(&self, issuer: &str, subject: &str, email: Option<&str>) -> Result<User> {
        let mut s = self.s.lock().unwrap();
        if let Some(u) = s
            .users
            .iter_mut()
            .find(|u| u.issuer == issuer && u.subject == subject)
        {
            if email.is_some() {
                u.email = email.map(Into::into);
            }
            return Ok(u.clone());
        }
        let u = User {
            id: new_id(),
            issuer: issuer.into(),
            subject: subject.into(),
            email: email.map(Into::into),
            disabled: false,
        };
        s.users.push(u.clone());
        Ok(u)
    }

    async fn list_users(&self) -> Result<Vec<User>> {
        Ok(self.s.lock().unwrap().users.clone())
    }

    async fn bindings_for_user(&self, user_id: &str) -> Result<Vec<Binding>> {
        Ok(self
            .s
            .lock()
            .unwrap()
            .bindings
            .iter()
            .filter(|b| b.user_id == user_id)
            .cloned()
            .collect())
    }

    async fn list_bindings(&self, tenant_id: Option<&str>) -> Result<Vec<Binding>> {
        Ok(self
            .s
            .lock()
            .unwrap()
            .bindings
            .iter()
            .filter(|b| b.tenant_id.as_deref() == tenant_id)
            .cloned()
            .collect())
    }

    async fn bind_role(
        &self,
        user_id: &str,
        tenant_id: Option<&str>,
        role: rbac::Role,
    ) -> Result<Binding> {
        let mut s = self.s.lock().unwrap();
        if !s.users.iter().any(|u| u.id == user_id) {
            return Err(StoreError::NotFound);
        }
        if let Some(b) = s
            .bindings
            .iter()
            .find(|b| b.user_id == user_id && b.tenant_id.as_deref() == tenant_id && b.role == role)
        {
            return Ok(b.clone());
        }
        let b = Binding {
            id: new_id(),
            user_id: user_id.into(),
            tenant_id: tenant_id.map(Into::into),
            role,
        };
        s.bindings.push(b.clone());
        Ok(b)
    }

    async fn unbind_role(&self, binding_id: &str) -> Result<()> {
        let mut s = self.s.lock().unwrap();
        let i = s
            .bindings
            .iter()
            .position(|b| b.id == binding_id)
            .ok_or(StoreError::NotFound)?;
        s.bindings.remove(i);
        Ok(())
    }

    async fn create_api_token(
        &self,
        tenant_id: &str,
        name: &str,
        role: rbac::Role,
        expires_at: Option<i64>,
    ) -> Result<(ApiToken, String)> {
        if role == rbac::Role::Owner {
            return Err(StoreError::NotFound); // platform role cannot be tenant-scoped
        }
        let (secret, hash) = new_secret(PREFIX_API);
        let t = ApiToken {
            id: new_id(),
            tenant_id: tenant_id.into(),
            name: name.into(),
            role,
            expires_at,
            revoked: false,
        };
        self.s.lock().unwrap().api_tokens.push((t.clone(), hash));
        Ok((t, secret))
    }

    async fn authenticate_api_token(&self, secret: &str, now: i64) -> Result<Option<ApiToken>> {
        if !secret.starts_with(PREFIX_API) {
            return Ok(None);
        }
        let h = hash_secret(secret);
        let s = self.s.lock().unwrap();
        Ok(s.api_tokens
            .iter()
            .find(|(t, hash)| *hash == h && !t.revoked && t.expires_at.is_none_or(|e| e > now))
            .map(|(t, _)| t.clone()))
    }

    async fn revoke_api_token(&self, tenant_id: &str, id: &str) -> Result<()> {
        let mut s = self.s.lock().unwrap();
        let (t, _) = s
            .api_tokens
            .iter_mut()
            .find(|(t, _)| t.id == id && t.tenant_id == tenant_id)
            .ok_or(StoreError::NotFound)?;
        t.revoked = true;
        Ok(())
    }

    async fn list_api_tokens(&self, tenant_id: &str) -> Result<Vec<ApiToken>> {
        Ok(self
            .s
            .lock()
            .unwrap()
            .api_tokens
            .iter()
            .filter(|(t, _)| t.tenant_id == tenant_id)
            .map(|(t, _)| t.clone())
            .collect())
    }

    async fn append_audit(&self, draft: Draft) -> Result<()> {
        let mut s = self.s.lock().unwrap();
        s.audit
            .entry(draft.tenant_id.clone())
            .or_default()
            .append(draft);
        Ok(())
    }

    async fn list_audit(&self, tenant_id: &str, limit: u32) -> Result<Vec<Event>> {
        let s = self.s.lock().unwrap();
        let ev = s
            .audit
            .get(tenant_id)
            .map(|l| l.events())
            .unwrap_or_default();
        Ok(ev[ev.len().saturating_sub(limit as usize)..].to_vec())
    }

    async fn verify_audit(&self, tenant_id: &str) -> Result<AuditStatus> {
        let s = self.s.lock().unwrap();
        match s.audit.get(tenant_id) {
            None => Ok(AuditStatus {
                events: 0,
                head: hygeia_audit::GENESIS.into(),
            }),
            Some(l) => {
                l.verify()?;
                Ok(AuditStatus {
                    events: l.events().len() as u64,
                    head: l.head().into(),
                })
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn memory_store_conformance() {
        let st = MemoryStore::new();
        crate::conformance::run(&st, ("t1", "g1", "g1b"), ("t2", "g2")).await;
        crate::conformance::run_identity(&MemoryStore::new()).await;
    }
}

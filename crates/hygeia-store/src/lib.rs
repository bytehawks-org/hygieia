//! Persistence for the control plane.
//!
//! [`MemoryStore`] is the reference implementation (tests, zero-config demo).
//! The PostgreSQL/SQLite schema lives in `migrations/`; an sqlx-backed store
//! implementing the same operations is the next step.

use std::collections::HashMap;
use std::sync::Mutex;

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

pub const PREFIX_ENROLL: &str = "hyg_enr_";
pub const PREFIX_DEVICE: &str = "hyg_dev_";

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

pub fn new_id() -> String {
    let mut raw = [0u8; 16];
    getrandom::fill(&mut raw).expect("OS randomness unavailable");
    raw.iter().map(|b| format!("{b:02x}")).collect()
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum StoreError {
    #[error("invalid, expired, exhausted or revoked token")]
    InvalidToken,
    #[error("not found")]
    NotFound,
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
}

#[derive(Default)]
pub struct MemoryStore {
    s: Mutex<State>,
}

impl MemoryStore {
    pub fn new() -> Self {
        Self::default()
    }

    /// Returns the plaintext secret exactly once; only its hash is kept.
    pub fn create_enrollment_token(
        &self,
        tenant_id: &str,
        group_id: &str,
        ttl_secs: i64,
        max_uses: Option<u32>,
        now: i64,
    ) -> (EnrollmentToken, String) {
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
        (t, secret)
    }

    pub fn revoke_enrollment_token(&self, id: &str) -> Result<(), StoreError> {
        let mut s = self.s.lock().unwrap();
        s.tokens.get_mut(id).ok_or(StoreError::NotFound)?.revoked = true;
        Ok(())
    }

    /// Exchange an enrollment token for a device credential (atomic use count).
    pub fn enroll(
        &self,
        secret: &str,
        info: &str,
        now: i64,
    ) -> Result<(Device, String), StoreError> {
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

    /// Authenticate a device by credential; updates `last_seen`.
    pub fn authenticate_device(&self, secret: &str, now: i64) -> Option<Device> {
        if !secret.starts_with(PREFIX_DEVICE) {
            return None;
        }
        let h = hash_secret(secret);
        let mut s = self.s.lock().unwrap();
        let d = s
            .devices
            .values_mut()
            .find(|d| d.secret_hash == h && !d.revoked)?;
        d.last_seen = now;
        Some(d.clone())
    }

    pub fn revoke_device(&self, id: &str) -> Result<(), StoreError> {
        let mut s = self.s.lock().unwrap();
        s.devices.get_mut(id).ok_or(StoreError::NotFound)?.revoked = true;
        Ok(())
    }

    pub fn list_devices(&self, tenant_id: &str) -> Vec<Device> {
        let s = self.s.lock().unwrap();
        s.devices
            .values()
            .filter(|d| d.tenant_id == tenant_id)
            .cloned()
            .collect()
    }

    pub fn add_rule(&self, mut r: Rule) -> Rule {
        r.id = new_id();
        self.s.lock().unwrap().rules.push(r.clone());
        r
    }

    pub fn delete_rule(&self, tenant_id: &str, id: &str) -> Result<Rule, StoreError> {
        let mut s = self.s.lock().unwrap();
        let i = s
            .rules
            .iter()
            .position(|r| r.id == id && r.tenant_id == tenant_id)
            .ok_or(StoreError::NotFound)?;
        Ok(s.rules.remove(i))
    }

    /// Rules effective for a group: tenant-wide plus group-specific.
    pub fn rules_for(&self, tenant_id: &str, group_id: &str) -> Vec<Rule> {
        let s = self.s.lock().unwrap();
        s.rules
            .iter()
            .filter(|r| {
                r.tenant_id == tenant_id && r.group_id.as_deref().is_none_or(|g| g == group_id)
            })
            .cloned()
            .collect()
    }

    pub fn list_rules(&self, tenant_id: &str) -> Vec<Rule> {
        let s = self.s.lock().unwrap();
        s.rules
            .iter()
            .filter(|r| r.tenant_id == tenant_id)
            .cloned()
            .collect()
    }

    pub fn next_bundle_version(&self, tenant_id: &str, group_id: &str) -> u64 {
        let mut s = self.s.lock().unwrap();
        let v = s
            .bundle_version
            .entry((tenant_id.into(), group_id.into()))
            .or_insert(0);
        *v += 1;
        *v
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn enroll_flow() {
        let st = MemoryStore::new();
        let (_, secret) = st.create_enrollment_token("t", "g", 60, Some(1), 100);
        assert!(secret.starts_with(PREFIX_ENROLL));
        let (dev, dsecret) = st.enroll(&secret, "chrome", 110).unwrap();
        assert_eq!((dev.tenant_id.as_str(), dev.group_id.as_str()), ("t", "g"));
        // max_uses = 1
        assert_eq!(st.enroll(&secret, "x", 111), Err(StoreError::InvalidToken));
        assert!(st.authenticate_device(&dsecret, 120).is_some());
        st.revoke_device(&dev.id).unwrap();
        assert!(st.authenticate_device(&dsecret, 121).is_none());
        // enrollment secrets are not device credentials
        assert!(st.authenticate_device(&secret, 0).is_none());
    }

    #[test]
    fn token_expiry_and_revoke() {
        let st = MemoryStore::new();
        let (_, s1) = st.create_enrollment_token("t", "g", 10, None, 0);
        assert!(st.enroll(&s1, "", 10).is_err());
        let (t2, s2) = st.create_enrollment_token("t", "g", 10, None, 0);
        st.revoke_enrollment_token(&t2.id).unwrap();
        assert!(st.enroll(&s2, "", 1).is_err());
    }

    #[test]
    fn rules_scoped_by_tenant_and_group() {
        let st = MemoryStore::new();
        let mk = |t: &str, g: Option<&str>| Rule {
            id: String::new(),
            tenant_id: t.into(),
            group_id: g.map(Into::into),
            action: RuleAction::Block,
            pattern: "a.test".into(),
            comment: String::new(),
        };
        st.add_rule(mk("t1", None));
        st.add_rule(mk("t1", Some("g1")));
        st.add_rule(mk("t1", Some("g2")));
        st.add_rule(mk("t2", None));
        assert_eq!(st.rules_for("t1", "g1").len(), 2);
        assert_eq!(st.list_rules("t2").len(), 1);
    }
}

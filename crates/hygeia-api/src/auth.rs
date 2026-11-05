//! Authentication and authorisation for the admin API.
//!
//! Credentials accepted on `/v1/admin/*` (all as `Authorization: Bearer`):
//! * `hyg_api_…`  tenant-scoped API token (role stored in the database)
//! * OIDC JWT     user identity `(iss, sub)`; roles from `role_bindings`
//! * break-glass: one static secret, staging/dev only, Owner-equivalent; every
//!   use is written to the audit chain
//!
//! Device credentials (`hyg_dev_…`) never authenticate admin calls.

use std::time::{Duration, Instant};

use axum::http::{HeaderMap, header};
use hygeia_store::rbac::{Permission, Role};
use hygeia_store::{Binding, PREFIX_API, Store, hash_secret};
use serde::Serialize;

use crate::oidc::OidcVerifier;

/// Minimum break-glass secret length (characters).
pub const BREAK_GLASS_MIN_LEN: usize = 32;

pub struct BreakGlass {
    hash: [u8; 32],
    deadline: Option<Instant>,
}

impl BreakGlass {
    /// `ttl`: the credential stops working this long after process start
    /// (`None` = never; avoid outside throwaway environments).
    pub fn new(secret: &str, ttl: Option<Duration>) -> Result<Self, String> {
        if secret.chars().count() < BREAK_GLASS_MIN_LEN {
            return Err(format!(
                "break-glass secret must be at least {BREAK_GLASS_MIN_LEN} characters"
            ));
        }
        Ok(Self {
            hash: hash_secret(secret),
            deadline: ttl.map(|t| Instant::now() + t),
        })
    }

    fn matches(&self, token: &str) -> bool {
        let a = hash_secret(token);
        // constant-time over the digests
        let eq = a
            .iter()
            .zip(self.hash.iter())
            .fold(0u8, |acc, (x, y)| acc | (x ^ y))
            == 0;
        eq && self.deadline.is_none_or(|d| Instant::now() < d)
    }
}

/// The machine owner's credential on a standalone node: Owner-equivalent, generated at install and
/// kept in a file only the owning account can read. Unlike break-glass it is the normal way in, so
/// it is not flagged as an emergency in the audit trail (actor `local-owner`).
pub struct LocalOwner {
    hash: [u8; 32],
}

impl LocalOwner {
    pub fn new(secret: &str) -> Result<Self, String> {
        if secret.chars().count() < BREAK_GLASS_MIN_LEN {
            return Err(format!(
                "local owner secret must be at least {BREAK_GLASS_MIN_LEN} characters"
            ));
        }
        Ok(Self {
            hash: hash_secret(secret),
        })
    }

    fn matches(&self, token: &str) -> bool {
        let a = hash_secret(token);
        a.iter()
            .zip(self.hash.iter())
            .fold(0u8, |acc, (x, y)| acc | (x ^ y))
            == 0
    }
}

#[derive(Default)]
pub struct AuthConfig {
    pub local_owner: Option<LocalOwner>,
    pub break_glass: Option<BreakGlass>,
    pub oidc: Option<OidcVerifier>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Principal {
    LocalOwner,
    BreakGlass,
    ApiToken {
        id: String,
        tenant_id: String,
        role: Role,
    },
    User {
        id: String,
        issuer: String,
        subject: String,
        email: Option<String>,
        bindings: Vec<Binding>,
    },
}

#[derive(Debug, PartialEq, Eq)]
pub enum AuthError {
    /// No or invalid credential (401).
    Unauthenticated,
    /// Valid credential, insufficient role (403).
    Forbidden,
    Backend,
}

impl Principal {
    /// Stable identifier for audit records.
    pub fn actor(&self) -> String {
        match self {
            Principal::LocalOwner => "local-owner".into(),
            Principal::BreakGlass => "break-glass".into(),
            Principal::ApiToken { id, .. } => format!("api-token:{id}"),
            Principal::User { id, .. } => format!("user:{id}"),
        }
    }

    pub fn is_break_glass(&self) -> bool {
        matches!(self, Principal::BreakGlass)
    }

    /// `tenant == None` asks about platform-level operations. Platform-level
    /// permissions (and tenant lifecycle) are only granted by platform-wide
    /// bindings; a tenant-scoped "owner" binding does not escalate.
    pub fn can(&self, perm: Permission, tenant: Option<&str>) -> bool {
        match self {
            Principal::LocalOwner | Principal::BreakGlass => true,
            Principal::ApiToken {
                tenant_id, role, ..
            } => {
                tenant == Some(tenant_id.as_str())
                    && perm != Permission::TenantsManage
                    && role.allows(perm)
            }
            Principal::User { bindings, .. } => bindings.iter().any(|b| {
                let scope_ok = match (&b.tenant_id, tenant) {
                    (None, _) => true,
                    (Some(bt), Some(t)) => bt == t,
                    (Some(_), None) => false,
                };
                let platform_only = perm == Permission::TenantsManage;
                scope_ok && (!platform_only || b.tenant_id.is_none()) && b.role.allows(perm)
            }),
        }
    }

    /// Does the principal hold *any* role allowing `perm` (anywhere)?
    pub fn can_anywhere(&self, perm: Permission) -> bool {
        match self {
            Principal::LocalOwner | Principal::BreakGlass => true,
            Principal::ApiToken { role, .. } => role.allows(perm),
            Principal::User { bindings, .. } => bindings.iter().any(|b| b.role.allows(perm)),
        }
    }

    /// No privilege escalation: a principal may only hand out roles whose
    /// permissions it holds itself in that scope.
    pub fn can_grant(&self, role: Role, tenant: Option<&str>) -> bool {
        Permission::ALL
            .iter()
            .filter(|p| role.allows(**p))
            .all(|p| self.can(*p, tenant))
    }
}

fn bearer(h: &HeaderMap) -> Option<&str> {
    h.get(header::AUTHORIZATION)?
        .to_str()
        .ok()?
        .strip_prefix("Bearer ")
}

pub async fn authenticate(
    cfg: &AuthConfig,
    store: &dyn Store,
    headers: &HeaderMap,
    now: i64,
) -> Result<Principal, AuthError> {
    let token = bearer(headers).ok_or(AuthError::Unauthenticated)?;

    if let Some(lo) = &cfg.local_owner
        && lo.matches(token)
    {
        return Ok(Principal::LocalOwner);
    }
    if let Some(bg) = &cfg.break_glass
        && bg.matches(token)
    {
        return Ok(Principal::BreakGlass);
    }
    if token.starts_with(PREFIX_API) {
        return match store.authenticate_api_token(token, now).await {
            Ok(Some(t)) => Ok(Principal::ApiToken {
                id: t.id,
                tenant_id: t.tenant_id,
                role: t.role,
            }),
            Ok(None) => Err(AuthError::Unauthenticated),
            Err(_) => Err(AuthError::Backend),
        };
    }
    if let Some(oidc) = &cfg.oidc
        && token.matches('.').count() == 2
    {
        let id = oidc.verify(token).await.map_err(|e| {
            tracing::debug!(error = %e, "oidc token rejected");
            AuthError::Unauthenticated
        })?;
        let user = store
            .upsert_user(&id.issuer, &id.subject, id.email.as_deref())
            .await
            .map_err(|_| AuthError::Backend)?;
        if user.disabled {
            return Err(AuthError::Unauthenticated);
        }
        let bindings = store
            .bindings_for_user(&user.id)
            .await
            .map_err(|_| AuthError::Backend)?;
        return Ok(Principal::User {
            id: user.id,
            issuer: user.issuer,
            subject: user.subject,
            email: user.email,
            bindings,
        });
    }
    Err(AuthError::Unauthenticated)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn b(tenant: Option<&str>, role: Role) -> Binding {
        Binding {
            id: "b".into(),
            user_id: "u".into(),
            tenant_id: tenant.map(Into::into),
            role,
        }
    }
    fn user(bindings: Vec<Binding>) -> Principal {
        Principal::User {
            id: "u".into(),
            issuer: "i".into(),
            subject: "s".into(),
            email: None,
            bindings,
        }
    }

    #[test]
    fn scoping_rules() {
        let p = user(vec![b(Some("t1"), Role::Admin)]);
        assert!(p.can(Permission::RulesWrite, Some("t1")));
        assert!(!p.can(Permission::RulesWrite, Some("t2")));
        assert!(
            !p.can(Permission::RulesWrite, None),
            "tenant admin has no platform scope"
        );
        assert!(!p.can(Permission::TenantsManage, Some("t1")));

        let platform = user(vec![b(None, Role::Owner)]);
        assert!(platform.can(Permission::TenantsManage, None));
        assert!(platform.can(Permission::RulesWrite, Some("anything")));

        // an "owner" bound to ONE tenant must not manage tenants
        let sneaky = user(vec![b(Some("t1"), Role::Owner)]);
        assert!(!sneaky.can(Permission::TenantsManage, Some("t1")));
        assert!(!sneaky.can(Permission::TenantsManage, None));

        assert!(
            !user(vec![]).can_anywhere(Permission::RulesRead),
            "no bindings, no access"
        );
    }

    #[test]
    fn api_token_is_tenant_bound() {
        let p = Principal::ApiToken {
            id: "x".into(),
            tenant_id: "t1".into(),
            role: Role::Editor,
        };
        assert!(p.can(Permission::RulesWrite, Some("t1")));
        assert!(!p.can(Permission::RulesWrite, Some("t2")));
        assert!(!p.can(Permission::AuditRead, Some("t1")));
        assert!(!p.can(Permission::RulesRead, None));
    }

    #[test]
    fn no_privilege_escalation() {
        let editor = user(vec![b(Some("t1"), Role::Editor)]);
        assert!(editor.can_grant(Role::Viewer, Some("t1")));
        assert!(editor.can_grant(Role::Editor, Some("t1")));
        assert!(!editor.can_grant(Role::Admin, Some("t1")));
        assert!(
            !editor.can_grant(Role::Auditor, Some("t1")),
            "cannot hand out audit access it lacks"
        );
        let admin = user(vec![b(Some("t1"), Role::Admin)]);
        assert!(!admin.can_grant(Role::Owner, Some("t1")));
        assert!(!admin.can_grant(Role::Viewer, Some("t2")));
    }

    #[test]
    fn break_glass_length_and_ttl() {
        assert!(BreakGlass::new("short", None).is_err());
        let long = "x".repeat(40);
        let bg = BreakGlass::new(&long, None).unwrap();
        assert!(bg.matches(&long) && !bg.matches("nope"));
        let expired = BreakGlass::new(&long, Some(Duration::ZERO)).unwrap();
        assert!(!expired.matches(&long), "expired break-glass is dead");
    }
}

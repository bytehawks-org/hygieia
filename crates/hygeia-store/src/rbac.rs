//! Role-based access control. Roles are a fixed set mapped to permissions in
//! code (reviewable, testable); bindings live in `role_bindings` (per tenant,
//! or platform-wide when tenant is NULL) and `api_tokens`.

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Permission {
    RulesRead,
    RulesWrite,
    DevicesRead,
    DevicesManage,
    TokensManage,
    AuditRead,
    UsersManage,
    TenantsManage,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Role {
    /// Platform operator (MSP): everything, including tenant lifecycle.
    Owner,
    /// Tenant administrator.
    Admin,
    /// Edits policy, manages devices; no users, no audit.
    Editor,
    Viewer,
    /// Read-only, including audit.
    Auditor,
}

impl Role {
    pub fn allows(self, p: Permission) -> bool {
        use Permission::*;
        match self {
            Role::Owner => true,
            Role::Admin => p != TenantsManage,
            Role::Editor => matches!(
                p,
                RulesRead | RulesWrite | DevicesRead | DevicesManage | TokensManage
            ),
            Role::Viewer => matches!(p, RulesRead | DevicesRead),
            Role::Auditor => matches!(p, RulesRead | DevicesRead | AuditRead),
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Role::Owner => "owner",
            Role::Admin => "admin",
            Role::Editor => "editor",
            Role::Viewer => "viewer",
            Role::Auditor => "auditor",
        }
    }
}

impl std::str::FromStr for Role {
    type Err = ();
    fn from_str(s: &str) -> Result<Self, ()> {
        Ok(match s {
            "owner" => Role::Owner,
            "admin" => Role::Admin,
            "editor" => Role::Editor,
            "viewer" => Role::Viewer,
            "auditor" => Role::Auditor,
            _ => return Err(()),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use Permission::*;

    #[test]
    fn matrix() {
        assert!(Role::Owner.allows(TenantsManage));
        assert!(!Role::Admin.allows(TenantsManage) && Role::Admin.allows(UsersManage));
        assert!(Role::Editor.allows(RulesWrite) && !Role::Editor.allows(AuditRead));
        assert!(Role::Auditor.allows(AuditRead) && !Role::Auditor.allows(RulesWrite));
        assert!(!Role::Viewer.allows(TokensManage));
        assert_eq!("auditor".parse::<Role>(), Ok(Role::Auditor));
        assert_eq!(Role::Admin.as_str(), "admin");
    }
}

use std::sync::Arc;
use std::time::Duration;

use axum::Json;
use axum::Router;
use axum::extract::{Path, Query, State};
use axum::http::{HeaderMap, StatusCode, header};
use axum::response::{IntoResponse, Response};
use axum::routing::{delete, get, post};
use hygeia_core::{Ruleset, RulesetData, SignedBundle};
use hygeia_store::rbac::{Permission, Role};
use hygeia_store::{Rule, RuleAction, StoreError};
use serde::{Deserialize, Serialize};
use serde_json::json;

use crate::auth::{AuthError, Principal, authenticate};
use crate::state::{AppState, DEFAULT_GROUP, DEFAULT_TENANT, now};

type S = State<Arc<AppState>>;

/// Non-secret deployment info for the UI (login screen, environment banner).
#[derive(Debug, Clone, Default, Serialize)]
pub struct PublicConfig {
    /// `server` (central) or `standalone` (single-machine node)
    pub mode: String,
    /// `production` | `staging` | `dev`
    pub environment: String,
    pub break_glass: bool,
    pub oidc: Option<OidcPublic>,
}

#[derive(Debug, Clone, Serialize)]
pub struct OidcPublic {
    pub issuer: String,
    pub client_id: String,
    pub scope: String,
}

/// API plus the static admin UI served from `ui` (API routes take precedence).
pub fn router_with_ui(state: Arc<AppState>, ui: crate::ui::Ui) -> Router {
    let svc = tower::ServiceBuilder::new()
        .layer(axum::middleware::from_fn_with_state(
            ui.clone(),
            crate::ui::headers,
        ))
        .service(ui.service());
    router(state).fallback_service(svc)
}

pub fn router(state: Arc<AppState>) -> Router {
    Router::new()
        .route("/healthz", get(|| async { "ok" }))
        // data plane (device credentials)
        .route("/v1/pubkey", get(pubkey))
        .route("/v1/enroll", post(enroll))
        .route("/v1/bundle", get(bundle))
        // identity
        .route("/v1/config", get(public_config))
        .route("/v1/me", get(me))
        // administration
        .route("/v1/admin/tenants", get(list_tenants).post(create_tenant))
        .route("/v1/admin/groups", get(list_groups).post(create_group))
        .route("/v1/admin/users", get(list_users))
        .route("/v1/admin/bindings", get(list_bindings).post(add_binding))
        .route("/v1/admin/bindings/{id}", delete(remove_binding))
        .route(
            "/v1/admin/api-tokens",
            get(list_api_tokens).post(create_api_token),
        )
        .route("/v1/admin/api-tokens/{id}", delete(revoke_api_token))
        .route("/v1/admin/enrollment-tokens", post(create_token))
        .route("/v1/admin/devices", get(list_devices))
        .route("/v1/admin/devices/{id}", delete(revoke_device))
        .route("/v1/admin/rules", get(list_rules).post(add_rule))
        .route("/v1/admin/rules/{id}", delete(delete_rule))
        .route("/v1/admin/lists", get(lists_status))
        .route("/v1/admin/lists/refresh", post(lists_refresh))
        .route(
            "/v1/admin/list-subscriptions",
            get(list_subscriptions).post(subscribe).delete(unsubscribe),
        )
        .route("/v1/admin/list-policy", axum::routing::put(set_list_policy))
        .route("/v1/admin/simulate", post(simulate))
        .route("/v1/admin/audit", get(audit))
        .route("/v1/admin/audit/verify", get(audit_verify))
        .with_state(state)
}

// ---------------------------------------------------------------- auth helpers

fn bearer(h: &HeaderMap) -> Option<&str> {
    h.get(header::AUTHORIZATION)?
        .to_str()
        .ok()?
        .strip_prefix("Bearer ")
}

impl Principal {
    /// Tenant used when a request does not name one: a token's own tenant,
    /// otherwise the default tenant (single-org deployments).
    fn default_tenant(&self) -> String {
        match self {
            Principal::ApiToken { tenant_id, .. } => tenant_id.clone(),
            _ => DEFAULT_TENANT.to_string(),
        }
    }
}

/// Authenticate only.
async fn authn(st: &AppState, h: &HeaderMap) -> Result<Principal, Response> {
    match authenticate(&st.auth, &*st.store, h, now()).await {
        Ok(p) => Ok(p),
        Err(AuthError::Unauthenticated | AuthError::Forbidden) => {
            // Slow down credential guessing against the admin API.
            tokio::time::sleep(Duration::from_millis(200)).await;
            Err(StatusCode::UNAUTHORIZED.into_response())
        }
        Err(AuthError::Backend) => Err(StatusCode::INTERNAL_SERVER_ERROR.into_response()),
    }
}

/// Authenticate, resolve the tenant and require `perm` on it.
/// `scope`: `Some(tenant)` / `None` = request's own default tenant; use
/// [`guard_platform`] for platform-level operations.
async fn guard(
    st: &AppState,
    h: &HeaderMap,
    perm: Permission,
    tenant: Option<String>,
    label: &str,
) -> Result<(Principal, String), Response> {
    let p = authn(st, h).await?;
    let tenant = tenant.unwrap_or_else(|| p.default_tenant());
    if !p.can(perm, Some(&tenant)) {
        return Err(StatusCode::FORBIDDEN.into_response());
    }
    note_break_glass(st, &p, &tenant, label).await;
    Ok((p, tenant))
}

/// Platform-level operation (tenant lifecycle, user directory, list refresh).
async fn guard_platform(
    st: &AppState,
    h: &HeaderMap,
    perm: Permission,
    label: &str,
) -> Result<Principal, Response> {
    let p = authn(st, h).await?;
    if !p.can(perm, None) {
        return Err(StatusCode::FORBIDDEN.into_response());
    }
    note_break_glass(st, &p, DEFAULT_TENANT, label).await;
    Ok(p)
}

/// Every break-glass request leaves a record in the audit chain of the tenant it touched.
async fn note_break_glass(st: &AppState, p: &Principal, tenant: &str, label: &str) {
    if p.is_break_glass() {
        tracing::warn!(label, tenant, "BREAK-GLASS credential used");
        st.record(tenant, &p.actor(), "auth.break_glass", label, None)
            .await;
    }
}

/// Map store failures to HTTP without leaking backend details to clients.
fn store_err(e: StoreError) -> Response {
    match e {
        StoreError::NotFound => StatusCode::NOT_FOUND.into_response(),
        StoreError::Conflict => StatusCode::CONFLICT.into_response(),
        StoreError::InvalidToken => StatusCode::UNAUTHORIZED.into_response(),
        other => {
            tracing::error!(error = %other, "store error");
            StatusCode::INTERNAL_SERVER_ERROR.into_response()
        }
    }
}

macro_rules! ok_or {
    ($e:expr) => {
        match $e {
            Ok(v) => v,
            Err(e) => return store_err(e),
        }
    };
}
macro_rules! gate {
    ($e:expr) => {
        match $e {
            Ok(v) => v,
            Err(r) => return r,
        }
    };
}

// ---------------------------------------------------------------- data plane

async fn pubkey(State(st): S) -> String {
    st.signing_key
        .verifying_key()
        .to_bytes()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

#[derive(Deserialize)]
struct EnrollReq {
    token: String,
    #[serde(default)]
    device_info: String,
}

async fn enroll(State(st): S, headers: HeaderMap, Json(req): Json<EnrollReq>) -> Response {
    // Informational only (not authenticated): which relay node vouched for this enrolment.
    let via = headers
        .get("x-hygeia-node")
        .and_then(|v| v.to_str().ok())
        .filter(|v| {
            !v.is_empty()
                && v.len() <= 64
                && v.bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
        })
        .map(str::to_string);
    match st.store.enroll(&req.token, &req.device_info, now()).await {
        Ok((dev, secret)) => {
            st.record(
                &dev.tenant_id,
                &dev.id,
                "device.enroll",
                &dev.id,
                Some(json!({"info": dev.info, "via_node": via})),
            )
            .await;
            Json(json!({"device_id": dev.id, "device_secret": secret})).into_response()
        }
        // Single generic error: do not reveal why a token was rejected.
        Err(StoreError::InvalidToken | StoreError::NotFound) => {
            StatusCode::UNAUTHORIZED.into_response()
        }
        Err(e) => store_err(e),
    }
}

async fn bundle(State(st): S, headers: HeaderMap) -> Response {
    let Some(secret) = bearer(&headers) else {
        return StatusCode::UNAUTHORIZED.into_response();
    };
    let dev = match st.store.authenticate_device(secret, now()).await {
        Ok(Some(d)) => d,
        Ok(None) => return StatusCode::UNAUTHORIZED.into_response(),
        Err(e) => return store_err(e),
    };
    let b: Arc<SignedBundle> = ok_or!(st.bundle_for(&dev.tenant_id, &dev.group_id).await);
    let etag = b.etag();
    let not_modified = headers
        .get(header::IF_NONE_MATCH)
        .and_then(|v| v.to_str().ok())
        .is_some_and(|v| v == etag);
    if not_modified {
        return (StatusCode::NOT_MODIFIED, [(header::ETAG, etag)]).into_response();
    }
    (
        [
            (header::ETAG, etag),
            (
                header::CONTENT_TYPE,
                "application/vnd.hygeia.bundle".to_string(),
            ),
            (header::CACHE_CONTROL, "private, no-cache".to_string()),
        ],
        b.0.clone(),
    )
        .into_response()
}

// ---------------------------------------------------------------- identity

async fn public_config(State(st): S) -> Response {
    Json(&st.public).into_response()
}

async fn me(State(st): S, h: HeaderMap) -> Response {
    let p = gate!(authn(&st, &h).await);
    Json(p).into_response()
}

// ---------------------------------------------------------------- tenants, groups, users

#[derive(Deserialize)]
struct NewTenant {
    slug: String,
    name: String,
}

async fn create_tenant(State(st): S, h: HeaderMap, Json(r): Json<NewTenant>) -> Response {
    let p = gate!(guard_platform(&st, &h, Permission::TenantsManage, "tenant.create").await);
    let t = ok_or!(st.store.create_tenant(&r.slug, &r.name).await);
    st.record(
        &t.id,
        &p.actor(),
        "tenant.create",
        &t.id,
        Some(json!({"after": t})),
    )
    .await;
    (StatusCode::CREATED, Json(t)).into_response()
}

async fn list_tenants(State(st): S, h: HeaderMap) -> Response {
    gate!(guard_platform(&st, &h, Permission::TenantsManage, "tenant.list").await);
    Json(ok_or!(st.store.list_tenants().await)).into_response()
}

#[derive(Deserialize)]
struct TenantQ {
    tenant_id: Option<String>,
}

#[derive(Deserialize)]
struct NewGroup {
    tenant_id: Option<String>,
    name: String,
}

async fn create_group(State(st): S, h: HeaderMap, Json(r): Json<NewGroup>) -> Response {
    let (p, tenant) = gate!(
        guard(
            &st,
            &h,
            Permission::GroupsManage,
            r.tenant_id,
            "group.create"
        )
        .await
    );
    let g = ok_or!(st.store.create_group(&tenant, &r.name).await);
    st.record(
        &tenant,
        &p.actor(),
        "group.create",
        &g.id,
        Some(json!({"after": g})),
    )
    .await;
    (StatusCode::CREATED, Json(g)).into_response()
}

async fn list_groups(State(st): S, h: HeaderMap, Query(q): Query<TenantQ>) -> Response {
    let (_, tenant) = gate!(guard(&st, &h, Permission::RulesRead, q.tenant_id, "group.list").await);
    Json(ok_or!(st.store.list_groups(&tenant).await)).into_response()
}

async fn list_users(State(st): S, h: HeaderMap) -> Response {
    gate!(guard_platform(&st, &h, Permission::TenantsManage, "user.list").await);
    Json(ok_or!(st.store.list_users().await)).into_response()
}

// ---------------------------------------------------------------- role bindings

#[derive(Deserialize)]
struct NewBinding {
    user_id: String,
    /// Omit for a platform-wide binding (requires platform scope).
    tenant_id: Option<String>,
    role: Role,
}

async fn add_binding(State(st): S, h: HeaderMap, Json(r): Json<NewBinding>) -> Response {
    let p = gate!(authn(&st, &h).await);
    let scope = r.tenant_id.as_deref();
    // Managing users needs UsersManage in that scope; platform-wide bindings need platform scope.
    if !p.can(Permission::UsersManage, scope) || !p.can_grant(r.role, scope) {
        return StatusCode::FORBIDDEN.into_response();
    }
    // `owner` exists only as a platform role.
    if r.role == Role::Owner && scope.is_some() {
        return (
            StatusCode::UNPROCESSABLE_ENTITY,
            "owner is a platform-wide role",
        )
            .into_response();
    }
    note_break_glass(&st, &p, scope.unwrap_or(DEFAULT_TENANT), "binding.create").await;
    let b = ok_or!(st.store.bind_role(&r.user_id, scope, r.role).await);
    st.record(
        scope.unwrap_or(DEFAULT_TENANT),
        &p.actor(),
        "binding.create",
        &b.id,
        Some(json!({"after": b})),
    )
    .await;
    (StatusCode::CREATED, Json(b)).into_response()
}

async fn list_bindings(State(st): S, h: HeaderMap, Query(q): Query<TenantQ>) -> Response {
    let (_, tenant) = gate!(
        guard(
            &st,
            &h,
            Permission::UsersManage,
            q.tenant_id,
            "binding.list"
        )
        .await
    );
    Json(ok_or!(st.store.list_bindings(Some(&tenant)).await)).into_response()
}

async fn remove_binding(
    State(st): S,
    h: HeaderMap,
    Path(id): Path<String>,
    Query(q): Query<TenantQ>,
) -> Response {
    let (p, tenant) = gate!(
        guard(
            &st,
            &h,
            Permission::UsersManage,
            q.tenant_id,
            "binding.delete"
        )
        .await
    );
    // Only bindings of the named tenant can be removed through it.
    let bindings = ok_or!(st.store.list_bindings(Some(&tenant)).await);
    let Some(b) = bindings.into_iter().find(|b| b.id == id) else {
        return StatusCode::NOT_FOUND.into_response();
    };
    ok_or!(st.store.unbind_role(&id).await);
    st.record(
        &tenant,
        &p.actor(),
        "binding.delete",
        &id,
        Some(json!({"before": b})),
    )
    .await;
    StatusCode::NO_CONTENT.into_response()
}

// ---------------------------------------------------------------- API tokens

#[derive(Deserialize)]
struct NewApiToken {
    tenant_id: Option<String>,
    name: String,
    role: Role,
    ttl_secs: Option<i64>,
}

async fn create_api_token(State(st): S, h: HeaderMap, Json(r): Json<NewApiToken>) -> Response {
    let (p, tenant) = gate!(
        guard(
            &st,
            &h,
            Permission::ApiTokensManage,
            r.tenant_id,
            "api-token.create"
        )
        .await
    );
    if r.role == Role::Owner || !p.can_grant(r.role, Some(&tenant)) {
        return StatusCode::FORBIDDEN.into_response();
    }
    let expires = r.ttl_secs.map(|t| now().saturating_add(t));
    let (t, secret) = ok_or!(
        st.store
            .create_api_token(&tenant, &r.name, r.role, expires)
            .await
    );
    // The secret is NOT in the audit diff.
    st.record(
        &tenant,
        &p.actor(),
        "api-token.create",
        &t.id,
        Some(json!({"after": t})),
    )
    .await;
    (
        StatusCode::CREATED,
        Json(json!({"id": t.id, "token": secret, "role": t.role, "expires_at": t.expires_at})),
    )
        .into_response()
}

async fn list_api_tokens(State(st): S, h: HeaderMap, Query(q): Query<TenantQ>) -> Response {
    let (_, tenant) = gate!(
        guard(
            &st,
            &h,
            Permission::ApiTokensManage,
            q.tenant_id,
            "api-token.list"
        )
        .await
    );
    Json(ok_or!(st.store.list_api_tokens(&tenant).await)).into_response()
}

async fn revoke_api_token(
    State(st): S,
    h: HeaderMap,
    Path(id): Path<String>,
    Query(q): Query<TenantQ>,
) -> Response {
    let (p, tenant) = gate!(
        guard(
            &st,
            &h,
            Permission::ApiTokensManage,
            q.tenant_id,
            "api-token.revoke"
        )
        .await
    );
    ok_or!(st.store.revoke_api_token(&tenant, &id).await);
    st.record(&tenant, &p.actor(), "api-token.revoke", &id, None)
        .await;
    StatusCode::NO_CONTENT.into_response()
}

// ---------------------------------------------------------------- devices, enrollment

#[derive(Deserialize)]
struct NewToken {
    tenant_id: Option<String>,
    #[serde(default = "d_group")]
    group_id: String,
    #[serde(default = "d_ttl")]
    ttl_secs: i64,
    max_uses: Option<u32>,
}
fn d_group() -> String {
    DEFAULT_GROUP.into()
}
fn d_ttl() -> i64 {
    3600
}

async fn create_token(State(st): S, h: HeaderMap, Json(r): Json<NewToken>) -> Response {
    let (p, tenant) = gate!(
        guard(
            &st,
            &h,
            Permission::TokensManage,
            r.tenant_id,
            "enrollment-token.create"
        )
        .await
    );
    let (t, secret) = ok_or!(
        st.store
            .create_enrollment_token(&tenant, &r.group_id, r.ttl_secs, r.max_uses, now())
            .await
    );
    // The secret is deliberately NOT in the audit diff.
    st.record(
        &tenant,
        &p.actor(),
        "token.create",
        &t.id,
        Some(json!({"group": r.group_id, "expires_at": t.expires_at, "max_uses": r.max_uses})),
    )
    .await;
    Json(json!({"id": t.id, "token": secret, "expires_at": t.expires_at})).into_response()
}

async fn list_devices(State(st): S, h: HeaderMap, Query(q): Query<TenantQ>) -> Response {
    let (_, tenant) =
        gate!(guard(&st, &h, Permission::DevicesRead, q.tenant_id, "device.list").await);
    Json(ok_or!(st.store.list_devices(&tenant).await)).into_response()
}

async fn revoke_device(
    State(st): S,
    h: HeaderMap,
    Path(id): Path<String>,
    Query(q): Query<TenantQ>,
) -> Response {
    let (p, tenant) = gate!(
        guard(
            &st,
            &h,
            Permission::DevicesManage,
            q.tenant_id,
            "device.revoke"
        )
        .await
    );
    ok_or!(st.store.revoke_device(&tenant, &id).await);
    st.record(&tenant, &p.actor(), "device.revoke", &id, None)
        .await;
    StatusCode::NO_CONTENT.into_response()
}

// ---------------------------------------------------------------- rules

async fn list_rules(State(st): S, h: HeaderMap, Query(q): Query<TenantQ>) -> Response {
    let (_, tenant) = gate!(guard(&st, &h, Permission::RulesRead, q.tenant_id, "rule.list").await);
    Json(ok_or!(st.store.list_rules(&tenant).await)).into_response()
}

#[derive(Deserialize)]
struct NewRule {
    tenant_id: Option<String>,
    group_id: Option<String>,
    action: RuleAction,
    pattern: String,
    #[serde(default)]
    comment: String,
}

async fn add_rule(State(st): S, h: HeaderMap, Json(r): Json<NewRule>) -> Response {
    let (p, tenant) =
        gate!(guard(&st, &h, Permission::RulesWrite, r.tenant_id, "rule.create").await);
    if hygeia_core::normalize(&r.pattern).is_none() {
        return (StatusCode::UNPROCESSABLE_ENTITY, "invalid domain pattern").into_response();
    }
    let rule = ok_or!(
        st.store
            .add_rule(Rule {
                id: String::new(),
                tenant_id: tenant.clone(),
                group_id: r.group_id,
                action: r.action,
                pattern: r.pattern,
                comment: r.comment,
            })
            .await
    );
    st.invalidate();
    st.record(
        &tenant,
        &p.actor(),
        "rule.create",
        &rule.id,
        Some(json!({"after": rule})),
    )
    .await;
    (StatusCode::CREATED, Json(rule)).into_response()
}

async fn delete_rule(
    State(st): S,
    h: HeaderMap,
    Path(id): Path<String>,
    Query(q): Query<TenantQ>,
) -> Response {
    let (p, tenant) =
        gate!(guard(&st, &h, Permission::RulesWrite, q.tenant_id, "rule.delete").await);
    let rule = ok_or!(st.store.delete_rule(&tenant, &id).await);
    st.invalidate();
    st.record(
        &tenant,
        &p.actor(),
        "rule.delete",
        &id,
        Some(json!({"before": rule})),
    )
    .await;
    StatusCode::NO_CONTENT.into_response()
}

// ---------------------------------------------------------------- lists

async fn lists_status(State(st): S, h: HeaderMap) -> Response {
    let p = gate!(authn(&st, &h).await);
    if !p.can_anywhere(Permission::RulesRead) {
        return StatusCode::FORBIDDEN.into_response();
    }
    Json(st.list_status()).into_response()
}

async fn lists_refresh(State(st): S, h: HeaderMap) -> Response {
    gate!(guard_platform(&st, &h, Permission::TenantsManage, "lists.refresh").await);
    st.refresh_requested.notify_one();
    StatusCode::ACCEPTED.into_response()
}

// ---------------------------------------------------------------- per-tenant list selection

async fn list_subscriptions(State(st): S, h: HeaderMap, Query(q): Query<TenantQ>) -> Response {
    let (_, tenant) = gate!(
        guard(
            &st,
            &h,
            Permission::RulesRead,
            q.tenant_id,
            "list-subscription.list"
        )
        .await
    );
    let policy = ok_or!(st.store.list_policy(&tenant).await);
    let subs = ok_or!(st.store.subscriptions(&tenant).await);
    let available: Vec<_> = st
        .available_sources()
        .into_iter()
        .map(|m| json!({"id": m.id, "name": m.name, "license": m.license}))
        .collect();
    Json(json!({"policy": policy, "subscriptions": subs, "available": available})).into_response()
}

#[derive(Deserialize)]
struct PolicyReq {
    tenant_id: Option<String>,
    policy: hygeia_store::ListPolicy,
}

async fn set_list_policy(State(st): S, h: HeaderMap, Json(r): Json<PolicyReq>) -> Response {
    let (p, tenant) = gate!(
        guard(
            &st,
            &h,
            Permission::RulesWrite,
            r.tenant_id,
            "list-policy.set"
        )
        .await
    );
    let before = ok_or!(st.store.list_policy(&tenant).await);
    ok_or!(st.store.set_list_policy(&tenant, r.policy).await);
    st.invalidate();
    st.record(
        &tenant,
        &p.actor(),
        "lists.policy",
        &tenant,
        Some(json!({"before": before, "after": r.policy})),
    )
    .await;
    StatusCode::NO_CONTENT.into_response()
}

#[derive(Deserialize)]
struct SubReq {
    tenant_id: Option<String>,
    group_id: Option<String>,
    source_id: String,
}

async fn subscribe(State(st): S, h: HeaderMap, Json(r): Json<SubReq>) -> Response {
    let (p, tenant) = gate!(
        guard(
            &st,
            &h,
            Permission::RulesWrite,
            r.tenant_id,
            "list-subscription.create"
        )
        .await
    );
    if !st.available_sources().iter().any(|m| m.id == r.source_id) {
        return (
            StatusCode::UNPROCESSABLE_ENTITY,
            "unknown or disabled list source",
        )
            .into_response();
    }
    ok_or!(
        st.store
            .subscribe(&tenant, r.group_id.as_deref(), &r.source_id)
            .await
    );
    st.invalidate();
    st.record(
        &tenant,
        &p.actor(),
        "lists.subscribe",
        &r.source_id,
        Some(json!({"group": r.group_id})),
    )
    .await;
    StatusCode::NO_CONTENT.into_response()
}

#[derive(Deserialize)]
struct UnsubQ {
    tenant_id: Option<String>,
    group_id: Option<String>,
    source_id: String,
}

async fn unsubscribe(State(st): S, h: HeaderMap, Query(q): Query<UnsubQ>) -> Response {
    let (p, tenant) = gate!(
        guard(
            &st,
            &h,
            Permission::RulesWrite,
            q.tenant_id,
            "list-subscription.delete"
        )
        .await
    );
    ok_or!(
        st.store
            .unsubscribe(&tenant, q.group_id.as_deref(), &q.source_id)
            .await
    );
    st.invalidate();
    st.record(
        &tenant,
        &p.actor(),
        "lists.unsubscribe",
        &q.source_id,
        Some(json!({"group": q.group_id})),
    )
    .await;
    StatusCode::NO_CONTENT.into_response()
}

// ---------------------------------------------------------------- simulate

#[derive(Deserialize)]
struct SimReq {
    tenant_id: Option<String>,
    #[serde(default = "d_group")]
    group_id: String,
    host: String,
    /// Dry-run: extra rules evaluated as if they were saved (not persisted).
    #[serde(default)]
    extra_rules: Vec<SimRule>,
}
#[derive(Deserialize)]
struct SimRule {
    action: RuleAction,
    pattern: String,
}

#[derive(Serialize)]
struct SimResp {
    current: hygeia_core::Verdict,
    with_changes: hygeia_core::Verdict,
}

/// "What would happen if": evaluates a host against the current bundle, and
/// against the bundle plus uncommitted rules.
async fn simulate(State(st): S, h: HeaderMap, Json(r): Json<SimReq>) -> Response {
    let (_, tenant) = gate!(guard(&st, &h, Permission::RulesRead, r.tenant_id, "simulate").await);
    let signed = ok_or!(st.bundle_for(&tenant, &r.group_id).await);
    let Ok(bundle) = SignedBundle::open(&signed.0, &st.signing_key.verifying_key()) else {
        return StatusCode::INTERNAL_SERVER_ERROR.into_response();
    };
    let current = Ruleset::from_data(&bundle.network).evaluate(&r.host);
    let mut data: RulesetData = bundle.network;
    for e in &r.extra_rules {
        if let Some(p) = hygeia_core::normalize(&e.pattern) {
            match e.action {
                RuleAction::Allow => data.custom_allow.push(p),
                RuleAction::Block => data.custom_block.push(p),
            }
        }
    }
    let with_changes = Ruleset::from_data(&data).evaluate(&r.host);
    Json(SimResp {
        current,
        with_changes,
    })
    .into_response()
}

// ---------------------------------------------------------------- audit

#[derive(Deserialize)]
struct AuditQ {
    tenant_id: Option<String>,
    #[serde(default = "d_limit")]
    limit: u32,
}
fn d_limit() -> u32 {
    200
}

async fn audit(State(st): S, h: HeaderMap, Query(q): Query<AuditQ>) -> Response {
    let (_, tenant) = gate!(guard(&st, &h, Permission::AuditRead, q.tenant_id, "audit.read").await);
    Json(ok_or!(
        st.store.list_audit(&tenant, q.limit.min(1000)).await
    ))
    .into_response()
}

async fn audit_verify(State(st): S, h: HeaderMap, Query(q): Query<TenantQ>) -> Response {
    let (_, tenant) =
        gate!(guard(&st, &h, Permission::AuditRead, q.tenant_id, "audit.verify").await);
    match st.store.verify_audit(&tenant).await {
        Ok(s) => Json(json!({"ok": true, "head": s.head, "events": s.events})).into_response(),
        Err(StoreError::Chain(e)) => {
            (StatusCode::CONFLICT, Json(json!({"ok": false, "error": e}))).into_response()
        }
        Err(e) => store_err(e),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth::{AuthConfig, BreakGlass};
    use crate::oidc::{OidcConfig, OidcVerifier};
    use axum::body::Body;
    use axum::http::Request;
    use ed25519_dalek::SigningKey;
    use http_body_util::BodyExt;
    use hygeia_store::{MemoryStore, Store};
    use tower::ServiceExt;

    const ADMIN: &str = "break-glass-secret-0123456789-abcdefghij";
    const EC_KEY: &str = "-----BEGIN PRIVATE KEY-----\nMIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgTqNA8KqOem7Q9HxJ\nqamBxx8isBNRHhW6ah265O/be++hRANCAAR/0MK4G9AeQtccDZy6CB4bZbUgidiq\n4DHAc5x7JREX3l5ggMoFU5nuMKGK8ZAQM31lkUEz1SKzPP+F18bIQu78\n-----END PRIVATE KEY-----";
    const EC_KEY_OTHER: &str = "-----BEGIN PRIVATE KEY-----\nMIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgIIG4/vTfKgagctoS\nVb4gJJlEkxkToqhaE1A1ivrWu0ShRANCAAS3wg5JYQD9oeH/fX79mtt5yv2DyrYy\n8GIGrhI9ocIX3KEN0Bp43MISYWU+vwklktrtGYaq3USFJtFlAfyeBGcb\n-----END PRIVATE KEY-----";
    const JWK_X: &str = "f9DCuBvQHkLXHA2cuggeG2W1IInYquAxwHOceyURF94";
    const JWK_Y: &str = "XmCAygVTme4woYrxkBAzfWWRQTPVIrM8_4XXxshC7vw";

    fn state(store: Arc<dyn Store>, oidc: Option<OidcVerifier>) -> Arc<AppState> {
        Arc::new(AppState::new(
            store,
            SigningKey::from_bytes(&[1u8; 32]),
            AuthConfig {
                break_glass: Some(BreakGlass::new(ADMIN, None).unwrap()),
                oidc,
                ..Default::default()
            },
        ))
    }

    fn app() -> (Router, Arc<AppState>) {
        let st = state(Arc::new(MemoryStore::new()), None);
        (router(st.clone()), st)
    }

    async fn call(
        app: &Router,
        method: &str,
        uri: &str,
        auth: Option<&str>,
        body: Option<serde_json::Value>,
    ) -> (StatusCode, HeaderMap, Vec<u8>) {
        let mut rb = Request::builder().method(method).uri(uri);
        if let Some(a) = auth {
            rb = rb.header("authorization", format!("Bearer {a}"));
        }
        let req = if let Some(b) = body {
            rb.header("content-type", "application/json")
                .body(Body::from(b.to_string()))
                .unwrap()
        } else {
            rb.body(Body::empty()).unwrap()
        };
        let resp = app.clone().oneshot(req).await.unwrap();
        let (p, b) = resp.into_parts();
        (
            p.status,
            p.headers,
            b.collect().await.unwrap().to_bytes().to_vec(),
        )
    }

    fn j(b: &[u8]) -> serde_json::Value {
        serde_json::from_slice(b).unwrap()
    }

    #[tokio::test]
    async fn full_flow_with_break_glass() {
        let (app, st) = app();
        assert_eq!(
            call(&app, "GET", "/v1/admin/rules", None, None).await.0,
            StatusCode::UNAUTHORIZED
        );
        assert_eq!(
            call(&app, "GET", "/v1/admin/rules", Some("nope"), None)
                .await
                .0,
            StatusCode::UNAUTHORIZED
        );

        let (s, _, b) = call(
            &app,
            "POST",
            "/v1/admin/enrollment-tokens",
            Some(ADMIN),
            Some(json!({"max_uses": 1})),
        )
        .await;
        assert_eq!(s, StatusCode::OK);
        let token = j(&b)["token"].as_str().unwrap().to_string();

        let (s, _, b) = call(
            &app,
            "POST",
            "/v1/enroll",
            None,
            Some(json!({"token": token, "device_info": "test"})),
        )
        .await;
        assert_eq!(s, StatusCode::OK);
        let dev = j(&b);
        let dsecret = dev["device_secret"].as_str().unwrap().to_string();
        assert_eq!(
            call(
                &app,
                "POST",
                "/v1/enroll",
                None,
                Some(json!({"token": token}))
            )
            .await
            .0,
            StatusCode::UNAUTHORIZED
        );
        assert_eq!(
            call(&app, "GET", "/v1/bundle", None, None).await.0,
            StatusCode::UNAUTHORIZED
        );
        // a device credential must not open the admin API
        assert_eq!(
            call(&app, "GET", "/v1/admin/rules", Some(&dsecret), None)
                .await
                .0,
            StatusCode::UNAUTHORIZED
        );

        let (s, _, _) = call(
            &app,
            "POST",
            "/v1/admin/rules",
            Some(ADMIN),
            Some(json!({"action": "block", "pattern": "ads.example.com"})),
        )
        .await;
        assert_eq!(s, StatusCode::CREATED);
        let (s, h, body) = call(&app, "GET", "/v1/bundle", Some(&dsecret), None).await;
        assert_eq!(s, StatusCode::OK);
        let bundle = SignedBundle::open(&body, &st.signing_key.verifying_key()).unwrap();
        assert_eq!(bundle.network.custom_block, vec!["ads.example.com"]);
        let etag = h.get("etag").unwrap().to_str().unwrap().to_string();

        let req = Request::builder()
            .uri("/v1/bundle")
            .header("authorization", format!("Bearer {dsecret}"))
            .header("if-none-match", &etag)
            .body(Body::empty())
            .unwrap();
        assert_eq!(
            app.clone().oneshot(req).await.unwrap().status(),
            StatusCode::NOT_MODIFIED
        );

        let (_, _, b) = call(&app, "POST", "/v1/admin/simulate", Some(ADMIN),
            Some(json!({"host": "x.ads.example.com", "extra_rules": [{"action": "allow", "pattern": "x.ads.example.com"}]}))).await;
        assert_eq!(j(&b)["current"]["action"], "Block");
        assert_eq!(j(&b)["with_changes"]["action"], "Allow");

        let id = dev["device_id"].as_str().unwrap();
        assert_eq!(
            call(
                &app,
                "DELETE",
                &format!("/v1/admin/devices/{id}"),
                Some(ADMIN),
                None
            )
            .await
            .0,
            StatusCode::NO_CONTENT
        );
        assert_eq!(
            call(&app, "GET", "/v1/bundle", Some(&dsecret), None)
                .await
                .0,
            StatusCode::UNAUTHORIZED
        );

        // audit: chain intact, secrets absent, every break-glass use recorded
        assert_eq!(
            call(&app, "GET", "/v1/admin/audit/verify", Some(ADMIN), None)
                .await
                .0,
            StatusCode::OK
        );
        let (_, _, b) = call(&app, "GET", "/v1/admin/audit", Some(ADMIN), None).await;
        let text = String::from_utf8(b).unwrap();
        assert!(!text.contains(&token) && !text.contains(&dsecret) && !text.contains(ADMIN));
        assert!(text.contains("rule.create") && text.contains("device.revoke"));
        assert!(
            text.matches("auth.break_glass").count() >= 4,
            "break-glass use must be audited"
        );
        assert!(text.contains("\"actor\":\"break-glass\""));
    }

    #[tokio::test]
    async fn local_owner_is_owner_without_break_glass_noise() {
        let local = "local-owner-secret-0123456789-abcdefghij";
        let st = Arc::new(AppState::new(
            Arc::new(MemoryStore::new()),
            SigningKey::from_bytes(&[1u8; 32]),
            AuthConfig {
                local_owner: Some(crate::auth::LocalOwner::new(local).unwrap()),
                ..Default::default()
            },
        ));
        st.store.bootstrap_default().await.unwrap();
        let app = router(st);
        assert!(crate::auth::LocalOwner::new("short").is_err());
        assert_eq!(
            call(
                &app,
                "GET",
                "/v1/me",
                Some("nope-nope-nope-nope-nope-nope-nope-no"),
                None
            )
            .await
            .0,
            StatusCode::UNAUTHORIZED
        );
        let (s, _, b) = call(&app, "GET", "/v1/me", Some(local), None).await;
        assert_eq!(s, StatusCode::OK);
        assert_eq!(j(&b)["kind"], "local_owner");
        assert_eq!(
            call(
                &app,
                "POST",
                "/v1/admin/rules",
                Some(local),
                Some(json!({"action": "block", "pattern": "a.test"}))
            )
            .await
            .0,
            StatusCode::CREATED
        );
        assert_eq!(
            call(
                &app,
                "POST",
                "/v1/admin/tenants",
                Some(local),
                Some(json!({"slug": "x", "name": "X"}))
            )
            .await
            .0,
            StatusCode::CREATED
        );
        let (_, _, b) = call(&app, "GET", "/v1/admin/audit", Some(local), None).await;
        let text = String::from_utf8(b).unwrap();
        assert!(text.contains(r#""actor":"local-owner""#) && !text.contains("auth.break_glass"));
    }

    #[tokio::test]
    async fn expired_break_glass_is_rejected() {
        let st = Arc::new(AppState::new(
            Arc::new(MemoryStore::new()),
            SigningKey::from_bytes(&[1u8; 32]),
            AuthConfig {
                break_glass: Some(BreakGlass::new(ADMIN, Some(Duration::ZERO)).unwrap()),
                oidc: None,
                ..Default::default()
            },
        ));
        let app = router(st);
        assert_eq!(
            call(&app, "GET", "/v1/me", Some(ADMIN), None).await.0,
            StatusCode::UNAUTHORIZED
        );
    }

    #[tokio::test]
    async fn api_tokens_are_tenant_scoped_and_cannot_escalate() {
        let (app, _) = app();
        let (_, _, b) = call(
            &app,
            "POST",
            "/v1/admin/tenants",
            Some(ADMIN),
            Some(json!({"slug": "acme", "name": "Acme"})),
        )
        .await;
        let acme = j(&b)["id"].as_str().unwrap().to_string();
        let (_, _, b) = call(
            &app,
            "POST",
            "/v1/admin/tenants",
            Some(ADMIN),
            Some(json!({"slug": "beta", "name": "Beta"})),
        )
        .await;
        let beta = j(&b)["id"].as_str().unwrap().to_string();
        assert_eq!(
            call(
                &app,
                "POST",
                "/v1/admin/tenants",
                Some(ADMIN),
                Some(json!({"slug": "acme", "name": "dup"}))
            )
            .await
            .0,
            StatusCode::CONFLICT
        );

        // admin token for acme
        let (s, _, b) = call(
            &app,
            "POST",
            "/v1/admin/api-tokens",
            Some(ADMIN),
            Some(json!({"tenant_id": acme, "name": "ops", "role": "admin"})),
        )
        .await;
        assert_eq!(s, StatusCode::CREATED);
        let admin_tok = j(&b)["token"].as_str().unwrap().to_string();
        // editor token for acme, created BY the acme admin
        let (s, _, b) = call(
            &app,
            "POST",
            "/v1/admin/api-tokens",
            Some(&admin_tok),
            Some(json!({"name": "ci", "role": "editor"})),
        )
        .await;
        assert_eq!(s, StatusCode::CREATED);
        let editor_tok = j(&b)["token"].as_str().unwrap().to_string();

        // tenant admin cannot create owner tokens, nor touch tenant lifecycle, nor other tenants
        assert_eq!(
            call(
                &app,
                "POST",
                "/v1/admin/api-tokens",
                Some(&admin_tok),
                Some(json!({"name": "x", "role": "owner"}))
            )
            .await
            .0,
            StatusCode::FORBIDDEN
        );
        assert_eq!(
            call(
                &app,
                "POST",
                "/v1/admin/tenants",
                Some(&admin_tok),
                Some(json!({"slug": "evil", "name": "x"}))
            )
            .await
            .0,
            StatusCode::FORBIDDEN
        );
        assert_eq!(
            call(
                &app,
                "GET",
                &format!("/v1/admin/rules?tenant_id={beta}"),
                Some(&admin_tok),
                None
            )
            .await
            .0,
            StatusCode::FORBIDDEN
        );
        assert_eq!(
            call(&app, "GET", "/v1/admin/users", Some(&admin_tok), None)
                .await
                .0,
            StatusCode::FORBIDDEN
        );

        // editor: can write rules (defaults to its own tenant), cannot read audit, cannot mint tokens
        assert_eq!(
            call(
                &app,
                "POST",
                "/v1/admin/rules",
                Some(&editor_tok),
                Some(json!({"action": "block", "pattern": "a.test"}))
            )
            .await
            .0,
            StatusCode::CREATED
        );
        let (_, _, b) = call(&app, "GET", "/v1/admin/rules", Some(&editor_tok), None).await;
        assert_eq!(j(&b).as_array().unwrap().len(), 1);
        assert_eq!(
            call(
                &app,
                "GET",
                &format!("/v1/admin/rules?tenant_id={beta}"),
                Some(&editor_tok),
                None
            )
            .await
            .0,
            StatusCode::FORBIDDEN
        );
        assert_eq!(
            call(&app, "GET", "/v1/admin/audit", Some(&editor_tok), None)
                .await
                .0,
            StatusCode::FORBIDDEN
        );
        assert_eq!(
            call(
                &app,
                "POST",
                "/v1/admin/api-tokens",
                Some(&editor_tok),
                Some(json!({"name": "y", "role": "viewer"}))
            )
            .await
            .0,
            StatusCode::FORBIDDEN
        );

        // the rule landed in acme, not in the default tenant
        let (_, _, b) = call(
            &app,
            "GET",
            &format!("/v1/admin/rules?tenant_id={acme}"),
            Some(ADMIN),
            None,
        )
        .await;
        assert_eq!(j(&b).as_array().unwrap().len(), 1);
        let (_, _, b) = call(&app, "GET", "/v1/admin/rules", Some(ADMIN), None).await;
        assert_eq!(j(&b).as_array().unwrap().len(), 0);

        // revocation
        let (_, _, b) = call(&app, "GET", "/v1/admin/api-tokens", Some(&admin_tok), None).await;
        let ed_id = j(&b)
            .as_array()
            .unwrap()
            .iter()
            .find(|t| t["name"] == "ci")
            .unwrap()["id"]
            .as_str()
            .unwrap()
            .to_string();
        assert_eq!(
            call(
                &app,
                "DELETE",
                &format!("/v1/admin/api-tokens/{ed_id}"),
                Some(&admin_tok),
                None
            )
            .await
            .0,
            StatusCode::NO_CONTENT
        );
        assert_eq!(
            call(&app, "GET", "/v1/me", Some(&editor_tok), None).await.0,
            StatusCode::UNAUTHORIZED
        );
    }

    #[tokio::test]
    async fn lists_flow_into_bundle() {
        use hygeia_core::cosmetic::{CosmeticRules, HostRules, ScriptletCall};
        use hygeia_core::{ParsedSource, SourceMeta};
        let (app, st) = app();
        let mut cos = CosmeticRules {
            generic: vec![".ad".into()],
            ..Default::default()
        };
        cos.by_host.insert(
            "a.com".into(),
            HostRules {
                scriptlets: vec![ScriptletCall {
                    name: "set-constant".into(),
                    args: vec!["x".into(), "1".into()],
                }],
                ..Default::default()
            },
        );
        st.set_lists(
            vec![Arc::new(ParsedSource {
                meta: SourceMeta {
                    id: "l1".into(),
                    name: "L1".into(),
                    url: "https://x".into(),
                    license: "MIT".into(),
                    attribution: "me".into(),
                },
                allow: vec![],
                block: vec!["tracker.test".into()],
                cosmetic: cos,
            })],
            json!([{"id": "l1", "license": "MIT"}]),
        )
        .await
        .unwrap();
        let b = st.bundle_for(DEFAULT_TENANT, DEFAULT_GROUP).await.unwrap();
        let bundle = SignedBundle::open(&b.0, &st.signing_key.verifying_key()).unwrap();
        assert_eq!(bundle.network.lists[0].block, vec!["tracker.test"]);
        assert_eq!(bundle.cosmetic.generic, vec![".ad"]);
        assert_eq!(
            bundle.cosmetic.by_host["a.com"].scriptlets[0].name,
            "set-constant"
        );
        assert_eq!(bundle.meta.sources[0].license, "MIT");

        assert_eq!(
            call(&app, "GET", "/v1/admin/lists", None, None).await.0,
            StatusCode::UNAUTHORIZED
        );
        let (s, _, body) = call(&app, "GET", "/v1/admin/lists", Some(ADMIN), None).await;
        assert_eq!(s, StatusCode::OK);
        assert!(String::from_utf8(body).unwrap().contains("\"MIT\""));
        assert_eq!(
            call(&app, "POST", "/v1/admin/lists/refresh", Some(ADMIN), None)
                .await
                .0,
            StatusCode::ACCEPTED
        );
    }

    #[tokio::test]
    async fn list_selection_per_tenant_and_group() {
        use hygeia_core::cosmetic::CosmeticRules;
        use hygeia_core::{ParsedSource, SourceMeta};
        let (app, st) = app();
        st.store.bootstrap_default().await.unwrap();
        let mk = |id: &str, domain: &str| {
            Arc::new(ParsedSource {
                meta: SourceMeta {
                    id: id.into(),
                    name: id.into(),
                    url: format!("https://x/{id}"),
                    license: "MIT".into(),
                    attribution: "me".into(),
                },
                allow: vec![],
                block: vec![domain.into()],
                cosmetic: CosmeticRules::default(),
            })
        };
        st.set_lists(vec![mk("l1", "a.test"), mk("l2", "b.test")], json!([]))
            .await
            .unwrap();
        let ids = |tenant: &str, group: &str| {
            let st = st.clone();
            let (tenant, group) = (tenant.to_string(), group.to_string());
            async move {
                let b = st.bundle_for(&tenant, &group).await.unwrap();
                SignedBundle::open(&b.0, &st.signing_key.verifying_key())
                    .unwrap()
                    .network
                    .lists
                    .into_iter()
                    .map(|l| l.id)
                    .collect::<Vec<_>>()
            }
        };

        // default policy: everything the platform enabled
        assert_eq!(ids(DEFAULT_TENANT, DEFAULT_GROUP).await, vec!["l1", "l2"]);
        let (s, _, b) = call(
            &app,
            "GET",
            "/v1/admin/list-subscriptions",
            Some(ADMIN),
            None,
        )
        .await;
        assert_eq!(s, StatusCode::OK);
        assert_eq!(j(&b)["policy"], "all");
        assert_eq!(j(&b)["available"].as_array().unwrap().len(), 2);

        // selected, nothing subscribed: no lists
        assert_eq!(
            call(
                &app,
                "PUT",
                "/v1/admin/list-policy",
                Some(ADMIN),
                Some(json!({"policy": "selected"}))
            )
            .await
            .0,
            StatusCode::NO_CONTENT
        );
        assert!(
            ids(DEFAULT_TENANT, DEFAULT_GROUP).await.is_empty(),
            "bundle must follow the change immediately"
        );

        // tenant-wide l1, group-only l2
        assert_eq!(
            call(
                &app,
                "POST",
                "/v1/admin/list-subscriptions",
                Some(ADMIN),
                Some(json!({"source_id": "l1"}))
            )
            .await
            .0,
            StatusCode::NO_CONTENT
        );
        assert_eq!(
            call(
                &app,
                "POST",
                "/v1/admin/list-subscriptions",
                Some(ADMIN),
                Some(json!({"source_id": "l2", "group_id": DEFAULT_GROUP}))
            )
            .await
            .0,
            StatusCode::NO_CONTENT
        );
        let (_, _, b) = call(
            &app,
            "POST",
            "/v1/admin/groups",
            Some(ADMIN),
            Some(json!({"name": "kids"})),
        )
        .await;
        let kids = j(&b)["id"].as_str().unwrap().to_string();
        assert_eq!(ids(DEFAULT_TENANT, DEFAULT_GROUP).await, vec!["l1", "l2"]);
        assert_eq!(
            ids(DEFAULT_TENANT, &kids).await,
            vec!["l1"],
            "group subscription must not leak to other groups"
        );

        // unknown source and foreign group are refused
        assert_eq!(
            call(
                &app,
                "POST",
                "/v1/admin/list-subscriptions",
                Some(ADMIN),
                Some(json!({"source_id": "nope"}))
            )
            .await
            .0,
            StatusCode::UNPROCESSABLE_ENTITY
        );
        assert_eq!(
            call(
                &app,
                "POST",
                "/v1/admin/list-subscriptions",
                Some(ADMIN),
                Some(
                    json!({"source_id": "l1", "group_id": "00000000-0000-0000-0000-0000000000aa"})
                )
            )
            .await
            .0,
            StatusCode::NOT_FOUND
        );

        // a viewer can read the selection but not change it
        let (_, _, b) = call(
            &app,
            "POST",
            "/v1/admin/api-tokens",
            Some(ADMIN),
            Some(json!({"name": "v", "role": "viewer"})),
        )
        .await;
        let viewer = j(&b)["token"].as_str().unwrap().to_string();
        assert_eq!(
            call(
                &app,
                "GET",
                "/v1/admin/list-subscriptions",
                Some(&viewer),
                None
            )
            .await
            .0,
            StatusCode::OK
        );
        assert_eq!(
            call(
                &app,
                "PUT",
                "/v1/admin/list-policy",
                Some(&viewer),
                Some(json!({"policy": "all"}))
            )
            .await
            .0,
            StatusCode::FORBIDDEN
        );
        assert_eq!(
            call(
                &app,
                "DELETE",
                "/v1/admin/list-subscriptions?source_id=l1",
                Some(&viewer),
                None
            )
            .await
            .0,
            StatusCode::FORBIDDEN
        );

        // unsubscribe + back to "all"
        assert_eq!(
            call(
                &app,
                "DELETE",
                &format!("/v1/admin/list-subscriptions?source_id=l2&group_id={DEFAULT_GROUP}"),
                Some(ADMIN),
                None
            )
            .await
            .0,
            StatusCode::NO_CONTENT
        );
        assert_eq!(ids(DEFAULT_TENANT, DEFAULT_GROUP).await, vec!["l1"]);
        assert_eq!(
            call(
                &app,
                "DELETE",
                "/v1/admin/list-subscriptions?source_id=l2",
                Some(ADMIN),
                None
            )
            .await
            .0,
            StatusCode::NOT_FOUND
        );
        assert_eq!(
            call(
                &app,
                "PUT",
                "/v1/admin/list-policy",
                Some(ADMIN),
                Some(json!({"policy": "all"}))
            )
            .await
            .0,
            StatusCode::NO_CONTENT
        );
        assert_eq!(ids(DEFAULT_TENANT, DEFAULT_GROUP).await, vec!["l1", "l2"]);

        // changes are audited
        let (_, _, b) = call(&app, "GET", "/v1/admin/audit", Some(ADMIN), None).await;
        let text = String::from_utf8(b).unwrap();
        for a in ["lists.policy", "lists.subscribe", "lists.unsubscribe"] {
            assert!(text.contains(a), "missing audit event {a}");
        }
    }

    // ------------------------------------------------------------ OIDC

    use jsonwebtoken::{Algorithm, EncodingKey, Header, encode};

    async fn mock_idp() -> String {
        let jwk = json!({"kty": "EC", "crv": "P-256", "x": JWK_X, "y": JWK_Y, "kid": "k1", "use": "sig", "alg": "ES256"});
        let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let base = format!("http://{}", l.local_addr().unwrap());
        let (b2, jwk2) = (base.clone(), jwk.clone());
        let app = Router::new()
            .route(
                "/.well-known/openid-configuration",
                get(move || {
                    let b = b2.clone();
                    async move { Json(json!({"issuer": b, "jwks_uri": format!("{b}/jwks")})) }
                }),
            )
            .route(
                "/jwks",
                get(move || {
                    let k = jwk2.clone();
                    async move { Json(json!({"keys": [k]})) }
                }),
            );
        tokio::spawn(async move { axum::serve(l, app).await.unwrap() });
        base
    }

    fn jwt(issuer: &str, aud: &str, sub: &str, exp_delta: i64, pem: &str, kid: &str) -> String {
        let exp = (now() + exp_delta) as u64;
        let mut h = Header::new(Algorithm::ES256);
        h.kid = Some(kid.into());
        encode(&h, &json!({"iss": issuer, "aud": aud, "sub": sub, "email": format!("{sub}@example.com"), "exp": exp}),
            &EncodingKey::from_ec_pem(pem.as_bytes()).unwrap()).unwrap()
    }

    #[tokio::test]
    async fn oidc_login_roles_from_bindings() {
        let idp = mock_idp().await;
        let verifier = OidcVerifier::new(OidcConfig {
            issuer: idp.clone(),
            audience: "hygeia-api".into(),
            leeway_secs: 5,
            allow_insecure_http: true,
        })
        .unwrap();
        let store: Arc<dyn Store> = Arc::new(MemoryStore::new());
        let st = state(store.clone(), Some(verifier));
        let app = router(st);

        let good = jwt(&idp, "hygeia-api", "alice", 300, EC_KEY, "k1");
        // authenticated, but no roles yet: no access to anything
        assert_eq!(
            call(&app, "GET", "/v1/me", Some(&good), None).await.0,
            StatusCode::OK
        );
        assert_eq!(
            call(&app, "GET", "/v1/admin/rules", Some(&good), None)
                .await
                .0,
            StatusCode::FORBIDDEN
        );
        assert_eq!(
            call(&app, "GET", "/v1/admin/lists", Some(&good), None)
                .await
                .0,
            StatusCode::FORBIDDEN
        );

        // operator (break-glass) binds alice as editor of the default tenant
        let user = store.upsert_user(&idp, "alice", None).await.unwrap();
        let (s, _, _) = call(
            &app,
            "POST",
            "/v1/admin/bindings",
            Some(ADMIN),
            Some(json!({"user_id": user.id, "tenant_id": DEFAULT_TENANT, "role": "editor"})),
        )
        .await;
        assert_eq!(s, StatusCode::CREATED);
        assert_eq!(
            call(
                &app,
                "POST",
                "/v1/admin/rules",
                Some(&good),
                Some(json!({"action": "block", "pattern": "x.test"}))
            )
            .await
            .0,
            StatusCode::CREATED
        );
        assert_eq!(
            call(&app, "GET", "/v1/admin/audit", Some(&good), None)
                .await
                .0,
            StatusCode::FORBIDDEN
        );
        let (_, _, b) = call(&app, "GET", "/v1/me", Some(&good), None).await;
        assert_eq!(j(&b)["kind"], "user");
        // audit trail names the human, not a shared secret
        let (_, _, b) = call(&app, "GET", "/v1/admin/audit", Some(ADMIN), None).await;
        assert!(
            String::from_utf8(b)
                .unwrap()
                .contains(&format!("user:{}", user.id))
        );

        // editor cannot grant roles
        let bob = store.upsert_user(&idp, "bob", None).await.unwrap();
        assert_eq!(
            call(
                &app,
                "POST",
                "/v1/admin/bindings",
                Some(&good),
                Some(json!({"user_id": bob.id, "tenant_id": DEFAULT_TENANT, "role": "viewer"}))
            )
            .await
            .0,
            StatusCode::FORBIDDEN
        );

        // tenant-scoped owner binding is refused; platform-wide owner via break-glass is fine
        assert_eq!(
            call(
                &app,
                "POST",
                "/v1/admin/bindings",
                Some(ADMIN),
                Some(json!({"user_id": bob.id, "tenant_id": DEFAULT_TENANT, "role": "owner"}))
            )
            .await
            .0,
            StatusCode::UNPROCESSABLE_ENTITY
        );
        assert_eq!(
            call(
                &app,
                "POST",
                "/v1/admin/bindings",
                Some(ADMIN),
                Some(json!({"user_id": bob.id, "role": "owner"}))
            )
            .await
            .0,
            StatusCode::CREATED
        );
        let bob_tok = jwt(&idp, "hygeia-api", "bob", 300, EC_KEY, "k1");
        assert_eq!(
            call(&app, "GET", "/v1/admin/tenants", Some(&bob_tok), None)
                .await
                .0,
            StatusCode::OK
        );
    }

    #[tokio::test]
    async fn oidc_rejects_bad_tokens() {
        let idp = mock_idp().await;
        let verifier = OidcVerifier::new(OidcConfig {
            issuer: idp.clone(),
            audience: "hygeia-api".into(),
            leeway_secs: 5,
            allow_insecure_http: true,
        })
        .unwrap();
        let app = router(state(Arc::new(MemoryStore::new()), Some(verifier)));
        let me = |t: String| {
            let app = app.clone();
            async move { call(&app, "GET", "/v1/me", Some(&t), None).await.0 }
        };

        assert_eq!(
            me(jwt(&idp, "hygeia-api", "a", 300, EC_KEY, "k1")).await,
            StatusCode::OK
        );
        assert_eq!(
            me(jwt(&idp, "other-aud", "a", 300, EC_KEY, "k1")).await,
            StatusCode::UNAUTHORIZED,
            "wrong audience"
        );
        assert_eq!(
            me(jwt(
                "https://evil.example.com",
                "hygeia-api",
                "a",
                300,
                EC_KEY,
                "k1"
            ))
            .await,
            StatusCode::UNAUTHORIZED,
            "wrong issuer"
        );
        assert_eq!(
            me(jwt(&idp, "hygeia-api", "a", -3600, EC_KEY, "k1")).await,
            StatusCode::UNAUTHORIZED,
            "expired"
        );
        assert_eq!(
            me(jwt(&idp, "hygeia-api", "a", 300, EC_KEY_OTHER, "k1")).await,
            StatusCode::UNAUTHORIZED,
            "signed by another key"
        );
        assert_eq!(
            me(jwt(&idp, "hygeia-api", "a", 300, EC_KEY, "unknown-kid")).await,
            StatusCode::UNAUTHORIZED,
            "unknown kid"
        );

        // alg=none and HS256 forgeries (public key material used as HMAC secret)
        let b64 = |s: &str| {
            use base64::Engine;
            base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(s)
        };
        let claims = b64(
            &json!({"iss": idp, "aud": "hygeia-api", "sub": "a", "exp": now() + 300}).to_string(),
        );
        let none = format!(
            "{}.{}.",
            b64(r#"{"alg":"none","typ":"JWT","kid":"k1"}"#),
            claims
        );
        assert_eq!(me(none).await, StatusCode::UNAUTHORIZED);
        let hs = encode(
            &Header {
                kid: Some("k1".into()),
                ..Header::new(Algorithm::HS256)
            },
            &json!({"iss": idp, "aud": "hygeia-api", "sub": "a", "exp": now() + 300}),
            &EncodingKey::from_secret(JWK_X.as_bytes()),
        )
        .unwrap();
        assert_eq!(me(hs).await, StatusCode::UNAUTHORIZED);
        assert_eq!(me("not.a.jwt".into()).await, StatusCode::UNAUTHORIZED);
    }
}

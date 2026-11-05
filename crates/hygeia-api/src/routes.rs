use std::sync::Arc;

use axum::Json;
use axum::Router;
use axum::extract::{Path, Query, State};
use axum::http::{HeaderMap, StatusCode, header};
use axum::response::{IntoResponse, Response};
use axum::routing::{delete, get, post};
use hygeia_core::{Ruleset, RulesetData, SignedBundle};
use hygeia_store::{Rule, RuleAction, StoreError, hash_secret};
use serde::{Deserialize, Serialize};
use serde_json::json;

use crate::state::{AppState, DEFAULT_GROUP, DEFAULT_TENANT, now};

type S = State<Arc<AppState>>;

pub fn router(state: Arc<AppState>) -> Router {
    Router::new()
        .route("/healthz", get(|| async { "ok" }))
        .route("/v1/pubkey", get(pubkey))
        .route("/v1/enroll", post(enroll))
        .route("/v1/bundle", get(bundle))
        .route("/v1/admin/enrollment-tokens", post(create_token))
        .route("/v1/admin/devices", get(list_devices))
        .route("/v1/admin/devices/{id}", delete(revoke_device))
        .route("/v1/admin/rules", get(list_rules).post(add_rule))
        .route("/v1/admin/rules/{id}", delete(delete_rule))
        .route("/v1/admin/lists", get(lists_status))
        .route("/v1/admin/lists/refresh", post(lists_refresh))
        .route("/v1/admin/simulate", post(simulate))
        .route("/v1/admin/audit", get(audit))
        .route("/v1/admin/audit/verify", get(audit_verify))
        .with_state(state)
}

fn bearer(h: &HeaderMap) -> Option<&str> {
    h.get(header::AUTHORIZATION)?
        .to_str()
        .ok()?
        .strip_prefix("Bearer ")
}

/// Constant-time comparison of SHA-256 digests.
fn admin_ok(st: &AppState, h: &HeaderMap) -> bool {
    let Some(t) = bearer(h) else { return false };
    let a = hash_secret(t);
    a.iter()
        .zip(st.admin_token_hash.iter())
        .fold(0u8, |acc, (x, y)| acc | (x ^ y))
        == 0
}

macro_rules! admin {
    ($st:expr, $h:expr) => {
        if !admin_ok(&$st, &$h) {
            return StatusCode::UNAUTHORIZED.into_response();
        }
    };
}

async fn pubkey(State(st): S) -> String {
    st.signing_key
        .verifying_key()
        .to_bytes()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

/// Map store failures to HTTP without leaking backend details to clients.
fn store_err(e: StoreError) -> Response {
    match e {
        StoreError::NotFound => StatusCode::NOT_FOUND.into_response(),
        StoreError::InvalidToken => StatusCode::UNAUTHORIZED.into_response(),
        other => {
            tracing::error!(error = %other, "store error");
            StatusCode::INTERNAL_SERVER_ERROR.into_response()
        }
    }
}

#[derive(Deserialize)]
struct EnrollReq {
    token: String,
    #[serde(default)]
    device_info: String,
}

async fn enroll(State(st): S, Json(req): Json<EnrollReq>) -> Response {
    match st.store.enroll(&req.token, &req.device_info, now()).await {
        Ok((dev, secret)) => {
            st.record(
                &dev.tenant_id,
                &dev.id,
                "device.enroll",
                &dev.id,
                Some(json!({"info": dev.info})),
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
    let b: Arc<SignedBundle> = match st.bundle_for(&dev.tenant_id, &dev.group_id).await {
        Ok(b) => b,
        Err(e) => return store_err(e),
    };
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

#[derive(Deserialize)]
struct NewToken {
    #[serde(default = "d_tenant")]
    tenant_id: String,
    #[serde(default = "d_group")]
    group_id: String,
    #[serde(default = "d_ttl")]
    ttl_secs: i64,
    max_uses: Option<u32>,
}
fn d_tenant() -> String {
    DEFAULT_TENANT.into()
}
fn d_group() -> String {
    DEFAULT_GROUP.into()
}
fn d_ttl() -> i64 {
    3600
}

async fn create_token(State(st): S, h: HeaderMap, Json(r): Json<NewToken>) -> Response {
    admin!(st, h);
    match st
        .store
        .create_enrollment_token(&r.tenant_id, &r.group_id, r.ttl_secs, r.max_uses, now())
        .await
    {
        Ok((t, secret)) => {
            // The secret is deliberately NOT in the audit diff.
            st.record(
                &r.tenant_id,
                "admin",
                "token.create",
                &t.id,
                Some(json!({"group": r.group_id, "expires_at": t.expires_at, "max_uses": r.max_uses})),
            )
            .await;
            Json(json!({"id": t.id, "token": secret, "expires_at": t.expires_at})).into_response()
        }
        Err(e) => store_err(e),
    }
}

#[derive(Deserialize)]
struct TenantQ {
    #[serde(default = "d_tenant")]
    tenant_id: String,
}

async fn list_devices(State(st): S, h: HeaderMap, Query(q): Query<TenantQ>) -> Response {
    admin!(st, h);
    match st.store.list_devices(&q.tenant_id).await {
        Ok(v) => Json(v).into_response(),
        Err(e) => store_err(e),
    }
}

async fn revoke_device(
    State(st): S,
    h: HeaderMap,
    Path(id): Path<String>,
    Query(q): Query<TenantQ>,
) -> Response {
    admin!(st, h);
    match st.store.revoke_device(&q.tenant_id, &id).await {
        Ok(()) => {
            st.record(&q.tenant_id, "admin", "device.revoke", &id, None)
                .await;
            StatusCode::NO_CONTENT.into_response()
        }
        Err(e) => store_err(e),
    }
}

async fn list_rules(State(st): S, h: HeaderMap, Query(q): Query<TenantQ>) -> Response {
    admin!(st, h);
    match st.store.list_rules(&q.tenant_id).await {
        Ok(v) => Json(v).into_response(),
        Err(e) => store_err(e),
    }
}

#[derive(Deserialize)]
struct NewRule {
    #[serde(default = "d_tenant")]
    tenant_id: String,
    group_id: Option<String>,
    action: RuleAction,
    pattern: String,
    #[serde(default)]
    comment: String,
}

async fn add_rule(State(st): S, h: HeaderMap, Json(r): Json<NewRule>) -> Response {
    admin!(st, h);
    if hygeia_core::normalize(&r.pattern).is_none() {
        return (StatusCode::UNPROCESSABLE_ENTITY, "invalid domain pattern").into_response();
    }
    let tenant = r.tenant_id.clone();
    let res = st
        .store
        .add_rule(Rule {
            id: String::new(),
            tenant_id: r.tenant_id,
            group_id: r.group_id,
            action: r.action,
            pattern: r.pattern,
            comment: r.comment,
        })
        .await;
    match res {
        Ok(rule) => {
            st.invalidate();
            st.record(
                &tenant,
                "admin",
                "rule.create",
                &rule.id,
                Some(json!({"after": rule})),
            )
            .await;
            (StatusCode::CREATED, Json(rule)).into_response()
        }
        Err(e) => store_err(e),
    }
}

async fn delete_rule(
    State(st): S,
    h: HeaderMap,
    Path(id): Path<String>,
    Query(q): Query<TenantQ>,
) -> Response {
    admin!(st, h);
    match st.store.delete_rule(&q.tenant_id, &id).await {
        Ok(rule) => {
            st.invalidate();
            st.record(
                &q.tenant_id,
                "admin",
                "rule.delete",
                &id,
                Some(json!({"before": rule})),
            )
            .await;
            StatusCode::NO_CONTENT.into_response()
        }
        Err(e) => store_err(e),
    }
}

async fn lists_status(State(st): S, h: HeaderMap) -> Response {
    admin!(st, h);
    Json(st.list_status()).into_response()
}

async fn lists_refresh(State(st): S, h: HeaderMap) -> Response {
    admin!(st, h);
    st.refresh_requested.notify_one();
    StatusCode::ACCEPTED.into_response()
}

#[derive(Deserialize)]
struct SimReq {
    #[serde(default = "d_tenant")]
    tenant_id: String,
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
    admin!(st, h);
    let signed = match st.bundle_for(&r.tenant_id, &r.group_id).await {
        Ok(b) => b,
        Err(e) => return store_err(e),
    };
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

#[derive(Deserialize)]
struct AuditQ {
    #[serde(default = "d_tenant")]
    tenant_id: String,
    #[serde(default = "d_limit")]
    limit: u32,
}
fn d_limit() -> u32 {
    200
}

async fn audit(State(st): S, h: HeaderMap, Query(q): Query<AuditQ>) -> Response {
    admin!(st, h);
    match st.store.list_audit(&q.tenant_id, q.limit.min(1000)).await {
        Ok(v) => Json(v).into_response(),
        Err(e) => store_err(e),
    }
}

async fn audit_verify(State(st): S, h: HeaderMap, Query(q): Query<TenantQ>) -> Response {
    admin!(st, h);
    match st.store.verify_audit(&q.tenant_id).await {
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
    use axum::body::Body;
    use axum::http::Request;
    use ed25519_dalek::SigningKey;
    use http_body_util::BodyExt;
    use tower::ServiceExt;

    fn app() -> (Router, Arc<AppState>) {
        let st = Arc::new(AppState::new(
            Arc::new(hygeia_store::MemoryStore::new()),
            SigningKey::from_bytes(&[1u8; 32]),
            "admin-secret",
        ));
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

    #[tokio::test]
    async fn full_flow() {
        let (app, st) = app();
        // admin endpoints reject missing/wrong credentials
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
            Some("admin-secret"),
            Some(json!({"max_uses": 1})),
        )
        .await;
        assert_eq!(s, StatusCode::OK);
        let token = serde_json::from_slice::<serde_json::Value>(&b).unwrap()["token"]
            .as_str()
            .unwrap()
            .to_string();

        let (s, _, b) = call(
            &app,
            "POST",
            "/v1/enroll",
            None,
            Some(json!({"token": token, "device_info": "test"})),
        )
        .await;
        assert_eq!(s, StatusCode::OK);
        let dev: serde_json::Value = serde_json::from_slice(&b).unwrap();
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

        // add a rule, pull bundle, verify signature and content
        let (s, _, _) = call(
            &app,
            "POST",
            "/v1/admin/rules",
            Some("admin-secret"),
            Some(json!({"action": "block", "pattern": "ads.example.com"})),
        )
        .await;
        assert_eq!(s, StatusCode::CREATED);
        let (s, h, body) = call(&app, "GET", "/v1/bundle", Some(&dsecret), None).await;
        assert_eq!(s, StatusCode::OK);
        let bundle = SignedBundle::open(&body, &st.signing_key.verifying_key()).unwrap();
        assert_eq!(bundle.network.custom_block, vec!["ads.example.com"]);
        let etag = h.get("etag").unwrap().to_str().unwrap().to_string();

        // conditional pull
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

        // simulation
        let (_, _, b) = call(&app, "POST", "/v1/admin/simulate", Some("admin-secret"),
            Some(json!({"host": "x.ads.example.com", "extra_rules": [{"action": "allow", "pattern": "x.ads.example.com"}]}))).await;
        let v: serde_json::Value = serde_json::from_slice(&b).unwrap();
        assert_eq!(v["current"]["action"], "Block");
        assert_eq!(v["with_changes"]["action"], "Allow");

        // revoke device -> 401
        let id = dev["device_id"].as_str().unwrap();
        assert_eq!(
            call(
                &app,
                "DELETE",
                &format!("/v1/admin/devices/{id}"),
                Some("admin-secret"),
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

        // audit chain intact and secrets absent from it
        let (s, _, _) = call(
            &app,
            "GET",
            "/v1/admin/audit/verify",
            Some("admin-secret"),
            None,
        )
        .await;
        assert_eq!(s, StatusCode::OK);
        let (_, _, b) = call(&app, "GET", "/v1/admin/audit", Some("admin-secret"), None).await;
        let text = String::from_utf8(b).unwrap();
        assert!(!text.contains(&token) && !text.contains(&dsecret));
        assert!(text.contains("rule.create") && text.contains("device.revoke"));
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
        );
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
        let (s, _, body) = call(&app, "GET", "/v1/admin/lists", Some("admin-secret"), None).await;
        assert_eq!(s, StatusCode::OK);
        assert!(String::from_utf8(body).unwrap().contains("\"MIT\""));
        assert_eq!(
            call(
                &app,
                "POST",
                "/v1/admin/lists/refresh",
                Some("admin-secret"),
                None
            )
            .await
            .0,
            StatusCode::ACCEPTED
        );
    }
}

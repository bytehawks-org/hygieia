//! OpenAPI 3.1 description of the HTTP API.
//!
//! Hand-curated on purpose: the handlers return untyped `Response`s, so a derive-based generator
//! would only see half of the contract. Drift is caught by tests instead:
//! * every route registered in `routes.rs` must be documented and vice versa;
//! * real responses of the main endpoints are validated against these schemas (see the
//!   `responses_match_the_openapi_schemas` test in `routes.rs`);
//! * the committed `docs/reference/openapi.json` must equal [`spec`] (regenerate with
//!   `scripts/gen-api.sh`), and the TypeScript types in `web/lib/api-schema.d.ts` are generated
//!   from that file, so a change here that breaks the UI fails `tsc`.

use serde_json::{Value, json};

fn r(name: &str) -> Value {
    json!({"$ref": format!("#/components/schemas/{name}")})
}
fn arr(items: Value) -> Value {
    json!({"type": "array", "items": items})
}
fn obj(required: &[&str], props: Value) -> Value {
    json!({"type": "object", "required": required, "properties": props})
}
fn s() -> Value {
    json!({"type": "string"})
}
fn nullable(t: &str) -> Value {
    json!({"type": [t, "null"]})
}
fn i() -> Value {
    json!({"type": "integer", "format": "int64"})
}
fn bool_() -> Value {
    json!({"type": "boolean"})
}
fn body(schema: Value) -> Value {
    json!({"required": true, "content": {"application/json": {"schema": schema}}})
}
fn ok(desc: &str, schema: Value) -> Value {
    json!({"description": desc, "content": {"application/json": {"schema": schema}}})
}
fn plain(desc: &str) -> Value {
    json!({"description": desc})
}
fn err(name: &str) -> Value {
    json!({"$ref": format!("#/components/responses/{name}")})
}
fn tenant_q() -> Value {
    json!({"$ref": "#/components/parameters/TenantId"})
}
fn path_p(name: &str, desc: &str) -> Value {
    json!({"name": name, "in": "path", "required": true, "description": desc, "schema": s()})
}
fn query_p(name: &str, desc: &str, schema: Value, required: bool) -> Value {
    json!({"name": name, "in": "query", "required": required, "description": desc, "schema": schema})
}
fn binary(media: &str, desc: &str) -> Value {
    json!({"description": desc, "content": {media: {"schema": {"type": "string", "format": "binary"}}}})
}
fn text(desc: &str) -> Value {
    json!({"description": desc, "content": {"text/plain": {"schema": s()}}})
}

#[derive(Clone, Copy)]
enum Auth {
    None,
    Admin,
    Device,
    Metrics,
}

struct Op {
    tag: &'static str,
    id: &'static str,
    summary: &'static str,
    auth: Auth,
    params: Vec<Value>,
    body: Option<Value>,
    responses: Vec<(&'static str, Value)>,
}

fn op(
    tag: &'static str,
    id: &'static str,
    summary: &'static str,
    auth: Auth,
    responses: Vec<(&'static str, Value)>,
) -> Op {
    Op {
        tag,
        id,
        summary,
        auth,
        params: vec![],
        body: None,
        responses,
    }
}

impl Op {
    fn params(mut self, p: Vec<Value>) -> Self {
        self.params = p;
        self
    }
    fn body(mut self, b: Value) -> Self {
        self.body = Some(b);
        self
    }
    fn render(self) -> Value {
        let mut responses = serde_json::Map::new();
        for (code, v) in self.responses {
            responses.insert(code.into(), v);
        }
        if !matches!(self.auth, Auth::None) {
            responses.insert("401".into(), err("Unauthorized"));
        }
        if matches!(self.auth, Auth::Admin) {
            responses.insert("403".into(), err("Forbidden"));
        }
        if self.body.is_some() {
            responses.entry("422").or_insert_with(|| err("Invalid"));
        }
        let security = match self.auth {
            Auth::None => json!([]),
            Auth::Admin => json!([{"adminToken": []}]),
            Auth::Device => json!([{"deviceToken": []}]),
            Auth::Metrics => json!([{"metricsToken": []}]),
        };
        let mut o = json!({
            "tags": [self.tag], "operationId": self.id, "summary": self.summary,
            "security": security, "responses": responses,
        });
        if !self.params.is_empty() {
            o["parameters"] = Value::Array(self.params);
        }
        if let Some(b) = self.body {
            o["requestBody"] = b;
        }
        o
    }
}

fn schemas_core() -> Value {
    let reason = json!({"oneOf": [
        obj(&["CustomAllow"], json!({"CustomAllow": obj(&["rule"], json!({"rule": s()}))})),
        obj(&["CustomBlock"], json!({"CustomBlock": obj(&["rule"], json!({"rule": s()}))})),
        obj(&["ListAllow"], json!({"ListAllow": obj(&["list", "rule"], json!({"list": s(), "rule": s()}))})),
        obj(&["ListBlock"], json!({"ListBlock": obj(&["list", "rule"], json!({"list": s(), "rule": s()}))})),
        {"type": "string", "enum": ["Default"]},
    ]});
    let principal = json!({"oneOf": [
        obj(&["kind"], json!({"kind": {"const": "local_owner"}})),
        obj(&["kind"], json!({"kind": {"const": "break_glass"}})),
        obj(&["kind", "id", "tenant_id", "role"], json!({
            "kind": {"const": "api_token"}, "id": s(), "tenant_id": s(), "role": r("Role")})),
        obj(&["kind", "id", "issuer", "subject", "email", "bindings"], json!({
            "kind": {"const": "user"}, "id": s(), "issuer": s(), "subject": s(),
            "email": nullable("string"), "bindings": arr(r("Binding"))})),
    ]});
    json!({
        "Role": {"type": "string", "enum": ["owner", "admin", "editor", "viewer", "auditor"],
            "description": "`owner` exists only as a platform-wide role."},
        "RuleAction": {"type": "string", "enum": ["allow", "block"]},
        "ListPolicy": {"type": "string", "enum": ["all", "selected"]},
        "Reason": reason,
        "Verdict": obj(&["action", "reason"], json!({
            "action": {"type": "string", "enum": ["Allow", "Block"]}, "reason": r("Reason")})),
        "Principal": principal,
        "PublicConfig": obj(&["mode", "environment", "break_glass", "oidc"], json!({
            "mode": {"type": "string", "description": "`server` (central) or `standalone` (single-machine node)"},
            "environment": {"type": "string", "description": "`production` | `staging` | `dev`"},
            "break_glass": bool_(),
            "oidc": {"oneOf": [{"type": "null"}, obj(&["issuer", "client_id", "scope"],
                json!({"issuer": s(), "client_id": s(), "scope": s()}))]},
        })),
        "Tenant": obj(&["id", "slug", "name"], json!({"id": s(), "slug": s(), "name": s()})),
        "Group": obj(&["id", "tenant_id", "name"], json!({"id": s(), "tenant_id": s(), "name": s()})),
        "User": obj(&["id", "issuer", "subject", "email", "disabled"], json!({
            "id": s(), "issuer": s(), "subject": s(), "email": nullable("string"), "disabled": bool_()})),
        "Binding": obj(&["id", "user_id", "tenant_id", "role"], json!({
            "id": s(), "user_id": s(), "tenant_id": nullable("string"), "role": r("Role")})),
        "ApiToken": obj(&["id", "tenant_id", "name", "role", "expires_at", "revoked"], json!({
            "id": s(), "tenant_id": s(), "name": s(), "role": r("Role"),
            "expires_at": nullable("integer"), "revoked": bool_()})),
        "Device": obj(&["id", "tenant_id", "group_id", "info", "last_seen", "revoked"], json!({
            "id": s(), "tenant_id": s(), "group_id": s(), "info": s(), "last_seen": i(), "revoked": bool_()})),
        "Rule": obj(&["id", "tenant_id", "group_id", "action", "pattern", "comment"], json!({
            "id": s(), "tenant_id": s(), "group_id": nullable("string"),
            "action": r("RuleAction"), "pattern": s(), "comment": s()})),
        "ListStatus": obj(&["id", "name", "url", "license", "attribution", "last_ok", "last_error",
            "block_domains", "allow_domains", "generic_selectors", "host_rule_sets", "scriptlet_calls",
            "skipped_lines", "dropped_trusted_scriptlets", "sha256"], json!({
            "id": s(), "name": s(), "url": s(), "license": s(), "attribution": s(),
            "last_ok": nullable("integer"), "last_error": nullable("string"),
            "block_domains": i(), "allow_domains": i(), "generic_selectors": i(), "host_rule_sets": i(),
            "scriptlet_calls": i(), "skipped_lines": i(), "dropped_trusted_scriptlets": i(),
            "sha256": nullable("string")})),
        "ListSelection": obj(&["policy", "subscriptions", "available"], json!({
            "policy": r("ListPolicy"),
            "subscriptions": arr(obj(&["group_id", "source_id"], json!({"group_id": nullable("string"), "source_id": s()}))),
            "available": arr(obj(&["id", "name", "license"], json!({"id": s(), "name": s(), "license": s()}))),
        })),
        "AuditEvent": obj(&["seq", "ts", "tenant_id", "actor", "action", "target", "prev_hash", "hash"], json!({
            "seq": i(), "ts": i(), "tenant_id": s(), "actor": s(), "action": s(), "target": s(),
            "diff": {"description": "Before/after of the change; never contains secrets."},
            "prev_hash": s(), "hash": s()})),
        "AuditVerify": obj(&["ok"], json!({"ok": bool_(), "head": s(), "events": i(), "error": s()})),
        "Simulation": obj(&["current", "with_changes"], json!({"current": r("Verdict"), "with_changes": r("Verdict")})),
    })
}

fn schemas_dns() -> Value {
    let counts = arr(obj(&["key", "count"], json!({"key": s(), "count": i()})));
    json!({
        "DnsToken": obj(&["id", "tenant_id", "group_id", "name", "expires_at", "revoked"], json!({
            "id": s(), "tenant_id": s(), "group_id": s(), "name": s(),
            "expires_at": nullable("integer"), "revoked": bool_(),
            "dot_label": {"type": ["string", "null"], "description": "SNI label for DoT/DoQ (an identifier, not a secret)."}})),
        "DnsNetwork": obj(&["id", "tenant_id", "group_id", "name", "cidr"], json!({
            "id": s(), "tenant_id": s(), "group_id": s(), "name": s(), "cidr": s()})),
        "DnsSettings": obj(&["log_enabled", "retention_days", "fail_open", "block_mode"], json!({
            "log_enabled": {"type": "boolean", "description": "Query log is off by default (data minimisation)."},
            "retention_days": {"type": "integer", "minimum": 1, "maximum": 365},
            "fail_open": nullable("boolean"),
            "block_mode": {"type": ["string", "null"], "description": "`nxdomain` | `null_ip`; null = server default"},
        })),
        "QueryLogEntry": obj(&["ts", "group_id", "token_id", "transport", "client", "qname", "qtype", "action", "reason"], json!({
            "ts": i(), "group_id": s(), "token_id": nullable("string"), "transport": s(),
            "client": {"type": "string", "description": "Keyed, daily-rotating pseudonym; never the IP address."},
            "qname": s(), "qtype": s(), "action": s(), "reason": s()})),
        "DnsStats": obj(&["queries", "blocked", "top_blocked", "top_clients", "by_transport"], json!({
            "queries": i(), "blocked": i(),
            "top_blocked": counts.clone(), "top_clients": counts.clone(), "by_transport": counts})),
        "Deleted": obj(&["deleted"], json!({"deleted": i()})),
        "Linked": obj(&["cidr"], json!({"cidr": s()})),
    })
}

fn schemas_requests() -> Value {
    json!({
        "EnrollRequest": obj(&["token"], json!({"token": s(), "device_info": s()})),
        "EnrollResponse": obj(&["device_id", "device_secret"], json!({"device_id": s(), "device_secret": s()})),
        "NewTenant": obj(&["slug", "name"], json!({"slug": s(), "name": s()})),
        "NewGroup": obj(&["name"], json!({"tenant_id": nullable("string"), "name": s()})),
        "NewBinding": obj(&["user_id", "role"], json!({
            "user_id": s(), "tenant_id": {"type": ["string", "null"], "description": "Omit for a platform-wide binding."},
            "role": r("Role")})),
        "NewApiToken": obj(&["name", "role"], json!({
            "tenant_id": nullable("string"), "name": s(), "role": r("Role"), "ttl_secs": nullable("integer")})),
        "CreatedApiToken": obj(&["id", "token", "role", "expires_at"], json!({
            "id": s(), "token": {"type": "string", "description": "Shown once."}, "role": r("Role"),
            "expires_at": nullable("integer")})),
        "NewDnsToken": obj(&["name"], json!({
            "tenant_id": nullable("string"), "group_id": {"type": "string", "default": "default"}, "name": s(),
            "ttl_secs": nullable("integer"),
            "dot": {"type": "boolean", "default": false, "description": "Also create a DoT/DoQ SNI label."}})),
        "CreatedDnsToken": obj(&["id", "token", "group_id", "dot_label", "expires_at", "doh_path"], json!({
            "id": s(), "token": {"type": "string", "description": "Shown once; it is the DoH credential."},
            "group_id": s(), "dot_label": nullable("string"), "expires_at": nullable("integer"),
            "doh_path": {"type": "string", "description": "`/dns-query/<token>`"}})),
        "DnsSettingsUpdate": obj(&["log_enabled", "retention_days"], json!({
            "tenant_id": nullable("string"), "log_enabled": bool_(),
            "retention_days": {"type": "integer", "minimum": 1, "maximum": 365},
            "fail_open": nullable("boolean"), "block_mode": nullable("string")})),
        "NewNetwork": obj(&["name", "cidr"], json!({
            "tenant_id": nullable("string"), "group_id": {"type": "string", "default": "default"},
            "name": s(), "cidr": {"type": "string", "description": "Public IPv4 >= /24, IPv6 >= /48; private blocks whole."}})),
        "NewEnrollmentToken": obj(&[], json!({
            "tenant_id": nullable("string"), "group_id": {"type": "string", "default": "default"},
            "ttl_secs": {"type": "integer", "default": 3600}, "max_uses": nullable("integer")})),
        "CreatedEnrollmentToken": obj(&["id", "token", "expires_at"], json!({
            "id": s(), "token": {"type": "string", "description": "Shown once."}, "expires_at": i()})),
        "NewRule": obj(&["action", "pattern"], json!({
            "tenant_id": nullable("string"), "group_id": nullable("string"), "action": r("RuleAction"),
            "pattern": s(), "comment": {"type": "string", "default": ""}})),
        "PolicyUpdate": obj(&["policy"], json!({"tenant_id": nullable("string"), "policy": r("ListPolicy")})),
        "NewSubscription": obj(&["source_id"], json!({
            "tenant_id": nullable("string"), "group_id": nullable("string"), "source_id": s()})),
        "SimulationRequest": obj(&["host"], json!({
            "tenant_id": nullable("string"), "group_id": {"type": "string", "default": "default"}, "host": s(),
            "extra_rules": {"type": "array", "default": [], "description": "Evaluated as if saved; not persisted.",
                "items": obj(&["action", "pattern"], json!({"action": r("RuleAction"), "pattern": s()}))}})),
    })
}

fn schemas() -> Value {
    let mut all = serde_json::Map::new();
    for part in [schemas_core(), schemas_dns(), schemas_requests()] {
        if let Value::Object(m) = part {
            all.extend(m);
        }
    }
    Value::Object(all)
}

type Routes = Vec<(&'static str, &'static str, Op)>;

fn paths_operations(p: &mut Routes) {
    use Auth::{Metrics, None as Open};
    p.push((
        "/healthz",
        "get",
        op(
            "Operations",
            "healthz",
            "Liveness",
            Open,
            vec![("200", plain("`ok`"))],
        ),
    ));
    p.push((
        "/readyz",
        "get",
        op(
            "Operations",
            "readyz",
            "Readiness (store reachable)",
            Open,
            vec![
                ("200", plain("`ready`")),
                ("503", plain("Store unavailable")),
            ],
        ),
    ));
    p.push((
        "/metrics",
        "get",
        op(
            "Operations",
            "metrics",
            "Prometheus metrics",
            Metrics,
            vec![
                ("200", text("Prometheus text format")),
                ("404", plain("Disabled (no metrics token configured)")),
            ],
        ),
    ));
    p.push((
        "/v1/openapi.json",
        "get",
        op(
            "Operations",
            "openapi",
            "This document",
            Open,
            vec![("200", ok("OpenAPI 3.1 document", json!({"type": "object"})))],
        ),
    ));
}

fn paths_data_plane(p: &mut Routes) {
    use Auth::{Admin, Device, None as Open};
    p.push((
        "/v1/pubkey",
        "get",
        op(
            "Data plane",
            "pubkey",
            "Bundle signing public key (64 hex)",
            Open,
            vec![(
                "200",
                text("Hex; trust-on-first-use: pin it through a trusted channel"),
            )],
        ),
    ));
    p.push((
        "/v1/enroll",
        "post",
        op(
            "Data plane",
            "enroll",
            "Exchange an enrollment token for a device credential",
            Open,
            vec![
                ("200", ok("Device credential", r("EnrollResponse"))),
                (
                    "401",
                    plain("Token invalid, expired, exhausted or revoked (one generic error)"),
                ),
            ],
        )
        .body(body(r("EnrollRequest"))),
    ));
    p.push(("/v1/bundle", "get", op("Data plane", "bundle", "Signed bundle (HYGB) for the device's group", Device,
        vec![("200", json!({"description": "Signed bundle", "headers": {"ETag": {"schema": s()}},
                "content": {"application/vnd.hygeia.bundle": {"schema": {"type": "string", "format": "binary"}}}})),
             ("304", plain("Not modified (If-None-Match)"))])
        .params(vec![json!({"name": "If-None-Match", "in": "header", "required": false, "schema": s()})])));
    p.push((
        "/v1/config",
        "get",
        op(
            "Identity",
            "publicConfig",
            "Non-secret deployment info (login screen)",
            Open,
            vec![("200", ok("OK", r("PublicConfig")))],
        ),
    ));
    p.push((
        "/v1/me",
        "get",
        op(
            "Identity",
            "me",
            "Who the presented credential is",
            Admin,
            vec![("200", ok("OK", r("Principal")))],
        ),
    ));
}

fn paths_admin(p: &mut Routes) {
    use Auth::Admin;
    let id_del = |tag, id, summary, what: &str| {
        op(
            tag,
            id,
            summary,
            Admin,
            vec![("204", plain("Deleted")), ("404", err("NotFound"))],
        )
        .params(vec![path_p("id", what), tenant_q()])
    };
    let list = |tag, id, summary, schema: &str| {
        op(
            tag,
            id,
            summary,
            Admin,
            vec![("200", ok("OK", arr(r(schema))))],
        )
        .params(vec![tenant_q()])
    };
    p.push((
        "/v1/admin/tenants",
        "get",
        op(
            "Tenants",
            "listTenants",
            "List tenants (platform scope)",
            Admin,
            vec![("200", ok("OK", arr(r("Tenant"))))],
        ),
    ));
    p.push((
        "/v1/admin/tenants",
        "post",
        op(
            "Tenants",
            "createTenant",
            "Create a tenant (platform scope)",
            Admin,
            vec![
                ("201", ok("Created", r("Tenant"))),
                ("409", err("Conflict")),
            ],
        )
        .body(body(r("NewTenant"))),
    ));
    p.push((
        "/v1/admin/groups",
        "get",
        list("Tenants", "listGroups", "List groups", "Group"),
    ));
    p.push((
        "/v1/admin/groups",
        "post",
        op(
            "Tenants",
            "createGroup",
            "Create a group",
            Admin,
            vec![("201", ok("Created", r("Group"))), ("409", err("Conflict"))],
        )
        .body(body(r("NewGroup"))),
    ));
    p.push((
        "/v1/admin/users",
        "get",
        op(
            "Users",
            "listUsers",
            "List users (platform scope)",
            Admin,
            vec![("200", ok("OK", arr(r("User"))))],
        ),
    ));
    p.push((
        "/v1/admin/bindings",
        "get",
        list("Users", "listBindings", "List role bindings", "Binding"),
    ));
    p.push((
        "/v1/admin/bindings",
        "post",
        op(
            "Users",
            "addBinding",
            "Bind a role to a user",
            Admin,
            vec![("201", ok("Created", r("Binding")))],
        )
        .body(body(r("NewBinding"))),
    ));
    p.push((
        "/v1/admin/bindings/{id}",
        "delete",
        id_del(
            "Users",
            "removeBinding",
            "Remove a role binding",
            "Binding id",
        ),
    ));
    p.push((
        "/v1/admin/api-tokens",
        "get",
        list("Tokens", "listApiTokens", "List API tokens", "ApiToken"),
    ));
    p.push((
        "/v1/admin/api-tokens",
        "post",
        op(
            "Tokens",
            "createApiToken",
            "Create an API token (secret shown once)",
            Admin,
            vec![("201", ok("Created", r("CreatedApiToken")))],
        )
        .body(body(r("NewApiToken"))),
    ));
    p.push((
        "/v1/admin/api-tokens/{id}",
        "delete",
        id_del(
            "Tokens",
            "revokeApiToken",
            "Revoke an API token",
            "Token id",
        ),
    ));
    p.push((
        "/v1/admin/enrollment-tokens",
        "post",
        op(
            "Devices",
            "createEnrollmentToken",
            "Create an enrollment token (secret shown once)",
            Admin,
            vec![("200", ok("OK", r("CreatedEnrollmentToken")))],
        )
        .body(body(r("NewEnrollmentToken"))),
    ));
    p.push((
        "/v1/admin/devices",
        "get",
        list("Devices", "listDevices", "List enrolled devices", "Device"),
    ));
    p.push((
        "/v1/admin/devices/{id}",
        "delete",
        id_del("Devices", "revokeDevice", "Revoke a device", "Device id"),
    ));
    p.push((
        "/v1/admin/rules",
        "get",
        list("Rules", "listRules", "List custom rules", "Rule"),
    ));
    p.push((
        "/v1/admin/rules",
        "post",
        op(
            "Rules",
            "addRule",
            "Add a custom rule",
            Admin,
            vec![("201", ok("Created", r("Rule")))],
        )
        .body(body(r("NewRule"))),
    ));
    p.push((
        "/v1/admin/rules/{id}",
        "delete",
        id_del("Rules", "deleteRule", "Delete a custom rule", "Rule id"),
    ));
    p.push((
        "/v1/admin/simulate",
        "post",
        op(
            "Rules",
            "simulate",
            "Evaluate a host now and with uncommitted rules",
            Admin,
            vec![("200", ok("OK", r("Simulation")))],
        )
        .body(body(r("SimulationRequest"))),
    ));
    p.push((
        "/v1/admin/lists",
        "get",
        op(
            "Filter lists",
            "listsStatus",
            "Status of the downloaded lists",
            Admin,
            vec![("200", ok("OK", arr(r("ListStatus"))))],
        ),
    ));
    p.push((
        "/v1/admin/lists/refresh",
        "post",
        op(
            "Filter lists",
            "listsRefresh",
            "Refresh the lists now",
            Admin,
            vec![("202", plain("Refresh started"))],
        ),
    ));
    p.push((
        "/v1/admin/list-subscriptions",
        "get",
        op(
            "Filter lists",
            "listSubscriptions",
            "Policy, subscriptions and available sources",
            Admin,
            vec![("200", ok("OK", r("ListSelection")))],
        )
        .params(vec![tenant_q()]),
    ));
    p.push((
        "/v1/admin/list-subscriptions",
        "post",
        op(
            "Filter lists",
            "subscribe",
            "Subscribe a tenant or group to a source",
            Admin,
            vec![("204", plain("Subscribed"))],
        )
        .body(body(r("NewSubscription"))),
    ));
    p.push((
        "/v1/admin/list-subscriptions",
        "delete",
        op(
            "Filter lists",
            "unsubscribe",
            "Remove a subscription",
            Admin,
            vec![("204", plain("Removed"))],
        )
        .params(vec![
            tenant_q(),
            query_p("source_id", "Source id", s(), true),
            query_p("group_id", "Group (omit for the whole tenant)", s(), false),
        ]),
    ));
    p.push((
        "/v1/admin/list-policy",
        "put",
        op(
            "Filter lists",
            "setListPolicy",
            "Choose all sources or selected only",
            Admin,
            vec![("204", plain("Updated"))],
        )
        .body(body(r("PolicyUpdate"))),
    ));
    p.push((
        "/v1/admin/audit",
        "get",
        op(
            "Audit",
            "audit",
            "Audit events (hash chained)",
            Admin,
            vec![("200", ok("OK", arr(r("AuditEvent"))))],
        )
        .params(vec![
            tenant_q(),
            query_p("limit", "Default 200", json!({"type": "integer"}), false),
        ]),
    ));
    p.push((
        "/v1/admin/audit/verify",
        "get",
        op(
            "Audit",
            "auditVerify",
            "Verify the hash chain",
            Admin,
            vec![
                ("200", ok("Chain intact", r("AuditVerify"))),
                ("409", ok("Chain broken", r("AuditVerify"))),
            ],
        )
        .params(vec![tenant_q()]),
    ));
}

fn paths_dns(p: &mut Routes) {
    use Auth::{Admin, None as Open};
    let id_del = |id, summary, what: &str| {
        op(
            "Cloud DNS",
            id,
            summary,
            Admin,
            vec![("204", plain("Deleted")), ("404", err("NotFound"))],
        )
        .params(vec![path_p("id", what), tenant_q()])
    };
    let list = |id, summary, schema: &str| {
        op(
            "Cloud DNS",
            id,
            summary,
            Admin,
            vec![("200", ok("OK", arr(r(schema))))],
        )
        .params(vec![tenant_q()])
    };
    p.push((
        "/dns-query/{token}",
        "get",
        op(
            "Cloud DNS",
            "dohGet",
            "DNS over HTTPS (RFC 8484 GET); the path is the credential",
            Open,
            vec![
                ("200", binary("application/dns-message", "DNS message")),
                ("404", plain("Unknown token (or DNS disabled)")),
                ("429", err("TooMany")),
            ],
        )
        .params(vec![
            path_p("token", "DNS token secret"),
            query_p("dns", "base64url DNS message", s(), true),
        ]),
    ));
    p.push(("/dns-query/{token}", "post", op("Cloud DNS", "dohPost", "DNS over HTTPS (RFC 8484 POST)", Open,
        vec![("200", binary("application/dns-message", "DNS message")),
             ("404", plain("Unknown token (or DNS disabled)")), ("413", plain("Message above 4 KiB")), ("429", err("TooMany"))])
        .params(vec![path_p("token", "DNS token secret")])
        .body(json!({"required": true, "content": {"application/dns-message": {"schema": {"type": "string", "format": "binary"}}}}))));
    p.push((
        "/v1/dns/link/{token}",
        "put",
        op(
            "Cloud DNS",
            "linkNetwork",
            "Register the caller's address as the token's client network",
            Open,
            vec![
                ("200", ok("Registered network", r("Linked"))),
                ("404", plain("Unknown token (or DNS disabled)")),
                ("422", plain("Address not registrable")),
                ("429", err("TooMany")),
            ],
        )
        .params(vec![path_p("token", "DNS token secret")]),
    ));
    p.push((
        "/v1/admin/dns-tokens",
        "get",
        list("listDnsTokens", "List DNS tokens", "DnsToken"),
    ));
    p.push((
        "/v1/admin/dns-tokens",
        "post",
        op(
            "Cloud DNS",
            "createDnsToken",
            "Create a DNS token (secret shown once)",
            Admin,
            vec![("201", ok("Created", r("CreatedDnsToken")))],
        )
        .body(body(r("NewDnsToken"))),
    ));
    p.push((
        "/v1/admin/dns-tokens/{id}",
        "delete",
        id_del("revokeDnsToken", "Revoke a DNS token", "Token id"),
    ));
    p.push((
        "/v1/admin/dns/settings",
        "get",
        op(
            "Cloud DNS",
            "getDnsSettings",
            "Query-log and failure-policy settings",
            Admin,
            vec![("200", ok("OK", r("DnsSettings")))],
        )
        .params(vec![tenant_q()]),
    ));
    p.push((
        "/v1/admin/dns/settings",
        "put",
        op(
            "Cloud DNS",
            "putDnsSettings",
            "Update the settings",
            Admin,
            vec![("200", ok("Updated", r("DnsSettings")))],
        )
        .body(body(r("DnsSettingsUpdate"))),
    ));
    p.push((
        "/v1/admin/dns/query-log",
        "get",
        op(
            "Cloud DNS",
            "getQueryLog",
            "Read the (pseudonymised) query log",
            Admin,
            vec![("200", ok("OK", arr(r("QueryLogEntry"))))],
        )
        .params(vec![
            tenant_q(),
            query_p("since", "Unix seconds", i(), false),
            query_p(
                "limit",
                "1..1000, default 100",
                json!({"type": "integer"}),
                false,
            ),
            query_p("q", "Substring of the query name", s(), false),
            query_p("action", "`allow` | `block`", s(), false),
        ]),
    ));
    p.push((
        "/v1/admin/dns/query-log",
        "delete",
        op(
            "Cloud DNS",
            "clearQueryLog",
            "Erase the tenant's query log",
            Admin,
            vec![("200", ok("OK", r("Deleted")))],
        )
        .params(vec![tenant_q()]),
    ));
    p.push((
        "/v1/admin/dns/stats",
        "get",
        op(
            "Cloud DNS",
            "dnsStats",
            "Aggregates over the query log",
            Admin,
            vec![("200", ok("OK", r("DnsStats")))],
        )
        .params(vec![
            tenant_q(),
            query_p("since", "Unix seconds", i(), false),
            query_p(
                "limit",
                "Entries considered",
                json!({"type": "integer"}),
                false,
            ),
        ]),
    ));
    p.push((
        "/v1/admin/dns/networks",
        "get",
        list(
            "listDnsNetworks",
            "List registered client networks",
            "DnsNetwork",
        ),
    ));
    p.push((
        "/v1/admin/dns/networks",
        "post",
        op(
            "Cloud DNS",
            "addDnsNetwork",
            "Register a client network (CIDR)",
            Admin,
            vec![
                ("201", ok("Created", r("DnsNetwork"))),
                ("409", err("Conflict")),
            ],
        )
        .body(body(r("NewNetwork"))),
    ));
    p.push((
        "/v1/admin/dns/networks/{id}",
        "delete",
        id_del("deleteDnsNetwork", "Remove a client network", "Network id"),
    ));
}

fn paths() -> Value {
    let mut p: Routes = vec![];
    paths_operations(&mut p);
    paths_data_plane(&mut p);
    paths_admin(&mut p);
    paths_dns(&mut p);
    let mut out = serde_json::Map::new();
    for (path, method, o) in p {
        let e = out.entry(path).or_insert_with(|| json!({}));
        e[method] = o.render();
    }
    Value::Object(out)
}

/// The whole document. Deterministic: tests compare it byte for byte with the committed copy.
pub fn spec() -> Value {
    let tags: Vec<Value> = [
        "Operations",
        "Data plane",
        "Identity",
        "Tenants",
        "Users",
        "Tokens",
        "Devices",
        "Rules",
        "Filter lists",
        "Cloud DNS",
        "Audit",
    ]
    .iter()
    .map(|t| json!({"name": t}))
    .collect();
    json!({
        "openapi": "3.1.0",
        "info": {
            "title": "Hygieia API",
            "version": env!("CARGO_PKG_VERSION"),
            "description": "Control plane, data plane and cloud DNS of Hygieia. Admin calls use a bearer \
    credential (OIDC access token, `hyg_api_…`, local owner `hyg_own_…`); devices use `hyg_dev_…`. \
    `tenant_id` defaults to the caller's single tenant where unambiguous.",
            "license": {"name": "Apache-2.0", "identifier": "Apache-2.0"},
        },
        "tags": tags,
        "paths": paths(),
        "components": {
            "securitySchemes": {
                "adminToken": {"type": "http", "scheme": "bearer", "description": "OIDC access token, API token or local owner credential."},
                "deviceToken": {"type": "http", "scheme": "bearer", "description": "Device credential from /v1/enroll."},
                "metricsToken": {"type": "http", "scheme": "bearer", "description": "HYGEIA_METRICS_TOKEN."},
            },
            "parameters": {
                "TenantId": {"name": "tenant_id", "in": "query", "required": false, "schema": {"type": "string"},
                    "description": "Tenant to act on (platform operators and multi-tenant users must set it)."},
            },
            "responses": {
                "Unauthorized": {"description": "Credential missing, expired or revoked"},
                "Forbidden": {"description": "The role does not allow this"},
                "NotFound": {"description": "Not found"},
                "Conflict": {"description": "Already exists"},
                "Invalid": {"description": "Invalid input"},
                "TooMany": {"description": "Rate limited"},
            },
            "schemas": schemas(),
        },
    })
}

/// Canonical text of the committed copy.
pub fn spec_pretty() -> String {
    let mut t = serde_json::to_string_pretty(&spec()).expect("serialisable");
    t.push('\n');
    t
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeSet;

    /// (path, METHOD) pairs registered with `.route(` in routes.rs (test code excluded).
    fn registered_routes() -> BTreeSet<(String, String)> {
        let src = include_str!("routes.rs");
        let src = &src[..src.find("#[cfg(test)]").expect("test module marker")];
        let mut out = BTreeSet::new();
        let mut rest = src;
        while let Some(at) = rest.find(".route(") {
            let after = &rest[at + ".route(".len()..];
            let mut depth = 1;
            let mut end = after.len();
            for (k, c) in after.char_indices() {
                match c {
                    '(' => depth += 1,
                    ')' => {
                        depth -= 1;
                        if depth == 0 {
                            end = k;
                            break;
                        }
                    }
                    _ => {}
                }
            }
            let call = &after[..end];
            let q1 = call.find('"').expect("path literal");
            let q2 = q1 + 1 + call[q1 + 1..].find('"').unwrap();
            let path = call[q1 + 1..q2].to_string();
            let tail = &call[q2..];
            for m in ["get", "post", "put", "delete"] {
                let needle = format!("{m}(");
                let mut from = 0;
                while let Some(k) = tail[from..].find(&needle) {
                    let pos = from + k;
                    let prev = tail[..pos].chars().last().unwrap_or(' ');
                    if !(prev.is_alphanumeric() || prev == '_') {
                        out.insert((path.clone(), m.to_uppercase()));
                    }
                    from = pos + needle.len();
                }
            }
            rest = &after[end..];
        }
        out
    }

    fn documented() -> BTreeSet<(String, String)> {
        let mut out = BTreeSet::new();
        for (path, item) in spec()["paths"].as_object().unwrap() {
            for method in item.as_object().unwrap().keys() {
                out.insert((path.clone(), method.to_uppercase()));
            }
        }
        out
    }

    #[test]
    fn every_route_is_documented_and_every_documented_route_exists() {
        let (reg, doc) = (registered_routes(), documented());
        assert!(reg.len() > 40, "route scan looks broken: {reg:?}");
        let undocumented: Vec<_> = reg.difference(&doc).collect();
        let phantom: Vec<_> = doc.difference(&reg).collect();
        assert!(
            undocumented.is_empty(),
            "routes missing from the spec: {undocumented:?}"
        );
        assert!(
            phantom.is_empty(),
            "spec documents routes that do not exist: {phantom:?}"
        );
    }

    #[test]
    fn references_resolve_and_operation_ids_are_unique() {
        fn walk(v: &Value, doc: &Value, ids: &mut Vec<String>) {
            match v {
                Value::Object(m) => {
                    if let Some(Value::String(r)) = m.get("$ref") {
                        let ptr = r.strip_prefix('#').expect("local ref");
                        assert!(doc.pointer(ptr).is_some(), "dangling $ref {r}");
                    }
                    if let Some(Value::String(id)) = m.get("operationId") {
                        ids.push(id.clone());
                    }
                    m.values().for_each(|x| walk(x, doc, ids));
                }
                Value::Array(a) => a.iter().for_each(|x| walk(x, doc, ids)),
                _ => {}
            }
        }
        let doc = spec();
        let mut ids = vec![];
        walk(&doc, &doc, &mut ids);
        let unique: BTreeSet<_> = ids.iter().collect();
        assert_eq!(ids.len(), unique.len(), "duplicate operationId");
        assert!(ids.len() > 40);
    }

    #[test]
    fn listing_schemas_carry_no_secret_or_hash() {
        let doc = spec();
        for name in ["ApiToken", "DnsToken", "Device", "Binding"] {
            let props = doc["components"]["schemas"][name]["properties"]
                .as_object()
                .unwrap();
            for k in props.keys() {
                assert!(
                    !k.contains("secret") && k != "token" && !k.contains("hash"),
                    "{name}.{k}"
                );
            }
        }
    }

    /// The committed copy is what the TypeScript types are generated from.
    /// Regenerate with `scripts/gen-api.sh` (sets UPDATE_OPENAPI=1).
    #[test]
    fn committed_openapi_json_is_up_to_date() {
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../docs/reference/openapi.json");
        let want = spec_pretty();
        if std::env::var_os("UPDATE_OPENAPI").is_some() {
            std::fs::write(&path, &want).unwrap();
            return;
        }
        let have = std::fs::read_to_string(&path).unwrap_or_default();
        assert!(
            have == want,
            "docs/reference/openapi.json is stale: run scripts/gen-api.sh"
        );
    }
}

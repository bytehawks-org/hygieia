# API reference

Base URL: the server (`http://127.0.0.1:8080`) or a standalone node (`http://127.0.0.1:8470`, same API). JSON in and out unless stated. Tenant-scoped admin endpoints accept an optional `tenant_id` (query parameter on reads and deletes, field in request bodies); principals bound to one tenant use theirs implicitly.

## Credentials

| Credential | Looks like | Identity | Notes |
|---|---|---|---|
| OIDC JWT | `eyJ…` | `(iss, sub)` → role bindings, per tenant or platform-wide | asymmetric algorithms only; issuer and audience mandatory |
| API token | `hyg_api_…` | one tenant + one role | optional expiry, revocable, shown once |
| Break-glass | `hyg_bg_…` | owner-equivalent | staging/dev only; every use audited |
| Local owner | `hyg_own_…` | owner of the standalone node | file `owner.token`; no break-glass noise in the audit |
| Enrolment token | `hyg_enr_…` | exchanged once for a device credential | short-lived, limited uses |
| Device credential | `hyg_dev_…` | device in a tenant + policy group | pulls bundles only; never opens the admin API |
| DNS token | `hyg_dns_…` | tenant + group for cloud DNS | path credential, see [Cloud DNS](../guides/cloud-dns.md) |

Send admin credentials as `Authorization: Bearer <credential>`. Only SHA-256 hashes of secrets are stored. A single generic 401 is returned for invalid enrolment tokens (no reason leaked). Behind a reverse proxy set `api.trusted_proxies`, otherwise the proxy's address is taken as the client.

## Roles and permissions

| Permission | owner | admin | editor | viewer | auditor |
|---|:-:|:-:|:-:|:-:|:-:|
| `RulesRead` | ✓ | ✓ | ✓ | ✓ | ✓ |
| `RulesWrite` | ✓ | ✓ | ✓ | | |
| `DevicesRead` | ✓ | ✓ | ✓ | ✓ | ✓ |
| `DevicesManage` | ✓ | ✓ | ✓ | | |
| `TokensManage` (enrolment tokens) | ✓ | ✓ | ✓ | | |
| `ApiTokensManage` (API and DNS tokens) | ✓ | ✓ | | | |
| `AuditRead` | ✓ | ✓ | | | ✓ |
| `UsersManage` | ✓ | ✓ | | | |
| `GroupsManage` | ✓ | ✓ | | | |
| `TenantsManage` | ✓ | | | | |

`owner` exists only platform-wide. You can only grant roles whose permissions you hold in that scope (no escalation); a tenant-scoped "owner" gains no tenant-management rights.

## Data plane (no admin credential)

| Method & path | Auth | Purpose |
|---|---|---|
| `GET /healthz` | none | liveness (`ok`) |
| `GET /readyz` | none | readiness: 200 if the store is reachable, else 503 |
| `GET /v1/pubkey` | none | bundle signing public key, 64 hex chars |
| `POST /v1/enroll` | enrolment token in body | `{"token","device_info"}` → `{"device_id","device_secret"}`; 401 for any invalid token |
| `GET /v1/bundle` | device credential | signed bundle (`application/vnd.hygeia.bundle`); `ETag`, `If-None-Match` → 304 |
| `GET /v1/config` | none | non-secret deployment info for the UI: `mode`, `environment`, `break_glass`, `oidc` |
| `GET\|POST /dns-query/{token}` | DNS token in path | RFC 8484 DoH, only when `[cloud_dns]` is enabled (else 404) |
| `PUT /v1/dns/link/{token}` | DNS token in path | register the caller's address as that token's client network (replaces its previous one) |
| `GET /metrics` | scrape token (`HYGEIA_METRICS_TOKEN`) | Prometheus text; 404 while unset |

Node-only: `GET /v1/node/status` (connected mode, bearer = local credential).

## Admin plane

All require a credential with the stated permission. Every mutating call is written to the audit chain; secrets never are.

| Method & path | Permission | Purpose |
|---|---|---|
| `GET /v1/me` | any principal | who am I (principal, roles) |
| `GET\|POST /v1/admin/tenants` | `TenantsManage` | list / create `{slug,name}` |
| `GET\|POST /v1/admin/groups` | `RulesRead` / `GroupsManage` | policy groups `{name}` |
| `GET /v1/admin/users` | `TenantsManage` | platform users |
| `GET\|POST /v1/admin/bindings`, `DELETE …/{id}` | `UsersManage` | role bindings |
| `GET\|POST /v1/admin/api-tokens`, `DELETE …/{id}` | `ApiTokensManage` | `{name,role,ttl_secs?}` → secret once |
| `GET\|POST /v1/admin/dns-tokens`, `DELETE …/{id}` | `ApiTokensManage` | `{name,group_id?,ttl_secs?,dot?}` → secret, `doh_path` and (with `dot`) `dot_label` once |
| `GET\|POST /v1/admin/dns/networks`, `DELETE …/{id}` | `ApiTokensManage` | registered client networks `{name,cidr,group_id?}` (broad ranges → 400, duplicate across tenants → 409) |
| `GET\|PUT /v1/admin/dns/settings` | `RulesRead` / `GroupsManage` | `{log_enabled, retention_days (1–365), fail_open?, block_mode?}` |
| `GET /v1/admin/dns/query-log` | `AuditRead` | `?since=&limit=(≤1000)&q=&action=allow\|block`; newest first |
| `DELETE /v1/admin/dns/query-log` | `GroupsManage` | erase the tenant's log (audited) |
| `GET /v1/admin/dns/stats` | `AuditRead` | totals, top blocked names, top client pseudonyms, by transport (newest 50 000 entries) |
| `POST /v1/admin/enrollment-tokens` | `TokensManage` | `{group_id?,ttl_secs?(3600),max_uses?}` |
| `GET /v1/admin/devices`, `DELETE …/{id}` | `DevicesRead` / `DevicesManage` | devices; revoke |
| `GET\|POST /v1/admin/rules`, `DELETE …/{id}` | `RulesRead` / `RulesWrite` | `{action: allow\|block, pattern, group_id?, comment?}` |
| `POST /v1/admin/simulate` | `RulesRead` | `{host, group_id?, extra_rules?}` → verdict now and with uncommitted rules |
| `GET /v1/admin/lists` | `RulesRead` | download status, counts, license, SHA-256 per source |
| `POST /v1/admin/lists/refresh` | `TenantsManage` | ask the list leader to download now |
| `GET\|POST\|DELETE /v1/admin/list-subscriptions`, `PUT /v1/admin/list-policy` | `RulesRead` / `RulesWrite` | per-tenant list selection |
| `GET /v1/admin/audit` | `AuditRead` | events of the tenant |
| `GET /v1/admin/audit/verify` | `AuditRead` | `{ok, head, events}`; 409 with the error if the chain is broken |

## Verdicts

`simulate` and the engine return `{action: Allow|Block, reason: …}` with the reason naming the rule class that decided: custom allow, custom block, list allow, list block, or default. Precedence: custom allow > custom block > list allow > list block > default.

## Errors

`401` unauthenticated or invalid credential · `403` authenticated but not permitted (or cross-origin on a node) · `404` unknown object (also DoH with an invalid token) · `409` conflict / broken audit chain · `421` unexpected `Host` (node) · `429` rate limited (DoH, link) · `502` upstream unreachable and nothing cached (connected node) · `503` store unavailable (`/readyz`).

## OpenAPI and the generated TypeScript client

The machine-readable contract is [`openapi.json`](openapi.json) (OpenAPI 3.1, every route, parameter, body and response). A running server or node also serves it at `GET /v1/openapi.json` (no credential needed; it describes routes, it exposes no data).

- **Source:** `crates/hygeia-api/src/openapi.rs`, hand-curated because the handlers return untyped responses.
- **Drift is a test failure:** every route registered in the router must be documented (and the reverse); real responses of the main endpoints are validated against the schemas; `openapi.json` must equal what the code produces.
- **TypeScript:** `web/lib/api-schema.d.ts` is generated from it (`openapi-typescript`); the UI's `web/lib/types.ts` derives its types from that file, so an API change that breaks the UI fails `tsc`. `web/lib/client.ts` is a typed client (`openapi-fetch`) for scripts and integrations:

```ts
import { apiClient } from './lib/client';
const c = apiClient('https://hygeia.example.com', 'hyg_api_…');
const { data } = await c.GET('/v1/admin/rules', { params: { query: { tenant_id: 't1' } } });
```

Regenerate after changing the API: `scripts/gen-api.sh` (and `scripts/gen-api.sh --check` to verify). Other languages: feed `openapi.json` to any OpenAPI 3.1 generator.

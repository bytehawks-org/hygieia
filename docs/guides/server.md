# Server guide

The central server (`hygeia`) is one binary: REST API, admin UI, optional DNS, optional DoH. It reads an optional TOML file (first CLI argument) and a few environment variables; every section is optional. Full key list: [Configuration reference](../reference/configuration.md).

```bash
hygeia /etc/hygeia/hygeia.toml
```

## 1. Database (PostgreSQL)

PostgreSQL 17 is the baseline (the schema needs 15+). Without `HYGEIA_DATABASE_URL` the server uses an in-memory store and says so loudly: **nothing survives a restart, including bundle versions**, and extensions will refuse the reset versions (rollback guard).

Create the runtime role **before** the first migration (grants are applied only if it exists), and keep the schema owner separate:

```sql
CREATE ROLE hygeia_owner LOGIN PASSWORD '…' ;           -- owns the schema, runs migrations
CREATE ROLE hygeia_app   LOGIN PASSWORD '…' NOSUPERUSER NOBYPASSRLS;   -- runtime: subject to row-level security
CREATE DATABASE hygeia OWNER hygeia_owner;
```

```bash
export HYGEIA_DATABASE_URL=postgres://hygeia_app:***@db/hygeia      # runtime role
export HYGEIA_MIGRATE_URL=postgres://hygeia_owner:***@db/hygeia     # optional: apply migrations at startup
```

Migrations (`crates/hygeia-store/migrations`): `0001` schema, RLS, enrolment functions · `0002` API-token lookup · `0003` list subscriptions · `0004` shared compiled bundles · `0005` shared blobs and leases · `0006` DNS tokens · `0007` DNS settings and query log · `0008` registered DNS networks and DoT labels. Run them with the owner role only; the runtime role cannot alter the schema, and `audit_events` is append-only even for the owner (trigger).

## 2. Signing key

```bash
export HYGEIA_SIGNING_KEY=$(openssl rand -hex 32)      # 64 hex chars: the bundle signing seed
```

Without it an ephemeral key is generated at every start and **every enrolled browser rejects the new bundles** (it pins the public key). All replicas must use the same key. Treat it as a root secret; see [Operations](../operations.md#signing-key-rotation) for rotation.

## 3. Authentication

| Method | When | Setup |
|---|---|---|
| **OIDC** (humans) | production | `[auth.oidc] issuer, audience` (+ `client_id` for the UI's SSO button). First owner: `bootstrap_owners = ["<sub claim>"]`. |
| **API tokens** `hyg_api_` | automation | created in the UI or `POST /v1/admin/api-tokens`; one tenant, one role, optional expiry. |
| **Break-glass** | staging/dev only | `environment = "staging"`, `[auth.break_glass] enabled = true`, secret in `HYGEIA_BREAK_GLASS_TOKEN` (≥ 32 chars, env only). Refused in production; every use is audited. |

OIDC details: the server is a **resource server**: it validates JWTs (JWKS discovery, issuer, audience, `exp`/`nbf`, asymmetric algorithms only). Identity is `(iss, sub)`; the e-mail claim is never used for authorisation. A user created by a first login has **no roles** until an admin binds one. The admin UI runs authorization-code + PKCE against your IdP and sends the **ID token**, so `audience` must equal the UI's `client_id` (or an audience your IdP puts in the ID token); the IdP must allow CORS on its token endpoint for the UI origin, and `ui_connect_src` lists extra origins the UI may call.

Roles: `owner` (platform-wide), `admin`, `editor`, `viewer`, `auditor`. Matrix in [API reference](../reference/api.md#roles-and-permissions). No privilege escalation: you can only grant what you hold in that scope.

## 4. Admin UI

Built once (`cd web && npm ci && npm run build`) and served by the binary from `api.web_dir` / `HYGEIA_WEB_DIR` / `/usr/share/hygeia/web`. No Node.js at runtime. The UI ships a strict CSP (SHA-256 of the inline bootstrap scripts, no `unsafe-inline` scripts), `frame-ancestors 'none'`, `nosniff`, `no-referrer`; the credential lives in `sessionStorage` (per tab) and is never persisted.

## 5. Container

```bash
podman build -f deploy/Containerfile -t hygeia .
podman run -p 8080:8080 \
  -e HYGEIA_DATABASE_URL -e HYGEIA_MIGRATE_URL -e HYGEIA_SIGNING_KEY \
  -v ./hygeia.toml:/etc/hygeia/hygeia.toml:ro hygeia /etc/hygeia/hygeia.toml
```

The image is distroless, non-root, ships the UI in `/usr/share/hygeia/web`. It exposes 8080/tcp (API + UI) and 5353/udp (DNS, off unless you listen on a reachable address). Terminate TLS in front (reverse proxy or ingress): the API speaks plain HTTP.

### Kubernetes (sketch)

Run N replicas of the same Deployment, a Service for 8080, an Ingress with TLS, and Secrets for the three environment variables. Probes: `livenessProbe: /healthz`, `readinessProbe: /readyz`. `terminationGracePeriodSeconds` ≥ 10 (SIGTERM drains). No sticky sessions needed.

## 6. Several replicas

Nothing to configure beyond a shared PostgreSQL and a shared `HYGEIA_SIGNING_KEY`. Bundles are compiled once and shared; one replica at a time downloads lists (lease) and publishes them for the others. Limits: failover of the list leader takes up to three minutes; a replica notices another's changes within five seconds. Design notes: [Architecture overview](../architecture/overview.md#central-redundancy).

## 7. TLS, reverse proxy and DNS

Two ways to get HTTPS: let the server do it (`api.tls = true` with `[tls] cert/key`; HTTP/1.1 and h2, HSTS, certificate re-read when the files change) or put a TLS-terminating proxy in front (then set `api.trusted_proxies` so client addresses are right).

If you use a proxy,  Redact request paths in access logs if you enable [cloud DNS](cloud-dns.md) (the path is a credential). Restrict `/v1/admin/*` at the network layer if you can; break-glass in particular must never be reachable from the Internet.

The built-in plain DNS server (`[dns]`, UDP, default tenant only) is meant for LAN use and tests. Internet-facing DNS is the DoH service.

## 8. Checklist before production

- [ ] PostgreSQL with the two roles, backups configured (see [Operations](../operations.md#backup-and-restore))
- [ ] `HYGEIA_SIGNING_KEY` set, backed up, shared by all replicas
- [ ] `environment = "production"` (the default): break-glass is refused
- [ ] OIDC configured and a bootstrap owner bound; verify login before removing other access
- [ ] TLS in front; admin paths restricted; DoH paths redacted in logs
- [ ] Lists: reviewed for **license** fit if you serve third parties ([Filter lists](filter-lists.md#licenses))
- [ ] `/readyz` wired to the load balancer; metrics/log shipping of your choice (no Prometheus endpoint yet)
- [ ] `scripts/smoke-server.sh` passes against your build

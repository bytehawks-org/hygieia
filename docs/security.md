# Security

This document states what the system protects, how, and — equally important — what is **not** covered. Report vulnerabilities privately to the repository owners (GitHub *Security → Report a vulnerability*); do not open public issues for them.

## Assets and trust boundaries

| Asset | Where | Protected by |
|---|---|---|
| Bundle signing key | server env / node `signing.key` | file mode 0600, never logged, shared secret between replicas (server) |
| Credentials (`hyg_*`) | clients, `owner.token` | only SHA-256 hashes stored; shown once; revocable; prefix for secret scanners |
| Tenant data | PostgreSQL / `state.json` | RLS + composite FKs / file mode 0600, atomic writes |
| Audit trail | per-tenant hash chain | append-only trigger, chain verification, node refuses a broken chain |
| Filter lists | downloaded | https only, size cap, shrink/empty guards, input validation |
| Admin session | browser `sessionStorage` | strict CSP, short-lived ID token |

Boundaries: Internet ⇄ reverse proxy (TLS) ⇄ server ⇄ PostgreSQL; browser ⇄ node (loopback); node ⇄ server; list hosts ⇄ downloader (untrusted content).

## Controls

**Authentication and authorisation**
- OIDC resource server: issuer and audience mandatory, `exp`/`nbf` checked, asymmetric algorithms only (`none`/HS* forgeries rejected, tested), identity is `(iss, sub)`; e-mail is never used for authorisation. A new user has no roles until bound.
- RBAC with five roles; no privilege escalation (`can_grant`); `owner` is platform-only. API and DNS tokens need a dedicated permission that editors lack.
- Tenant and group always derive from the credential on data-plane endpoints, never from parameters.
- Break-glass is refused in production (also against `HYGEIA_ENVIRONMENT` overrides), needs a ≥ 32-char env-only secret, uses constant-time comparison on digests, delays failures by 200 ms, expires with the process TTL, and **audits every use** with a WARN log.
- Credentials: 256-bit random, SHA-256 at rest (fast hash is appropriate for full-entropy secrets and allows indexed lookup); enrolment tokens are short-lived with limited uses; device credentials never open the admin API; unknown enrolment tokens give one generic 401.

**Integrity of what is enforced**
- Bundles are ed25519-signed; clients verify before decoding and refuse rollbacks; the extension pins the key; the connected node pins the central key and re-verifies its disk cache on every read.
- Lists are untrusted input: CSS-breakout validation of selectors, scriptlets as data with a packaged table (no `eval`, restricted property paths), `trusted-*` scriptlets dropped, unsupported constructs skipped and counted.

**Database**
- `hygeia_app` (runtime) is non-owner and subject to RLS (`app.tenant` set per transaction; absent = no rows); the schema owner is separate; pre-tenant lookups go through narrow `SECURITY DEFINER` functions; `audit_events` is append-only even for the owner.

**Cloud DNS** — attribution is mandatory (token, label or registered network; registrable networks are limited so nobody can register `0.0.0.0/0`); per-token and per-source rate limits with a failed-authentication budget; DoT upstreams are certificate-verified and replies are id-checked; QUIC Retry; the query log is opt-in with keyed, daily-rotating pseudonyms; the metrics endpoint is off unless a token is set and compares digests.

**Network surfaces**
- Admin UI: CSP without `unsafe-inline` scripts (hashes of the build's bootstrap scripts), `frame-ancestors 'none'`, `nosniff`, `no-referrer`; data rendered through React escaping only.
- Node: loopback default; `Host` allow-list (DNS rebinding); `Origin` check on state-changing requests (extension origins only on the extension endpoints); credential never in process arguments; LAN exposure needs two explicit settings.
- Cloud DNS: token in the path or nothing is resolved; per-token rate limit; query size cap; negative caching for garbage tokens.
- The Linux unit runs as a dynamic user with `ProtectSystem=strict`, a syscall filter and a minimal capability set.

## Known gaps (read before deploying)

| Gap | Impact / mitigation |
|---|---|
| TLS is optional in the server (`api.tls` + `[tls]`); the node serves plain HTTP on loopback | for the server enable native TLS or terminate in front; if a proxy is used, redact DoH paths in its logs and set `api.trusted_proxies` |
| No rate limiting on the admin and enrolment endpoints (DNS transports are limited per token, per source and for failed authentications) | rate-limit at the proxy; break-glass delays failures by 200 ms only |
| OIDC session has no refresh | session ends with the ID token |
| Admin credential in `sessionStorage` | an XSS could read it; mitigated by CSP, not eliminated |
| DoH token is in the URL; the DoT/DoQ label is visible in the SNI | proxies, browsers and logs may record the token; the label is an identifier by design (anyone who learns it can use that tenant's resolver within its rate limit) — use registered networks where addresses are stable, per-device tokens with expiry, revoke on leak |
| Cloud DNS: no DNSSEC validation, no active upstream health probes, no per-source *connection* limits (global caps only), UDP `REFUSED` answers go to spoofable sources (header-only, never larger than the query) | not an open resolver; review before running it as a public SaaS; put volumetric DDoS protection in front |
| Audit sinks | no syslog/OTLP sink, no external anchoring of the chain head; an attacker with database owner rights could rewrite the whole chain consistently |
| Node trust model | a compromised connected node sees device secrets passing through and can withhold updates; it cannot forge bundles |
| Windows and Firefox | not run on real systems; treat as experimental |
| Signed releases | artefacts are unsigned (no Authenticode, no AMO signature) |
| Dependencies | `cargo audit` currently reports one *unmaintained* (not vulnerable) transitive crate, `atomic-polyfill` (via `postcard`); tracked by `cargo audit`, `cargo deny` and `npm audit` in CI and Dependabot; there is no SBOM yet |

## Supply chain

CI workflows: `ci` (fmt, clippy `-D warnings`, tests incl. PostgreSQL, wasm check, e2e, packaging), `codeql` (Rust, JavaScript/TypeScript, Actions), `audit` (RustSec advisories, licence/ban/source policy in `deny.toml`, npm advisories), `coverage`. Dependabot opens weekly update PRs.

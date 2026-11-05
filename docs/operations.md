# Operations

## Health and logs

| Endpoint | Meaning |
|---|---|
| `GET /healthz` | process is up |
| `GET /readyz` | store reachable (503 otherwise): use for load-balancer readiness |
| `GET /v1/admin/lists` | per-source `last_ok`, `last_error`, counts, SHA-256 |
| `GET /v1/admin/audit/verify` | audit chain intact (`ok`, `head`, `events`) |
| `GET /v1/node/status` | node in connected mode: node id, upstream, last contact |

Logs are structured `tracing` output on stderr; filter with `RUST_LOG` (e.g. `RUST_LOG=info,hygeia_api=debug`). Secrets and DoH tokens are never logged by the application. Things worth alerting on: `list refresh` errors, `refusing rollback`, `bundle failed verification`, `readiness check failed`, `break-glass` warnings, audit append failures.

Metrics: set `HYGEIA_METRICS_TOKEN` and scrape `GET /metrics` with that bearer token (queries by tenant/transport/outcome, latency histogram, auth failures, refused, rate limited, SERVFAIL, list freshness; see the [Cloud DNS guide](guides/cloud-dns.md#metrics) for alerts). Counters are per process: aggregate across replicas in Prometheus. Set `api.access_log = true` for a request log with DoH/link credentials redacted.

## Backup and restore

- **PostgreSQL:** back up the whole database (`pg_dump` or physical backups). Rules, devices, tokens, tenants, bindings, audit chains and bundle versions live there. Restoring an old backup **rolls back bundle versions**; browsers that saw newer versions will refuse older bundles until the version passes them. Prefer point-in-time recovery to the latest state.
- **Signing key:** `HYGEIA_SIGNING_KEY` (server) or `signing.key` (node) must be backed up separately and securely. Losing it forces every browser to be re-pinned.
- **Node:** copy the data directory while the node is stopped (or rely on `state.json.bak`). Keep `signing.key` and `owner.token` private.

## Upgrades

1. Back up (above).
2. Roll the server replicas one at a time; migrations are applied by the first replica started with `HYGEIA_MIGRATE_URL` (use the owner role only for that run). Migrations are additive. Replicas of different versions can share a database during a rolling upgrade only if the new migration is additive for the old code; check the release notes.
3. The node and extension are tolerant of server outages; upgrade order is free.
4. Verify with `scripts/smoke-server.sh` against a staging instance.

## Signing key rotation

There is no online rotation: browsers pin one key. To rotate:

1. Publish the new public key to users through your trusted channel.
2. Set the new `HYGEIA_SIGNING_KEY` on **all** replicas at once; bundles signed by the new key replace the cached ones (the stored compiled bundles are keyed on the key, so they are rebuilt).
3. Re-pin the key in every extension (options page) or reinstall with the new key. Browsers keep the old bundle until then and keep enforcing it.

Plan for an overlapping-key mechanism if you need zero-touch rotation (not implemented).

## Common operations

| Task | How |
|---|---|
| Renew the TLS certificate | replace the files named in `[tls]`; the server reloads them within a minute (watch for `TLS certificate reloaded` or the error that keeps the old one) |
| Apply query-log retention now | automatic hourly; `DELETE /v1/admin/dns/query-log` erases a tenant's log |
| Revoke a device | UI → Devices, or `DELETE /v1/admin/devices/{id}`; effective on its next bundle pull (immediately through a connected node when the server is reachable) |
| Revoke an API or DNS token | `DELETE /v1/admin/api-tokens/{id}` / `dns-tokens/{id}` |
| Force a list refresh | UI → Filter lists, or `POST /v1/admin/lists/refresh` (the lease holder downloads) |
| Add the first admin | `auth.oidc.bootstrap_owners` or break-glass in staging; bind roles in the UI |
| Check what a rule would do | UI → Rules → what-if, or `POST /v1/admin/simulate` |
| Export audit | `GET /v1/admin/audit` (JSON); CEF formatting exists in the library but has no endpoint yet |

## Troubleshooting

| Symptom | Check |
|---|---|
| Browsers reject all bundles | signing key changed (ephemeral key?), or in-memory server restarted (version reset) |
| Rule change not visible | ≤ 5 s between replicas; extensions poll every 30 min (use the options page to sync); DNS follows within 5 s |
| Lists empty / not updating | `GET /v1/admin/lists`: `last_error`; outbound https to the list hosts; the shrink/empty guard may be keeping the old copy on purpose |
| `/readyz` 503 | PostgreSQL unreachable or credentials wrong |
| Node refuses to start | damaged or tampered `state.json` (restore `.bak`), `http.listen` not loopback without `allow_lan` + `allowed_hosts`, port in use |
| Connected node returns 502 | server unreachable and the device never got a bundle through this node; check `upstream.url`, the pinned key and `GET /v1/node/status` |
| Node returns 421 | the `Host` header is not allowed: use the node's own URL or add the name to `http.allowed_hosts` |
| DoH 404 | token invalid, expired, revoked or `[cloud_dns]` disabled |
| DoH 429 / DNS silently dropped | per-token or per-source rate limit (`rate_per_sec`, `burst`, `ip_rate_per_sec`, `ip_burst`) or a spent failed-authentication budget for that address (wait, or fix the client's token) |
| Plain DNS / DoT answers `REFUSED` | the client's source address is not a registered network (and, for DoT/DoQ, the SNI label does not match a token); behind NAT or a proxy check the address the server sees |
| Query log empty | `log_enabled` is false for the tenant (default), or the writer queue overflowed (`hygeia_dns_query_log_dropped_total`) |
| DNS port 53 in use on Linux | systemd-resolved stub; see the [Node guide](guides/node.md#linux-deb-systemd) |

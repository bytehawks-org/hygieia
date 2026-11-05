# Configuration reference

Both binaries read an optional TOML file; **every section and key is optional**, an empty file is valid, unknown keys are errors (typos fail loudly). Secrets never come from the file.

## Server (`hygeia [config.toml]`)

| Key | Default | Meaning |
|---|---|---|
| `api.listen` | `127.0.0.1:8080` | API + UI listen address |
| `api.web_dir` | `` | built admin UI; empty → `HYGEIA_WEB_DIR`, then `/usr/share/hygeia/web`, else no UI |
| `api.tls` | `false` | serve API, UI and DoH over HTTPS using `[tls]` (sends HSTS). Off: plain HTTP behind a TLS proxy |
| `api.access_log` | `false` | one log line per request; DoH and link tokens are redacted from the path |
| `api.trusted_proxies` | `[]` | CIDRs of reverse proxies whose `X-Forwarded-For` is trusted for the client address |
| `tls.cert`, `tls.key` | `` | PEM certificate chain and key for HTTPS, DoT and DoQ; re-read when the files change |
| `auth.environment` | `production` | `production` \| `staging` \| `dev` (`HYGEIA_ENVIRONMENT` overrides) |
| `auth.break_glass.enabled` | `false` | allow the break-glass credential (refused in production) |
| `auth.break_glass.ttl_hours` | `12` | credential dies this long after process start (0 = no limit) |
| `auth.oidc.issuer` | `` | empty = OIDC disabled |
| `auth.oidc.audience` | `hygeia-api` | required audience |
| `auth.oidc.client_id` | `` | UI's public client id (empty = no SSO button) |
| `auth.oidc.ui_connect_src` | `[]` | extra origins the UI may call (CSP `connect-src`) |
| `auth.oidc.leeway_secs` | `30` | clock skew tolerance |
| `auth.oidc.allow_insecure_http` | `false` | lab only |
| `auth.oidc.bootstrap_owners` | `[]` | `sub` claims granted platform `owner` at startup (idempotent, additive) |
| `dns.enabled` | `true` | built-in plain-UDP DNS server (default tenant only) |
| `dns.listen` | `127.0.0.1:5353` | |
| `dns.upstream` | `["9.9.9.9:53"]` | plain-UDP upstream (first is used) |
| `dns.block_mode` | `nxdomain` | or `null_ip` |
| `cloud_dns.enabled` | `false` | DoH at `/dns-query/<token>` |
| `cloud_dns.upstreams` | `[]` → `udp://9.9.9.9:53` | resolvers tried in order with failover: `udp://ip:53`, `tls://ip:853#server.name`, `https://host/dns-query` |
| `cloud_dns.upstream` | `` | single plain-UDP upstream (`ip:port`), used only if `upstreams` is empty |
| `cloud_dns.udp_listen`, `tcp_listen` | `` | plain DNS for registered networks (empty = off) |
| `cloud_dns.dot_listen`, `doq_listen` | `` | DNS over TLS / QUIC (need `[tls]` and `dot_domain`) |
| `cloud_dns.dot_domain` | `` | SNI `<label>.<dot_domain>` selects a token created with `"dot": true` |
| `cloud_dns.ip_rate_per_sec`, `ip_burst` | `100`, `200` | per source address, all transports |
| `cloud_dns.block_mode` | `nxdomain` | or `null_ip` |
| `cloud_dns.rate_per_sec`, `burst` | `50`, `100` | per token |
| `cloud_dns.fail_open` | `false` | answer when no bundle is available instead of SERVFAIL |
| `lists.*` | see below | filter lists |

### Environment variables (server)

| Variable | Meaning |
|---|---|
| `HYGEIA_DATABASE_URL` | runtime PostgreSQL role (non-owner, RLS applies). Unset → in-memory store |
| `HYGEIA_MIGRATE_URL` | schema owner; when set, migrations run at startup |
| `HYGEIA_SIGNING_KEY` | 64 hex chars bundle signing seed; unset → ephemeral key (a warning is logged) |
| `HYGEIA_LOG_KEY` | 64 hex chars: master secret of the query-log client pseudonyms; unset → random per process (pseudonyms change at restart) |
| `HYGEIA_METRICS_TOKEN` | ≥ 16 chars: enables `GET /metrics` (bearer); unset → 404 |
| `HYGEIA_ENVIRONMENT` | overrides `auth.environment` |
| `HYGEIA_BREAK_GLASS_TOKEN` | break-glass secret, ≥ 32 chars; in `dev` a throwaway one is generated if unset |
| `HYGEIA_WEB_DIR` | built UI directory |
| `RUST_LOG` | log filter (default `info`) |

## Node (`hygeia-proxy`, `<data-dir>/hygeia-proxy.toml` or `--config`)

| Key | Default | Meaning |
|---|---|---|
| `mode` | `standalone` | `standalone` \| `connected` |
| `http.listen` | `127.0.0.1:8470` | non-loopback needs `allow_lan = true` **and** `allowed_hosts` |
| `http.allow_lan` | `false` | |
| `http.allowed_hosts` | `[]` | extra accepted `Host` values (`host:port`) |
| `http.web_dir` | `` | built UI; empty = autodetect (`HYGEIA_WEB_DIR`, next to the binary, `/usr/share/hygeia/web`) |
| `dns.mode` | `off` | `off` \| `local` (not available in connected mode yet) |
| `dns.listen` | `127.0.0.1:5353` | |
| `dns.upstream` | `["9.9.9.9:53"]` | plain UDP |
| `dns.block_mode` | `nxdomain` | or `null_ip` |
| `upstream.url` | `` | connected: `https://…` (required) |
| `upstream.public_key` | `` | connected: central signing key, 64 hex (required, pinned) |
| `upstream.allow_insecure_http` | `false` | labs only |
| `upstream.timeout_secs` | `10` | |
| `lists.*` | see below | standalone only |

Environment (node): `HYGEIA_PROXY_DATA_DIR`, `HYGEIA_WEB_DIR`, `HYGEIA_PROXY_OPEN_LINGER_SECS` (how long `open` keeps its redirect page, default 15), `RUST_LOG`. The packaged Linux unit reads `/etc/hygeia-proxy/hygeia-proxy.toml`; a root shell uses it too when it exists.

## `[lists]` (server and standalone node)

| Key | Default | Meaning |
|---|---|---|
| `enabled` | `true` | download lists |
| `refresh_hours` | `12` | |
| `allow_insecure_http` | `false` | plain-http list URLs (labs, trusted mirrors) |
| `sources` | unset | catalogue ids; unset = default set. Unknown id → error |
| `[[lists.custom]]` | – | `id, name, url, format (hosts\|domains\|abp), license, attribution, network, cosmetic`; license and attribution mandatory |

Catalogue and semantics: [Filter lists](../guides/filter-lists.md).

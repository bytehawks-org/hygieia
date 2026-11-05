# Cloud DNS guide

Filtering DNS for clients that are not on your LAN: DNS over HTTPS, DNS over TLS, DNS over QUIC and plain DNS from registered networks, all answered with the tenant's signed bundle. Design constraints: [dns-service.md](../architecture/dns-service.md).

**The rule: never an open resolver.** A query is answered only if it can be attributed to a tenant and policy group; everything else is refused (HTTP 404, DNS `REFUSED`) and nothing is recursed.

## Transports and how a client is identified

| Transport | Endpoint | Identified by | Refusal |
|---|---|---|---|
| **DoH** (RFC 8484) | `https://dns.example.com/dns-query/<token>` | the `hyg_dns_…` token in the path (a secret) | 404 |
| **DoT** (RFC 7858) | `tls://<label>.dns.example.com:853` | the token's **label** in the SNI (an identifier, visible on the wire), else the client's registered network | `REFUSED` |
| **DoQ** (RFC 9250) | `quic://<label>.dns.example.com:853` | same as DoT | `REFUSED` |
| Plain DNS (UDP/TCP) | `:53` | the client's **registered network** only | `REFUSED` (header only, never larger than the query) |

Choose by risk: the DoH token is a secret; a DoT/DoQ label is an *identifier* (SNI is not encrypted), so anyone who learns it can use that tenant's filtering resolver, within the token's rate limit, until you revoke it. Prefer registered networks where addresses are stable. Create a token with a label only when you need DoT/DoQ roaming (`"dot": true`).

## Enable

```toml
[tls]                                  # HTTPS, DoT and DoQ share the certificate (re-read when the files change)
cert = "/etc/hygeia/tls.crt"
key  = "/etc/hygeia/tls.key"

[api]
tls = true                             # serve the API, UI and DoH over HTTPS (HSTS). Or terminate TLS in a proxy.
trusted_proxies = ["10.0.0.0/8"]       # only if a proxy sits in front: its X-Forwarded-For is then believed
access_log = true                      # one line per request, DoH/link paths redacted

[cloud_dns]
enabled = true
upstreams = ["tls://9.9.9.9:853#dns.quad9.net", "https://dns.quad9.net/dns-query", "udp://9.9.9.9:53"]
block_mode = "nxdomain"                # or "null_ip"
udp_listen = "0.0.0.0:53"              # plain DNS for registered networks (empty = off)
tcp_listen = "0.0.0.0:53"
dot_listen = "0.0.0.0:853"             # needs [tls] and dot_domain
doq_listen = "0.0.0.0:853"             # UDP; needs [tls] and dot_domain
dot_domain = "dns.example.com"         # SNI <label>.dns.example.com; the certificate must cover *.dns.example.com
rate_per_sec = 50                      # per token
burst = 100
ip_rate_per_sec = 100                  # per source address, all transports
ip_burst = 200
fail_open = false                      # no bundle available: SERVFAIL (default) or answer anyway (per-tenant override below)
```

Environment: `HYGEIA_LOG_KEY` (64 hex, stable query-log pseudonyms), `HYGEIA_METRICS_TOKEN` (enables `/metrics`). Listening on port 53 or 853 needs privileges (`CAP_NET_BIND_SERVICE`) or a redirect.

Certificates: obtain them with your ACME client (e.g. certbot DNS-01 for the wildcard) and let it rewrite the files; the server reloads them within a minute and keeps the old certificate if the new files are broken. Ports 853 over TCP (DoT) and UDP (DoQ) need to be open.

## Upstream resolvers and failover

`upstreams` are tried in order; the first valid reply wins. Forms: `udp://ip:53`, `tls://ip:853#server.name` (the certificate is verified against the name), `https://host/dns-query`. A reply is accepted only if it parses and carries the query's id. An upstream that fails twice in a row is skipped for 30 seconds (all are retried if all are down). DoT keeps an idle connection per upstream. Order them by preference: encrypted first, plain UDP last, or omit plain UDP entirely.

## Tokens, networks, "link my IP"

```bash
# DoH token (+ DoT/DoQ label); the secret is shown once
curl -XPOST https://hygeia.example.com/v1/admin/dns-tokens -H "authorization: Bearer $TOKEN" \
  -H 'content-type: application/json' -d '{"name":"laptop","group_id":"<policy group>","ttl_secs":31536000,"dot":true}'
# -> {"id":…,"token":"hyg_dns_…","doh_path":"/dns-query/hyg_dns_…","dot_label":"…"}

# register an office network for plain DNS (public ranges must be /24 or smaller)
curl -XPOST https://hygeia.example.com/v1/admin/dns/networks -H "authorization: Bearer $TOKEN" \
  -H 'content-type: application/json' -d '{"name":"office","cidr":"203.0.113.0/24","group_id":"<policy group>"}'

# a client with a dynamic address re-registers itself with its token (replaces its previous address)
curl -XPUT https://hygeia.example.com/v1/dns/link/hyg_dns_…
```

Registration rules (open-resolver protection): a CIDR belongs to exactly one tenant; private blocks may be registered whole (`10.0.0.0/8`, `192.168.0.0/16`, `fd00::/32`…), public IPv4 must be at least a `/24`, public IPv6 at least a `/48`; `0.0.0.0/0` and friends are refused. The most specific registration wins. Changes take effect at once on the replica that made them and within 30 seconds elsewhere. Tokens and networks are audited; secrets never are. Revoking a DNS token stops its DoH path and its label (≤ 30 s on other replicas).

## Per-tenant settings

`GET|PUT /v1/admin/dns/settings` (admin or owner):

```json
{"log_enabled": false, "retention_days": 30, "fail_open": null, "block_mode": null}
```

`fail_open` and `block_mode` override the server defaults for this tenant (`null` = server default). Changes are audited with before/after.

## Query log (off by default) and privacy

When `log_enabled` is true, each answered query is logged as: time, policy group, token or network id, transport, **client pseudonym**, query name, type, action (`allow`/`block`) and the deciding rule class. Never the IP, never a token.

The pseudonym is `HMAC-SHA256(HMAC-SHA256(master, "tenant|UTC-day"), client address)` truncated to 64 bits; IPv6 addresses are reduced to their /64 first. It is stable within a day (so statistics like "top clients" work), changes every day, differs per tenant, and cannot be reversed without `HYGEIA_LOG_KEY`. Without that variable a random key is used per process (pseudonyms also change at restart).

Retention is per tenant (1–365 days, default 30) and enforced hourly. Read with `GET /v1/admin/dns/query-log?since=&limit=&q=&action=` and `GET /v1/admin/dns/stats` (auditor, admin, owner); erase everything for the tenant with `DELETE /v1/admin/dns/query-log` (audited). Query names are personal data: tell your users, keep retention short, see [Privacy](../privacy-compliance.md).

## Metrics

`GET /metrics` (Prometheus text) with `Authorization: Bearer $HYGEIA_METRICS_TOKEN`; 404 while the variable is unset.

| Metric | Meaning |
|---|---|
| `hygeia_dns_queries_total{tenant,transport,outcome}` | answered queries; outcome `allowed` / `blocked` / `servfail` |
| `hygeia_dns_resolve_seconds` | latency histogram (resolution only) |
| `hygeia_dns_auth_failures_total` | unknown/revoked/expired tokens |
| `hygeia_dns_refused_total` | unregistered sources |
| `hygeia_dns_rate_limited_total` | rate-limited queries |
| `hygeia_dns_upstream_servfail_total` | SERVFAIL (upstream failure or no bundle) |
| `hygeia_dns_query_log_dropped_total` | log entries dropped (writer queue full) |
| `hygeia_list_block_domains{source}`, `hygeia_list_last_ok_timestamp_seconds{source}` | list health |
| `hygeia_up`, `hygeia_build_info{version}` | store reachable; version |

```yaml
scrape_configs:
  - job_name: hygeia
    scheme: https
    authorization: { credentials_file: /etc/prometheus/hygeia.token }
    static_configs: [{ targets: ["hygeia.example.com"] }]
```

Useful alerts: `rate(hygeia_dns_upstream_servfail_total[5m]) > 0`, `increase(hygeia_dns_auth_failures_total[5m]) > 100` (token guessing), `time() - hygeia_list_last_ok_timestamp_seconds > 86400`, `hygeia_up == 0`.

## Limits and abuse controls

| Control | Behaviour |
|---|---|
| Per token | token bucket (`rate_per_sec`, `burst`); 429 on DoH |
| Per source address | `ip_rate_per_sec`, `ip_burst`, shared by all transports; IPv6 per /64 |
| Failed authentications | each failure draws from a small per-address budget (burst 20, 0.5/s): once spent, that address is refused even with a valid token until it refills |
| Query size | 4 KiB; oversized frames close the connection |
| Connections | at most 2048 concurrent TCP/TLS/QUIC connections; 15 s idle timeout |
| QUIC | Retry (address validation) always on |
| UDP replies | over 1232 bytes are replaced by a truncated reply (client retries over TCP) |

## Client setup

| Client | Setting |
|---|---|
| Firefox | Settings → Privacy → *DNS over HTTPS* → Custom → `https://dns.example.com/dns-query/<token>` |
| Chrome / Edge | Settings → Privacy → *Use secure DNS* → Custom |
| Android | *Private DNS* → `<label>.dns.example.com` (DoT) |
| Windows 11 | per-adapter encrypted DNS with a DoH template; check the current `netsh dns add encryption` syntax for your build |
| Linux (systemd-resolved) | `DNS=<ip>#<label>.dns.example.com` with `DNSOverTLS=yes` |
| Routers / servers on a fixed address | register the public address as a network and use plain DNS |

Verify: `scripts/smoke-server.sh` against a local server, or `kdig -d @dns.example.com +tls-host=<label>.dns.example.com example.org` for DoT.

## Not covered

HTTP/3 for DoH, EDNS client-subnet handling, DNSSEC validation (replies are passed through), per-user policy via IdP identity, anycast/multi-region. Per-connection limits per source address are not implemented (only global and per-query limits).

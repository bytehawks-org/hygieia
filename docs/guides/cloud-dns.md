# Cloud DNS (DoH) guide

Status: **first slice implemented**: per-token DNS over HTTPS with the tenant's signed bundle. Not yet: DoT, registered-CIDR plain DNS, DoT/DoH upstream, query log, metrics. Design constraints: [dns-service.md](../architecture/dns-service.md).

## How it works

`GET|POST https://dns.example.com/dns-query/<token>` (RFC 8484, wire format). The token (`hyg_dns_…`) is the **only** way a query is attributed to a tenant and policy group; without a valid token nothing is resolved (404): it is never an open resolver. Blocked names get NXDOMAIN (or `0.0.0.0`/`::` with `block_mode = "null_ip"`); allowed queries go to the configured upstream resolver (plain UDP for now). If no bundle is available the answer is SERVFAIL (`fail_open = true` forwards instead).

## Enable

```toml
[cloud_dns]
enabled = true
upstream = "9.9.9.9:53"          # plain-UDP recursive resolver (DoT/DoH upstream: not yet)
block_mode = "nxdomain"          # or "null_ip"
rate_per_sec = 50                # per token
burst = 100
fail_open = false
```

## Issue and revoke tokens

```bash
curl -XPOST https://hygeia.example.com/v1/admin/dns-tokens -H "authorization: Bearer $TOKEN" \
  -H 'content-type: application/json' \
  -d '{"name":"laptop","group_id":"<policy group>","ttl_secs":31536000}'
# -> {"id":"…","token":"hyg_dns_…","doh_path":"/dns-query/hyg_dns_…"}   (the secret is shown once)
curl -XDELETE https://hygeia.example.com/v1/admin/dns-tokens/<id> -H "authorization: Bearer $TOKEN"
```

Requires the same permission as API tokens (admin or owner). Creation and revocation are audited; the secret never is. Revocation is immediate on the replica that handles it and takes at most 30 seconds on the others (token-lookup cache).

## Put TLS in front, and redact the path

The server speaks plain HTTP. The URL path is a credential: configure the proxy to redact it from access logs.

```nginx
# nginx: terminate TLS, log without the token
log_format dns '$remote_addr [$time_local] "$request_method /dns-query/<redacted>" $status';
server {
  listen 443 ssl http2;  server_name dns.example.com;
  ssl_certificate     /etc/ssl/dns.example.com.pem;
  ssl_certificate_key /etc/ssl/dns.example.com.key;
  location /dns-query/ { access_log /var/log/nginx/dns.log dns; proxy_pass http://127.0.0.1:8080; }
  location / { return 404; }      # do not expose the admin API on this name
}
```

Expose the DoH hostname separately from the admin hostname.

## Use it from a client

| Client | Setting |
|---|---|
| Firefox | Settings → Privacy → *DNS over HTTPS* → Custom → `https://dns.example.com/dns-query/<token>` |
| Chrome / Edge | Settings → Privacy → *Use secure DNS* → Custom |
| Windows 11 | per-adapter DNS with an encryption template (`netsh dns add encryption`); check the current syntax for your build |
| Android | *Private DNS* needs DoT (not implemented yet) |
| Any other OS | run the node's *cloud forward* option when it ships, or a local DoH proxy |

Verify with `curl`: `curl -s -H 'accept: application/dns-message' "https://dns.example.com/dns-query/<token>?dns=<base64url query>" | xxd`, or run `scripts/smoke-server.sh` against a local server.

## Behaviour you should know

- Limits: 4 KiB per query; token-bucket rate limit per token (429); positive/negative token-lookup caching so garbage tokens do not become database load.
- The bundle for the token's group is decoded once and cached for 5 seconds between checks, so rule changes reach DNS within seconds.
- Counters (queries, blocked, forwarded, auth failures, rate limited, servfail) exist in memory; there is no metrics endpoint yet.
- Privacy: **no query log is written yet**; when it is, IPs will be pseudonymised and retention bounded (see [Privacy and compliance](../privacy-compliance.md)).

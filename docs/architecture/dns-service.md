# DNS service (SaaS / central, multi-instance)

The central server can expose filtering DNS over the network: the "cloud DNS" users may choose instead of (or besides) the node's local DNS. Same engine and signed rulesets as everywhere else; what changes is that it faces the Internet.

## Constraints (design before code)

1. **Never an open resolver.** Every query must be attributable to a tenant by one of the mechanisms below; unattributed queries are refused (REFUSED), not recursed. This avoids abuse and amplification.
2. **Tenant identification** (`TenantKey` in `hygeia-core`):
   - DoH: `/dns-query/<token>` (`hyg_dns_…`, revocable, per tenant/group/device). Reverse proxies must redact the path in access logs.
   - DoT: SNI `<id>.dns.example.com` (wildcard certificate, ACME DNS-01).
   - Plain DNS from a fixed network: registered source CIDR (and a "link my current IP" update endpoint for dynamic addresses). Plain UDP/TCP on the public Internet is **off** unless CIDRs are registered.
   - DoQ later.
3. **Rate limiting and quotas** per tenant and per source; response-rate limiting on UDP; bounded in-flight upstream queries; EDNS buffer limits.
4. **Privacy / compliance** (GDPR, NIS2): query-log IP pseudonymisation (keyed hash with rotating key), per-tenant retention, deletion on tenant removal, EU-resident storage option, log schema without raw tokens. The token in a DoH path is a credential: never logged.
5. **Upstream recursion** over DoT/DoH to configurable resolvers (EU defaults), with health checks and failover; DNSSEC validation pass-through.
6. **Operations**: stateless replicas behind a load balancer (UDP/TCP/TLS/HTTPS), readiness gated on having a verified bundle for each served tenant, metrics per tenant/list (Prometheus), graceful drain.
7. **Failure policy** per tenant (fail-open / fail-closed when no bundle is available) and recorded in the audit chain when changed.

## Status

Implemented (first slice, `[cloud_dns] enabled = true`, off by default):

- **DoH** `GET|POST /dns-query/<token>` (RFC 8484, wire format), token `hyg_dns_…` per tenant + group, SHA-256 stored, revocable, optional expiry, issued via `POST /v1/admin/dns-tokens` (permission `ApiTokensManage`; secret shown once, never in audit or list). Unknown/revoked/expired token = 404 and nothing is resolved (never an open resolver).
- Per-token token-bucket rate limit (429), 4 KiB query cap, positive (30 s) and negative (10 s) token-lookup cache so garbage tokens do not hit the database; local revocation is immediate, other replicas lag at most 30 s.
- Decision with the tenant's signed bundle (same engine as everywhere), NXDOMAIN or null-IP; allowed queries go to a plain-UDP upstream; failure policy global `fail_open` (default closed = SERVFAIL).
- Counters (queries, blocked, forwarded, auth failures, rate limited, servfail) in memory.

Not implemented: DoT (SNI), registered-CIDR plain DNS, DoQ; DoT/DoH upstream and health-checked failover; **query log with IP pseudonymisation and retention**; Prometheus metrics endpoint; per-tenant failure policy; per-source-IP limits (needs connection info in the API server). TLS is terminated by a reverse proxy in front: it must redact the request path in its logs.

## Relation to the node

The node's *cloud forward* option is a thin local stub that sends queries to this service over DoH/DoT with the device's DNS token; the node itself never needs the bundle for DNS in that mode. DNS tokens are issued from the central UI like enrolment tokens and can be bound to the node or to a single browser/device.

## Out of scope for now

Anycast / multi-region steering, DDoS mitigation (delegated to the fronting network), per-user policy via IdP identity on DNS.

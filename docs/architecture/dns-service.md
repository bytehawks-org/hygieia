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

## Status (implemented, `[cloud_dns] enabled = true`)

| Constraint | Implementation |
|---|---|
| 1. Never an open resolver | every query must be attributed: DoH token (404), DoT/DoQ SNI label or registered network, plain DNS registered network (`REFUSED`, header-only, no amplification); registrable CIDRs are limited (public IPv4 ≥ /24, IPv6 ≥ /48) |
| 2. Tenant identification | `hyg_dns_` tokens (DoH path, optional DoT/DoQ label), registered networks with longest-prefix match, "link my IP" for dynamic addresses |
| 3. Rate limiting | per token and per source address (IPv6 per /64), failed-auth budget per address, query size cap, connection cap, QUIC Retry, UDP truncation |
| 4. Privacy | query log **off by default**; client pseudonym = HMAC with a daily-rotating, per-tenant key; no raw IP or token logged; per-tenant retention (1–365 d) with an hourly purge; erase endpoint |
| 5. Upstream | ordered failover over UDP, DoT (verified TLS, connection reuse) and DoH; reply-id validation; 30 s back-off after two failures. Not implemented: active health probes, DNSSEC validation (replies pass through) |
| 6. Operations | stateless replicas (settings, networks, tokens in PostgreSQL; ≤ 30 s propagation), `/readyz`, Prometheus `/metrics`, graceful drain, certificate hot-reload |
| 7. Failure policy | per-tenant `fail_open` and `block_mode` settings (audited), server defaults |

Transports: DoH, DoT, DoQ, plain UDP/TCP, and native HTTPS for the API (or a TLS-terminating proxy). Guide: [Cloud DNS](../guides/cloud-dns.md).

Not implemented: HTTP/3 for DoH, EDNS client subnet, per-user policy, anycast. Connection limits per source address (global caps only). Metrics are per process (aggregate across replicas in Prometheus).

## Relation to the node

The node's *cloud forward* option is a thin local stub that sends queries to this service over DoH/DoT with the device's DNS token; the node itself never needs the bundle for DNS in that mode. DNS tokens are issued from the central UI like enrolment tokens and can be bound to the node or to a single browser/device.

## Out of scope for now

Anycast / multi-region steering, DDoS mitigation (delegated to the fronting network), per-user policy via IdP identity on DNS.

# Privacy and compliance notes (GDPR, NIS2)

Hygieia is designed so that a deployment *can* meet these frameworks; **it does not make a deployment compliant by itself**. This page states what the software does today and what is still missing. It is engineering documentation, not legal advice.

## What data exists

| Data | Personal? | Where | Retention today |
|---|---|---|---|
| Admin identities `(iss, sub)`, optional e-mail from the IdP | yes (staff) | `users`, `role_bindings` | until removed; no automatic deletion |
| Device records (id, `device_info` free text supplied by the client, enrolment time) | possibly (device names) | `device_credentials` | until revoked/deleted |
| Rules and comments written by admins | no (but may contain names) | `rules` | until deleted |
| Audit events (actor, action, target, diff) | yes (actor identity, targets) | per-tenant chain | append-only by design; **cannot be deleted without breaking the chain** |
| DNS queries (cloud DNS) | yes (browsing behaviour) | `query_log`, **off by default**, per tenant opt-in | per tenant 1–365 days (default 30), purged hourly; erasable on demand |
| Client networks and DNS tokens | possibly (an office IP, a device name) | `dns_networks`, `dns_tokens` | until deleted/revoked |
| Extension | blocking happens locally; the extension sends nothing but the periodic bundle request and enrolment | – | – |

## GDPR posture

- **Data minimisation:** the extension and the node record nothing about browsing. The cloud DNS query log is **off by default** and is enabled per tenant by an admin (the change is audited). When on, it stores the query name, type, decision and a **client pseudonym**, never the IP address or a token. The pseudonym is a keyed HMAC whose key rotates daily and differs per tenant (IPv6 reduced to /64), so it supports same-day statistics but cannot be linked across days or tenants, nor reversed without the operator's master secret (`HYGEIA_LOG_KEY`; keep it separate from the database and from backups of the database). The query name itself is personal data: it can identify a person's activity. Decide a purpose, keep retention short, inform the data subjects.
- **Retention and erasure:** per-tenant retention (1–365 days, default 30) is enforced by an hourly purge; `DELETE /v1/admin/dns/query-log` erases a tenant's log immediately (audited); deleting a tenant cascades. Backups of the database keep log rows until the backup expires: align backup retention with the longest log retention you promise.
- **No per-user data subject access** is possible by design: pseudonyms are not reversible and rotate; you cannot answer "what did person X query" from the log (a feature for minimisation, a limit for access requests; document it in your notice).
- **Tenant isolation** is enforced by the database (RLS) and tested.
- **Deletion and rectification:** tenants and their data can be removed through the database (cascading foreign keys); there is no self-service export/erase endpoint yet. The audit chain is the deliberate exception (tamper evidence vs erasure): treat audit data as an operational security record with a documented legal basis and retention, and keep personal data out of rule comments and `device_info`.
- **Processor role:** if you offer Hygieia as a service, you are a processor for your tenants' admin and (later) DNS data; you need a DPA, sub-processor list and a data-residency decision (PostgreSQL location; EU-hosted by choice, nothing in the software sends data elsewhere except list downloads and the DNS upstream you configure).
- **Transfers:** the DNS upstream receives allowed queries from the server's address (not the client's); choose an EU resolver. List hosts see the server's IP only.

## NIS2-oriented measures present

| Measure | Status |
|---|---|
| Access control and least privilege | RBAC, no escalation, scoped API tokens, break-glass restricted and audited |
| Logging and tamper evidence | hash-chained audit, verify endpoint, CEF formatter; Prometheus metrics; access log with credential redaction; no remote sink yet |
| Cryptography | ed25519 signed artefacts; secrets hashed; TLS is delegated to the deployment |
| Supply-chain security | RustSec, licence policy, CodeQL, Dependabot; no SBOM or signed releases yet |
| Incident handling / vulnerability disclosure | private reporting channel; no formal process documented here |
| Business continuity | stateless replicas, offline-tolerant nodes and extensions; backups are the operator's responsibility ([Operations](operations.md)) |
| Retention automation | query log: implemented; audit chain: by design not deleted |
| Open: log shipping (syslog/OTLP), DPIA template | not implemented |

## Before you rely on it

1. Decide a legal basis and retention for audit data; keep personal data out of free-text fields.
2. Place the database and logs in the jurisdiction you promise.
3. Review list licenses ([Filter lists](guides/filter-lists.md#licenses)) before redistributing derived bundles.
4. Re-read the [Security known gaps](security.md#known-gaps-read-before-deploying).

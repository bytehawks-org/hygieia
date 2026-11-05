# Roadmap

What is **left to do**, in priority order. What exists is in the [Changelog](../CHANGELOG.md).
Status of every item: `todo` unless stated.

## Delivered

Core engine and signed bundles · audit chain · PostgreSQL store with RLS · filter lists · browser extension (Chrome, Firefox build) · OIDC/API-token/break-glass auth with RBAC · admin UI · standalone and connected node · central redundancy · packaging (Linux `.deb`/systemd; Windows service, tray, zip, MSI + setup wizard) · cloud DNS (DoH, DoT, DoQ, plain by network, failover, limits, query log, metrics, native TLS) · OpenAPI 3.1 and generated TypeScript client · tag-only CI.

## 1. Verify what has never run (next)

| Item | How |
|---|---|
| All workflows on GitHub (`ci` via `release`, `codeql`, `audit`, `coverage`, `extension-e2e`, `windows`) | push a tag such as `v0.1.0-rc1`; fix what fails; promote advisory jobs to required |
| Windows: MSI, wizard, service, tray | install the MSI from the draft release on Windows 11; unattended `msiexec /qn` too |
| Firefox | manual pass: enrol, ads page, console |
| systemd on a live host, RPM build | `systemctl enable --now`; `rpmbuild` on Fedora |
| PostgreSQL suites in CI | already wired in `ci`; confirm on the first tag |

## 2. Cloud DNS hardening

- Load test (throughput, latency under load, memory) and interoperability run with real DoT/DoQ/DoH clients and public resolvers.
- Per-source connection limits (today only global caps); active upstream health probes.
- DNSSEC validation; HTTP/3 for DoH.
- Log shipping (syslog/OTLP) and an external anchor for the audit chain head.

## 3. Node

- Cloud forward: send the node's DNS to the tenant's cloud endpoint.
- Local DNS in connected mode; audit and telemetry forwarding to the central server.
- Pause-blocking API (so the tray can offer it); OS-resolver integration only as an explicit opt-in step with safe revert.

## 4. Product

- OIDC refresh in the UI; UI for cloud DNS (tokens, networks, query log, stats).
- Extension: more scriptlets, procedural cosmetic selectors, earlier script injection; Chrome DNR budget measurements.
- Per-tenant fail-closed policy for the extension.

## 5. Delivery and operations

- Sign release artefacts (MSI Authenticode, checksums/signatures for `.deb` and zips); publish to winget/apt.
- Container image and Helm chart for the server; example reverse-proxy configs.
- Independent security review; SBOM generation in the release workflow.

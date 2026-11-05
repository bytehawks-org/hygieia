# Changelog

All notable changes to this project are documented here. Format based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/); versions follow
[Semantic Versioning](https://semver.org/) once a first release is tagged.

Nothing has been released yet: everything below is **Unreleased** (`0.1.0` in development).
Items marked *unverified* have never run on a real target (see [Roadmap](docs/ROADMAP.md)).

## [Unreleased]

### Added

**Core and control plane**
- `hygeia-core`: filtering engine (I/O-free, WASM-ready) and signed bundles (`HYGB`, ed25519, rollback guard, ETag).
  Precedence: custom allow > custom block > list allow > list block > default.
- Hash-chained audit log with CEF export.
- `Store` trait with in-memory, file and PostgreSQL backends (sqlx, row-level security, composite FKs) and one shared conformance suite.
- REST control plane: tenants, groups, users and role bindings, rules, `simulate`, devices, enrolment, API tokens, per-tenant list selection, audit.
- Authentication: OIDC resource server, API tokens, break-glass (staging/dev), local owner (node); RBAC `owner/admin/editor/viewer/auditor`.
- Central redundancy: compiled bundles shared through PostgreSQL, lease-based coordinated list refresh, `/readyz`, graceful SIGTERM drain.
- OpenAPI 3.1 description (`docs/reference/openapi.json`, served at `/v1/openapi.json`) with drift tests, generated TypeScript types and a typed client (`web/lib/client.ts`); `scripts/gen-api.sh`.

**Filter lists**
- Catalogue, downloader and parsers for open-licence lists (network, cosmetic, scriptlets), shrink guard against truncated or poisoned downloads.

**Browser extension and UI**
- Chrome MV3 extension (declarativeNetRequest) and Firefox MV3 build driven by the signed bundle through the WASM engine.
- Admin UI (Next.js, strict CSP, OIDC PKCE).

**Node (`hygeia-proxy`)**
- Standalone mode (own rules, lists and signing key, file state) and connected mode (relay enrolment, pinned central key, rollback guard, disk cache, offline serving).
- Local DNS as an explicit opt-in; the system resolver is never touched.
- `hygeia-proxy setup`: first-run wizard (interactive or flag-driven, validated, atomic write with backup).

**Cloud DNS**
- DoH, DoT (SNI labels), DoQ, and plain UDP/TCP for registered client networks; never an open resolver (`REFUSED`, no amplification).
- Upstream pool: UDP, DoT and DoH with ordered failover.
- Per-token, per-source and failed-auth rate limits; per-tenant failure and block policy.
- Opt-in query log with daily-rotating keyed IP pseudonyms, retention purger, erase endpoint.
- Prometheus `/metrics` (token-protected); native HTTPS with certificate hot reload, HSTS, access log with credential redaction, trusted-proxy client IP.

**Packaging and delivery**
- Linux: `.deb` and hardened systemd unit; RPM spec (*unverified*).
- Windows (*unverified*): service (`hygeia-winsvc`), tray icon, zip with PowerShell scripts, MSI (WiX) with an optional elevated setup wizard.
- Release workflow: `.deb`, tarballs, Windows zip and MSI, extension zips, `SHA256SUMS` into a draft GitHub Release.

**Quality and documentation**
- Documentation under `docs/` (guides, reference, architecture, security, privacy/compliance, operations, testing), README with status badges.
- `scripts/check-all.sh`, behaviour smoke scenarios (`smoke-node.sh`, `smoke-server.sh`), real-Chromium end-to-end tests of the extension and the UI.
- CodeQL, audit (`cargo audit`, `cargo deny`, `npm audit`), coverage, Dependabot.

### Changed
- GitHub Actions run **only on release tags** (or manually); `ci` is reusable and gates `release`. The day-to-day gate is `scripts/check-all.sh --all`.
- UI types are derived from the generated OpenAPI schema instead of being hand-maintained.

### Fixed
- Release workflow: the `publish` job downloaded the UI build artefact together with the release assets and failed on `sha256sum`; it now downloads only `linux`, `windows` and `extensions`.
- Windows MSI build (first run on GitHub): duplicate sequence entry, empty public properties ignored, relative source paths resolved under the install tree; `build-msi.ps1` now fails when `wix` fails instead of reporting success.

### Security
- Credentials are stored as SHA-256 hashes and shown once; the DoH token path is redacted in access logs; client IPs are never logged by the query log.

### Known limitations
- No DNSSEC validation, no HTTP/3, no load or interoperability testing of cloud DNS.
- Windows, Firefox, a live systemd host and the RPM have never been exercised; release artefacts are unsigned.
- Node: no cloud forwarding, no local DNS in connected mode, no pause-blocking API. UI: no OIDC refresh.

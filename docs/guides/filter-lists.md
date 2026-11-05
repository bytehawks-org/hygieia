# Filter lists

Lists are **downloaded at runtime and never vendored** into this repository. The server (or the standalone node) fetches them over https only (default every 12 hours, bounded to 64 MiB each, conditional GET with ETag), parses them, and compiles them with your rules into the signed bundle. Each source's license and attribution are recorded in the bundle metadata.

## Built-in catalogue

| id | Name | Format | License | Feeds | Default |
|---|---|---|---|---|---|
| `hagezi-pro` | HaGeZi Multi PRO | domains | GPL-3.0 | network | yes |
| `hagezi-tif` | HaGeZi Threat Intelligence Feeds (≈1.7M domains) | domains | GPL-3.0 | network | no (memory) |
| `stevenblack` | StevenBlack unified hosts | hosts | MIT | network | no |
| `urlhaus` | abuse.ch URLhaus (malware hosts) | hosts | CC0-1.0 | network | no |
| `easylist` | EasyList | abp | GPL-3.0-or-later OR CC-BY-SA-3.0 | cosmetic | yes |
| `easyprivacy` | EasyPrivacy | abp | GPL-3.0-or-later OR CC-BY-SA-3.0 | network + cosmetic | yes |
| `ublock-filters` | uBlock filters | abp | GPL-3.0 | cosmetic | yes |
| `ublock-quick-fixes` | uBlock filters – Quick fixes | abp | GPL-3.0 | cosmetic | yes |
| `ublock-privacy` | uBlock filters – Privacy | abp | GPL-3.0 | network + cosmetic | yes |
| `ublock-unbreak` | uBlock filters – Unbreak | abp | GPL-3.0 | cosmetic | yes |
| `ublock-annoyances-cookies` | uBlock filters – Cookie notices | abp | GPL-3.0 | cosmetic | no |

*Network* rules (domains) feed DNS and the extension's request blocking; *cosmetic* rules (element hiding, scriptlet calls) feed the extension. Licenses are as stated by each project; re-verify before redistribution.

## Choose sources (platform level)

```toml
[lists]
enabled = true                 # false: no downloads (rules only)
refresh_hours = 12
sources = ["hagezi-pro", "easylist", "ublock-filters", "ublock-quick-fixes"]   # unset = defaults above

[[lists.custom]]                # license + attribution are mandatory
id = "mine"
name = "My list"
url = "https://example.com/list.txt"     # https only
format = "domains"              # hosts | domains | abp
license = "CC0-1.0"
attribution = "me"
network = true                  # feeds DNS / request blocking
cosmetic = false                # feeds element hiding + scriptlets
```

Unknown catalogue ids are a startup error. `allow_insecure_http = true` permits plain-http list URLs for labs and trusted mirrors only (an attacker on the path could poison list content before it is signed).

## Choose sources (per tenant)

The platform decides which sources are *available*. Each tenant then has a policy: **`all`** (default: every available list) or **`selected`** (only its subscriptions, tenant-wide or per policy group; a group subscription never reaches other groups). Manage it in the UI (**Filter lists**) or via `GET /v1/admin/list-subscriptions`, `PUT /v1/admin/list-policy`, `POST`/`DELETE /v1/admin/list-subscriptions` (needs the rules-write permission; audited; effective at the next bundle compile). Sources removed from configuration are disabled, not deleted, so subscriptions survive.

## Safety: lists are untrusted input

- Selectors are validated against CSS breakout (`}`, `;`, `@`, `url(`, unbalanced quotes or brackets) before they can reach a page.
- Scriptlets are shipped as data (name + string arguments); `trusted-*` scriptlets are **dropped** by default (they are privileged in uBlock Origin).
- Unsupported syntax is skipped and counted per source in **Filter lists → status**: procedural selectors (`:has-text`, `:xpath`, …), HTML filters (`##^`), `#?#`, `#$#`, AdGuard `#%#`, entity domains (`google.*`).
- A refresh that returns no usable rules, or shrinks below 50% of the previous count (for lists over 100 rules), is **rejected** and the previous copy is kept.
- Each source is atomic: on any failure the previous good copy stays in use; per-source status shows `last_ok`, `last_error`, counts and SHA-256.

## Footprint

Measured on HaGeZi PRO (240k domains): ruleset build ≈ 0.2–0.4 s, +63 MB RSS, ≈ 1 µs per lookup; signed bundle ≈ 5–8 MB. Reproduce on synthetic data: `cargo test -p hygeia-core --release --test scale -- --ignored --nocapture`.

## Licenses

Not bundling the lists keeps copyleft off this code base (Apache-2.0). **Distributing list-derived bundles to third parties is a separate question**: GPL-3.0 and CC-BY-SA lists may impose obligations on derived artefacts. Verify with your own counsel before offering Hygieia as a service to other organisations; the attribution carried in each bundle is a starting point, not legal advice.

## Check against upstream

```bash
cargo test -p hygeia-lists --test live -- --ignored --nocapture      # downloads the real lists (network required)
```

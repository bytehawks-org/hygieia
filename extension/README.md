# Hygieia Blocker (Chrome MV3 and Firefox MV3)

Standalone content blocker driven by the same **signed bundle** as the DNS server.
The engine is `hygeia-blocker` compiled to WASM; it is the only thing that parses bundle data.

```
options page ──enroll──▶ POST /v1/enroll  → device credential (hyg_dev_…)
service worker ──pull──▶ GET /v1/bundle    (ETag / 304, every 30 min)
      │ verify ed25519 signature against the PINNED key, refuse older versions, then decode
      ├─ network rules  → declarativeNetRequest dynamic rules (grouped requestDomains)
      ├─ cosmetic rules → content.js hides elements (CSS.supports-validated, grouped)
      └─ scriptlets     → executeScript(world: MAIN, func: packaged scriptlets, args: data)
```

## Browser differences

| | Chromium | Firefox (>= 140) |
|---|---|---|
| Background | service worker | event page (`background.scripts`, ES module) |
| Network blocking | `declarativeNetRequest` dynamic rules built from the engine's plan | `webRequest.onBeforeRequest` (blocking) calling the engine on every request: no rule-count limit, exact precedence |
| Element hiding | constructed stylesheet (CSP-exempt) | `scripting.insertCSS` user stylesheet (content scripts cannot use `adoptedStyleSheets` through Xray wrappers; the same fallback exists on Chromium) |
| Scriptlets | `scripting.executeScript(world: MAIN)` | same (needs Firefox >= 128) |
| Host access | granted at install | requested from the options page on first use if missing |

`node extension/package.mjs firefox|chrome` writes the browser-specific build to `extension/dist/<browser>/` (the repo root stays loadable as is in Chrome). Firefox: `about:debugging` → *This Firefox* → *Load Temporary Add-on* → `extension/dist/firefox/manifest.json`; for distribution set your own add-on id in `package.mjs` and sign it through AMO (`web-ext sign`).

## Build and load

```bash
rustup target add wasm32-unknown-unknown
cargo install wasm-bindgen-cli --version 0.2.130 --locked   # must match the wasm-bindgen crate in Cargo.lock
./extension/build.sh
```

Chrome → `chrome://extensions` → Developer mode → *Load unpacked* → `extension/`. Open the extension options, enter the server URL, an enrollment token (admin API `POST /v1/admin/enrollment-tokens`) and the server public key (`GET /v1/pubkey`; pin it through a trusted channel — "Fetch" is trust-on-first-use).

## Tests

```bash
node --test extension/test/*.test.mjs                      # scriptlets (hostile input) + background.js on a fake browser API
                                                 # (Firefox and Chromium code paths, real WASM engine, real signed bundle)
npx web-ext lint -s extension/dist/firefox       # manifest/API lint for Firefox
cargo test -p hygeia-blocker                     # engine: signature, rollback, DNR plan
cargo build -p hygeia && node extension/test/e2e.mjs   # real Chromium + extension + hygeia (needs Playwright)
```

**Verification status:** the Chromium build is tested in a real browser (e2e below). The Firefox build is covered by `web-ext lint` (0 errors) and by the fake-API test of the same `background.js`, **but has not been run in a real Firefox** (none was available in the development sandbox). Do a manual pass in Firefox before relying on it: enroll, load a page with ads, check `about:debugging` console.

The Chromium e2e test verifies: enrollment, signed-bundle install, DNR blocking of a subresource and of a navigation, element hiding (generic and per host), a `set-constant` scriptlet in the page world, and that `trusted-*` scriptlets are dropped.

## Security properties

- The bundle signature is verified before decoding; a bundle with a lower version than the installed one is refused.
- Lists can only choose a scriptlet *name* from the packaged table and pass string arguments. No `eval`, no regex from lists, property paths restricted to `[A-Za-z_$][\w$]*` segments without `__proto__`/`prototype`/`constructor`. Unknown names are ignored.
- Selectors were validated server-side against CSS breakout; the content script validates each again with `CSS.supports` and uses constructed stylesheets (not subject to page CSP).
- The enrollment token is cleared from the form after use; the device credential lives in `chrome.storage.local`.

## Known limits

| Limit | Detail |
|---|---|
| Scriptlet timing | Injection happens from `webNavigation.onCommitted` with `injectImmediately`. Chrome MV3 cannot register content scripts with runtime-generated code, so a script that runs in the very first chunk of the HTML can win the race. Scripts that load or run later are covered. Reliable early injection needs the proxy (selective MITM, tier 3) or Firefox `contentScripts.register`. |
| Service-worker wake | The engine is rebuilt from the cached bundle when the worker restarts (a few hundred ms for a 240k-domain list). Cosmetics for the first page after a wake are delayed accordingly. |
| DNR budget | 500k domains by default. Chrome accepted 1M domains in 1000 grouped rules in testing; the browsing-latency cost at that size is not measured. When truncated, higher-precedence groups are kept first and `dnr.truncated` reports the rest. No frequency ordering yet. |
| Revocation / outage | On 401 (revoked) or an unreachable server the last good bundle stays in force (fail open for configuration, not for rules). A per-tenant fail-closed policy is not implemented. |
| Rollback guard vs. in-memory server | Bundle versions are monotonic only with the PostgreSQL store. With the in-memory store a server restart resets the version to 1 and the extension will refuse the new bundles. |
| Not supported | Procedural cosmetic selectors, HTML filtering, `#?#`/`#$#`, AdGuard syntax, redirect/removeparam. Only 5 scriptlets: `set-constant`, `abort-on-property-read/write`, `no-setTimeout-if`, `no-setInterval-if` (+ uBO aliases). |

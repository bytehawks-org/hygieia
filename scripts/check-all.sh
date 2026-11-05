#!/usr/bin/env bash
# One command to learn the state of the repository: runs every check and prints a summary table.
#
#   scripts/check-all.sh            fast set: format, clippy, Rust tests, wasm check, JS unit tests
#   scripts/check-all.sh --e2e      + real-browser end-to-end suites (needs Playwright Chromium, wasm toolchain)
#   scripts/check-all.sh --smoke    + behaviour smoke scenarios against the real binaries
#   scripts/check-all.sh --all      everything
#
# PostgreSQL suites run when HYGEIA_TEST_PG_ADMIN and HYGEIA_TEST_PG_APP are set (see docs/testing.md).
# Logs of every step: target/check-all/<step>.log
set -u
cd "$(dirname "$0")/.."
E2E=0; SMOKE=0
for a in "$@"; do case $a in --e2e) E2E=1;; --smoke) SMOKE=1;; --all) E2E=1; SMOKE=1;; -h|--help) sed -n 2,12p "$0"; exit 0;; *) echo "unknown option $a" >&2; exit 2;; esac; done
LOG=target/check-all; mkdir -p "$LOG"
names=(); results=(); times=()
run() { # name, command...
  local name=$1; shift
  printf '%-34s ' "$name"
  local t0=$SECONDS
  if "$@" >"$LOG/$name.log" 2>&1; then r=PASS; else r=FAIL; fi
  local dt=$((SECONDS - t0))
  printf '%s (%ss)\n' "$r" "$dt"
  names+=("$name"); results+=("$r"); times+=("$dt")
}
skip() { printf '%-34s SKIP (%s)\n' "$1" "$2"; names+=("$1"); results+=("SKIP"); times+=("-"); }

echo "== Rust =="
run fmt            cargo fmt --all -- --check
run clippy         cargo clippy --workspace --all-targets -- -D warnings
run rust-tests     cargo test --workspace
if [ -n "${HYGEIA_TEST_PG_ADMIN:-}" ] && [ -n "${HYGEIA_TEST_PG_APP:-}" ]; then
  run postgres-suites cargo test -p hygeia-store --test pg
else skip postgres-suites "HYGEIA_TEST_PG_* not set"; fi
if rustup target list --installed 2>/dev/null | grep -q wasm32-unknown-unknown; then
  run wasm-core    cargo check -p hygeia-core --target wasm32-unknown-unknown
  run wasm-blocker cargo check -p hygeia-blocker --target wasm32-unknown-unknown
else skip wasm-core "wasm32 target missing"; fi

echo "== JavaScript =="
if command -v node >/dev/null; then
  run extension-unit node --test extension/test/scriptlets.test.mjs extension/test/background.test.mjs
  [ -d web/node_modules ] && { run web-typecheck bash -c 'cd web && npx tsc --noEmit'; run web-unit node --test web/test/oidc.test.mjs; } \
    || skip web-typecheck "web/node_modules missing (cd web && npm ci)"
else skip extension-unit "node not installed"; fi

if [ $E2E = 1 ]; then
  echo "== End-to-end (real Chromium) =="
  run build-wasm     ./extension/build.sh
  run build-web      bash -c 'cd web && npm run build'
  run build-bins     cargo build -p hygeia -p hygeia-proxy
  run e2e-extension  node extension/test/e2e.mjs
  run e2e-ext-node   env E2E_TARGET=node node extension/test/e2e.mjs
  run e2e-web-server node web/test/e2e.mjs
  run e2e-web-node   node web/test/e2e-node.mjs
fi

if [ $SMOKE = 1 ]; then
  echo "== Behaviour smoke scenarios =="
  run smoke-node     scripts/smoke-node.sh
  run smoke-server   scripts/smoke-server.sh
fi

echo; echo "Summary"; echo "-------"
fail=0
for i in "${!names[@]}"; do printf '  %-26s %-5s %s\n' "${names[$i]}" "${results[$i]}" "${times[$i]}"; [ "${results[$i]}" = FAIL ] && fail=1; done
[ $fail = 1 ] && { echo; echo "Failed steps: see $LOG/<step>.log"; exit 1; }
echo; echo "All executed steps passed."

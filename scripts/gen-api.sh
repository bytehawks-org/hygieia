#!/usr/bin/env bash
# Regenerate the OpenAPI document and the TypeScript types from it.
#   scripts/gen-api.sh          rewrite docs/reference/openapi.json and web/lib/api-schema.d.ts
#   scripts/gen-api.sh --check  fail if either is stale (no files are changed)
set -euo pipefail
cd "$(dirname "$0")/.."
if [ "${1:-}" = "--check" ]; then
  cargo test -q -p hygeia-api --lib committed_openapi_json_is_up_to_date
  tmp=$(mktemp); trap 'rm -f "$tmp"' EXIT
  (cd web && npx --no-install openapi-typescript ../docs/reference/openapi.json --default-non-nullable false -o "$tmp" >/dev/null)
  cmp -s "$tmp" web/lib/api-schema.d.ts || { echo "web/lib/api-schema.d.ts is stale: run scripts/gen-api.sh" >&2; exit 1; }
  echo "OpenAPI document and TypeScript types are up to date"
  exit 0
fi
UPDATE_OPENAPI=1 cargo test -q -p hygeia-api --lib committed_openapi_json_is_up_to_date
(cd web && npx --no-install openapi-typescript ../docs/reference/openapi.json --default-non-nullable false -o lib/api-schema.d.ts)

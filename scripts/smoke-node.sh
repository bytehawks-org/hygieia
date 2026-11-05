#!/usr/bin/env bash
# Behaviour scenario for the standalone node (hygeia-proxy): starts the real binary in a temp
# directory and exercises identity, local-port security, enrolment, signed bundle, opt-in DNS,
# audit chain and persistence across a restart.   usage: scripts/smoke-node.sh   (needs curl, python3)
set -u
cd "$(dirname "$0")/.."
. scripts/lib-smoke.sh
BIN=${HYGEIA_PROXY_BIN:-target/debug/hygeia-proxy}
[ -x "$BIN" ] || cargo build -q -p hygeia-proxy || exit 1
D=$(mktemp -d); HP=$(free_port); DP=$(free_port); B=http://127.0.0.1:$HP
cat > "$D/hygeia-proxy.toml" <<CFG
[http]
listen = "127.0.0.1:$HP"
[lists]
enabled = false
[dns]
mode = "local"
listen = "127.0.0.1:$DP"
upstream = ["127.0.0.1:9"]
CFG
PID=
start() { "$BIN" --data-dir "$D" run >"$D/node.log" 2>&1 & PID=$!; wait_http "$B/healthz" 10; }
stop()  { [ -n "$PID" ] && kill "$PID" 2>/dev/null && wait "$PID" 2>/dev/null; PID=; }
trap 'stop; rm -rf "$D"' EXIT

say "Standalone node smoke test ($BIN)"
check "node starts and answers /healthz" start
OWNER=$("$BIN" --data-dir "$D" token); PUB=$("$BIN" --data-dir "$D" pubkey)
A=(-H "authorization: Bearer $OWNER"); J=(-H 'content-type: application/json')

say; say "Identity and local-port security"
ceq "reports mode=standalone" "$(curl -s $B/v1/config | jget mode)" standalone
ceq "admin API without credential -> 401" "$(code $B/v1/admin/rules)" 401
ceq "owner token authenticates as local_owner" "$(curl -s "${A[@]}" $B/v1/me | jget kind)" local_owner
ceq "unexpected Host header (DNS rebinding) -> 421" "$(code -H 'host: evil.example' $B/v1/config)" 421
ceq "cross-site POST to the admin API -> 403" "$(code -XPOST "${A[@]}" "${J[@]}" -H 'origin: https://evil.example' -d '{"action":"block","pattern":"x.test"}' $B/v1/admin/rules)" 403
ceq "public key is 64 hex chars" "${#PUB}" 64

say; say "Rules, enrolment, signed bundle"
ceq "create a block rule" "$(code -XPOST "${A[@]}" "${J[@]}" -d '{"action":"block","pattern":"ads.example.com"}' $B/v1/admin/rules)" 201
TOK=$(curl -s -XPOST "${A[@]}" "${J[@]}" -d '{}' $B/v1/admin/enrollment-tokens | jget token)
SEC=$(curl -s -XPOST "${J[@]}" -d "{\"token\":\"$TOK\",\"device_info\":\"smoke\"}" $B/v1/enroll | jget device_secret)
check "enrolment token -> device credential (hyg_dev_)" has "$SEC" hyg_dev_
ceq "bogus enrolment token -> 401" "$(code -XPOST "${J[@]}" -d '{"token":"hyg_enr_bogus","device_info":""}' $B/v1/enroll)" 401
curl -s -D "$D/h" -o "$D/bundle" -H "authorization: Bearer $SEC" $B/v1/bundle
check "bundle starts with the HYGB magic" has "$(head -c4 "$D/bundle")" HYGB
ETAG=$(grep -i '^etag:' "$D/h" | cut -d' ' -f2 | tr -d '\r')
ceq "If-None-Match -> 304" "$(code -H "authorization: Bearer $SEC" -H "if-none-match: $ETAG" $B/v1/bundle)" 304
ceq "bundle without credential -> 401" "$(code $B/v1/bundle)" 401
ceq "simulate: the rule blocks x.ads.example.com" "$(curl -s -XPOST "${A[@]}" "${J[@]}" -d '{"host":"x.ads.example.com"}' $B/v1/admin/simulate | jget current.action)" Block

say; say "Opt-in local DNS (follows the bundle every 5 s)"
retry_ceq 12 "blocked name -> NXDOMAIN" 3 dns_rcode_udp 127.0.0.1 "$DP" x.ads.example.com

say; say "Audit"
ceq "audit hash chain verifies" "$(curl -s "${A[@]}" $B/v1/admin/audit/verify | jget ok)" True

say; say "Persistence across restart"
stop; start
ceq "signing key is stable (browsers pin it)" "$("$BIN" --data-dir "$D" pubkey)" "$PUB"
ceq "enrolled device still authenticates" "$(code -H "authorization: Bearer $SEC" $B/v1/bundle)" 200
ceq "audit chain still verifies" "$(curl -s "${A[@]}" $B/v1/admin/audit/verify | jget ok)" True
report

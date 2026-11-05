# Shared helpers for the smoke scenarios (sourced, not executed).
# Needs: bash, curl, python3. Every check prints PASS/FAIL with a description; the script exits non-zero on any FAIL.
PASS=0; FAIL=0
say()   { printf '%s\n' "$*"; }
check() { # description, command...   (command succeeds => PASS)
  local d=$1; shift
  if "$@" >/dev/null 2>&1; then PASS=$((PASS+1)); printf '  PASS  %s\n' "$d"; else FAIL=$((FAIL+1)); printf '  FAIL  %s\n' "$d"; fi
}
ceq()   { # description, actual, expected   (equality check)
  if [ "$2" = "$3" ]; then PASS=$((PASS+1)); printf '  PASS  %s\n' "$1"; else FAIL=$((FAIL+1)); printf '  FAIL  %s (got %s, want %s)\n' "$1" "$2" "$3"; fi
}
# retry_ceq <seconds> <description> <expected> <command...>: re-run the command until it prints <expected>
retry_ceq() { local n=$1 d=$2 want=$3; shift 3; local got=
  for _ in $(seq 1 $((n * 2))); do got=$("$@" 2>/dev/null); [ "$got" = "$want" ] && break; sleep 0.5; done
  ceq "$d" "$got" "$want"
}
eq()    { [ "$1" = "$2" ]; }              # eq actual expected
has()   { case $1 in *"$2"*) true;; *) false;; esac; }   # has haystack needle
code()  { curl -s -o /dev/null -w '%{http_code}' "$@"; }  # HTTP status of a curl invocation
wait_http() { # url, seconds
  for _ in $(seq 1 $(( $2 * 10 ))); do curl -fs -o /dev/null "$1" && return 0; sleep 0.1; done; return 1
}
free_port() { python3 - <<'PY'
import socket
s = socket.socket(); s.bind(("127.0.0.1", 0)); print(s.getsockname()[1]); s.close()
PY
}
# dns_query <host> <port> <qname>  -> prints the RCODE of the reply (0 NOERROR, 3 NXDOMAIN) over UDP
dns_rcode_udp() { python3 - "$@" <<'PY'
import socket, sys
host, port, name = sys.argv[1], int(sys.argv[2]), sys.argv[3]
q = bytes([0x12,0x34,1,0,0,1,0,0,0,0,0,0]) + b"".join(bytes([len(l)])+l.encode() for l in name.split(".")) + b"\0\0\1\0\1"
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); s.settimeout(3); s.sendto(q, (host, port))
print(s.recvfrom(512)[0][3] & 15)
PY
}
# doh_status <base-url> <token> <qname> -> prints "<http status> <rcode|->"
doh() { python3 - "$@" <<'PY'
import sys, urllib.request, urllib.error
base, tok, name = sys.argv[1:4]
q = bytes([0x12,0x34,1,0,0,1,0,0,0,0,0,0]) + b"".join(bytes([len(l)])+l.encode() for l in name.split(".")) + b"\0\0\1\0\1"
r = urllib.request.Request(f"{base}/dns-query/{tok}", data=q, headers={"content-type": "application/dns-message"})
try:
    b = urllib.request.urlopen(r, timeout=5).read(); print(200, b[3] & 15)
except urllib.error.HTTPError as e:
    print(e.code, "-")
PY
}
jget() { python3 -c 'import sys,json; d=json.load(sys.stdin)
for k in sys.argv[1].split("."):
    d = d[int(k)] if isinstance(d, list) else d[k]
print(d)' "$1"; }
report() { say; say "Result: $PASS passed, $FAIL failed"; [ "$FAIL" = 0 ]; }

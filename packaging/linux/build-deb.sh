#!/usr/bin/env bash
# Build a .deb for the node.   usage: build-deb.sh <hygeia-proxy binary> <built web dir (web/out)> <out dir> [arch]
set -euo pipefail
BIN=${1:?binary}; WEB=${2:?web dir}; OUT=${3:?out dir}; ARCH=${4:-$(dpkg --print-architecture)}
HERE=$(cd "$(dirname "$0")" && pwd)
VERSION=$(sed -n 's/^version = "\(.*\)"/\1/p' "$HERE/../../Cargo.toml" | head -1)
[ -f "$WEB/index.html" ] || { echo "no built UI in $WEB (npm run build in web/)" >&2; exit 1; }
ROOT=$(mktemp -d); trap 'rm -rf "$ROOT"' EXIT
install -Dm755 "$BIN" "$ROOT/usr/bin/hygeia-proxy"
install -Dm644 "$HERE/hygeia-proxy.service" "$ROOT/usr/lib/systemd/system/hygeia-proxy.service"
install -Dm644 "$HERE/hygeia-proxy.toml" "$ROOT/etc/hygeia-proxy/hygeia-proxy.toml"
install -d "$ROOT/usr/share/hygeia"
cp -r "$WEB" "$ROOT/usr/share/hygeia/web"
install -Dm644 "$HERE/../../LICENSE" "$ROOT/usr/share/doc/hygeia-proxy/copyright"
install -d "$ROOT/DEBIAN"
SIZE=$(du -sk "$ROOT" | cut -f1)
cat > "$ROOT/DEBIAN/control" <<EOC
Package: hygeia-proxy
Version: $VERSION
Section: net
Priority: optional
Architecture: $ARCH
Depends: libc6
Installed-Size: $SIZE
Maintainer: Hygieia <noreply@example.com>
Homepage: https://github.com/bytehawks-org/hygieia
Description: Hygieia node: local filtering server and browser-extension endpoint
 Light local server for the Hygieia browser extension with a local admin UI.
 Optional local DNS filtering (off by default) and connected mode to a central
 Hygieia server. Installing does not change the system resolver.
EOC
echo /etc/hygeia-proxy/hygeia-proxy.toml > "$ROOT/DEBIAN/conffiles"
cat > "$ROOT/DEBIAN/postinst" <<'EOC'
#!/bin/sh
set -e
if [ "$1" = configure ] && [ -d /run/systemd/system ]; then
  systemctl daemon-reload || true
  if [ -n "$2" ] && systemctl is-active --quiet hygeia-proxy; then systemctl restart hygeia-proxy || true; fi
fi
if [ "$1" = configure ] && [ -z "$2" ]; then
  echo "hygeia-proxy installed. Start it with:  systemctl enable --now hygeia-proxy"
  echo "Then:  sudo hygeia-proxy token   (sign in at http://127.0.0.1:8470/login/)"
fi
exit 0
EOC
cat > "$ROOT/DEBIAN/prerm" <<'EOC'
#!/bin/sh
set -e
if [ "$1" = remove ] || [ "$1" = deconfigure ]; then
  if [ -d /run/systemd/system ]; then systemctl disable --now hygeia-proxy 2>/dev/null || true; fi
fi
exit 0
EOC
cat > "$ROOT/DEBIAN/postrm" <<'EOC'
#!/bin/sh
set -e
[ -d /run/systemd/system ] && systemctl daemon-reload || true
if [ "$1" = purge ]; then
  echo "State kept in /var/lib/hygeia-proxy (signing key, credentials). Remove it manually to forget everything."
fi
exit 0
EOC
chmod 755 "$ROOT/DEBIAN/postinst" "$ROOT/DEBIAN/prerm" "$ROOT/DEBIAN/postrm"
mkdir -p "$OUT"
dpkg-deb --root-owner-group --build "$ROOT" "$OUT/hygeia-proxy_${VERSION}_${ARCH}.deb" >/dev/null
echo "$OUT/hygeia-proxy_${VERSION}_${ARCH}.deb"

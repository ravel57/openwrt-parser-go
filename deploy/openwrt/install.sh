#!/bin/sh
set -eu

SCRIPT_DIR="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)"
PROJECT_DIR="$(CDPATH= cd -- "$SCRIPT_DIR/../.." && pwd)"

[ "$(id -u)" -eq 0 ] || {
    echo 'Run this installer as root.' >&2
    exit 1
}

[ -f /etc/openwrt_release ] || {
    echo 'This installer must be run on OpenWrt.' >&2
    exit 1
}

[ -x "$PROJECT_DIR/openwrt-parser" ] || {
    echo "ARM binary is missing: $PROJECT_DIR/openwrt-parser" >&2
    exit 1
}

[ -f "$PROJECT_DIR/web/dist/index.html" ] || {
    echo "Frontend build is missing: $PROJECT_DIR/web/dist" >&2
    exit 1
}

if [ -x /etc/init.d/openwrt-parser ]; then
    /etc/init.d/openwrt-parser stop 2>/dev/null || true
fi

mkdir -p /var/lib/openwrt-parser /usr/share/openwrt-parser/web
cp "$PROJECT_DIR/openwrt-parser" /usr/bin/openwrt-parser
chmod 755 /usr/bin/openwrt-parser
cp -R "$PROJECT_DIR/web/dist/." /usr/share/openwrt-parser/web/

cp "$SCRIPT_DIR/init.d/openwrt-parser" /etc/init.d/openwrt-parser
chmod 755 /etc/init.d/openwrt-parser

if [ ! -f /etc/config/openwrt-parser ]; then
    cp "$SCRIPT_DIR/etc/config/openwrt-parser" /etc/config/openwrt-parser
    chmod 600 /etc/config/openwrt-parser
fi

/etc/init.d/openwrt-parser enable
/etc/init.d/openwrt-parser restart

echo
echo 'OpenWrt Parser is running.'
echo "Open the panel at: http://$(uci -q get network.lan.ipaddr || echo ROUTER_IP):$(uci -q get openwrt-parser.main.http_port || echo 8080)/"

command -v sing-box >/dev/null 2>&1 ||
    echo 'Warning: sing-box is not installed; config upload cannot be applied.' >&2
[ -x /usr/libexec/lan-mode-vpn-setup ] ||
    echo 'Warning: lan-mode-vpn-setup is absent; uploads will restart sing-box without configuring the TUN/PBR transport.' >&2

# openwrt-parser-go

Backend of the existing `mikrotik_parser` UI rewritten for OpenWrt.

The old HTTP API is preserved, so the current frontend continues to work. MikroTik RouterOS API calls were replaced with OpenWrt data sources:

- active connections: `/proc/net/nf_conntrack`;
- DHCP clients: `/tmp/dhcp.leases`;
- DNS-to-IP mapping: recent `dnsmasq` query/reply records from `logread`;
- address lists: persistent PBR policies in `/etc/config/pbr`;
- enable/disable address-list item: PBR policy option `enabled`;
- applying changes: `uci commit pbr` plus PBR reload/restart.

## Address-list mapping

Two lists used by the old UI are created as PBR policies:

- `ignoreVpn`: each domain is a separate policy with `dest_addr`, routed through `APP_IGNORE_VPN_INTERFACE`;
- `ignoreLanToVpn`: each client IP is a separate policy with `src_addr`, routed through `APP_IGNORE_LAN_TO_VPN_INTERFACE`.

Both interfaces default to `wan`, which means bypassing the VPN. To use the domain list as a list that must go through sing-box, set:

```sh
APP_IGNORE_VPN_INTERFACE=singbox
```

Each application-created PBR policy contains metadata options `app_list`, `app_kind` and `app_address`. PBR ignores these unknown options, while the application uses them to find and manage only its own policies.

## Immediate apply behavior

Address-list writes are serialized and the HTTP request returns only after the PBR configuration has been committed and reloaded. For destination-domain items the backend then queries the local dnsmasq to prefill the `dnsmasq.nftset` set and deletes existing conntrack entries for all currently resolved destination IPs. For source-IP items it deletes conntrack entries originating from that IP/subnet. This makes new TCP/UDP connections follow the changed route immediately instead of waiting for DNS TTL, a new client lookup, or conntrack expiry.

The `conntrack` package is optional at runtime, but without it already established browser/QUIC connections can continue over the previous route until they expire.

## Required OpenWrt packages

```sh
apk update
apk add pbr luci-app-pbr dnsmasq-full conntrack
```

On OpenWrt 24.10 with `opkg`, replace `apk add` with `opkg install`.

Enable PBR and nft-set based domain resolution:

```sh
uci set pbr.config.enabled='1'
uci set pbr.config.resolver_set='dnsmasq.nftset'
uci commit pbr
service pbr restart
```

For the connection screen to show DNS names, dnsmasq query logging must be enabled:

```sh
uci set dhcp.@dnsmasq[0].logqueries='1'
uci commit dhcp
service dnsmasq restart
```

Address-list management works without query logging, but observed connections will have an empty `dstDNS` until a matching dnsmasq log record exists.

## Native OpenWrt mode

Environment:

```sh
export APP_HTTP_PORT=8080
export APP_SQLITE_DSN='file:/var/lib/openwrt-parser/openwrt-parser.sqlite?_pragma=busy_timeout(5000)&_pragma=journal_mode(WAL)&_pragma=foreign_keys(ON)'

export APP_OPENWRT_MODE=local
export APP_OPENWRT_DHCP_LEASES_PATH=/tmp/dhcp.leases
export APP_OPENWRT_CONNTRACK_PATH=/proc/net/nf_conntrack
export APP_OPENWRT_DNS_LOG_LINES=4000

export APP_IGNORE_VPN_LIST=ignoreVpn
export APP_IGNORE_LAN_TO_VPN_LIST=ignoreLanToVpn
export APP_IGNORE_VPN_INTERFACE=wan
export APP_IGNORE_LAN_TO_VPN_INTERFACE=wan
export APP_COLLECT_SECONDS=10
```

The provided procd files are under `deploy/openwrt`.

Example installation after cross-compiling the binary:

```sh
mkdir -p /var/lib/openwrt-parser
cp openwrt-parser /usr/bin/openwrt-parser
chmod +x /usr/bin/openwrt-parser
cp deploy/openwrt/init.d/openwrt-parser /etc/init.d/openwrt-parser
cp deploy/openwrt/etc/config/openwrt-parser /etc/config/openwrt-parser
chmod +x /etc/init.d/openwrt-parser
/etc/init.d/openwrt-parser enable
/etc/init.d/openwrt-parser start
```

## Docker/remote SSH mode

A container cannot normally see the host router's conntrack table, UCI configuration or DHCP leases. In Docker, use SSH mode and let the application execute commands on OpenWrt:

```sh
docker run -d --name openwrt-parser \
  --restart unless-stopped \
  -p 8080:8080 \
  -v openwrt-parser-data:/data \
  -v "$HOME/.ssh/openwrt_ed25519:/run/secrets/openwrt_key:ro" \
  -e APP_HTTP_PORT=8080 \
  -e APP_SQLITE_DSN='file:/data/openwrt-parser.sqlite?_pragma=busy_timeout(5000)&_pragma=journal_mode(WAL)&_pragma=foreign_keys(ON)' \
  -e APP_OPENWRT_MODE=ssh \
  -e APP_OPENWRT_ADDR='172.22.0.63:22' \
  -e APP_OPENWRT_USER='root' \
  -e APP_OPENWRT_KEY_FILE='/run/secrets/openwrt_key' \
  -e APP_OPENWRT_INSECURE_HOST_KEY=true \
  -e APP_IGNORE_VPN_INTERFACE='wan' \
  -e APP_IGNORE_LAN_TO_VPN_INTERFACE='wan' \
  openwrt-parser:latest
```

Password authentication is also supported with `APP_OPENWRT_PASSWORD`, but an SSH key is preferable.

## API compatibility

Preserved endpoints:

- `GET /api/v1/config`
- `GET /api/v1/src?srcIp=192.168.1.10`
- `GET /api/v1/dns?find=youtube`
- `POST /api/v1/dns?dns=youtube.com,googlevideo.com&enabled=true`
- `GET /api/v1/ignore-lan-to-vpn?find=192.168`
- `POST /api/v1/ignore-lan-to-vpn` with JSON `{ "ip": "192.168.1.10", "enabled": true }`

Generic address-list API added:

- `GET /api/v1/address-lists/{listName}?find=...`
- `POST /api/v1/address-lists/{listName}` with JSON `{ "address": "example.com", "enabled": true }`
- `DELETE /api/v1/address-lists/{listName}?address=example.com`

Only lists configured through `APP_IGNORE_VPN_LIST` and `APP_IGNORE_LAN_TO_VPN_LIST` are accepted.

## Build

```sh
docker buildx build --platform linux/arm64 -t openwrt-parser:latest --load .
```

Native ARM64 binary:

```sh
CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -trimpath -ldflags='-s -w' -o openwrt-parser ./cmd/server
```

ARMv7:

```sh
CGO_ENABLED=0 GOOS=linux GOARCH=arm GOARM=7 go build -trimpath -ldflags='-s -w' -o openwrt-parser ./cmd/server
```

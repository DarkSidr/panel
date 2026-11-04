#!/bin/sh
# Run on the OpenWrt LAN gateway. Allows one AWG endpoint before QUIC blocks.
# Usage: sh openwrt-awg-exception.sh 203.0.113.10 443
set -eu
server_ip=${1:?Specify the AWG server IPv4 address}
server_port=${2:-443}
case "$server_ip" in *[!0-9.]*|'') echo 'Expected an IPv4 address' >&2; exit 1;; esac
awk -v ip="$server_ip" 'BEGIN {n=split(ip,a,".");if(n!=4)exit 1;for(i=1;i<=4;i++)if(a[i]==""||a[i]<0||a[i]>255)exit 1}'
case "$server_port" in *[!0-9]*|'') echo 'Expected a UDP port' >&2; exit 1;; esac
[ "$server_port" -ge 1 ] && [ "$server_port" -le 65535 ]
if [ -n "$(uci changes firewall)" ]; then
    echo 'Save or revert pending firewall edits first.' >&2
    exit 1
fi
if uci -q get firewall.proxy_stack_awg >/dev/null; then
    [ "$(uci -q get firewall.proxy_stack_awg.name)" = 'Proxy-stack AWG endpoint' ] || {
        echo 'The UCI section already belongs to another rule.' >&2; exit 1;
    }
fi
umask 077
backup_dir=/root/proxy-stack-backups
mkdir -p "$backup_dir"
backup_file="$backup_dir/firewall-$(date -u +%Y%m%dT%H%M%SZ)-$$"
cp /etc/config/firewall "$backup_file"
rollback() {
    trap - EXIT HUP INT TERM
    uci -q revert firewall || true
    cp "$backup_file" /etc/config/firewall
    /etc/init.d/firewall reload >/dev/null 2>&1 || true
    echo "Firewall restored from $backup_file" >&2
    exit 1
}
trap rollback EXIT HUP INT TERM
uci set firewall.proxy_stack_awg=rule
uci set 'firewall.proxy_stack_awg.name=Proxy-stack AWG endpoint'
uci set firewall.proxy_stack_awg.src=lan
uci set firewall.proxy_stack_awg.dest=wan
uci set firewall.proxy_stack_awg.family=ipv4
uci set firewall.proxy_stack_awg.proto=udp
uci set "firewall.proxy_stack_awg.dest_ip=$server_ip"
uci set "firewall.proxy_stack_awg.dest_port=$server_port"
uci set firewall.proxy_stack_awg.target=ACCEPT
uci set firewall.proxy_stack_awg.enabled=1
uci reorder firewall.proxy_stack_awg=0
fw4 check
uci commit firewall
/etc/init.d/firewall reload
nft list chain inet fw4 forward_lan | grep -F 'Proxy-stack AWG endpoint' >/dev/null
trap - EXIT HUP INT TERM
echo "Allowed LAN -> $server_ip:$server_port/UDP; backup: $backup_file"

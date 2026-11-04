#!/bin/sh
set -eu
umask 077
if nft list table inet proxy_stack >/dev/null 2>&1; then
    echo 'delete table inet proxy_stack'
fi > /run/proxy-stack-firewall.nft
cat /etc/proxy-stack/firewall.nft >> /run/proxy-stack-firewall.nft
nft -f /run/proxy-stack-firewall.nft

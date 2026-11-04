#!/bin/sh
# Download the GitHub sources before executing; no git client is required.
set -eu
url=${PROXY_BUNDLE_URL:-https://github.com/DarkSidr/panel/archive/refs/heads/main.tar.gz}
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT HUP INT TERM
if command -v curl >/dev/null 2>&1; then
    curl --fail --location --proto '=https' --proto-redir '=https' --tlsv1.2 "$url" -o "$work/bundle.tar.gz"
else
    wget --https-only "$url" -O "$work/bundle.tar.gz"
fi
# Optional independent digest pin (get it through a trusted channel).
if [ -n "${PROXY_BUNDLE_SHA256:-}" ]; then
    printf '%s  %s\n' "$PROXY_BUNDLE_SHA256" "$work/bundle.tar.gz" | sha256sum -c -
fi
mkdir "$work/source"
# GitHub archives and locally built bundles both contain one top-level directory.
tar -xzf "$work/bundle.tar.gz" -C "$work/source" --strip-components=1 --no-same-owner
if [ ! -f "$work/source/proxyctl.py" ]; then
    printf '%s\n' 'Invalid source archive: proxyctl.py is missing.' >&2
    exit 1
fi
python3 "$work/source/proxyctl.py" "$@"

#!/bin/sh
set -eu
base=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)
mkdir -p "$base/dist"
tar --exclude=dist --exclude=__pycache__ --exclude=.git --exclude=.agents --exclude=.codex --exclude=.aws --transform='s,^\.,proxy-stack,' -czf "$base/dist/proxy-stack.tar.gz" -C "$base" .
cp "$base/install.sh" "$base/dist/install.sh"
(cd "$base/dist" && sha256sum proxy-stack.tar.gz install.sh > SHA256SUMS)

#!/bin/sh
# Installs OpenGrep of exactly package.json's "opengrep" version for `npm run test:rules` (Linux
# x86-64), checked against its SHA-256 before it is installed. The pin equals qualor's
# tools/analyzers/install.sh (OPENGREP_VERSION, OPENGREP_SHA256_X64); tools/check.test.mjs checks
# that it equals package.json. DEST (default $RUNNER_TEMP/opengrep, else ./.tmp/opengrep).
set -eu
OPENGREP_VERSION=1.30.0
OPENGREP_SHA256_X64=35779bdd72e92129c8df2a77f0c55e8c08356801ea92591ef32108d6b28d564c
DEST="${DEST:-${RUNNER_TEMP:-.tmp}/opengrep}"
mkdir -p "$DEST"
curl -fsSL --proto '=https' --proto-redir '=https' --tlsv1.2 --retry 7 --retry-connrefused \
  -o "$DEST/opengrep.download" \
  "https://github.com/opengrep/opengrep/releases/download/v$OPENGREP_VERSION/opengrep_manylinux_x86"
echo "$OPENGREP_SHA256_X64  $DEST/opengrep.download" | sha256sum -c - >/dev/null \
  || { echo "install-opengrep.sh: checksum mismatch" >&2; exit 1; }
mv "$DEST/opengrep.download" "$DEST/opengrep"
chmod 0755 "$DEST/opengrep"
echo "installed OpenGrep $OPENGREP_VERSION into $DEST"

#!/bin/sh
# Builds a payload that drops the preflight and postflight scripts into
# /usr/local/munki. On macOS, pkgbuild wraps that payload. Elsewhere this
# script only lays the payload out so CI can see the files.
set -eu
ROOT="$(CDPATH= cd -- "$(dirname "$0")" && pwd)"
OUT="${1:-${ROOT}/payload}"
rm -rf "${OUT}"
mkdir -p "${OUT}/usr/local/munki"
cp "${ROOT}/preflight" "${ROOT}/postflight" "${OUT}/usr/local/munki/"
chmod 755 "${OUT}/usr/local/munki/preflight" "${OUT}/usr/local/munki/postflight"
if command -v pkgbuild >/dev/null 2>&1; then
  pkgbuild --root "${OUT}" --identifier com.missioncontrol.munki-client \
    --version 1.0.0 --install-location / "${ROOT}/MissionControlMunkiClient.pkg"
  echo "wrote ${ROOT}/MissionControlMunkiClient.pkg"
else
  echo "pkgbuild is not available; payload is at ${OUT}"
fi

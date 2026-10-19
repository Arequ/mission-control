#!/bin/sh
# Checks the compose stack: health, SSO, osquery, Munki, Elastic logs, coverage, vulnerabilities.
set -eu
ROOT="$(CDPATH= cd -- "$(dirname "$0")/.." && pwd)"
python3 "${ROOT}/scripts/smoke.py"

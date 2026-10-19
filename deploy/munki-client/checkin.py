#!/usr/bin/env python3
"""Fake Munki client for docker compose. Retries until the enrollment secret exists."""
import gzip
import os
import time
import urllib.error
import urllib.request
import uuid
from datetime import datetime, timezone

BASE = os.environ.get("MC_URL", "http://server:8080").rstrip("/")
SERIAL = os.environ.get("MC_SERIAL", "C02DEMO0001")
SECRET = os.environ.get("MC_SECRET", "example-munki-enrollment-secret")
HOST = os.environ.get("MC_HOSTNAME", "ava-mbp.local")


def req(method: str, path: str, body: bytes | None = None, headers: dict | None = None):
    r = urllib.request.Request(BASE + path, data=body, method=method)
    r.add_header("Authorization", "Basic " + __import__("base64").b64encode(f"{SERIAL}:{SECRET}".encode()).decode())
    for k, v in (headers or {}).items():
        r.add_header(k, v)
    with urllib.request.urlopen(r, timeout=15) as res:
        return res.status, res.read()


def report() -> bytes:
    now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    return f"""<?xml version="1.0" encoding="UTF-8"?>
<plist version="1.0"><dict>
<key>MachineInfo</key><dict>
  <key>hostname</key><string>{HOST}</string>
  <key>serial_number</key><string>{SERIAL}</string>
  <key>os_vers</key><string>15.1.1</string>
  <key>machine_model</key><string>Mac16,8</string>
</dict>
<key>ManifestName</key><string>site_default</string>
<key>ManagedInstallVersion</key><string>6.6.3</string>
<key>ConsoleUser</key><string>ava</string>
<key>StartTime</key><date>{now}</date>
<key>EndTime</key><date>{now}</date>
<key>InstalledItems</key><array><dict>
  <key>name</key><string>Firefox</string>
  <key>display_name</key><string>Firefox</string>
  <key>installed_version</key><string>132.0.1</string>
  <key>installed</key><true/>
</dict></array>
<key>ItemsToInstall</key><array><dict>
  <key>name</key><string>GoogleChrome</string>
  <key>version_to_install</key><string>131.0.6778.86</string>
</dict></array>
<key>ItemsToRemove</key><array/>
<key>Errors</key><array/>
<key>Warnings</key><array><string>Optional item Slack skipped</string></array>
</dict></plist>
""".encode()


def once() -> bool:
    status, body = req("GET", f"/repo/manifests/{SERIAL}")
    if b"included_manifests" not in body and b"catalogs" not in body:
        raise RuntimeError(f"manifest {status} {body[:200]!r}")
    status, body = req("GET", "/repo/catalogs/production")
    if status != 200:
        raise RuntimeError(f"catalog {status}")
    raw = gzip.compress(report())
    status, body = req("POST", "/munki/checkin", raw, {
        "Content-Type": "application/xml",
        "Content-Encoding": "gzip",
        "Idempotency-Key": uuid.uuid4().hex,
    })
    print("checkin", status, body.decode()[:300])
    return status == 200


def main() -> None:
    for attempt in range(60):
        try:
            if once():
                # Stay up so compose does not restart the one-shot in a loop
                # that would post a newer report every restart.
                while True:
                    time.sleep(3600)
        except Exception as exc:
            print(f"waiting ({attempt}): {exc}", flush=True)
            time.sleep(5)
    raise SystemExit(1)


if __name__ == "__main__":
    main()

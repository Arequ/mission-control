#!/usr/bin/env python3
"""Smoke the local compose stack. Exits non-zero on the first failed check."""
import json
import os
import re
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
import http.cookiejar

BASE = os.environ.get("MC_URL", "http://127.0.0.1:8080").rstrip("/")
TOKEN = os.environ.get("MC_ADMIN_TOKEN", "mc_dev_admin_token")
ES = os.environ.get("ES_URL", "http://127.0.0.1:9200").rstrip("/")


def fail(msg: str) -> None:
    print("FAIL", msg, file=sys.stderr)
    raise SystemExit(1)


def ok(msg: str) -> None:
    print("ok", msg)


def api(method: str, path: str, body: dict | None = None, token: str = TOKEN):
    data = None if body is None else json.dumps(body).encode()
    req = urllib.request.Request(BASE + path, data=data, method=method)
    if token:
        req.add_header("Authorization", "Bearer " + token)
    if data is not None:
        req.add_header("Content-Type", "application/json")
    try:
        with urllib.request.urlopen(req, timeout=30) as res:
            raw = res.read()
            return res.status, json.loads(raw.decode() or "null")
    except urllib.error.HTTPError as exc:
        return exc.code, exc.read().decode()[:400]


def wait_health() -> None:
    for _ in range(40):
        try:
            with urllib.request.urlopen(BASE + "/healthz", timeout=5) as res:
                if res.status == 200:
                    ok("health")
                    return
        except Exception:
            time.sleep(2)
    fail("health")


def sso_login() -> None:
    status, providers = api("GET", "/api/v1/sso/providers", token="")
    # public endpoint; the helper always sets Authorization. Call without it.
    req = urllib.request.Request(BASE + "/api/v1/sso/providers")
    with urllib.request.urlopen(req, timeout=15) as res:
        providers = json.loads(res.read().decode())
    items = providers.get("providers") or []
    if not items:
        fail("no sso providers")
    provider = items[0]["id"]
    jar = http.cookiejar.CookieJar()
    opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(jar))
    url = f"{BASE}/api/v1/sso/login?provider={urllib.parse.quote(provider)}&return=/"
    # Follow redirects until the Dex login form.
    page = opener.open(url, timeout=20)
    html = page.read().decode(errors="replace")
    action = re.search(r'<form[^>]*action="([^"]+)"', html)
    if not action:
        fail("dex login form missing")
    action_url = urllib.parse.urljoin(page.geturl(), action.group(1).replace("&amp;", "&"))
    form = urllib.parse.urlencode({"login": "ava@example.com", "password": "example-oidc-password"}).encode()
    try:
        done = opener.open(action_url, data=form, timeout=20)
        done.read()
    except urllib.error.HTTPError as exc:
        fail(f"dex login {exc.code} {exc.read()[:200]!r}")
    session = opener.open(BASE + "/api/v1/session", timeout=15)
    user = json.loads(session.read().decode())
    if user.get("email") != "ava@example.com" or user.get("role") not in ("viewer", "operator", "admin"):
        fail(f"session {user}")
    if not user.get("csrf_token"):
        fail("missing csrf")
    ok(f"sso {user['email']} role={user['role']}")


def device_by_serial(serial: str) -> dict | None:
    status, page = api("GET", "/api/v1/devices?limit=200")
    if status != 200:
        fail(f"devices {status} {page}")
    for device in page.get("devices") or []:
        if device.get("serial") == serial:
            return device
    return None


def wait_osquery() -> dict:
    for _ in range(40):
        found = device_by_serial("C02")  # placeholder, replaced below
        status, page = api("GET", "/api/v1/devices?q=mbp-eng-0217&limit=20")
        if status == 200:
            for device in page.get("devices") or []:
                if device.get("hostname") == "mbp-eng-0217":
                    ok(f"osquery enrolled {device['id']}")
                    return device
        time.sleep(3)
    fail("osquery device did not enroll")
    return {}


def live_query(device_id: str) -> None:
    status, query = api("POST", "/api/v1/live-queries", {"device_ids": [device_id], "sql": "SELECT 1 AS ok;"})
    if status not in (200, 201):
        fail(f"live query create {status} {query}")
    qid = query.get("id")
    for _ in range(30):
        status, got = api("GET", f"/api/v1/live-queries/{qid}")
        if status != 200:
            fail(f"live query {status}")
        if got.get("status") in ("complete", "completed", "error", "failed"):
            text = json.dumps(got)
            if "1" not in text:
                fail(f"live query result {text[:400]}")
            ok("live query")
            return
        time.sleep(2)
    fail("live query timed out")


def wait_munki() -> None:
    for _ in range(40):
        found = device_by_serial("C02DEMO0001")
        if found:
            status, device = api("GET", f"/api/v1/devices/{found['id']}")
            card = (device or {}).get("munki") if status == 200 else None
            if card and card.get("munki_version"):
                ok(f"munki card status={card.get('status')} pending={card.get('pending')}")
                return
        time.sleep(3)
    fail("munki check-in did not show on a device")


def seed_and_logs(hostname: str, serial: str, uuid: str) -> None:
    env = os.environ.copy()
    env["ES_URL"] = ES
    env["HOST_NAME"] = hostname
    env["HOST_SERIAL"] = serial
    env["HOST_UUID"] = uuid
    import subprocess
    subprocess.check_call([sys.executable, os.path.join(os.path.dirname(__file__), "..", "deploy", "elastic", "seed.py")], env=env)
    status, views = api("GET", "/api/v1/log-views")
    if status != 200:
        fail(f"log views {status}")
    view_id = ""
    for view in views.get("views") or []:
        if view.get("name") == "Endpoint logs":
            view_id = view["id"]
    if not view_id:
        fail("endpoint log view missing")
    found = None
    status, page = api("GET", f"/api/v1/devices?q={urllib.parse.quote(hostname)}&limit=20")
    for device in (page.get("devices") or []) if status == 200 else []:
        if device.get("hostname") == hostname or device.get("serial") == serial:
            found = device
            break
    if not found:
        found = device_by_serial(serial)
    if not found:
        fail("log device missing")
    body = {
        "device_id": found["id"],
        "from": "2026-10-19T00:00:00Z",
        "to": "2026-10-20T00:00:00Z",
    }
    status, result = api("POST", f"/api/v1/log-views/{view_id}/query", body)
    if status != 200:
        fail(f"logs {status} {result}")
    lines = result.get("lines") or result.get("events") or []
    if not lines:
        fail(f"logs empty {json.dumps(result)[:400]}")
    ok(f"logs {len(lines)} lines")


def coverage_and_vulns() -> None:
    status, matrix = api("GET", "/api/v1/coverage/matrix")
    if status != 200:
        fail(f"coverage {status} {matrix}")
    ok("coverage")
    status, issues = api("GET", "/api/v1/vulnerability-issues")
    if status != 200:
        fail(f"vulnerabilities {status} {issues}")
    ok("vulnerabilities")


def main() -> None:
    wait_health()
    sso_login()
    device = wait_osquery()
    live_query(device["id"])
    wait_munki()
    seed_and_logs(device.get("hostname") or "mbp-eng-0217", device.get("serial") or "", device.get("hardware_uuid") or "")
    coverage_and_vulns()
    print("smoke passed")


if __name__ == "__main__":
    main()

#!/usr/bin/env python3
"""Enroll a few pretend Macs over the osquery TLS API and post inventory.

Usage:
  python3 scripts/simulate_agent.py
  python3 scripts/simulate_agent.py --server http://127.0.0.1:8080 --secret dev-enroll-secret
"""

import argparse
import json
import urllib.error
import urllib.request

DEVICES = [
    {
        "host_identifier": "ADA-UUID",
        "hostname": "ada.local",
        "computer_name": "Ada's MacBook Pro",
        "uuid": "A1A1A1A1-0000-4000-8000-000000000001",
        "hardware_serial": "C02ADA001",
        "hardware_model": "MacBookPro18,3",
        "cpu_brand": "Apple M3 Pro",
        "cpu_physical_cores": "12",
        "physical_memory": "38654705664",
        "os_name": "macOS",
        "os_version": "15.1",
        "os_major": "15",
        "os_build": "24B83",
        "user": "ada",
        "apps": [
            ("Safari", "com.apple.Safari", "/Applications/Safari.app", "18.1"),
            ("Slack", "com.tinyspeck.slackmacgap", "/Applications/Slack.app", "4.41.0"),
            ("1Password", "com.1password.1password", "/Applications/1Password.app", "8.10.56"),
            ("Google Chrome", "com.google.Chrome", "/Applications/Google Chrome.app", "131.0.6778.86"),
        ],
    },
    {
        "host_identifier": "LIN-UUID",
        "hostname": "lin.local",
        "computer_name": "Lin's MacBook Air",
        "uuid": "B2B2B2B2-0000-4000-8000-000000000002",
        "hardware_serial": "C02LIN002",
        "hardware_model": "MacBookAir10,1",
        "cpu_brand": "Apple M1",
        "cpu_physical_cores": "8",
        "physical_memory": "17179869184",
        "os_name": "macOS",
        "os_version": "14.6.1",
        "os_major": "14",
        "os_build": "23G93",
        "user": "lin",
        "apps": [
            ("Safari", "com.apple.Safari", "/Applications/Safari.app", "17.6"),
            ("Zoom", "us.zoom.xos", "/Applications/zoom.us.app", "6.2.0"),
            ("iTerm", "com.googlecode.iterm2", "/Applications/iTerm.app", "3.5.5"),
        ],
    },
    {
        "host_identifier": "MINI-UUID",
        "hostname": "mini.local",
        "computer_name": "Studio Mini",
        "uuid": "C3C3C3C3-0000-4000-8000-000000000003",
        "hardware_serial": "C02MINI003",
        "hardware_model": "Macmini9,1",
        "cpu_brand": "Apple M1",
        "cpu_physical_cores": "8",
        "physical_memory": "17179869184",
        "os_name": "macOS",
        "os_version": "15.0.1",
        "os_major": "15",
        "os_build": "24A348",
        "user": "ops",
        "apps": [
            ("Safari", "com.apple.Safari", "/Applications/Safari.app", "18.0"),
        ],
    },
]


def post(server, path, payload):
    data = json.dumps(payload).encode()
    req = urllib.request.Request(
        server.rstrip("/") + path,
        data=data,
        headers={"Content-Type": "application/json"},
    )
    try:
        with urllib.request.urlopen(req, timeout=20) as resp:
            return json.load(resp)
    except urllib.error.HTTPError as exc:
        body = exc.read().decode()
        raise SystemExit(f"{path} returned {exc.code}: {body}") from exc


def snapshot_for(name, device):
    base = name.rsplit("/", 1)[-1]
    if base == "system_info":
        return [{
            "hostname": device["hostname"],
            "computer_name": device["computer_name"],
            "uuid": device["uuid"],
            "hardware_serial": device["hardware_serial"],
            "hardware_model": device["hardware_model"],
            "hardware_vendor": "Apple Inc.",
            "cpu_brand": device["cpu_brand"],
            "cpu_physical_cores": device["cpu_physical_cores"],
            "physical_memory": device["physical_memory"],
        }]
    if base == "os_version":
        return [{
            "name": device["os_name"],
            "version": device["os_version"],
            "major": device["os_major"],
            "minor": device["os_version"].split(".")[1] if "." in device["os_version"] else "0",
            "build": device["os_build"],
            "platform": "darwin",
        }]
    if base == "users":
        return [{"uid": "501", "gid": "20", "username": device["user"], "directory": f"/Users/{device['user']}", "shell": "/bin/zsh"}]
    if base == "apps":
        return [
            {"name": name_, "bundle_identifier": bundle, "path": path, "bundle_short_version": version}
            for name_, bundle, path, version in device["apps"]
        ]
    if base == "label_macbooks":
        return [{"1": "1"}] if device["hardware_model"].startswith("MacBook") else []
    if base == "label_sequoia":
        return [{"1": "1"}] if device["os_major"] == "15" else []
    return [{"ok": "1"}]


def queries_from_config(cfg):
    found = []
    for name in (cfg.get("schedule") or {}):
        found.append(name)
    for pack, body in (cfg.get("packs") or {}).items():
        for name in (body.get("queries") or {}):
            found.append(f"pack/{pack}/{name}")
    return found


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--server", default="http://127.0.0.1:8080")
    parser.add_argument("--secret", default="dev-enroll-secret")
    args = parser.parse_args()
    for device in DEVICES:
        enrolled = post(args.server, "/osquery/enroll", {
            "enroll_secret": args.secret,
            "host_identifier": device["host_identifier"],
            "host_details": {
                "system_info": snapshot_for("system_info", device)[0],
                "os_version": snapshot_for("os_version", device)[0],
                "osquery_info": {"version": "5.15.0"},
            },
        })
        node_key = enrolled["node_key"]
        cfg = post(args.server, "/osquery/config", {"node_key": node_key})
        if cfg.get("node_invalid"):
            raise SystemExit("config rejected the node key")
        data = []
        for name in queries_from_config(cfg):
            data.append({
                "name": name,
                "unixTime": 1729000000,
                "snapshot": snapshot_for(name, device),
            })
        post(args.server, "/osquery/log", {"node_key": node_key, "log_type": "result", "data": data})
        print(f"enrolled {device['computer_name']} ({device['hardware_serial']})")


if __name__ == "__main__":
    main()

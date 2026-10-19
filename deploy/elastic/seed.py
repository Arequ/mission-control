#!/usr/bin/env python3
"""Index a few lines into the local Elasticsearch so Logs is not the seed reader."""
import json
import os
import urllib.request

ES = os.environ.get("ES_URL", "http://127.0.0.1:9200").rstrip("/")
HOST = os.environ.get("HOST_NAME", "mbp-eng-0217")
SERIAL = os.environ.get("HOST_SERIAL", "C02DEMO0001")
UUID = os.environ.get("HOST_UUID", "")


def bulk(index: str, lines: list[dict]) -> None:
    body = []
    for i, doc in enumerate(lines):
        body.append(json.dumps({"index": {"_index": index, "_id": f"demo-{i}"}}))
        body.append(json.dumps(doc))
    data = ("\n".join(body) + "\n").encode()
    req = urllib.request.Request(ES + "/_bulk", data=data, method="POST")
    req.add_header("Content-Type", "application/x-ndjson")
    with urllib.request.urlopen(req, timeout=20) as res:
        raw = json.loads(res.read().decode())
    if raw.get("errors"):
        raise SystemExit(json.dumps(raw)[:500])


def doc(message: str, dataset: str, offset: int) -> dict:
    return {
        "@timestamp": "2026-10-19T18:00:%02dZ" % offset,
        "message": message,
        "host": {"name": HOST, "serial": SERIAL, "id": UUID or SERIAL},
        "log": {"file": {"path": f"/var/log/{dataset}.log", "offset": offset}},
        "event": {"dataset": dataset},
    }


def main() -> None:
    bulk("logs-munki.install-000001", [
        doc("Installing Firefox 132.0.1", "munki.install", 1),
        doc("Install of Firefox complete", "munki.install", 2),
    ])
    bulk("logs-autopkg.run-000001", [
        doc("autopkg run Firefox", "autopkg", 1),
    ])
    bulk("logs-osquery.result-000001", [
        doc("osquery distributed query finished", "osquery.result", 1),
    ])
    bulk("logs-crowdstrike.falcon-000001", [
        doc("Falcon sensor healthy", "crowdstrike.falcon", 1),
    ])
    urllib.request.urlopen(urllib.request.Request(ES + "/_refresh", method="POST"), timeout=20).read()
    print("indexed")


if __name__ == "__main__":
    main()

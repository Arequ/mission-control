#!/usr/bin/env python3
"""Index a few lines into the local Elasticsearch so Logs is not the seed reader."""
import json
import os
import urllib.request
from datetime import datetime, timedelta, timezone

ES = os.environ.get("ES_URL", "http://127.0.0.1:9200").rstrip("/")
HOST = os.environ.get("HOST_NAME", "mbp-eng-0217")
SERIAL = os.environ.get("HOST_SERIAL", "C02DEMO0001")
UUID = os.environ.get("HOST_UUID", "")


def bulk(index: str, lines: list[dict]) -> None:
    # logs-*-* is a data stream in Elasticsearch 8. create is the allowed write.
    body = []
    for doc in lines:
        body.append(json.dumps({"create": {"_index": index}}))
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
        "@timestamp": (datetime.now(timezone.utc) - timedelta(minutes=30 - offset)).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "message": message,
        "host": {"name": HOST, "serial": SERIAL, "id": UUID or SERIAL},
        "log": {"file": {"path": f"/var/log/{dataset}.log", "offset": offset}},
        "event": {"dataset": dataset},
    }


def main() -> None:
    bulk("logs-munki.install-demo", [
        doc("Installing Firefox 132.0.1", "munki.install", 1),
        doc("Install of Firefox complete", "munki.install", 2),
    ])
    bulk("logs-autopkg.run-demo", [
        doc("autopkg run Firefox", "autopkg", 1),
    ])
    bulk("logs-osquery.result-demo", [
        doc("osquery distributed query finished", "osquery.result", 1),
    ])
    bulk("logs-crowdstrike.falcon-demo", [
        doc("Falcon sensor healthy", "crowdstrike.falcon", 1),
    ])
    urllib.request.urlopen(urllib.request.Request(ES + "/_refresh", method="POST"), timeout=20).read()
    print("indexed")


if __name__ == "__main__":
    main()

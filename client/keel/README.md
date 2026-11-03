# Keel client

Keel is the configuration agent on the Macs. It is built in another
repository. This directory holds a reference client (`main.go`, standard
library only) that shows the two calls Keel makes. The contract is
`keel/docs/reporting.md` in the Keel repository.

## Enroll once

Each Mac generates an Ed25519 key pair on its first run and keeps the private
key at `/opt/coreweave/cert/keel-report.key` (mode `0600`, root). It then
binds the public key to its serial:

```
POST /api/v1/keel/enroll
Authorization: Bearer <keel enroll secret>

{"serial": "DF7XP7HY3N", "hostname": "CW-DF7XP7HY3N-L", "public_key": "<base64, 32 bytes>"}
```

The enroll secret is `missioncontrol_keel_enroll_secret` in Terraform and
reaches the Mac as the `KEEL_ENROLL_SECRET` data bag. It is only sent on this
call. A new serial is `201`, the same key again is `200`, and a different key
is `409` until an admin runs `DELETE /api/v1/keel/devices/{serial}/key`
(scope `keel:admin` or `*`). A leaked enroll secret can claim a serial that
never enrolled, not one that already has a key.

## Report every run

```
POST /api/v1/keel/report
X-Keel-Serial: DF7XP7HY3N
X-Keel-Timestamp: 1793750400
X-Keel-Signature: <base64 Ed25519 signature>
```

The signature covers `keel-report-v1\n<serial>\n<timestamp>\n<hex sha256 of
the exact body>`. Sign the bytes you send and do not re-encode them. The server
rejects a timestamp more than 300 seconds from its clock and any timestamp that
is not after the last accepted one for that serial. Success is `202`.

## Try it

```bash
go build -o keel-report ./client/keel
./keel-report -key ./dev.key init
KEEL_ENROLL_SECRET=example-keel-enroll-secret \
  ./keel-report -server http://localhost:8080 -key ./dev.key -serial C02KEELDEV1 -hostname keel-dev enroll
./keel-report -server http://localhost:8080 -key ./dev.key -serial C02KEELDEV1 report run.json
```

`run.json` is a `keel.report/v1` body whose `device.serial` is the same serial.
The key file format (PKCS#8 PEM here) is a choice of this example, not part of
the contract. `example-keel-enroll-secret` is the local placeholder from
`examples/terraform`, not a production secret.

# Mission Control

Mission Control is a Mac and endpoint console in the spirit of Zentral and Fleet: one API, one UI, and configuration that lives in git.

This repository is the foundation. Osquery enrollment, inventory, fleet aggregates, and a real config-as-code engine are running. Munki and AutoPkg are modeled end to end and queued, and the pieces that need a package repo or a Mac are called out in [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) rather than faked.

## What works

- Go server, Postgres, embedded migrations, OpenAPI at `/api/openapi.yaml`
- Bearer tokens (`viewer` / `operator` / `admin`) and a bootstrap admin token
- Osquery TLS routes: enroll, config, log, distributed read/write
- Device list and detail, fleet summary (OS versions, apps, drift)
- Declarative YAML (`apiVersion` / `kind` / `metadata` / `spec`) with validation, plan, and apply
- `mcctl validate`, `plan`, `apply`, `export`
- Directory sync from `MC_CONFIG_DIR` (optional `git pull`)
- Munki and AutoPkg resources stored from that config, plus an AutoPkg job queue and `mc-runner`
- React UI: fleet, devices, and read-only views of queries, Munki, AutoPkg, and config

## What is stubbed

- Munki client repo (`GET /munki/repo/...` returns 501). Catalogs and manifests are data, not plists yet.
- AutoPkg trust verification, cron dispatch, and promotion into Munki. The runner executes `autopkg` when it is installed and otherwise fails the job honestly.
- S3 blob storage (the interface and local driver exist; S3 returns a clear not-implemented error).
- `Role` and `Integration` resources are stored and not enforced. Token roles are what the API checks.
- Status-log retention and query-history pruning.

## Local quickstart

The compose file uses obvious local-only placeholders (`dev-bootstrap-token`, `dev-enroll-secret`, database password `missioncontrol`). Do not reuse them anywhere else.

```bash
docker compose up --build
```

Open http://localhost:8080 and sign in with `dev-bootstrap-token`. The server syncs `examples/config` on startup, so packs, labels, Munki, and the Chrome pipeline are already applied.

In another shell, from a clone that has the Python script:

```bash
python3 scripts/simulate_agent.py --server http://localhost:8080 --secret dev-enroll-secret
```

Three Macs enroll, pull config, and post inventory. They show up on Fleet and Devices.

Config workflow:

```bash
go build -o bin/mcctl ./cmd/mcctl
export MC_SERVER=http://localhost:8080
export MC_TOKEN=dev-bootstrap-token

./bin/mcctl validate -f examples/config
./bin/mcctl plan -f examples/config
./bin/mcctl apply -f examples/config
```

`plan` and `apply` do not delete other resources unless you pass `--prune`. The in-process directory sync does prune, and it refuses to apply an invalid tree.

UI development uses the Vite server, which proxies API calls:

```bash
cd web && npm install && npm run dev
```

### Without Docker

```bash
# Postgres database "missioncontrol", user/password missioncontrol
export MC_DATABASE_URL='postgres://missioncontrol:missioncontrol@127.0.0.1:5432/missioncontrol?sslmode=disable'
export MC_BOOTSTRAP_TOKEN=dev-bootstrap-token
export MC_ENROLL_SECRET=dev-enroll-secret
export MC_CONFIG_DIR=$PWD/examples/config
export MC_WEB_DIR=$PWD/web/dist   # after: cd web && npm ci && npm run build

go run ./cmd/mc-server
```

## A real osquery agent

The TLS plugin speaks HTTPS. Set `MC_TLS_CERT` and `MC_TLS_KEY`, or terminate TLS in front of the server, then start osquery with [examples/osquery/osquery.flags](examples/osquery/osquery.flags) and `--tls_server_certs` pointed at your CA. `MC_ENROLL_SECRET` must match.

## AutoPkg runner

```bash
# admin token
curl -s -H "Authorization: Bearer $MC_TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{"name":"mac-mini"}' \
  http://localhost:8080/api/v1/runners

go run ./cmd/mc-runner --server http://localhost:8080 --token "$RUNNER_TOKEN"
```

Queue a run from the AutoPkg page, or `POST /api/v1/autopkg/pipelines/google-chrome/runs`. On a Mac with `autopkg` installed the runner executes the recipe. Trust checks and Munki promotion are described in the architecture doc and are not done by this build.

## Tests

```bash
make test
```

Config, osquery, and API tests use an in-memory store. `MC_DATABASE_URL` additionally runs a Postgres round trip (enroll, re-enroll, apply, drift). GitHub Actions sets that variable.

## Layout

See [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) for the resource model, reconcile rules, osquery flow, and the Munki and AutoPkg phases.

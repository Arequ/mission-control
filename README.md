# Mission Control

API-first Munki, AutoPkg, and osquery inventory for a Mac fleet. The server is a stateless Go service on Postgres. Configuration is applied by Terraform, not edited in the UI. AutoPkg runs on Macs through `mc-runner`, which only makes outbound calls. osqueryd uses the TLS remote API.

Security Coverage joins osquery, Munki, and six security tools into one matrix. Logs and vulnerabilities are described in [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md).

## Quickstart

Requires Docker.

```bash
docker compose up --build
```

That starts Postgres and the server on http://localhost:8080. The UI is served from the same origin. Sign in with the local admin token `mc_dev_admin_token`. These compose credentials are for local development only.

In another shell, build the local provider and the fake AutoPkg binary, then apply the example stack:

```bash
make build tf-dev
export TF_CLI_CONFIG_FILE="$PWD/bin/dev.tfrc"
terraform -chdir=examples/terraform apply -auto-approve
```

That creates a runner pool, the AutoPkg recipe repo, a Firefox override, a 06:15 schedule, fleet pipeline limits, a 7-day promotion from `testing` to `production`, two Munki manifests, an osquery enroll secret, labels, a query, a pack, and a connector for each coverage source. Dev overrides skip the Terraform registry, so you do not need `terraform init`. Connector credentials in the example are placeholders (`example-crowdstrike-client-secret`, `example-kolide-api-token`, `example-elastic-api-key`).

Apply the example stack to a database that was not seeded. `MC_DEV_SEED=1` already inserts resources with those names, including the local enroll secret `mc_dev_enroll_secret`. The example variable `enroll_secret` defaults to `example-enroll-secret`. Both values are local placeholders.

Start a runner with the fake executor (this is what CI and Linux use; on a Mac, pass `--autopkg autopkg` and `--sync-repos`):

```bash
./bin/mc-runner \
  --server http://127.0.0.1:8080 \
  --bootstrap-token mc_dev_bootstrap_token \
  --name mini-1 \
  --labels macos,autopkg \
  --pool mac-minis \
  --autopkg "$PWD/bin/fake-autopkg" \
  --state "$PWD/bin/runner.json"
```

The morning schedule waits for its next cron instant. Enqueue a run immediately:

```bash
curl -s -X POST http://127.0.0.1:8080/api/v1/jobs \
  -H "Authorization: Bearer mc_dev_admin_token" \
  -H "Content-Type: application/json" \
  -d "{\"recipe_id\":\"$(terraform -chdir=examples/terraform output -raw firefox_recipe_id)\"}"
```

The runner leases the job, runs `fake-autopkg`, streams the log, and uploads Firefox 130.0. The UI shows the run and the package in the testing catalog.

Promotion to production happens after `soak_days` (7 in the example). To see it immediately, either:

- apply with `-var soak_days=0` before the run, or
- restart the server with `MC_CLOCK_OFFSET=168h`, or
- `POST /api/v1/packages/{id}/promote`

Munki clients use `http://munki:mc_dev_repo_token@localhost:8080/repo` as the repo URL. Catalogs are at `/repo/catalogs/testing` and `/repo/catalogs/production`.

osqueryd enrolls at the same host. The server speaks HTTP; put TLS in front, or point `--tls_server_certs` at a certificate you terminate locally. osquery 5 ships with empty endpoint defaults, so set the historical paths explicitly:

```bash
osqueryd \
  --tls_hostname=mc.example:443 \
  --enroll_secret_path=/etc/osquery/enroll.secret \
  --enroll_tls_endpoint=/enroll \
  --config_plugin=tls --config_tls_endpoint=/config \
  --logger_plugin=tls --logger_tls_endpoint=/logger \
  --distributed_plugin=tls \
  --disable_distributed=false \
  --distributed_tls_read_endpoint=/distributed_read \
  --distributed_tls_write_endpoint=/distributed_write
```

`--disable_distributed=false` is required. osquery leaves distributed queries off unless that flag is set at startup.

With the dev seed, the enroll secret file contains `mc_dev_enroll_secret`. A seeded fleet of about forty Macs is already in the UI, plus ghost and conflicting records in Security Coverage. A host that enrolls for real shows up next to them. Packs and labels from Terraform are delivered on `POST /config`. Live queries from the UI are delivered on the distributed read/write endpoints. The seed also inserts placeholder connector credentials (`mc_dev_crowdstrike_credential` and the same pattern for the other sources). The API never returns them.

`docker compose --profile runner up --build` also starts a fake runner on the compose network. It idles until a recipe and a job exist.

## Without Docker

```bash
# Postgres database missioncontrol, user missioncontrol, password missioncontrol
make test
make ui
make server
```

`make server` listens on `:8080` with the same local tokens.

## Tests

```bash
make test
```

Covers fleet concurrency and per-runner parallelism, label and pool matching, lease expiry and retry, cron enqueue, catalog generation, soak promotion and manual hold, an end-to-end runner against the HTTP API, the osquery enroll/config/log/distributed round trip (including node invalidation and re-enrollment), and `terraform apply` / update / plan / import / destroy of `examples/terraform` against a test server. `TestOsquerydLive` runs a real `osqueryd` when the binary is on `PATH` and skips otherwise.

`TEST_DATABASE_ADMIN` overrides the admin connection string used to create throwaway databases. The default is `postgres://missioncontrol:missioncontrol@127.0.0.1:5432/postgres?sslmode=disable`.

## Layout

| Path | What |
| --- | --- |
| `cmd/server` | API, scheduler, Munki repo |
| `cmd/mc-runner` | outbound runner |
| `cmd/fake-autopkg` | Linux stand-in for `autopkg` |
| `internal/httpapi/openapi.yaml` | OpenAPI document, also served at `/api/v1/openapi.yaml` |
| `terraform-provider-missioncontrol` | Terraform provider |
| `examples/terraform` | example stack for the config repo |
| `web` | React UI |
| `deploy/k8s/server.yaml` | Deployment and Service |

## Configuration

See [.env.example](.env.example). Storage is `MC_STORAGE_DRIVER=local` or `s3` (`MC_S3_ENDPOINT`, bucket, keys, `MC_S3_USE_SSL`). `MC_SYNC_REPOS=1` makes the runner clone recipe repos before each run.

# Mission Control

API-first Munki and AutoPkg for a Mac fleet. The server is a stateless Go service on Postgres. Configuration is applied by Terraform, not edited in the UI. AutoPkg runs on Macs through `mc-runner`, which only makes outbound calls.

The broader system (osquery, a unified device view, logs, vulnerabilities) is described in [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md). This repository is the Munki and AutoPkg slice.

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

That creates a runner pool, the AutoPkg recipe repo, a Firefox override, a 06:15 schedule, fleet pipeline limits, a 7-day promotion from `testing` to `production`, and two Munki manifests. Dev overrides skip the Terraform registry, so you do not need `terraform init`.

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

Covers fleet concurrency and per-runner parallelism, label and pool matching, lease expiry and retry, cron enqueue, catalog generation, soak promotion and manual hold, an end-to-end runner against the HTTP API, and `terraform apply` / update / plan / destroy of `examples/terraform` against a test server.

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

# Architecture

Mission Control is an API-first service for a Mac fleet. This repository currently implements the Munki and AutoPkg slice. Later slices (osquery, a unified device view, log search, vulnerability correlation) sit on the same API and the same GitOps flow. They are not built yet.

## Principles

**The HTTP API is the product.** The UI, the Terraform provider, `mc-runner`, and Munki clients are all clients of `/api/v1` or `/repo`. The OpenAPI document is served at `/api/v1/openapi.yaml`.

**Configuration is GitOps.** There is no in-app editor, no git sync inside the server, and no plan/apply engine. Desired state lives in a separate config repository (`Arequ/terraform-mission-control`, not this repo) and is applied by the Terraform provider in this repo when that config merges. Every config resource carries `managed_by` (the provider sends `terraform`). Every create, update, delete, import, promotion, and job completion writes an audit row: actor, kind (`api_token`, `runner`, or `system`), action, resource, and a JSON detail blob.

**The server is stateless apart from Postgres and object storage.** It is meant to run as more than one replica on Kubernetes. Package bytes go to local disk or S3-compatible storage. AutoPkg itself does not run in the cluster.

## Topology

```
                         pull request
                              │
                              ▼
                  terraform-mission-control
                              │  terraform apply
                              ▼
                    terraform-provider-missioncontrol
                              │  HTTPS, API token
                              ▼
┌──────────────────────── Kubernetes ────────────────────────┐
│  mission-control (stateless)                               │
│    /api/v1     config, jobs, runners, catalogs             │
│    /repo       Munki catalogs, manifests, pkgs             │
│    scheduler   cron enqueue, lease reclaim, promotion      │
│         │                         │                        │
│         ▼                         ▼                        │
│     Postgres                  S3 or disk                   │
└────────────────────────────────────────────────────────────┘
          ▲
          │  outbound only: register, heartbeat, long-poll lease,
          │  log lines, artifact upload, complete
          │
   ┌──────┴──────┐
   │  mc-runner  │  Mac mini, EC2 Mac, MacStadium
   │  autopkg    │  no inbound ports
   └─────────────┘
          │
          ▼
   Munki clients  ──HTTPS──►  /repo  (basic auth or bearer)
```

Runners never accept connections. A dead runner is detected when its lease expires; the job is requeued until `max_retries` is exhausted.

## Auth

API tokens are random, stored as SHA-256, and carry scopes (`config:read`, `config:write`, `jobs:read`, `jobs:write`, `runners:read`, `munki:read`, `munki:write`, `audit:read`, `admin`, or `*`). A write scope implies the matching read. `MC_ADMIN_TOKEN` is upserted at startup as the `admin` token with scope `*`. The compose file uses obvious local values; production supplies these from a Kubernetes secret and does not commit them.

Runners register with `MC_BOOTSTRAP_TOKEN` and receive a one-time runner token (`mcr_…`). That token is the only credential on the lease, log, renew, artifact, and complete routes.

Munki clients authenticate to `/repo` with HTTP basic (the password is `MC_REPO_TOKEN` or an API token that has `munki:read`) or with a bearer token.

## Runner protocol

1. `POST /api/v1/runners/register` with the bootstrap token. Body: name, labels, pool name, host facts. Response: runner id and runner token.
2. `POST /api/v1/runners/heartbeat` every loop.
3. `POST /api/v1/runners/lease?wait_seconds=20` long-polls. `204` means the queue was empty. `200` returns the job id, attempt, lease expiry, timeout, the recipe override, trust info, and the recipe repos to sync.
4. The runner writes the override and trust file, optionally `git clone`s repos (`MC_SYNC_REPOS=1`), runs `autopkg verify-trust-info`, then `autopkg run`. On Linux and in tests, `fake-autopkg` implements the same two commands.
5. Stdout and stderr are posted as log lines. `POST /jobs/{id}/renew` extends the lease and marks the job running.
6. A pkginfo plist and package are uploaded as multipart. The server fills `installer_item_hash` (SHA-256), `installer_item_size` (kilobytes, Munki's unit), and `installer_item_location`, and inserts the item into the promotion rule's `from_catalog` (default `testing`). A duplicate name and version is reported as already present.
7. `POST /jobs/{id}/complete` with `no_change`, `new_version`, `trust_failed`, or `error`.

Trust failures are not retried. `error` and an expired lease are retried until `attempt` reaches `max_retries + 1`, then the job is `failed`.

## Scheduler

A single loop (`MC_SCHEDULER_INTERVAL`, default 5s) does three things:

**Enqueue.** Enabled schedules use a five-field cron expression. Creating a schedule sets `last_enqueued_at` to now, so the first automatic run is the next cron instant rather than an immediate backfill. When that instant has passed, one job is queued per recipe. If a scheduled job for that recipe is already queued or running, the missed window is collapsed instead of stacking. Operators enqueue immediately with `POST /api/v1/jobs` (`{"recipe_id": "…"}`), which is what the UI's Run now button calls. That route is operational, not configuration.

**Lease.** Leasing takes a row lock on the pipeline settings, counts fleet-wide `leased` and `running` jobs against `max_concurrency`, counts that runner's active jobs against `per_runner_parallelism`, then claims the oldest queued job with `FOR UPDATE SKIP LOCKED`. A job matches a runner when the recipe's pool is unset or equal to the runner's pool, and the recipe's labels are a subset of the runner's labels (an empty label list matches everyone).

**Reclaim and promote.** Leases whose `lease_expires_at` is before the server clock are requeued or failed. Promotion then moves pkginfo whose soak has elapsed.

The server clock is `time.Now()` plus `MC_CLOCK_OFFSET`. Tests inject a manual clock. That is how a 7-day soak is exercised without waiting.

## Munki repo

Package bytes are stored under `pkgs/<filename>` via a small `Storage` interface. `local` is a directory. `s3` is any S3-compatible API (MinIO included) using static credentials and an optional TLS flag.

Catalogs are not hand-edited. `RegenerateCatalogs` loads every pkginfo in a catalog, normalizes JSON numbers back to integers, and writes an XML plist array. That is the makecatalogs equivalent. `testing` and `production` always exist, even when empty. Clients fetch:

- `GET /repo/catalogs/{name}`
- `GET /repo/manifests/{name}`
- `GET /repo/pkgs/{filename}`

Manifests are config resources (catalogs, included manifests, managed and optional installs, managed uninstalls) rendered as plist on request.

**Promotion** is a move, not a copy. A new import sets `catalogs` to the rule's `from_catalog` and starts the soak. When `now >= soak_started_at + soak_days` and the rule is enabled and not on manual hold, the package's catalog becomes `to_catalog`, `promoted_at` is set, and both catalogs are regenerated. `soak_days = 0` promotes on the next pass. `manual_hold` blocks the automatic pass; `POST /api/v1/packages/{id}/promote` moves the package anyway. Chained rules each see the soak clock reset at promotion, so a second hop waits its own soak unless that soak is zero.

The example manifest `testing` lists both the `testing` and `production` catalogs, which is the usual way a pilot group sees soaking items and already-promoted items together. `site_default` lists only `production`.

## Terraform provider

`terraform-provider-missioncontrol` is a terraform-plugin-framework provider. Resources:

| Resource | API |
| --- | --- |
| `missioncontrol_recipe_repo` | `/api/v1/recipe-repos` |
| `missioncontrol_recipe` | `/api/v1/recipes` |
| `missioncontrol_schedule` | `/api/v1/schedules` |
| `missioncontrol_pipeline_settings` | `/api/v1/pipeline-settings` (singleton; destroy resets defaults) |
| `missioncontrol_promotion_rule` | `/api/v1/promotion-rules` |
| `missioncontrol_runner_pool` | `/api/v1/runner-pools` |
| `missioncontrol_manifest` | `/api/v1/manifests` |

`examples/terraform` is a realistic slice of what will live in the config repo: a Mac mini pool, the public AutoPkg recipes repo, a Firefox override with trust info, a morning schedule, fleet limits, a 7-day promotion, and two manifests. It is applied with a dev override (`make tf-dev`), not the Terraform registry.

## UI

The UI is a Vite, React, and TypeScript app with no component library. The server serves `web/dist` from the same origin. Pages are Recipes, Runs, Run detail (plain log), Runners, Catalogs, Manifests, and Settings. Config shows a violet Managed by Terraform badge and is not editable. Run now is the only mutation. Visual tokens (type, color, radii, frosted shell, cards, pills) follow the approved mockups. Motion is CSS on `transform` and `opacity` only: page enter, staggered rows, a sliding sidebar indicator, soak bars via `scaleX`, and a View Transitions crossfade for light and dark. `prefers-reduced-motion` disables it.

## Kubernetes

`deploy/k8s/server.yaml` is a Deployment and Service. Probes hit `/healthz` and `/readyz`. Postgres is external. Package storage in that manifest is S3 so replicas do not need a shared disk. `mc-runner` is not a cluster workload; ship the Darwin binary to the Macs.

## What is real, and what is stubbed

Real in this slice: token auth, audit log, config CRUD, cron scheduling, concurrency and per-runner limits, lease expiry and retry, fake and interface-compatible autopkg execution, log streaming, catalog generation, soak promotion, manual promote, Munki repo serving, the Terraform provider, and the UI.

Stubbed or deliberately thin:

- Recipe repo sync is a real `git clone` / `fetch` when `MC_SYNC_REPOS=1`, but the server does not verify upstream trust the way a full AutoPkg install does. `fake-autopkg` checks a small JSON trust document (`fail`, `expected_override_sha256`, parent `sha256: "invalid"`). On a Mac, point `--autopkg` at real `autopkg`.
- The fake executor reads `NAME` and `VERSION` out of the override. It does not download vendor packages.
- S3 is implemented, but local dev and tests use the disk backend.
- There is no in-cluster leader election. The scheduler is safe to run on multiple replicas because enqueue collapses duplicates and leasing uses row locks, but two replicas will both attempt promotion. Promotion is idempotent given the catalog check.
- No osquery, device inventory, Elastic log viewer, vulnerability correlation, CrowdStrike, Rapid7, Netskope, Proofpoint, BlastShield, or Kolide integration yet.

## Roadmap

**Osquery.** An enroll endpoint and a node key, plus a scheduled query pack delivered on the same outbound style as `mc-runner` (or a small osquery extension that posts results). Results land in Postgres first; high-volume tables can move to the log store later. Devices become a first-class resource keyed by serial number.

**Unified device view.** One device record that joins osquery with read-only pulls from CrowdStrike, Rapid7, Netskope, Proofpoint, BlastShield, and Kolide. Those pulls are connectors with tokens supplied by Terraform, not typed into the UI. The API returns one device with a `sources` array and a freshness timestamp per source. Missing sources stay empty rather than blocking the page.

**Logs.** A narrow query API over Elasticsearch (time range, host, source, a query string) and a single log page. Mission Control does not become a second Kibana.

**Vulnerabilities.** Correlate Munki installed versions and osquery packages with Rapid7 or a CVE feed. The output is a per-device, per-package finding, linked back to the Munki item that would clear it when a promoted version exists.

**Swift client.** A later native app on the same `/api/v1` surface. No private endpoints.

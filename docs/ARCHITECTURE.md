# Architecture

Mission Control is an API-first service for a Mac fleet. This repository implements the Munki, AutoPkg, and osquery inventory slices. Later slices (a unified device view, log search, vulnerability correlation) sit on the same API and the same GitOps flow.

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

API tokens are random, stored as SHA-256, and carry scopes (`config:read`, `config:write`, `jobs:read`, `jobs:write`, `runners:read`, `munki:read`, `munki:write`, `osquery:read`, `osquery:write`, `audit:read`, `admin`, or `*`). A write scope implies the matching read. `MC_ADMIN_TOKEN` is upserted at startup as the `admin` token with scope `*`. The compose file uses obvious local values; production supplies these from a Kubernetes secret and does not commit them.

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

## Osquery

osqueryd talks to the standard TLS remote API. The process itself speaks HTTP, the same way Munki does; TLS terminates at the ingress. The paths are the historical osquery defaults. osquery 5 compiles those endpoint flags as empty, so a host sets them explicitly along with `--tls_hostname`, `--enroll_secret_path`, `--config_plugin=tls`, `--logger_plugin=tls`, and `--distributed_plugin=tls`:

- `POST /enroll`
- `POST /config`
- `POST /logger` (status and result)
- `POST /distributed_read`
- `POST /distributed_write`

A bad node key returns HTTP 200 with `{"node_invalid": true}`. osquery re-enrolls on that response. The previous key hash stays in the row so the server can tell an invalidated key from an unknown one.

Enroll secrets are Terraform resources. The API stores SHA-256 and never returns the raw secret. More than one secret can be enabled, which is how a rotation overlaps. Node keys are 32 random bytes, hex-encoded, and stored as SHA-256.

A device is matched by hardware UUID, then by serial. Re-enrollment keeps the same device id. If the UUID and the serial point at two different rows, the UUID wins and the serial is left on the other row.

Built-in inventory queries are always on the schedule. Their names start with `mc_` and cannot be used by Terraform. The interval is `MC_INVENTORY_INTERVAL` (default 5 minutes). They are snapshots: `system_info`, `os_version`, platform info, interface addresses, logged-in user, macOS apps, disk encryption, and uptime. The latest rows are stored raw, and a normalized device record is updated from them. The first apps snapshot is a baseline. Later snapshots write audit events: OS version, hostname, user, disk encryption, and app installed, updated, or removed.

Dynamic labels are snapshot queries named `mc_label_<name>`. A non-empty result means the host is a member. Manual labels are serials or device ids. A pack is included when it is enabled and the host is in any of its labels. A pack with no labels applies to every host. Platform, shard, and discovery are passed through for osquery to filter. A pack interval overrides the query interval; otherwise each query keeps its own interval, snapshot, and differential settings. Queries with `scheduled` also go on the global schedule.

Live queries are operational, not config. `POST /api/v1/live-queries` needs `osquery:write` and an explicit set of device ids or label names (at most 2000). Distributed read hands the SQL to those hosts and distributed write stores the rows. The UI polls. Targets that are still pending when `timeout_seconds` elapses become `timeout`. osquery does not poll distributed read unless it was started with `--disable_distributed=false`. The config document also sets that option, but the runner is started before the first config arrives.

Result logs are inserted in batches. `MC_ELASTIC_URL` optionally forwards the same rows to Elasticsearch `_bulk` (`MC_ELASTIC_INDEX`, `MC_ELASTIC_API_KEY`). Postgres stays the source of record. A forwarder error is logged and the agent still gets HTTP 200. An empty URL uses a no-op forwarder.

`MC_DEV_SEED=1` loads about forty fake Macs, the local enroll secret `mc_dev_enroll_secret`, and the same query, pack, and label names as `examples/terraform`. Those names collide if you apply the example stack onto a seeded database. Use a fresh database for `terraform apply`, the same way the provider test does.

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
| `missioncontrol_osquery_query` | `/api/v1/osquery/queries` |
| `missioncontrol_osquery_pack` | `/api/v1/osquery/packs` |
| `missioncontrol_osquery_label` | `/api/v1/osquery/labels` |
| `missioncontrol_osquery_enroll_secret` | `/api/v1/osquery/enroll-secrets` |
| `missioncontrol_source_connector` | `/api/v1/source-connectors` |
| `missioncontrol_log_view` | `/api/v1/log-views` |

`examples/terraform` is a realistic slice of what will live in the config repo: a Mac mini pool, the public AutoPkg recipes repo, a Firefox override with trust info, a morning schedule, fleet limits, a 7-day promotion, two manifests, an enroll secret, an Apple silicon label, a manual canary label, a launch-daemon query, a pack scoped to that label, and one connector for each of the eight coverage sources. It is applied with a dev override (`make tf-dev`), not the Terraform registry. The enroll secret and the connector credentials in that example are local placeholders.

The enroll secret, connector credentials (`client_secret`, `api_token`, `elastic_api_key`), and a log view's `elastic_api_key` are write-only attributes. Terraform sends them on create and update. The API stores them and never returns them, and state stores only a SHA-256 fingerprint. A second plan is empty. Import leaves the fingerprint null, so import does not plan an update. After import, a credential in configuration plans one apply that records the fingerprint. An empty credential on update keeps the stored value. A log view may omit its own URL and key and set `connector_id` to reuse a source connector's Elastic connection.

## UI

The UI is a Vite, React, and TypeScript app with no component library. The server serves `web/dist` from the same origin. Fleet pages are Overview (device count, online, macOS distribution, a small AutoPKG status), Devices, device detail (hardware header, then Overview, Software, and a live query), Queries (Terraform packs and queries, plus Live query), and Logs. Security Coverage is its own sidebar section: a devices-by-source matrix, a per-device pane at `/coverage/devices/:id`, and a connector health page. The general device page shows a `Coverage N/8` chip and a Logs link for that device. Software pages are still Recipes, Runs, Run detail, Runners, Catalogs, and Manifests, plus Settings. Config shows a violet Managed by Terraform badge and is not editable. Propose change links to the config repo. Run now, live query, and reading a log view are the operational actions. The fleet pages are intentionally sparse compared with the original mockups. Visual tokens (type, color, radii, frosted shell, cards, pills) follow those mockups. Source tiles use two-letter initials, not vendor logos. Motion is CSS on `transform` and `opacity` only: page enter, staggered rows, a sliding sidebar indicator, bars via `scaleX`, and a View Transitions crossfade for light and dark. `prefers-reduced-motion` disables it.

## Kubernetes

`deploy/k8s/server.yaml` is a Deployment and Service. Probes hit `/healthz` and `/readyz`. Postgres is external. Package storage in that manifest is S3 so replicas do not need a shared disk. `mc-runner` is not a cluster workload; ship the Darwin binary to the Macs.

## What is real, and what is stubbed

Real in this slice: token auth, audit log, config CRUD, cron scheduling, concurrency and per-runner limits, lease expiry and retry, fake and interface-compatible autopkg execution, log streaming, catalog generation, soak promotion, manual promote, Munki repo serving, the osquery TLS API, inventory and change events, label membership, live queries, the Terraform provider, and the UI.

Stubbed or deliberately thin:

- Recipe repo sync is a real `git clone` / `fetch` when `MC_SYNC_REPOS=1`, but the server does not verify upstream trust the way a full AutoPkg install does. `fake-autopkg` checks a small JSON trust document (`fail`, `expected_override_sha256`, parent `sha256: "invalid"`). On a Mac, point `--autopkg` at real `autopkg`.
- The fake executor reads `NAME` and `VERSION` out of the override. It does not download vendor packages.
- S3 is implemented, but local dev and tests use the disk backend.
- There is no in-cluster leader election. The scheduler is safe to run on multiple replicas because enqueue collapses duplicates and leasing uses row locks, but two replicas will both attempt promotion. Promotion is idempotent given the catalog check.
- Elasticsearch forwarding is a real `_bulk` client behind an interface. It runs only when `MC_ELASTIC_URL` is set. Log views are a separate read path: predefined KQL over indexes the organization already ships, not a search explorer. Dev seed views read a built-in corpus when no Elasticsearch is configured.
- The osquery TLS routes are HTTP. Terminate TLS in front of the process. A real `osqueryd` test in this repo does that with an in-process certificate when the binary is installed.
- Rapid7, Netskope, Proofpoint, and BlastShield have no documented device-list API wired here. Their default connector is an Elasticsearch field mapping. `mode = "api"` for those four calls `GET {base}/v1/devices` with a bearer token and a body of `{devices:[{id,serial,...}]}`. That path is a test double, not the vendor API. A real tenant credential will not return devices until a vendor-specific client replaces the stub. CrowdStrike Falcon (`/oauth2/token`, device scroll, device entities) and Kolide (`/api/v0/devices`) are real clients and need tenant credentials to verify against production.
- There is no vulnerability correlation yet.

## Security coverage

Coverage answers which of eight tools currently see an endpoint: osquery, Munki, CrowdStrike, Rapid7, Netskope, Proofpoint, BlastShield, and Kolide. Each connector is one Terraform resource, `missioncontrol_source_connector`, and there is one row per source. osquery and Munki are `native`: osquery is projected from the enrolled device, and Munki is whatever snapshots a later client check-in stores. CrowdStrike and Kolide poll vendor APIs. The other four read an Elasticsearch index the organization already ships (index pattern, KQL or DSL, time field, field map).

Each source keeps its own latest snapshot per native id. Snapshots are not merged into the device row. Matching uses normalized keys and drops placeholder serials, UUIDs, and MACs (`System Serial Number`, `To Be Filled By O.E.M.`, the nil and all-F UUIDs, all-zero and all-F MACs). A real serial or hardware UUID is strong. If those strong keys point at different devices, the record is a conflict and is not attached, and weak keys are not consulted. Otherwise a MAC, or a hostname together with a primary user, is a weak match. Hostname alone never matches. An unmatched security record is a ghost: it appears in Security Coverage and is not a row in Devices. Conflicts use their own subject id so they do not collapse into the ghost of one of the candidates.

A cell is seen when the newest snapshot is inside that source's `stale_after_seconds`, stale when it is older, and missing when there is no snapshot. Percents are seen divided by the unfiltered fleet. Filters are gaps, missing a named source, seen by exactly one source (a stale snapshot still counts as present), ghosts (no osquery snapshot), and stale for at least N days. Change events record the first sighting, the loss of the last snapshot, a field disagreement against the unified device, a rematch, and an identity conflict. Agent version is stored and is not a disagreement, because a Falcon version and an osquery version are different facts.

## Logs

A log view is a named set of Elastic queries, managed only by `missioncontrol_log_view`. The viewer prints the message lines the way they read in the original file, merged across the view's sources. Order is timestamp, then source position, then sequence, then a tiebreaker, so two lines from one file stay in order when their timestamps match. There is no query builder, histogram, or field sidebar.

Runs take a time window and, for a device-scoped view, a device id. Placeholders `{{serial}}`, `{{hostname}}`, and `{{hardware_uuid}}` are replaced with quoted KQL literals. The compiler accepts a small KQL subset (`and`, `or`, `not`, parentheses, `field: value`, quoted phrases, and a `*` or `?` wildcard only when the configured value itself contains one). A quoted field value with no whitespace is a `term` on that field and on `field.keyword`, so a device name cannot match a longer one. A quoted value with whitespace is `match_phrase`. It does not pass the string to `query_string`. Each source is read with a point-in-time and `search_after`, sorted by timestamp, optional sequence, and `_shard_doc`. Pages merge with a heap. The cursor remembers every line on the open page. Tail opens a fresh point-in-time so a line ingested late, with a timestamp inside the page, is returned once; lines older than the first line stay on the backward read, which re-reads that range. When a point-in-time expires, the next page resumes from the boundary key and drops ids already shown, because `_shard_doc` belongs to one snapshot. Context around a line is the same merge and reaches back ten years. `max_lines` caps a viewing session. One response holds at most 2000 lines. Zoneless timestamps are interpreted in the view's IANA time zone; values that already carry an offset keep it.

`POST /api/v1/log-views/{id}/query`, `/tail`, and `/context` require `logs:read`. Creating a view requires the Terraform client header. The API never returns `elastic_api_key`. A run writes an audit row with the view name, operation, device id, and line count, not the query after substitution and not the key. `MC_DEV_SEED=1` inserts Endpoint logs, Munki install log, AutoPKG run log, osquery errors, and Falcon sensor. Those names match `examples/terraform`. Apply the example to a database that was not seeded.

## Roadmap

**Vulnerabilities.** Correlate Munki installed versions and osquery packages with Rapid7 or a CVE feed. The output is a per-device, per-package finding, linked back to the Munki item that would clear it when a promoted version exists.

**Swift client.** A later native app on the same `/api/v1` surface. No private endpoints.

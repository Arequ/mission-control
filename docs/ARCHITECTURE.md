# Mission Control architecture

Mission Control is one console for endpoint visibility and Mac software management. It follows the Zentral and Fleet tradition: osquery for what is on the machine, declarative configuration for what should be, and a repo of packages the clients install. It is not an MDM. Automated Device Enrollment, APNs, and configuration profiles are out of scope.

This document describes the system the foundation is built toward, and marks what the current code actually does.

## Layout

```
cmd/mc-server     HTTP API, osquery TLS, config sync, static UI
cmd/mcctl         validate / plan / apply / export
cmd/mc-runner     Mac worker that claims AutoPkg jobs
internal/         config engine, store, API, osquery, sync
migrations        embedded SQL (internal/migrate/sql)
openapi/          OpenAPI document served at /api/openapi.yaml
web/              React UI
examples/config/  a complete sample of every resource kind
```

One Go module, three binaries. Postgres is the only required service.

## Components

```
                 git repo or directory
                        │
                        ▼
  mcctl ──HTTP──►  mc-server  ──►  Postgres
                      │  ▲
         osquery TLS  │  │  runner protocol
                      ▼  │
                  osqueryd   mc-runner ──► autopkg
                      │
                      ▼
                  Munki client   (phase 2: HTTP repo)
```

- **mc-server** is the only process that talks to Postgres. It serves `/api/v1`, the osquery TLS routes, and (when `MC_WEB_DIR` is set) the built UI.
- **mcctl** is a thin client of that API, except `validate`, which is local.
- **mc-runner** is deliberately dumb. It authenticates with a runner token, heartbeats, claims a job, runs `autopkg`, and uploads logs. Scheduling, trust policy, and promotion live on the server so a laptop cannot invent its own catalog rules.
- **Blob store** (`internal/blob`) is where package bytes will live. The local driver works. The S3-compatible driver is a typed stub (`ErrNotImplemented`) so the configuration shape is stable before the Munki phase fills it in.

## Config as code

### Why this format

Resources are YAML documents with `apiVersion`, `kind`, `metadata`, and `spec`:

```yaml
apiVersion: missioncontrol.io/v1
kind: OsqueryPack
metadata:
  name: macos-security
spec:
  platform: darwin
  queries:
    - name: sip
      query: SELECT * FROM sip_config;
      interval: 3600
      snapshot: true
```

Kubernetes-style YAML won over CUE for the foundation:

- A pull request diff is readable in any git host, without a CUE toolchain.
- Mac admins already live in plist, profile manifests, and osquery packs. A small envelope is easier to teach than a new language.
- Safety comes from typed Go specs. Unknown fields are rejected, names are DNS labels, queries must be `SELECT`/`WITH`, intervals are positive, and cron is a 5-field expression. That is the check CUE would have provided.
- The envelope is stable. A later CUE or JSON Schema frontend can emit the same documents. The server would not change.

`status` is server-owned. The loader strips it so a file cannot forge generation or ownership.

### Kinds

| Kind | Effect today | Later |
| --- | --- | --- |
| `OsqueryQuery`, `OsqueryPack` | Merged into the config served to agents | Same, plus UI editing stays forbidden |
| `Label` | Scheduled as `label_<name>`. Rows mean member | Static labels, manual membership |
| `MunkiRepo`, `MunkiCatalog`, `MunkiManifest`, `MunkiPkgInfo` | Stored and listed by the API | Rendered as the plist repo clients fetch |
| `AutoPkgRepo`, `AutoPkgPipeline` | Stored. A pipeline can be queued as a job | Schedule fires, trust + promotion run |
| `Role` | Stored only | Bound to tokens and OIDC groups |
| `Integration` | Stored only. Prefer `urlRef: env://NAME` | Actually deliver webhooks |

Identity is `kind + namespace + name`. Namespace defaults to `default`.

### Reconcile

```
files ─► parse ─► validate & canonicalize ─► hash ─► plan ─► apply
                                              ▲
                                         Postgres resources
```

1. Load every `.yaml` / `.yml` under the directory (multi-document files included). Hidden files are skipped.
2. Validate. Any diagnostic aborts the operation. Directory sync refuses to apply an invalid tree, so a bad commit cannot prune the fleet.
3. Canonicalize specs (ints stay ints; empty maps do not flap) and hash labels, annotations, and spec with SHA-256.
4. Plan against rows in `resources`:
   - missing → create
   - same hash and same owner → unchanged
   - different hash, or an API-owned row the files now claim → update (config adopts it)
   - config-owned row missing from the desired set → delete, only when prune is on
5. Apply in one transaction. Generation increments on update.

**Prune is off for `mcctl apply` and on for directory sync.** Sync treats the directory as the whole desired world. The CLI does not, unless you pass `--prune`, so applying one file does not delete everything else.

`MC_CONFIG_DIR` is polled on `MC_CONFIG_SYNC_INTERVAL` (default 30s). `MC_CONFIG_GIT_PULL=true` runs `git pull --ff-only` when the directory is a checkout. The server does not clone or store credentials; mount a deploy key the normal way. `POST /api/v1/config/sync` runs one tick.

### Ownership and drift

Every stored resource has `managedBy`. Config-managed resources are what git last applied. The API has no generic update route for specs, so the UI shows them as managed and read-only.

Two drift signals:

- **Git drift** is a plan that is not all `unchanged`. Sync status exposes the last plan summary and the last error.
- **Device drift** is a node whose last received config hash differs from the hash the server would hand that platform now. The fleet summary counts those devices. A node that has never fetched config counts as drifted once a desired hash exists.

Node keys and API tokens are stored as SHA-256 hashes. The enroll secret is compared by hashing both sides and using a constant-time compare.

## API and auth

`/api/v1` is the only control plane. The UI and `mcctl` both use it. `/api/openapi.yaml` is the contract.

Bearer tokens have roles `viewer` < `operator` < `admin`.

| Role | Can |
| --- | --- |
| viewer | Read devices, resources, Munki, AutoPkg, fleet |
| operator | Plan, live queries, queue AutoPkg runs |
| admin | Apply, sync, create tokens, register runners |

`MC_BOOTSTRAP_TOKEN` upserts a token named `bootstrap`. If it is unset, the server generates one and prints it once. Runner tokens (`mcr_…`) are a separate table and only authenticate `/api/v1/runner/*`.

Osquery routes are not bearer-authenticated. Enroll checks the enroll secret. Every later call checks the node key and returns `{"node_invalid": true}` with HTTP 200 when the key is unknown, which is what osquery needs in order to re-enroll.

## Data model

Postgres, migrated on startup from `internal/migrate/sql`.

- `api_tokens` — name, hash, role, last used
- `devices` — identity, hardware, OS, label array, latest inventory snapshots, config hash
- `device_apps` — normalized applications for fleet-wide counts
- `query_results` — scheduled query history (append-only; retention is a later phase)
- `resources` — the declarative documents and their hashes
- `distributed_queries` / `distributed_targets` — live queries
- `runners` / `autopkg_jobs` — the worker queue

Device re-enrollment matches hardware serial when one was reported, otherwise host identifier, and rotates the node key. The old key stops working.

## Osquery

Routes, all `POST`:

| Path | Purpose |
| --- | --- |
| `/osquery/enroll` | Check secret, return `node_key` |
| `/osquery/config` | Packs, schedule, options |
| `/osquery/log` | Result logs update inventory; status logs only refresh `last_seen` |
| `/osquery/distributed/read` | Pending live queries |
| `/osquery/distributed/write` | Results, status `0` completes the target |

`examples/osquery/osquery.flags` is a starting flagfile. The osquery TLS plugin speaks HTTPS, so production terminates TLS (`MC_TLS_CERT` / `MC_TLS_KEY` or a proxy). The simulator and the tests speak the same JSON over plain HTTP.

Config build:

- Packs and top-level queries whose platform matches the device are included. Empty platform means all. `posix` matches darwin and linux.
- Each `Label` becomes schedule query `label_<name>` with `snapshot: true`.
- Built-in `system_info`, `os_version`, `users`, and `apps` queries are added only when config did not already define that name. The sample pack therefore replaces the built-ins instead of double-scheduling them.
- `options.pack_delimiter` is `/`, so log names look like `pack/macos-inventory/system_info`.

Ingest recognizes those names (and the un-packed forms). Snapshots of `system_info`, `os_version`, `users`, and `apps` update the device row and replace that device's application list. Label snapshots with at least one row add the label; an empty snapshot removes it. Other queries are stored as results and do not change identity.

Live queries are operational, not configuration. `POST /api/v1/queries/live` with a `SELECT` enqueues the SQL for every device, or for an explicit id list. Agents receive it on the next distributed read and keep receiving it until they write a result.

## Fleet aggregation

`GET /api/v1/fleet/summary` counts devices, who was seen in the last 30 minutes, config drift, and buckets by platform, OS version, and model. Application counts are `COUNT(DISTINCT device)` grouped by name. The UI polls this. At the current scale the summary reads the device table in Go; a rollup table can wait until that is actually slow.

## Munki

The model is already declarative:

- A `MunkiRepo` names the repository and its public base URL.
- `MunkiCatalog` is a catalog, with an optional `soakHours` hint used by promotion.
- `MunkiManifest` points at one catalog and lists managed, optional, and uninstall names. Included manifests are a list, so site defaults can be composed.
- `MunkiPkgInfo` is the item name, version, catalogs, installer type, and a `packageKey` into the blob store. The bytes are not in git.

Today those documents are validated, stored, and returned by `/api/v1/munki/*`. `GET /munki/repo/...` responds **501**. Phase 2 turns the same rows into the on-disk (or blob-backed) repo Munki clients already understand:

- Render `catalogs/<name>` as a plist array of pkginfo.
- Render `manifests/<name>` including included manifests.
- Serve `pkgs/<file>` and icons from the blob store, with hashes recorded on the pkginfo.
- Keep client auth separate from the admin API (a repo key or client cert), because Munki clients are not bearer-token callers.

Nothing in that phase requires a second source of truth. Git remains the catalog membership; the blob store remains the bytes.

## AutoPkg

A pipeline names a repo, a recipe, an optional 5-field cron schedule, a trust flag, and a promotion policy (`testingCatalog`, `productionCatalog`, `soakHours`).

The queue is `autopkg_jobs`:

1. `POST /api/v1/autopkg/pipelines/{name}/runs` copies the pipeline spec onto a `queued` job. The cron ticker that does this on a schedule is not built yet; queueing by hand is.
2. `mc-runner` heartbeats, then `POST /api/v1/runner/jobs/claim`. The claim is `UPDATE … FOR UPDATE SKIP LOCKED`, so two runners do not take the same job.
3. The runner appends logs and `POST …/complete` with `succeeded` or `failed`.
4. If `autopkg` is not on `PATH`, the runner fails the job and says so. It does not pretend a package was imported.

Phase 3, on the server side of that same job:

- Dispatch from `schedule` instead of only from the button.
- Before `autopkg run`, require `autopkg verify-trust-info` when `trust.verify` is true. A trust failure fails the job and does not touch Munki.
- On success, the runner uploads the built package to the blob store (local or S3) and returns the new version, hashes, and pkginfo fragment.
- The server writes a `MunkiPkgInfo` into the testing catalog (as config, or as an API-managed overlay that a human promotes back into git — the promotion PR is the likely shape, so git stays authoritative).
- After `soakHours` with no failure report, the item's catalogs move from testing to production. That write is another reconcile, not a shell script.

Runner registration is `POST /api/v1/runners` (admin). The token is returned once.

## Security

- Do not commit tokens, enroll secrets, or webhook URLs. Integrations use `env://VAR` refs. The compose file's `dev-bootstrap-token` and `dev-enroll-secret` are local placeholders.
- API tokens and node keys are hashed at rest. Losing the database does not reveal the bearer value, but it does let an attacker who can write rows impersonate devices; treat Postgres as sensitive.
- Admin apply and runner registration are the sharp edges. Keep the bootstrap token out of CI logs.
- Osquery must use TLS outside local simulation. A node key is a device credential.
- Live queries are arbitrary `SELECT`s on every enrolled host. Operator is the minimum role, and the statement has to look like a query, but that is not a sandbox. Audit logging of who ran what is phase 4.
- `Role` resources do not yet change authorization. The token's role column does.

## Roadmap

**Phase 0 — this tree.** Server, Postgres, migrations, OpenAPI, token auth, osquery enroll/config/log/distributed, inventory and fleet summary, config engine with `mcctl`, example resources, Munki and AutoPkg models plus the job queue and runner, glass UI for fleet and devices.

**Phase 1 — fleet operations.** Faceted device search, status-log retention and a cap on `query_results`, label evaluation for differential results already accepted, a drift view per device, git webhook to sync immediately, and an audit row for apply and live query.

**Phase 2 — Munki repo.** Blob-backed pkgs and icons, plist catalogs and manifests generated from the stored resources, `GET /munki/repo/...` actually serving clients, hash verification on upload.

**Phase 3 — AutoPkg for real.** Cron dispatch, trust verification, artifact upload, promotion into testing, soak timer, promotion into production, run log viewer. The runner binary gains a launchd plist and a documented Mac install, not a new control plane.

**Phase 4 — access.** Map `Role` resources onto tokens, OIDC login, bind groups to roles, deliver `Integration` webhooks when a promotion is ready or a pipeline fails.

Non-goals unless a later design explicitly takes them on: MDM enrollment, configuration profiles, and replacing Munki's client.

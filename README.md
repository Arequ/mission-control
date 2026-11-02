# Mission Control

API-first Munki, AutoPkg, and osquery inventory for a Mac fleet. The server is a stateless Go service on Postgres. Configuration is applied by Terraform, not edited in the UI. AutoPkg runs on Macs through `mc-runner`, which only makes outbound calls. osqueryd uses the TLS remote API.

Security Coverage joins osquery, Munki, and six security tools into one matrix. Vulnerabilities correlate that inventory with NVD, CISA KEV, FIRST EPSS, and Apple security releases. The longer map is [HANDOFF.md](HANDOFF.md). Logs and the matching rules are described in [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md). The design tokens live in [web/src/styles.css](web/src/styles.css).

## How to launch it

### 60-second demo

Requires Docker. From a checkout of this branch:

```bash
make demo
make smoke
```

`make demo` (`scripts/demo.sh`) generates a three-day TLS certificate under `.demo/tls` (gitignored), adds `127.0.0.1 dex` to `/etc/hosts`, accepts forwarded packets if an old `iptables-legacy` policy is DROP, stops a host Postgres listening on 5432, and runs `docker compose up -d --build`. It then builds the local Terraform provider and applies `examples/terraform`. A second plan must be empty.

Open **http://localhost:8080** (that host, not `127.0.0.1`: the session cookie is host-only and the OIDC redirect is `MC_PUBLIC_URL`). Sign in as `ava@example.com` / `example-oidc-password`. Dex does not send groups for that static user, so the role is **viewer**. You should see the fleet shell, a device for the fake Munki client (`C02DEMO0001`, hostname `ava-mbp.local`) with a Munki card, an enrolled osquery host `mbp-eng-0217`, and Logs after `make smoke` indexes a few Elasticsearch lines. `make smoke` checks health, that login, osquery enrollment and `SELECT 1`, the Munki card, those log lines, the coverage matrix, and the vulnerability list (empty until a feed sync, because `MC_DEV_SEED=0`).

| Port | What |
| --- | --- |
| 8080 | API and UI |
| 8443 | osquery TLS |
| 5432 | Postgres (`missioncontrol` / `missioncontrol`) |
| 9200 | Elasticsearch 8, security off |
| 5556 | Dex. Issuer `http://dex:5556/dex` |

These values are local placeholders, the same class as `mc_dev_admin_token`. Do not reuse them outside this repo. API tokens still work: `Authorization: Bearer mc_dev_admin_token`.

### Native dev server

Postgres database `missioncontrol`, user `missioncontrol`, password `missioncontrol`, listening on `127.0.0.1:5432`. Then:

```bash
make test
make ui
make server
```

`make server` listens on `:8080` with `MC_DEV_SEED=1` unless you override it, and the same local tokens as `.env.example`. The UI is served from `web/dist`. The browser does not accept the API token. Without an OIDC provider the sign-in screen says no identity provider is configured. For a local UI session, turn break-glass on (off in production and in compose):

```bash
MC_BREAK_GLASS=1 MC_BREAK_GLASS_PASSWORD=example-break-glass-password make server
```

The password form is on the sign-in screen only while that flag is on. `cd web && npm run dev` serves the UI on http://localhost:5173 and proxies `/api`, `/repo`, and `/healthz` to `127.0.0.1:8080`.

`TEST_DATABASE_ADMIN` overrides the admin connection the tests use to create throwaway databases. The default is `postgres://missioncontrol:missioncontrol@127.0.0.1:5432/postgres?sslmode=disable`.

### Production

There is no Helm chart. `deploy/k8s/server.yaml` is a Deployment (two replicas) and a Service. It expects a Secret named `mission-control` and external Postgres. Package bytes go to S3 so replicas do not share a disk. This manifest has not been applied to a cluster from this repo's test environment.

Secret keys: `database-url`, `admin-token`, `bootstrap-token`, `repo-token`, `s3-access-key`, `s3-secret-key`. Plain env in the manifest: `MC_STORAGE_DRIVER=s3`, `MC_S3_ENDPOINT`, `MC_S3_BUCKET`, `MC_HTTP_ADDR=:8080`, `MC_DEV_SEED=0`, `MC_COOKIE_SECURE=1`, `MC_BREAK_GLASS=0`, `MC_PUBLIC_URL` (change `https://mc.example`), `MC_CONFIG_REPO=Arequ/terraform-mission-control`.

First boot upserts `MC_ADMIN_TOKEN` as the `admin` API token with scope `*`. That token is how Terraform authenticates. It is not a browser session. Break-glass (`MC_BREAK_GLASS=1` plus `MC_BREAK_GLASS_PASSWORD`) is the emergency local admin and stays off.

Point a checkout of the private config repo `Arequ/terraform-mission-control` at the cluster:

```bash
make build tf-dev
export TF_CLI_CONFIG_FILE="$PWD/bin/dev.tfrc"
# In that repo, set the provider endpoint and the admin token, then:
terraform apply
```

SSO is `missioncontrol_sso_provider` (issuer, client id, write-only client secret, allowed domains, group claim) and `missioncontrol_role_binding` (IdP group to viewer, operator, or admin). Register the redirect `https://<MC_PUBLIC_URL host>/api/v1/sso/callback` at the IdP. The provider in `examples/terraform` is the local Dex issuer and is not a production IdP.

Enroll a Mac (the server side of this is what compose exercises; a physical Mac was not enrolled from this environment):

- osqueryd: `--tls_hostname=<ingress>:443`, `--tls_server_certs` for that certificate, the historical endpoints `/enroll`, `/config`, `/logger`, `/distributed_read`, `/distributed_write`, and `--disable_distributed=false`. The enroll secret file contains the Terraform `missioncontrol_osquery_enroll_secret` value.
- Munki: `SoftwareRepoURL` `https://<host>/repo`, `AdditionalHttpHeaders` with `Authorization: Basic` or `Bearer` using the enrollment secret or the per-serial HMAC described in `client/munki/README.md`. Install the package built by `client/munki/build-pkg.sh` on macOS (`pkgbuild` is not available on Linux). The postflight posts `ManagedInstallReport.plist` to `POST /munki/checkin`.
- AutoPkg: run `mc-runner` on the Mac with `--autopkg autopkg`, `--sync-repos`, the bootstrap token, and a pool label that matches the recipe.

Terminate TLS at the ingress for both the UI and osquery, or set `MC_TLS_CERT` and `MC_TLS_KEY` and publish `MC_TLS_ADDR` (compose uses `:8443`).

## Quickstart

Requires Docker. `make demo` (or `scripts/demo.sh`) generates a short-lived TLS certificate under `.demo/tls` (not committed), adds `127.0.0.1 dex` to `/etc/hosts` so the browser can use the Dex issuer, stops a host Postgres that is holding port 5432, and runs `docker compose up -d --build`.

That stack is Postgres, Elasticsearch 8 with security disabled, Dex, the server (UI included) on http://localhost:8080, a TLS listener on :8443 for osquery, a real `osqueryd`, and a fake Munki client. `MC_DEV_SEED=0` so the example Terraform names do not collide with seeded rows. `MC_BREAK_GLASS` is off. The demo then builds the local provider and applies `examples/terraform`. A second `terraform plan` must be empty.

```bash
make demo
make smoke
```

Sign in at http://localhost:8080 as `ava@example.com` / `example-oidc-password`. Dex static passwords do not emit groups, so that user is a viewer through the `*` role binding. API tokens still work for Terraform and automation (`mc_dev_admin_token`). These compose values are local placeholders, the same class as the dev tokens. Do not reuse them outside this repo.

The placeholders used by the example stack are `example-enroll-secret`, `example-oidc-client-secret`, `example-oidc-password`, `example-munki-enrollment-secret`, and empty Elastic credentials pointed at `http://elasticsearch:9200`.

To apply the example yourself after the server is up:

```bash
make build tf-dev
export TF_CLI_CONFIG_FILE="$PWD/bin/dev.tfrc"
terraform -chdir=examples/terraform apply -auto-approve
```

That creates a runner pool, the AutoPkg recipe repo, a Firefox override, a 06:15 schedule, fleet pipeline limits, a 7-day promotion from `testing` to `production`, two Munki manifests, a Munki enrollment and demo client, an osquery enroll secret, labels, a query, a pack, a connector for each coverage source, two log views (a device-scoped endpoint timeline and an AutoPKG run log), vulnerability feed settings with one CPE override, a Dex SSO provider, and role bindings. Dev overrides skip the Terraform registry, so you do not need `terraform init`. Connector credentials, the log view API key, the NVD API key, the OIDC client secret, and the Munki enrollment secret in the example are placeholders. The NVD key, OIDC secret, and enrollment secret are write-only.

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

Munki clients use `http://munki:mc_dev_repo_token@localhost:8080/repo` as the repo URL, or a per-device Basic user (the serial) with the enrollment-derived token. Catalogs are at `/repo/catalogs/testing` and `/repo/catalogs/production`. Manifests, pkgsinfo, and icons are under `/repo` as well. `client/munki` is the preflight and postflight that post `ManagedInstallReport.plist` to `POST /munki/checkin`. The compose fake client uses serial `C02DEMO0001` and the example enrollment secret. The device page shows the Munki card after that check-in.

osqueryd enrolls at the TLS listener. Compose points `--tls_hostname=server:8443` and `--tls_server_certs` at the generated certificate. osquery 5 ships with empty endpoint defaults, so set the historical paths explicitly:

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

With the dev seed, the enroll secret file contains `mc_dev_enroll_secret`. A seeded fleet of about forty Macs is already in the UI, plus ghost and conflicting records in Security Coverage. A host that enrolls for real shows up next to them. Packs and labels from Terraform are delivered on `POST /config`. Live queries from the UI are delivered on the distributed read/write endpoints. The seed also inserts placeholder connector credentials (`mc_dev_crowdstrike_credential` and the same pattern for the other sources) and five log views that read a built-in corpus, so Logs works without Elasticsearch. The API never returns those credentials. Apply `examples/terraform` to a database that was not seeded: the example log views use the same names.

The same seed correlates real CVEs (Chrome, Firefox, Zoom, and two Sequoia KEV items) so Vulnerabilities works offline. The rows are marked `fixture` until a feed sync replaces them. CVE ids are not invented. Chrome and Firefox fixes sit in the testing catalog, so those issues ask for a promotion pull request. Zoom is still behind its fix, so that issue can run its recipe. Promotion links to `Arequ/terraform-mission-control` and does not change a catalog from the UI. With `MC_DEV_SEED=0`, the vulnerability list stays empty until a feed sync. Munki check-in versions are evidence when a feed has matched them.

`make smoke` checks health, the Dex login, osquery enrollment and a live query, the Munki card, a Logs query against Elasticsearch (the script indexes a few lines first), the coverage matrix, and the vulnerabilities list.

`docker compose --profile runner up --build` also starts a fake runner on the compose network. It idles until a recipe and a job exist. SAML is not implemented. Propose-change links for SSO and Munki enrollment wait until the config repo adds `access/sso.tf` and `munki/clients.tf`.

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
| `client/munki` | Munki preflight, postflight, and pkg build script |
| `deploy/dex` | Dex config for the compose OIDC provider |
| `scripts/demo.sh` | Compose up, terraform apply, empty second plan |
| `scripts/smoke.sh` | End-to-end checks against the compose stack |

## Configuration

See [.env.example](.env.example). Storage is `MC_STORAGE_DRIVER=local` or `s3` (`MC_S3_ENDPOINT`, bucket, keys, `MC_S3_USE_SSL`). `MC_SYNC_REPOS=1` makes the runner clone recipe repos before each run.

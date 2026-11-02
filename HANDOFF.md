# Mission Control

Mission Control is the API-first control plane for a Mac fleet: Munki and AutoPkg, osquery, a unified device page, security coverage, predefined log views, and a vulnerability issue list. Humans and agents should be able to launch it and change it from this file.

## How to launch it

### 60-second demo

Docker is required. From this repo:

```bash
make demo
make smoke
```

`make demo` runs `scripts/demo.sh`. It writes a three-day certificate under `.demo/tls` (gitignored), adds `127.0.0.1 dex` to `/etc/hosts`, sets `iptables-legacy` FORWARD to ACCEPT when that policy is still DROP, stops a host Postgres on port 5432, and runs `docker compose up -d --build`. It then builds the Terraform provider and applies `examples/terraform`. The second plan must be empty.

Open **http://localhost:8080**. Use that hostname. The OIDC redirect is `http://localhost:8080/api/v1/sso/callback`, and the session cookie is host-only, so `127.0.0.1` will not complete login.

Sign in as `ava@example.com` / `example-oidc-password`. Dex static passwords do not emit groups, so this user is a **viewer** through the `*` role binding. You should see the fleet shell. After the fake client checks in, Devices includes `ava-mbp.local` (`C02DEMO0001`) with a Munki card (version, pending install, warning). osquery enrolls as `mbp-eng-0217`. `make smoke` indexes a few lines into Elasticsearch and checks Logs, the coverage matrix, and the vulnerability list. The vulnerability list is empty until a feed sync because compose sets `MC_DEV_SEED=0`.

| Port | Process |
| --- | --- |
| 8080 | API and the built UI |
| 8443 | osquery TLS (`MC_TLS_ADDR`) |
| 5432 | Postgres, user and database `missioncontrol`, password `missioncontrol` |
| 9200 | Elasticsearch 8.15, security disabled |
| 5556 | Dex. Issuer `http://dex:5556/dex` |

Placeholders, not production secrets: `mc_dev_admin_token`, `mc_dev_bootstrap_token`, `mc_dev_repo_token`, `example-enroll-secret`, `example-oidc-client-secret`, `example-oidc-password`, `example-munki-enrollment-secret`. Terraform and curl keep using `Authorization: Bearer mc_dev_admin_token`.

`docker compose --profile runner up --build` also starts a fake AutoPkg runner. It idles until a recipe and a job exist.

### Native dev server

Create the database the tests and `make server` expect:

```bash
# Ubuntu package postgres, then:
sudo -u postgres psql -c "CREATE ROLE missioncontrol LOGIN PASSWORD 'missioncontrol' SUPERUSER"
sudo -u postgres psql -c "CREATE DATABASE missioncontrol OWNER missioncontrol"
```

```bash
make test
make ui
MC_BREAK_GLASS=1 MC_BREAK_GLASS_PASSWORD=example-break-glass-password make server
```

`make server` listens on `:8080`, serves `web/dist`, and seeds a fake fleet when `MC_DEV_SEED` is unset or `1`. The browser has no API-token field. Break-glass is the local sign-in and is off unless both variables are set. The password form is labeled Break-glass local admin.

For UI edits without rebuilding the Go binary:

```bash
cd web && npm run dev
```

Vite listens on http://localhost:5173 and proxies `/api`, `/repo`, and `/healthz` to `127.0.0.1:8080`.

`TEST_DATABASE_ADMIN` defaults to `postgres://missioncontrol:missioncontrol@127.0.0.1:5432/postgres?sslmode=disable`.

### Production

No Helm chart. `deploy/k8s/server.yaml` is a two-replica Deployment and a Service. Probes are `/healthz` and `/readyz`. Postgres is outside the cluster. Packages go to S3. **This manifest has not been applied to a cluster in the environment that wrote this file.**

Secret `mission-control` keys:

| Key | Env |
| --- | --- |
| `database-url` | `DATABASE_URL` |
| `admin-token` | `MC_ADMIN_TOKEN` |
| `bootstrap-token` | `MC_BOOTSTRAP_TOKEN` |
| `repo-token` | `MC_REPO_TOKEN` |
| `s3-access-key` | `MC_S3_ACCESS_KEY` |
| `s3-secret-key` | `MC_S3_SECRET_KEY` |

Plain env already in the manifest: `MC_STORAGE_DRIVER=s3`, `MC_S3_ENDPOINT`, `MC_S3_BUCKET`, `MC_HTTP_ADDR=:8080`, `MC_DEV_SEED=0`, `MC_COOKIE_SECURE=1`, `MC_BREAK_GLASS=0`, `MC_PUBLIC_URL=https://mc.example` (change this), `MC_CONFIG_REPO=Arequ/terraform-mission-control`. Set `MC_S3_USE_SSL` if the endpoint is HTTPS. Leave break-glass off. Do not put the OIDC client secret or the Munki enrollment secret in the pod env. Terraform sends those and the API stores them.

First boot upserts `MC_ADMIN_TOKEN` as an API token named `admin` with scope `*`. That is the Terraform credential. It does not create a browser session.

From a workstation with the provider built (`make tf-dev`):

```bash
export TF_CLI_CONFIG_FILE="$PWD/bin/dev.tfrc"
```

In the private repo `Arequ/terraform-mission-control`, set the provider endpoint to the public URL and the token to `MC_ADMIN_TOKEN`, then `terraform apply`. SSO resources are `missioncontrol_sso_provider` and `missioncontrol_role_binding`. The IdP must allow redirect `https://<public host>/api/v1/sso/callback`. Map an admin group before you rely on the UI. `examples/terraform` targets the compose Dex issuer and the compose Elasticsearch URL. Do not apply that example unchanged against production.

Enroll a Mac. Compose verifies the server side with a real `osqueryd` container and a fake Munki client. A physical Mac was not enrolled here.

- osqueryd needs a TLS hostname, `--tls_server_certs`, `--enroll_secret_path`, `--config_plugin=tls`, `--logger_plugin=tls`, `--distributed_plugin=tls`, `--disable_distributed=false`, and the endpoints `/enroll`, `/config`, `/logger`, `/distributed_read`, `/distributed_write`. The secret file is the value of `missioncontrol_osquery_enroll_secret`. Terminate TLS at the ingress, or set `MC_TLS_CERT` and `MC_TLS_KEY` and publish `MC_TLS_ADDR` (compose uses `:8443`).
- Munki `SoftwareRepoURL` is `https://<host>/repo`. Send `Authorization` via `AdditionalHttpHeaders` (Basic username `munki` and the enrollment secret, or Basic username = serial and the derived device token). `client/munki/build-pkg.sh` builds the preflight and postflight package on macOS. `pkgbuild` does not exist on Linux, so that script was not run here. The postflight posts `ManagedInstallReport.plist` to `POST /munki/checkin`. See `client/munki/README.md`.
- AutoPkg runs on the Mac through `mc-runner` (`--server`, `--bootstrap-token`, `--pool`, `--labels`, `--autopkg autopkg`, `--sync-repos`). Runners only make outbound calls.

## What it is

One Go process serves `/api/v1`, the Munki `/repo`, the osquery TLS routes, and the React UI. State is Postgres. Package bytes are local disk or S3. Elasticsearch is the log store the organization already has. Mission Control does not replace Kibana. It reads predefined views.

## Product decisions

- Go API-first. The UI, Terraform, `mc-runner`, osqueryd, and Munki are clients.
- React, TypeScript, and Vite. No component library. The server serves `web/dist` from the same origin.
- Configuration is Terraform-only, applied from the private repo `Arequ/terraform-mission-control` by `terraform-provider-missioncontrol` in this repo. The UI is read-only for config. Writes need `config:write` and `X-Mission-Control-Client: terraform`.
- Kibana and Elasticsearch stay the log store. Log views are named KQL queries, not a search explorer.
- The UI is a minimal Apple-polished reading of the fleet and device mockups. Tokens are in `web/src/styles.css`.

## Repo map

| Path | What |
| --- | --- |
| `cmd/server` | API, scheduler, repo, osquery, optional TLS listener |
| `cmd/mc-runner` | Outbound AutoPkg worker |
| `cmd/fake-autopkg` | Linux stand-in for `autopkg` |
| `internal/httpapi/openapi.yaml` | OpenAPI, also served at `/api/v1/openapi.yaml` |
| `internal/configrepo` | Propose-change path allowlist |
| `internal/sso` | OIDC authorization code, PKCE, role mapping |
| `internal/munki` | Catalogs, manifests, check-in plist |
| `client/munki` | Preflight, postflight, pkg build script |
| `terraform-provider-missioncontrol` | Provider module |
| `examples/terraform` | Example stack, also the provider CRUD test |
| `web` | React UI |
| `deploy/k8s/server.yaml` | Deployment and Service |
| `deploy/dex` | Compose OIDC provider |
| `scripts/demo.sh`, `scripts/smoke.sh` | Full stack and the smoke checks |
| `docs/ARCHITECTURE.md` | How the pieces behave |
| `docs/design/README.md` | UI rules |

## How each slice works

**Munki and AutoPkg.** Recipes, schedules, runner pools, and promotion rules are Terraform. `mc-runner` registers with the bootstrap token, long-polls a lease, runs `autopkg`, and uploads a pkginfo and package. The server regenerates catalogs. Promotion moves a package from `testing` to `production` after the soak. Manifests render as plist, including conditional items.

**Munki check-in.** Munki has no check-in protocol. `/repo` serves catalogs, manifests, pkgsinfo, icons, and pkgs to a client authenticated with the repo token, an enrollment secret, a per-device token, or a `munki:read` API token. Names are one path segment. Range and ETag work for local files. S3 redirects to a presigned URL. A manifest name that looks like a serial is rendered from the client override, else the enrollment manifest, else `site_default`. `POST /munki/checkin` parses `ManagedInstallReport.plist` (gzip, size caps, no entity expansion). State is stored on the device matched by serial, then hardware UUID. That row feeds the device Munki card, native Munki coverage, and vulnerability evidence.

**osquery.** The historical TLS API: `/enroll`, `/config`, `/logger`, `/distributed_read`, `/distributed_write`. A bad node key returns HTTP 200 and `node_invalid: true`. Inventory queries named `mc_*` are always scheduled. Live queries are operational. The main API is HTTP. Compose adds a TLS listener on `:8443` so a real `osqueryd` can enroll.

**Security coverage.** Eight sources: osquery, Munki, CrowdStrike, Rapid7, Netskope, Proofpoint, BlastShield, Kolide. Each is one `missioncontrol_source_connector`. osquery and Munki are native. CrowdStrike and Kolide poll their APIs. The other four read Elasticsearch. Snapshots stay per source. Strong keys are serial and hardware UUID. A cell is seen, stale, or missing.

**Logs.** `missioncontrol_log_view` is a named set of Elastic queries. The viewer prints message lines merged across sources. Device-scoped views bind `{{serial}}`, `{{hostname}}`, and `{{hardware_uuid}}` as quoted KQL. The API never returns `elastic_api_key`. With no Elastic URL, dev seed views read a built-in corpus. Compose points the example views at `http://elasticsearch:9200` with an empty API key.

**Vulnerabilities.** One issue per CVE and product. Inputs are osquery apps, the macOS version, Munki catalog items, Munki check-in installs, AutoPkg recipes, and an optional Rapid7 finding. Feeds are NVD, CISA KEV, EPSS, and SOFA. SOFA trains win over NVD ranges. A Windows-only configuration is dropped. An app qualified with a macOS version keeps that bound. NVD `apple:macos` ranges are stored and are not synced as a product. With no SOFA train, only a same-major bound matches. The fix path opens a GitHub compare URL against `Arequ/terraform-mission-control`. It does not edit a catalog.

**SSO.** OIDC authorization code plus PKCE. Okta, Entra ID, and Google fit the same resource: issuer, client id, write-only secret, allowed domains, group claim. `missioncontrol_role_binding` maps a group to viewer, operator, or admin, which expand to the existing token scopes. `config:write` stays on admin. Sessions are `mc_session` (HttpOnly, SameSite=Lax, Secure unless `MC_COOKIE_SECURE=0`), hashed at rest, idle 30m, absolute 12h, revocable. Mutating cookie calls send `X-CSRF-Token`. A present `Authorization` header does not fall through to the cookie. Login state is one-time and bound to `mc_oidc`. The return path is a same-origin path. Logout revokes the session and returns an RP-initiated end-session URL only when that endpoint is on the issuer host. SAML is not implemented.

## Contributing

Stacked PRs: branch from the parent head, and set the PR base to that branch. Review the diff yourself before pushing, and add a regression test for every bug you fix. Run `gofmt`, `go vet`, `staticcheck`, `go test -race ./...` in both modules, the Terraform apply test, and `npm run build`. See `AGENTS.md`.

OpenAPI stays in `internal/httpapi/openapi.yaml`. The test that walks configrepo kinds fails if a kind is missing from `ServerMeta`.

Config kinds map to files in `internal/configrepo`. Add a kind to that map and to `TestMappedPathsAreRealFiles` only when the file exists in the allowlist. The config repo still needs `access/sso.tf` and `munki/clients.tf` before those propose links exist.

Design: `web/src/styles.css`, CSS `transform` and `opacity` only, light and dark, minimal pages. Config stays read-only.

## Known gaps and TODO

Ordered by what blocks a real fleet:

1. Real API clients for Rapid7, Netskope, Proofpoint, and BlastShield. Elastic mode is the default. `mode = "api"` is a test double (`GET {base}/v1/devices` or `GET {base}/v1/findings`), not the vendor API.
2. Live-tenant verification of CrowdStrike and Kolide. The clients are real and untested against a production tenant.
3. Leader election. Two replicas can both promote. Promotion is idempotent given the catalog check, and leasing uses row locks, but there is no leader.
4. SAML. Not implemented.
5. Dex static passwords do not emit groups. The `engineering` to `admin` binding is unit-tested and applies when the IdP sends the group. Group membership changes apply on the next login. Binding changes apply on the next request.
6. NVD and the vulnerability list stay empty without `MC_DEV_SEED=1` or a successful feed sync. Compose uses `MC_DEV_SEED=0` so Terraform names do not collide.
7. osquery in Docker has a limited table set. It enrolls and answers `SELECT 1`.
8. `client/munki/build-pkg.sh` needs `pkgbuild` on macOS.
9. `deploy/k8s/server.yaml` has not been applied to a cluster from here.
10. Propose links for SSO and Munki client auth wait on `access/sso.tf` and `munki/clients.tf` in the config repo.
11. A Swift client is still only a roadmap note. No private endpoints.

## Pitfalls

- `MC_DEV_SEED=1` inserts the same names as `examples/terraform`, including `mc_dev_enroll_secret`. Apply the example to a database that was not seeded. Compose sets `MC_DEV_SEED=0`.
- The browser host must match `MC_PUBLIC_URL`. `localhost` and `127.0.0.1` are different cookie hosts.
- Elasticsearch 8 treats `logs-*-*` as data streams. Writes use the `create` op. The smoke seed uses `logs-munki.install-demo` and the same pattern for the other three indexes.
- Official osquery images are tagged `5.17.0-ubuntu24.04`, not `5.14.1`. There is no `osquery/osquery:5.14.1`.
- An `iptables-legacy` FORWARD policy of DROP next to Docker's nftables rules blackholes container-to-container traffic. `scripts/demo.sh` sets that policy to ACCEPT when it sees DROP.
- The OIDC client secret and the Munki enrollment secret are stored so they can be presented again. They are never returned in JSON. Session ids and per-device tokens are SHA-256.
- Do not derive the public URL from `X-Forwarded-Host`. `MC_PUBLIC_URL` is the redirect base. When it is unset, only a loopback `Host` is accepted, which is how the tests run.
- A present `Authorization` header is exclusive. A bad bearer with a valid session cookie is 401.
- Query-string tokens on `/repo` are rejected. The Basic username is not compared for the shared repo token, so the token is not the access-log user.
- Write-only Terraform attributes use a fingerprint in state. An empty update keeps the stored secret. Conditional manifest blocks use a null list when omitted so a second plan stays empty.

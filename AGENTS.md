# Agent rules

This repository is public. Never commit secrets, `.env`, `.demo/` (TLS keys and enroll secrets), Terraform state, or real IdP credentials. Local placeholders (`mc_dev_admin_token`, `example-oidc-client-secret`, `example-munki-enrollment-secret`, `example-enroll-secret`, `example-keel-enroll-secret`) are the same class as the compose file and are not production secrets.

## Before pushing

```bash
gofmt -w $(find . -name '*.go' -not -path './web/*')
go vet ./...
staticcheck ./...
cd terraform-provider-missioncontrol && go vet ./... && staticcheck ./...
go test -race ./...
cd terraform-provider-missioncontrol && go test -race ./...
cd web && npm run build
```

`TestTerraformProviderCRUD` (`go test ./internal/integration/ -run TestTerraformProviderCRUD`) needs `terraform` on `PATH` and Postgres. It applies `examples/terraform` and requires an empty second plan. A UI change needs a browser pass of the affected flow, not only a screenshot of the first paint.

## Config

Configuration is Terraform-only. Config writes need scope `config:write` and `X-Mission-Control-Client: terraform`. The UI must not send that header. Secrets on those resources are write-only: the API never returns them. New config kinds get an OpenAPI path and a provider resource. Propose-change links come from `internal/configrepo`. Add a kind, and extend `TestMappedPathsAreRealFiles`, only when that file is already in the config-repo allowlist. Otherwise name the file the config repo should add (`access/sso.tf`, `munki/clients.tf`).

Keep `internal/httpapi/openapi.yaml` in sync. `TestOpenAPIDocumentsConfigLinks` fails if a configrepo kind is missing from `ServerMeta`.

## UI

The design system is `web/src/styles.css` (tokens taken from the approved mockup `app.css`). See `docs/design/README.md`. No component library. Motion is CSS `transform` and `opacity` only, in light and dark. Pages stay sparse. Config is read-only in the UI.

## Stacked PRs

Branch from the parent PR's head. Open the PR with that branch as the base. After you change behavior, add a regression test for the bug you fixed. Review your own diff for auth, path traversal, and secret leakage before you push.

Read `HANDOFF.md` for the product decisions and the known gaps.

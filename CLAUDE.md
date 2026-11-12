# CLAUDE.md

Repo: `github.com/kotoyants/secrets-ui` (Go module path).
Web app for managing Kubernetes secrets with Google login and tag-based roles.
- Requirements: `SPEC.md` (source of truth: update it when requirements change)
- Roadmap and progress: `PLAN.md` (tick off checkboxes as work completes)

## Stack
Go · chi · html/template + htmx (no JS build) · PostgreSQL (pgx + sqlc + goose) · go-oidc · client-go · Helm

## Commands
Tooling runs in Docker; do not require local installs beyond Go + Docker.
- `make db-up` then `make run` — run locally (copy `.env.example` to `.env`)
- `make test` — all tests; DB tests start Postgres via testcontainers (`go test -short ./...` skips them,
  `TEST_DATABASE_URL` reuses an existing DB)
- `make lint` — golangci-lint (Docker image if not installed)
- `make sqlc` — regenerate `internal/store/db` after editing `internal/store/queries/*.sql`; `make sqlc-check` verifies
- `make migrate` — apply migrations (the server also applies them at startup)
- `make build` / `make docker`

## Rules
- **Never** store, log, cache or put secret values in audit events. Values live only in the provider.
- The app is **stateless**: no in-memory sessions, caches or local files. All state is in Postgres or signed cookies.
- Every secret access goes through `internal/authz`. Do not duplicate the tag logic elsewhere.
  Rule: secret.tags ⊆ union of the user's role tags (writes use only `read_write` roles). Admin bypasses it.
- Provider-specific code stays in `internal/provider/<name>/`. The core uses only the `Provider` interface,
  `provider.Registry` and the sentinel errors (`ErrNotFound`, `ErrConflict`, `ErrForbidden`, ...).
- Local `make run` needs `KUBE_CONTEXT` set; the user's default kubectl context is **production** — never point
  local runs or ad-hoc kubectl commands at it without asking.
- DB schema changes = a new goose migration in `migrations/` (`NNNNN_name.sql`); never edit an applied migration.
- Multi-statement DB operations go in `internal/store/store.go` using `InTx`; map driver errors with `mapErr`
  (`ErrNotFound`, `ErrConflict`, `ErrBuiltinRole`). Tags are always normalized via `internal/tags`.
- Do not edit sqlc-generated files by hand.
- Config comes only from env vars, via `internal/config`.
- Responses containing secret values: `Cache-Control: no-store`.
- Audit events go through `internal/audit` (slog JSON to stdout).
- Handlers get the user via `auth.FromContext(ctx)`; protect routes with `auth.RequireUser` / `auth.RequireAdmin`.
  Never trust anything but the DB-loaded principal (the session cookie holds only the user ID).

## Conventions
- Errors: wrap with `fmt.Errorf("...: %w", err)`; handlers map them to user-friendly messages.
- Tests: table-driven; authz must have full coverage; k8s via the fake clientset; DB tests on real Postgres.
  Auth/web tests use `internal/auth/authtest` (fake Google OIDC provider + in-memory user store);
  web tests needing a DB use `internal/store/storetest.New(t)`.
- UI: server-rendered `html/template` pages in `internal/web/templates` (layout + one file per page, registered in
  `pages.go`). POST handlers end with `h.done(...)` (flash + redirect); errors map via `describeErr`. Return
  `errorf("...")` for messages meant for the user. No inline JS/CSS (CSP); use htmx attributes.
- Keep handlers thin: parse the request → call the service/store → render.

## Workflow
- Ask clarifying questions when requirements are unclear; do not guess silently.
- Do not commit without explicit approval.
- Commit messages use Conventional Commits prefixes (`feat:`, `fix:`, `ci:`, `chore:`, `docs:`, `refactor:`, `test:`).
  CI builds an image on main only for `feat`/`fix`.
- Release = bump `version`/`appVersion` in `Chart.yaml` (+ `values-prod.example.yaml`, README) and push to main; CI
  then builds the `X.Y.Z` image, publishes the chart and creates the `vX.Y.Z` tag. Never push release tags by hand.

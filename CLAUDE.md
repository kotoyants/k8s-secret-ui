# CLAUDE.md

Repo: `github.com/kotoyants/k8s-secret-ui` (Go module path).
Web app for managing Kubernetes secrets with Google login and tag-based roles.
- Requirements: `SPEC.md` (source of truth: update it when requirements change)
- Roadmap and progress: `PLAN.md` (tick off checkboxes as work completes)

## Stack
Go · chi · html/template + htmx (no JS build) · PostgreSQL (pgx + sqlc + goose) · go-oidc · client-go · Helm

## Commands
- `make run` — run locally (needs `docker compose up -d` for Postgres)
- `make test` — all tests (`go test ./...`)
- `make lint` — golangci-lint
- `make sqlc` — regenerate DB code after editing `internal/store/queries/*.sql`
- `make build` / `make docker`

## Rules
- **Never** store, log, cache or put secret values in audit events. Values live only in the provider.
- The app is **stateless**: no in-memory sessions, caches or local files. All state is in Postgres or signed cookies.
- Every secret access goes through `internal/authz`. Do not duplicate the tag logic elsewhere.
  Rule: secret.tags ⊆ union of the user's role tags (writes use only `read_write` roles). Admin bypasses it.
- Provider-specific code stays in `internal/provider/<name>/`. The core uses only the `Provider` interface.
- DB schema changes = a new goose migration in `migrations/`; never edit an applied migration.
- Do not edit sqlc-generated files by hand.
- Config comes only from env vars, via `internal/config`.
- Responses containing secret values: `Cache-Control: no-store`.
- Audit events go through `internal/audit` (slog JSON to stdout).

## Conventions
- Errors: wrap with `fmt.Errorf("...: %w", err)`; handlers map them to user-friendly messages.
- Tests: table-driven; authz must have full coverage; k8s via the fake clientset; DB tests on real Postgres.
- Keep handlers thin: parse the request → call the service/store → render.

## Workflow
- Ask clarifying questions when requirements are unclear; do not guess silently.
- Do not commit without explicit approval.

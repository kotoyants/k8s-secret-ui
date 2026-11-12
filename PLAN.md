# Secret Manager — Implementation Plan

See `SPEC.md` for requirements. Each phase ends in a working, tested state.

## Project layout

```
cmd/secret-manager/main.go        # wiring, config, server start
internal/config/                  # env parsing + validation
internal/auth/                    # Google OIDC, JWT session cookie, middleware, CSRF
internal/authz/                   # tag-matching rules (pure functions)
internal/store/                   # DB access (sqlc-generated + thin wrappers)
internal/store/queries/*.sql      # sqlc input
internal/provider/                # Provider interface, registry
internal/provider/k8s/            # Kubernetes implementation
internal/audit/                   # slog-based audit logger
internal/web/                     # handlers, routing, view models
internal/web/templates/           # html/template files (embedded)
internal/web/static/              # htmx, css (embedded)
migrations/                       # goose SQL migrations (embedded)
deploy/helm/secret-manager/       # Helm chart
docker-compose.yml                # local Postgres
Makefile
```

## Phase 0 — Scaffolding
- [x] `go mod init`, Makefile (`run`, `test`, `lint`, `build`, `docker`, `db-up`); `sqlc`/`migrate` targets come in Phase 1
- [x] `golangci-lint` config, `.editorconfig`, `.gitignore`
- [x] `docker-compose.yml` with Postgres for local dev
- [x] `internal/config`: load and validate env (fail fast)
- [x] Minimal server: chi router, `/healthz`, `/readyz`, graceful shutdown, slog JSON
- [x] Multi-stage Dockerfile (distroless, non-root)

## Phase 1 — Database
- [ ] `/readyz` DB ping check
- [ ] Migration `001_init.sql`:
  - `users(id, email UNIQUE, name, avatar_url, disabled, created_at, last_login_at)`
  - `roles(id, name UNIQUE, permission ENUM('read','read_write'), builtin BOOL)`
  - `role_tags(role_id, tag)`, `user_roles(user_id, role_id)`
  - `secrets(id, provider, locator JSONB, created_at, created_by)` with `UNIQUE(provider, locator)`
  - `secret_tags(secret_id, tag)`
  - seed the built-in `admin` and `default` roles
- [ ] sqlc queries + generated code; run migrations at startup
- [ ] Store tests against real Postgres

## Phase 2 — Authentication
- [ ] Google OIDC login / callback; `state` + `nonce` in a signed short-lived cookie
- [ ] Check `email_verified` and `ALLOWED_DOMAINS` (`hd` claim)
- [ ] Upsert the user on login; assign `default` on first login; `admin` for `ADMIN_EMAILS`
- [ ] JWT session cookie; middleware loads the user + roles from the DB on each request; reject disabled users
- [ ] Logout; CSRF middleware; security headers
- [ ] Audit: `login`, `login_denied`, `logout`

## Phase 3 — Authorization core
- [ ] `authz.CanRead(user, secret)`, `authz.CanWrite(user, secret)` per SPEC §4.1
- [ ] Table-driven tests covering: union of roles, mixed read/read_write, untagged secrets, admin, disabled
- [ ] Filter secret lists through authz (an SQL pre-filter is optional; the Go check is authoritative)

## Phase 4 — Provider layer
- [ ] `Provider` interface + registry
- [ ] K8s provider: in-cluster config (kubeconfig fallback for local dev), `ALLOWED_NAMESPACES`,
      list `Opaque` secrets, get, update with `resourceVersion`
- [ ] Tests with the `client-go` fake clientset (namespace allowlist, type filter, conflict)

## Phase 5 — Admin UI
- [ ] Layout, navigation, flash messages (htmx)
- [ ] Users: list, assign or remove roles, disable or enable
- [ ] Roles: CRUD, tags (autocomplete), permission, members
- [ ] Import: browse namespaces → secrets, tag and import; mark already-imported secrets
- [ ] Secrets: edit tags, un-import, "missing" status
- [ ] Audit events for all admin actions

## Phase 6 — User UI
- [ ] Secret list (filtered by authz), filter by tag or namespace, search
- [ ] Secret view: keys with masked values, reveal and copy per key (`no-store`), audit `secret.reveal`
- [ ] Edit (read_write): edit, add or remove keys; handle conflicts; audit `secret.update`

## Phase 7 — Deployment
- [ ] Helm chart: Deployment (2+ replicas), Service, Ingress, ServiceAccount,
      per-namespace Role/RoleBinding from `allowedNamespaces`, env from a k8s Secret
- [ ] Probes, resource limits, `readOnlyRootFilesystem`, `runAsNonRoot`
- [ ] Local end-to-end run with `kind` + docker-compose Postgres
- [ ] README: Google OAuth client setup, deploying to DOKS

## Phase 8 — Hardening & polish
- [ ] Rate limiting on login and reveal
- [ ] CSP review, dependency scan (`govulncheck`)
- [ ] GitHub Actions: lint, test, build and push image (GHCR)

## Later (not v1)
- More providers (AWS Secrets Manager, GCP, Vault), multiple clusters
- Audit log in the DB with a UI
- Creating secrets in the provider

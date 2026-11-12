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
- [x] `/readyz` DB ping check
- [x] Migration `001_init.sql`:
  - `users(id, email UNIQUE, name, avatar_url, disabled, created_at, last_login_at)`
  - `roles(id, name UNIQUE, permission ENUM('read','read_write'), builtin BOOL)`
  - `role_tags(role_id, tag)`, `user_roles(user_id, role_id)`
  - `secrets(id, provider, locator JSONB, created_at, created_by)` with `UNIQUE(provider, locator)`
  - `secret_tags(secret_id, tag)`
  - seed the built-in `admin` and `default` roles
- [x] sqlc queries + generated code (`make sqlc` via Docker); migrations run at startup (advisory lock) and via `secret-manager migrate`
- [x] Store tests against real Postgres (testcontainers; `-short` skips them)
- [x] `internal/tags`: tag validation/normalization shared by store and UI

## Phase 2 — Authentication
- [x] Google OIDC login / callback with PKCE (S256); `state` + `nonce` + verifier in a signed short-lived cookie
- [x] Check `email_verified` and `ALLOWED_DOMAINS` (`hd` claim + email domain); `hd` hint sent when one domain
- [x] Upsert the user on login; assign `default` on first login; `admin` for `ADMIN_EMAILS`
- [x] JWT session cookie (HS256, key derived per purpose); middleware loads the user + roles from the DB on each request; disabled/deleted users lose access immediately
- [x] Logout; CSRF via `http.CrossOriginProtection`; security headers (CSP, HSTS on https, nosniff, frame deny)
- [x] Audit: `login`, `login_denied`, `logout` (`internal/audit`)
- [x] Minimal login + home pages (proper layout/CSS in Phase 5)
- [x] Tests: full browser flow against a fake OIDC provider (`internal/auth/authtest`)

## Phase 3 — Authorization core
- [x] `authz.Subject` (built from `auth.Principal`) with `CanRead` / `CanWrite` / `Can` per SPEC §4.1
- [x] `authz.Filter` for lists (Go check is authoritative; no SQL pre-filter for now)
- [x] Table-driven tests: union of roles, mixed read/read_write, untagged secrets, admin, disabled, unknown permission
- [x] Property test vs. an independent reference implementation (5000 random cases); 100% coverage; mutation-checked

## Phase 4 — Provider layer
- [x] `provider.Provider` interface (`List`/`Get`/`Update`), `SecretRef`, sentinel errors, `Registry`
- [x] K8s provider: in-cluster config; outside a cluster requires explicit `KUBE_CONTEXT` (never the current context);
      `ALLOWED_NAMESPACES` enforced on every call; `Opaque` only; update with `resourceVersion` optimistic locking;
      key validation; metadata preserved; only the core/v1 client is used
- [x] Detect externally managed secrets (owner refs, Helm, Argo CD, Flux) → `External.ManagedBy`
- [x] Tests with the `client-go` fake clientset (allow-list, type filter, conflict, RBAC forbidden, validation)

## Phase 5 — Admin UI
- [x] Layout + navigation (Pico.css 2.1.1, htmx 2.0.11 vendored in `internal/web/static`; `hx-boost`, `hx-confirm`)
- [x] Flash messages via short-lived cookie (POST → redirect → GET)
- [x] Users: list, assign or remove roles, disable or enable (cannot disable yourself / drop your own admin role)
- [x] Roles: create, edit (name, permission, tags), delete, members; built-in roles read-only
- [x] Import: browse namespaces → secrets, tag and import; mark already-imported and external (managed-by) secrets;
      import validated through the provider (allowed namespace, type, exists)
- [x] Secrets: edit tags inline, un-import, "missing" status, external badge
- [x] Import page merged with Imported: two lists (Imported with tag editing / un-import, Available to import);
      `GET /admin/secrets` removed
- [x] Audit events for all admin actions
- [x] Tests: full admin flows on real Postgres + fake k8s (`internal/store/storetest`), access control, CSRF, no value leaks

## Phase 6 — User UI
- [x] Secret list (filtered by authz) as the home page; filter by tag, namespace, search; shows read vs read & write
- [x] Secret view: keys with masked values; reveal one key at a time (POST, htmx fragment or full page), copy button
      (`static/app.js`), `no-store`, audit `secret.reveal` (key name only); binary values shown as base64
- [x] Unreadable secrets return 404 (existence not revealed); read-only users get 403 on edit
- [x] Edit (read_write) without revealing values: blank = keep, delete checkboxes, add new keys; CRLF normalized;
      optimistic locking (handler + provider); audit `secret.update` with key names (changed/added/removed)
- [x] External secrets editable with a warning (edit page + after save)
- [x] Tests: visibility matrix, reveal (page + fragment), edit flows, conflict, external, missing, binary; mutation-checked
- [x] UI polish: "Reveal all" (view + edit), per-key reveal on the edit page prefills the textarea (htmx OOB swaps,
      binary skipped, audited with key names); equal-height filter controls; fixed 75% base font (Pico upscales to 131%);
      per-key reveal is a checkbox (untick hides again / clears an unedited field), Reveal all stays a button

## Phase 7 — Deployment
- [x] Helm chart `deploy/helm/k8s-secret-ui`: Deployment (2 replicas), Service, ServiceAccount, PDB,
      per-namespace Role/RoleBinding from `config.allowedNamespaces`, env from `existingSecret`; optional Ingress (off)
- [x] Probes, resource limits, `readOnlyRootFilesystem`, `runAsNonRoot`, dropped capabilities, seccomp
- [x] Required-value validation; `values-prod.example.yaml` (namespace `admin`, host secrets.prod.nexora.promo)
- [x] `make helm-lint` (helm lint + kubeconform)
- [x] README: Google OAuth client setup, Terraform prerequisites, deploying
- [x] GitHub Actions (moved up from Phase 8): test, lint, sqlc-check, helm checks, build & push image to GHCR;
      on `v*` tags also publish the chart to `oci://ghcr.io/kotoyants/charts`
- [x] Faster CI: tag runs skip checks (already run on main) and only build image + chart; binary built with a
      cached Go build and copied into the image (`Dockerfile` target `prebuilt`); newer pushes cancel older runs;
      on main the image is built only for `feat`/`fix` commits (Conventional Commits), tags always build
- [ ] First deploy to DOKS (namespaces, DB, Secret, Ingress via Terraform; then `helm upgrade --install`)

## Phase 8 — Hardening & polish
- [ ] Rate limiting on login and reveal
- [ ] Real client IP for audit behind the ingress (trusted proxy / `X-Forwarded-For` config)
- [ ] CSP review, dependency scan (`govulncheck`)

## Later (not v1)
- More providers (AWS Secrets Manager, GCP, Vault), multiple clusters
- Audit log in the DB with a UI
- Creating secrets in the provider

# Secret Manager — Specification (v1.0)

## 1. Purpose

A web application for managing secrets stored in external secret storages.
Secrets are **imported** from a provider (v1: **Kubernetes Secrets** in the DOKS cluster the app runs in),
labeled with **tags**, and access is granted to users through **roles**, based on tags.

The provider layer is pluggable, so other storages (AWS Secrets Manager / SSM, GCP Secret Manager,
Vault, ...) can be added later without changing the core.

## 2. Users and authentication

- Login via **Google OAuth 2.0 / OpenID Connect** only.
- Login can be limited to one or more **Google Workspace domains**:
  `ALLOWED_DOMAINS=a.com,b.com` (empty = any Google account). The verified `hd` claim must match
  one of the domains, and `email_verified` must be true.
- On first successful login, the user is **auto-created** and assigned the built-in **default** role.
- Bootstrap admins: users whose email is in `ADMIN_EMAILS` are given the **admin** role at login.
- An admin can disable a user, which blocks their login and immediately revokes their access.

## 3. Stateless architecture

- The app server keeps **no local state**: no server-side sessions and no local files.
  Any number of replicas can run behind a load balancer.
- Session = signed (HS256), short-lived JWT in an `HttpOnly`, `Secure`, `SameSite=Lax` cookie.
  The JWT carries only the user ID; the user's status and roles are loaded from the DB on every request.
- The OAuth `state` and `nonce` are kept in a short-lived signed cookie (not on the server).
- Persistent data (users, roles, tags, secret references) lives in **PostgreSQL**
  (DigitalOcean Managed PostgreSQL).
- **Secret values are never stored** in the DB, logs or cache. They are read from or written to
  the provider on demand.

## 4. Core concepts

| Entity | Description |
|---|---|
| **User** | Google identity (email, name, avatar), status (active/disabled), roles |
| **Role** | Name, set of **tags**, permission `read` or `read_write`, members |
| **Tag** | Free-text label (lowercase, `[a-z0-9-_]`), e.g. `front`, `prod` |
| **Provider** | Connection to a secret storage. v1: in-cluster Kubernetes |
| **Secret** | Reference to a whole secret in a provider (k8s: `namespace/name`) + tags. The value stays in the provider |

### 4.1 Access rule (tag matching)

The user must have **all** tags the secret has. A user's tags are the **union of the tags of all
their roles**.

```
user_tags(user, perms)  = ⋃ role.tags  for role ∈ user.roles where role.permission ∈ perms

can_read(user, secret)  = user.is_admin OR
                          secret.tags ⊆ user_tags(user, {read, read_write})

can_write(user, secret) = user.is_admin OR
                          secret.tags ⊆ user_tags(user, {read_write})
```

- Example: role A=`{front}` (read) and role B=`{prod}` (read) → the user **can read** a secret
  tagged `{front, prod}`.
- Example: role A=`{front}` (read_write) and role B=`{prod}` (read) → the user can **read** a secret
  tagged `{front, prod}` but **not write** it, because `prod` comes only from a read role.
- A secret with **no tags** is visible to admins only.
- Disabled users have no access.

### 4.2 Permissions

| Permission | Allows |
|---|---|
| `read` | see the secret in the list; reveal and copy the values of its keys |
| `read_write` | `read` + change the values of existing keys, add keys, remove keys |

Admin only: import or un-import secrets, edit secret tags, manage roles and users.

### 4.3 Built-in roles

- `admin` — full access, bypasses the tag check. Cannot be deleted.
- `default` — assigned on first login; no tags, so no secret access. Cannot be deleted.
  An admin moves users from `default` into real roles.

## 5. Features (v1)

### Admin
1. **Import** (one page, two lists):
   - **Imported:** edit tags, un-import (removes it from the app only; the k8s Secret is **not** deleted).
     Show a "missing" status if the k8s Secret no longer exists.
   - **Available:** not-yet-imported k8s Secrets (types `Opaque` only) in the allowed namespaces; assign tags, import.
3. **Roles:** create, rename, delete; set tags and permission; add or remove members.
4. **Users:** list (email, name, roles, last login, status); assign or remove roles; disable or enable.
5. **Tags:** created on the fly when typed on a role or secret; the list of existing tags is offered as autocomplete.

### User
1. Log in with Google.
2. List the secrets they can read (filter by tag or namespace, search by name).
3. Open a secret: the key names are shown and values are **masked**; reveal a value per key or all at once
   (the "Reveal" button; once everything is revealed it becomes "Hide" and masks all again), and copy it by double-clicking. Values (masked or revealed) are shown in equal-width
   read-only fields, matching the edit form; masked and unchanged fields show "••••••••".
4. With `read_write`: edit, add or remove keys and save, which updates the k8s Secret.
   The edit form hides current values by default: a blank value keeps the existing one. Each row is
   key | value | Reveal | delete, with the same "Reveal" toggle button above; Reveal loads the current value into the field (audited).
   Binary values cannot be revealed for editing, only replaced.
   Secrets the user cannot read return 404, so their existence is not revealed.
   Uses `resourceVersion` for optimistic locking (conflict → error with a reload prompt).

## 6. Provider abstraction

```go
type Provider interface {
    ID() string                                                // e.g. "k8s-local"
    List(ctx context.Context) ([]SecretRef, error)             // importable secrets
    Get(ctx context.Context, ref SecretRef) (*SecretData, error)
    Update(ctx context.Context, ref SecretRef, data *SecretData) error
}

type SecretRef  struct { Provider string; Locator map[string]string } // k8s: {namespace, name}
type SecretData struct { Values map[string][]byte; Version string }   // Version = resourceVersion
```

`SecretRef.Locator` is stored as JSONB.

### 6.1 Kubernetes provider (v1)

- Uses the in-cluster config (the app's ServiceAccount). Only the cluster the app is deployed in.
- Namespaces are limited by `ALLOWED_NAMESPACES=ns1,ns2` (required, no wildcard).
- RBAC: a `Role` + `RoleBinding` **per allowed namespace** with `get, list, update` on `secrets`.
  No ClusterRole.
- Only `Opaque` secrets are listed (no service-account tokens, TLS or docker-config secrets).
- **External secrets:** secrets managed by another tool are shown and marked as *external* with the
  manager's name (owner reference kind such as `ExternalSecret`/`SealedSecret`, or Helm, Argo CD, Flux).
  Changes made here may be overwritten by that tool, and the UI warns about it.
- Outside a cluster (local development) the kubeconfig context must be named explicitly with `KUBE_CONTEXT`;
  the current kubectl context is never used implicitly.

## 7. Audit log

- Written to **stdout** as structured JSON lines (`log/slog`), marked with `"audit": true`.
- Fields: `ts`, `actor_email`, `actor_id`, `action`, `target_type`, `target_id`, `details`, `result`, `ip`.
- Events: `login`, `login_denied`, `logout`, `secret.import`, `secret.unimport`, `secret.tags_update`,
  `secret.reveal`, `secret.update` (key names only), `role.*`, `user.role_assign`,
  `user.role_remove`, `user.disable`, `user.enable`.
- **Never** includes secret values.

## 8. Tech stack

| Layer | Choice |
|---|---|
| Language | Go (latest stable) |
| HTTP | stdlib `net/http` + `go-chi/chi` |
| UI | Server-rendered `html/template` + **htmx**, minimal CSS (e.g. Pico.css); no JS build step |
| DB | PostgreSQL, `jackc/pgx` + `sqlc`; migrations with `pressly/goose`, embedded and run at startup |
| Auth | `coreos/go-oidc` + `golang.org/x/oauth2`; `golang-jwt/jwt` |
| K8s | `k8s.io/client-go` |
| Deploy | Distroless Docker image; Helm chart for DOKS |

## 9. Configuration (env)

| Var | Description |
|---|---|
| `DATABASE_URL` | Postgres DSN |
| `GOOGLE_CLIENT_ID`, `GOOGLE_CLIENT_SECRET` | OAuth client |
| `BASE_URL` | Public URL; used to build the OAuth redirect URL |
| `SESSION_SECRET` | ≥32 bytes; key for signing the JWT and cookies |
| `SESSION_TTL` | default `8h` |
| `ALLOWED_DOMAINS` | comma-separated; empty = any Google account |
| `ADMIN_EMAILS` | comma-separated bootstrap admins |
| `ALLOWED_NAMESPACES` | comma-separated k8s namespaces |
| `KUBE_CONTEXT` | kubeconfig context; only used outside a cluster (local dev) |
| `LOG_LEVEL` | default `info` |
| `LISTEN_ADDR` | default `:8080` |

## 10. Non-functional

- HTTPS terminated at the ingress; `Secure` cookies; HSTS.
- CSRF protection on all state-changing requests; strict CSP; security headers.
- Responses that contain secret values are sent with `Cache-Control: no-store`.
- Health endpoints: `/healthz` (liveness), `/readyz` (DB ping).
- Graceful shutdown.
- Unit tests for the authorization rules (table-driven); provider tests with the `client-go` fake clientset;
  DB tests against a real Postgres (testcontainers or docker-compose).

## 11. Out of scope (v1)

- Creating or deleting k8s Secrets (only import and edit existing ones).
- Multiple clusters or other providers (only the interface is ready).
- Secret rotation or version history.
- Public API or CLI.
- Audit log stored in the DB or searchable in the UI.

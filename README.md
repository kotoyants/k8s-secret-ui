# k8s-secret-ui

A web app for managing Kubernetes secrets, with Google sign-in and tag-based access control.

- Admins **import** existing `Opaque` secrets from allowed namespaces and put **tags** on them.
- **Roles** have tags and a permission (`read` or `read_write`). A user can access a secret only if their
  roles together have **all** of the secret's tags.
- Users reveal values per key or all at once (every reveal is audited) and, with `read_write`, edit them.
- Secrets managed by other tools (External Secrets, Sealed Secrets, Helm, Argo CD, Flux) are marked *external*.
- Stateless: any number of replicas. Data (users, roles, tags) lives in PostgreSQL; secret values never leave Kubernetes.

See [SPEC.md](SPEC.md) for the full specification and [PLAN.md](PLAN.md) for progress.

## Local development

Requirements: Go and Docker. Other tools (sqlc, golangci-lint, kubeconform) run in Docker.

```sh
cp .env.example .env          # fill in Google OAuth client, SESSION_SECRET, ADMIN_EMAILS
make db-up                    # Postgres in Docker
make run KUBE_CONTEXT=<kubeconfig context> ALLOWED_NAMESPACES=<namespace>
```

Open http://localhost:8080. Outside a cluster `KUBE_CONTEXT` is required on purpose: the app never uses the
current kubectl context implicitly.

| Command | Description |
|---|---|
| `make test` | All tests (DB tests start Postgres via testcontainers; `go test -short ./...` skips them) |
| `make lint` | golangci-lint |
| `make sqlc` / `make sqlc-check` | Regenerate / verify DB code from `internal/store/queries` |
| `make helm-lint` | Lint and schema-validate the Helm chart |
| `make docker` | Build the image |

## Google OAuth client

In Google Cloud Console → APIs & Services → Credentials, create an **OAuth client ID** of type *Web application*
with these authorized redirect URIs:

- `https://<your host>/auth/callback`
- `http://localhost:8080/auth/callback` (local development)

To limit sign-in to your Google Workspace, set `ALLOWED_DOMAINS` (Helm: `config.allowedDomains`).

## Deployment

Images are built by GitHub Actions and pushed to `ghcr.io/kotoyants/k8s-secret-ui`:
`latest` and `sha-<commit>` for `feat:`/`fix:` commits on `main`.

**Releasing:** bump `version` and `appVersion` in `deploy/helm/k8s-secret-ui/Chart.yaml` (plus the examples in
`values-prod.example.yaml` and this README) and push to `main`. When that version has no `vX.Y.Z` tag yet, the run
also tags the image `X.Y.Z`, publishes the Helm chart to `oci://ghcr.io/kotoyants/charts/k8s-secret-ui` and creates
the `vX.Y.Z` git tag. Don't push release tags by hand.

> The first push creates each GHCR package (image and chart) as **private**. Make them public once in
> GitHub → Packages → Package settings → Change visibility.

### Created outside the chart (e.g. Terraform)

1. **Namespaces:** the app's namespace (e.g. `admin`) and every namespace listed in `config.allowedNamespaces`.
2. **PostgreSQL** database (e.g. DigitalOcean Managed PostgreSQL). Migrations run automatically at startup.
3. **Secret** in the app's namespace (name = `existingSecret`) with keys:

   | Key | Value |
   |---|---|
   | `DATABASE_URL` | `postgres://user:pass@host:25060/db?sslmode=require` |
   | `GOOGLE_CLIENT_ID` | OAuth client ID |
   | `GOOGLE_CLIENT_SECRET` | OAuth client secret |
   | `SESSION_SECRET` | random, at least 32 bytes (e.g. `openssl rand -base64 48`) |

4. **Ingress** with TLS for your host, routing `/` to Service `k8s-secret-ui`, port `80`
   (port name `http`), when `fullnameOverride: k8s-secret-ui` is set.

### Install

The chart is published as an OCI artifact for every release `X.Y.Z`:

```sh
helm upgrade --install k8s-secret-ui oci://ghcr.io/kotoyants/charts/k8s-secret-ui \
  --version 0.3.6 --namespace admin -f values-prod.yaml
```

Terraform (`helm_release`):

```hcl
resource "helm_release" "k8s_secret_ui" {
  name       = "k8s-secret-ui"
  namespace  = "admin"
  repository = "oci://ghcr.io/kotoyants/charts"
  chart      = "k8s-secret-ui"
  version    = "0.3.6"
  values     = [file("values-prod.yaml")]
}
```

From a checkout: `helm upgrade --install k8s-secret-ui deploy/helm/k8s-secret-ui -n admin -f values-prod.yaml`.

The chart creates the Deployment (non-root, read-only filesystem), the Service, a ServiceAccount, a
PodDisruptionBudget, and in **each allowed namespace** a Role + RoleBinding with `get/list/update` on secrets.
It creates no cluster-wide permissions. The Ingress is optional (`ingress.enabled`, off by default).

Changing the app Secret does not restart pods automatically; run
`kubectl -n admin rollout restart deployment/k8s-secret-ui` afterwards.

### Audit log

Security events (logins, reveals, updates, imports, role and user changes) are written to stdout as JSON lines
with `"audit": true`. Values are never logged. Collect them with your log pipeline.

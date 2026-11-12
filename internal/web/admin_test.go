package web

import (
	"bytes"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/fake"

	"github.com/kotoyants/k8s-secret-ui/internal/audit"
	"github.com/kotoyants/k8s-secret-ui/internal/auth"
	"github.com/kotoyants/k8s-secret-ui/internal/auth/authtest"
	"github.com/kotoyants/k8s-secret-ui/internal/provider"
	"github.com/kotoyants/k8s-secret-ui/internal/provider/k8s"
	"github.com/kotoyants/k8s-secret-ui/internal/store"
	"github.com/kotoyants/k8s-secret-ui/internal/store/storetest"
)

// fullApp is the router wired to a real Postgres store and a fake Kubernetes cluster.
type fullApp struct {
	*testApp
	store *store.Store
	kube  *fake.Clientset
	audit *bytes.Buffer
}

func newFullApp(t *testing.T) *fullApp {
	t.Helper()
	st := storetest.New(t)
	idp := authtest.NewFakeIDP(t, "client-id")
	var handler http.Handler
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { handler.ServeHTTP(w, r) }))
	t.Cleanup(srv.Close)
	base, _ := url.Parse(srv.URL)

	yes := true
	kube := fake.NewClientset(
		&corev1.Secret{ObjectMeta: metav1.ObjectMeta{Namespace: "front", Name: "api", ResourceVersion: "1"},
			Type: corev1.SecretTypeOpaque, Data: map[string][]byte{"TOKEN": []byte("t0p-s3cret")}},
		&corev1.Secret{ObjectMeta: metav1.ObjectMeta{Namespace: "front", Name: "synced", ResourceVersion: "1",
			OwnerReferences: []metav1.OwnerReference{{Kind: "ExternalSecret", Name: "synced", Controller: &yes}}},
			Type: corev1.SecretTypeOpaque, Data: map[string][]byte{"A": []byte("1")}},
		&corev1.Secret{ObjectMeta: metav1.ObjectMeta{Namespace: "kube-system", Name: "hidden", ResourceVersion: "1"},
			Type: corev1.SecretTypeOpaque},
	)
	reg, err := provider.NewRegistry(k8s.New(kube.CoreV1(), []string{"front"}))
	if err != nil {
		t.Fatal(err)
	}

	auditBuf := &bytes.Buffer{}
	log := slog.New(slog.DiscardHandler)
	auditLog := audit.New(slog.New(slog.NewJSONHandler(auditBuf, nil)))
	svc, err := auth.New(t.Context(), auth.Config{
		Issuer: idp.Issuer(), ClientID: "client-id", ClientSecret: "s", BaseURL: base,
		SessionSecret: []byte(strings.Repeat("k", 32)), SessionTTL: time.Hour,
		AdminEmails: []string{"admin@corp.com"},
	}, st, auditLog, log)
	if err != nil {
		t.Fatal(err)
	}
	handler = NewRouter(Deps{Logger: log, Auth: svc, Store: st, Providers: reg, Audit: auditLog})
	return &fullApp{testApp: &testApp{srv: srv, idp: idp}, store: st, kube: kube, audit: auditBuf}
}

func (a *fullApp) loginAs(t *testing.T, email string) *http.Client {
	t.Helper()
	c := newClient()
	a.idp.SetIdentity(authtest.Identity{Email: email, EmailVerified: true})
	if resp, _ := a.do(t, c, http.MethodGet, "/auth/login", nil); resp.URL.Path != "/" {
		t.Fatalf("login as %s ended at %s", email, resp.URL)
	}
	return c
}

func (a *fullApp) post(t *testing.T, c *http.Client, path string, form url.Values) (result, string) {
	t.Helper()
	req, _ := http.NewRequestWithContext(t.Context(), http.MethodPost, a.srv.URL+path, strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := c.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	b, _ := io.ReadAll(resp.Body)
	return result{StatusCode: resp.StatusCode, Header: resp.Header, URL: resp.Request.URL}, string(b)
}

func (a *fullApp) userID(t *testing.T, email string) string {
	t.Helper()
	u, err := a.store.GetUserByEmail(t.Context(), email)
	if err != nil {
		t.Fatal(err)
	}
	return idStr(u.ID)
}

func (a *fullApp) roleID(t *testing.T, name string) string {
	t.Helper()
	roles, err := a.store.ListRoles(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range roles {
		if r.Name == name {
			return idStr(r.ID)
		}
	}
	t.Fatalf("role %q not found", name)
	return ""
}

func mustContain(t *testing.T, body string, want ...string) {
	t.Helper()
	for _, w := range want {
		if !strings.Contains(body, w) {
			t.Errorf("body missing %q", w)
		}
	}
	if t.Failed() {
		t.Logf("body:\n%s", body)
	}
}

func TestAdminRequiresAdmin(t *testing.T) {
	a := newFullApp(t)
	bob := a.loginAs(t, "bob@corp.com")
	for _, p := range []string{"/admin/users", "/admin/roles", "/admin/import"} {
		if resp, _ := a.do(t, bob, http.MethodGet, p, nil); resp.StatusCode != http.StatusForbidden {
			t.Errorf("GET %s as user = %d, want 403", p, resp.StatusCode)
		}
	}
	if resp, _ := a.post(t, bob, "/admin/roles", url.Values{"name": {"x"}, "permission": {"read"}}); resp.StatusCode != http.StatusForbidden {
		t.Errorf("POST as user = %d, want 403", resp.StatusCode)
	}
	if resp, _ := a.do(t, newClient(), http.MethodGet, "/admin/users", nil); resp.URL.Path != "/login" {
		t.Errorf("anonymous → %s, want /login", resp.URL)
	}
}

func TestAdminRolesAndUsers(t *testing.T) {
	a := newFullApp(t)
	admin := a.loginAs(t, "admin@corp.com")
	bobC := a.loginAs(t, "bob@corp.com")
	bob := a.userID(t, "bob@corp.com")

	_, body := a.do(t, admin, http.MethodGet, "/admin/users", nil)
	mustContain(t, body, "admin@corp.com", "bob@corp.com", `<span class="tag">default</span>`)

	// Create a role.
	resp, body := a.post(t, admin, "/admin/roles", url.Values{"name": {"front-rw"}, "permission": {"read_write"}, "tags": {"Front, prod"}})
	if !strings.HasPrefix(resp.URL.Path, "/admin/roles/") {
		t.Fatalf("after create: %s", resp.URL)
	}
	mustContain(t, body, "Role created.", `value="front, prod"`, `<option value="read_write" selected>`)
	roleID := a.roleID(t, "front-rw")

	// Validation errors come back as flash messages.
	_, body = a.post(t, admin, "/admin/roles", url.Values{"name": {"bad"}, "permission": {"read"}, "tags": {"no!"}})
	mustContain(t, body, "flash-error", "invalid tag")
	_, body = a.post(t, admin, "/admin/roles", url.Values{"name": {"front-rw"}, "permission": {"read"}})
	mustContain(t, body, "already exists")
	_, body = a.post(t, admin, "/admin/roles", url.Values{"name": {"x"}, "permission": {"owner"}})
	mustContain(t, body, "valid permission")

	// Add bob to the role; bob sees it.
	_, body = a.post(t, admin, "/admin/roles/"+roleID+"/members", url.Values{"user_id": {bob}})
	mustContain(t, body, "Member added.", "bob@corp.com")
	_, body = a.do(t, bobC, http.MethodGet, "/", nil)
	mustContain(t, body, `title="read_write: front, prod">front-rw</span>`)

	// Update role.
	_, body = a.post(t, admin, "/admin/roles/"+roleID, url.Values{"name": {"front"}, "permission": {"read"}, "tags": {"front"}})
	mustContain(t, body, "Role saved.", `value="front"`)

	// Built-in roles cannot be changed or deleted.
	adminRole := a.roleID(t, store.RoleAdmin)
	_, body = a.post(t, admin, "/admin/roles/"+adminRole, url.Values{"name": {"root"}, "permission": {"read"}})
	mustContain(t, body, "Built-in roles cannot be changed.")
	_, body = a.post(t, admin, "/admin/roles/"+adminRole+"/delete", nil)
	mustContain(t, body, "Built-in roles cannot be changed.")

	// Remove bob's role from the user page, then delete the role.
	_, body = a.post(t, admin, "/admin/users/"+bob+"/roles/"+roleID+"/remove", nil)
	mustContain(t, body, "Role removed.")
	resp, body = a.post(t, admin, "/admin/roles/"+roleID+"/delete", nil)
	if resp.URL.Path != "/admin/roles" {
		t.Fatalf("after delete: %s", resp.URL)
	}
	mustContain(t, body, "Role deleted.")

	// Assign a role from the user page.
	_, body = a.post(t, admin, "/admin/users/"+bob+"/roles", url.Values{"role_id": {adminRole}})
	mustContain(t, body, "Role assigned.")

	// Unknown IDs.
	if resp, _ := a.do(t, admin, http.MethodGet, "/admin/users/999999", nil); resp.StatusCode != http.StatusNotFound {
		t.Errorf("unknown user = %d", resp.StatusCode)
	}
	if resp, _ := a.do(t, admin, http.MethodGet, "/admin/roles/abc", nil); resp.StatusCode != http.StatusNotFound {
		t.Errorf("bad role id = %d", resp.StatusCode)
	}

	for _, action := range []string{"role.create", "role.update", "role.delete", "user.role_assign", "user.role_remove"} {
		if !strings.Contains(a.audit.String(), `"action":"`+action+`"`) {
			t.Errorf("missing audit event %s", action)
		}
	}
}

func TestAdminSelfProtectionAndDisable(t *testing.T) {
	a := newFullApp(t)
	admin := a.loginAs(t, "admin@corp.com")
	bobC := a.loginAs(t, "bob@corp.com")
	me, bob := a.userID(t, "admin@corp.com"), a.userID(t, "bob@corp.com")
	adminRole := a.roleID(t, store.RoleAdmin)

	_, body := a.post(t, admin, "/admin/users/"+me+"/disable", nil)
	mustContain(t, body, "You cannot disable yourself.")
	_, body = a.post(t, admin, "/admin/users/"+me+"/roles/"+adminRole+"/remove", nil)
	mustContain(t, body, "You cannot remove your own admin role.")
	_, body = a.post(t, admin, "/admin/roles/"+adminRole+"/members/"+me+"/remove", nil)
	mustContain(t, body, "You cannot remove your own admin role.")

	// Disabling bob revokes his session immediately.
	_, body = a.post(t, admin, "/admin/users/"+bob+"/disable", nil)
	mustContain(t, body, "User disabled.")
	if resp, _ := a.do(t, bobC, http.MethodGet, "/", nil); resp.URL.Path != "/login" {
		t.Fatalf("disabled bob still logged in: %s", resp.URL)
	}
	_, body = a.post(t, admin, "/admin/users/"+bob+"/enable", nil)
	mustContain(t, body, "User enabled.")
}

func TestAdminImportAndSecrets(t *testing.T) {
	a := newFullApp(t)
	admin := a.loginAs(t, "admin@corp.com")

	_, body := a.do(t, admin, http.MethodGet, "/admin/import", nil)
	mustContain(t, body, "<h2>Imported</h2>", "Nothing imported yet.", "<h2>Available</h2>", "<td>front</td>", "api", "synced", "external: ExternalSecret")
	if strings.Contains(body, "kube-system") {
		t.Error("secret from a non-allowed namespace is listed")
	}
	if strings.Contains(body, "t0p-s3cret") {
		t.Fatal("secret value leaked into import page")
	}

	loc := `{"name":"api","namespace":"front"}`
	mustContain(t, body, `value="{&#34;name&#34;:&#34;api&#34;`) // listed as available
	_, body = a.post(t, admin, "/admin/import", url.Values{"provider": {"k8s"}, "locator": {loc}, "tags": {"front prod"}})
	mustContain(t, body, "Secret imported.")
	_, body = a.do(t, admin, http.MethodGet, "/admin/import", nil)
	// Moved from Available to Imported, with editable tags.
	mustContain(t, body, `value="front, prod"`)
	if strings.Contains(body, `value="{&#34;name&#34;:&#34;api&#34;`) {
		t.Error("imported secret still listed as available")
	}

	// Re-import, forbidden namespace, bad input.
	_, body = a.post(t, admin, "/admin/import", url.Values{"provider": {"k8s"}, "locator": {loc}})
	mustContain(t, body, "already exists")
	_, body = a.post(t, admin, "/admin/import", url.Values{"provider": {"k8s"}, "locator": {`{"name":"hidden","namespace":"kube-system"}`}})
	mustContain(t, body, "not allowed")
	_, body = a.post(t, admin, "/admin/import", url.Values{"provider": {"k8s"}, "locator": {`{"name":"nope","namespace":"front"}`}})
	mustContain(t, body, "no longer exists")
	_, body = a.post(t, admin, "/admin/import", url.Values{"provider": {"aws"}, "locator": {loc}})
	mustContain(t, body, "Unknown storage.")
	_, body = a.post(t, admin, "/admin/import", url.Values{"provider": {"k8s"}, "locator": {"not json"}})
	mustContain(t, body, "Invalid secret reference.")

	// Import the external one too.
	_, _ = a.post(t, admin, "/admin/import", url.Values{"provider": {"k8s"}, "locator": {`{"name":"synced","namespace":"front"}`}, "tags": {"front"}})

	_, body = a.do(t, admin, http.MethodGet, "/admin/import", nil)
	mustContain(t, body, `value="front, prod"`, "external: ExternalSecret", "No secrets left to import")

	// The old Imported page is gone.
	if resp, _ := a.do(t, admin, http.MethodGet, "/admin/secrets", nil); resp.StatusCode != http.StatusNotFound && resp.StatusCode != http.StatusMethodNotAllowed {
		t.Errorf("GET /admin/secrets = %d, want 404/405", resp.StatusCode)
	}

	secrets, _ := a.store.ListSecrets(t.Context())
	var apiID string
	for _, s := range secrets {
		if strings.Contains(string(s.Locator), `"api"`) {
			apiID = idStr(s.ID)
		}
	}

	_, body = a.post(t, admin, "/admin/secrets/"+apiID, url.Values{"tags": {"back"}})
	mustContain(t, body, "Tags saved.", `value="back"`)

	// Secret deleted in the cluster → shown as missing.
	if err := a.kube.CoreV1().Secrets("front").Delete(t.Context(), "api", metav1.DeleteOptions{}); err != nil {
		t.Fatal(err)
	}
	_, body = a.do(t, admin, http.MethodGet, "/admin/import", nil)
	mustContain(t, body, ">missing<")

	_, body = a.post(t, admin, "/admin/secrets/"+apiID+"/delete", nil)
	mustContain(t, body, "Secret removed from the app")
	if strings.Contains(body, `value="back"`) {
		t.Error("removed secret still listed")
	}

	for _, action := range []string{"secret.import", "secret.tags_update", "secret.unimport"} {
		if !strings.Contains(a.audit.String(), `"action":"`+action+`"`) {
			t.Errorf("missing audit event %s", action)
		}
	}
	if strings.Contains(a.audit.String(), "t0p-s3cret") {
		t.Fatal("secret value in audit log")
	}
}

func TestAdminCrossSitePostBlocked(t *testing.T) {
	a := newFullApp(t)
	admin := a.loginAs(t, "admin@corp.com")
	req, _ := http.NewRequestWithContext(t.Context(), http.MethodPost, a.srv.URL+"/admin/roles",
		strings.NewReader("name=evil&permission=read_write&tags=front"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Sec-Fetch-Site", "cross-site")
	resp, err := admin.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("cross-site admin POST = %d, want 403", resp.StatusCode)
	}
	if _, err := a.store.ListRoles(t.Context()); err == nil {
		if strings.Contains(a.audit.String(), `"action":"role.create"`) {
			t.Fatal("cross-site POST created a role")
		}
	}
}

func TestStaticAssets(t *testing.T) {
	app := newTestApp(t)
	for _, p := range []string{"/static/pico.min.css", "/static/htmx.min.js", "/static/app.css"} {
		resp, body := app.do(t, http.DefaultClient, http.MethodGet, p, nil)
		if resp.StatusCode != http.StatusOK || len(body) == 0 {
			t.Errorf("GET %s = %d (%d bytes)", p, resp.StatusCode, len(body))
		}
	}
	if resp, _ := app.do(t, http.DefaultClient, http.MethodGet, "/static/../go.mod", nil); resp.StatusCode == http.StatusOK {
		t.Error("path traversal served a file")
	}
}

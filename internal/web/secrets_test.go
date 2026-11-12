package web

import (
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"testing"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/kotoyants/secrets-ui/internal/store/db"
)

const apiValue = "t0p-s3cret"

// secretsFixture: imported secrets
//
//	front/api    tags {front, prod}   TOKEN=t0p-s3cret
//	front/synced tags {front}         external (ExternalSecret)
//	front/bin    tags {}              admin only
//
// users
//
//	alice: read {front}                         → synced only
//	bob:   read {front} + read_write {prod}     → read api, synced; write none
//	carol: read_write {front} + read_write {prod} → read & write api, synced
type secretsFixture struct {
	*fullApp
	admin, alice, bob, carol *http.Client
	api, synced, bin         string
}

func newSecretsFixture(t *testing.T) *secretsFixture {
	t.Helper()
	a := newFullApp(t)
	ctx := t.Context()
	// A binary (non-UTF-8) secret, untagged.
	if _, err := a.kube.CoreV1().Secrets("front").Create(ctx, &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Namespace: "front", Name: "bin", ResourceVersion: "1"},
		Type:       corev1.SecretTypeOpaque, Data: map[string][]byte{"BLOB": {0xff, 0xfe, 0x00}},
	}, metav1.CreateOptions{}); err != nil {
		t.Fatal(err)
	}

	f := &secretsFixture{fullApp: a}
	f.admin = a.loginAs(t, "admin@corp.com")
	f.alice = a.loginAs(t, "alice@corp.com")
	f.bob = a.loginAs(t, "bob@corp.com")
	f.carol = a.loginAs(t, "carol@corp.com")

	role := func(name string, perm db.RolePermission, tags ...string) int64 {
		id, err := a.store.CreateRoleWithTags(ctx, name, perm, tags)
		if err != nil {
			t.Fatal(err)
		}
		return id
	}
	frontR := role("front-r", db.RolePermissionRead, "front")
	frontRW := role("front-rw", db.RolePermissionReadWrite, "front")
	prodRW := role("prod-rw", db.RolePermissionReadWrite, "prod")
	assign := func(email string, roles ...int64) {
		u, err := a.store.GetUserByEmail(ctx, email)
		if err != nil {
			t.Fatal(err)
		}
		for _, r := range roles {
			if err := a.store.AddUserRole(ctx, db.AddUserRoleParams{UserID: u.ID, RoleID: r}); err != nil {
				t.Fatal(err)
			}
		}
	}
	assign("alice@corp.com", frontR)
	assign("bob@corp.com", frontR, prodRW)
	assign("carol@corp.com", frontRW, prodRW)

	imp := func(name string, tags ...string) string {
		id, err := a.store.ImportSecret(ctx, "k8s", map[string]string{"namespace": "front", "name": name}, tags, nil)
		if err != nil {
			t.Fatal(err)
		}
		return idStr(id)
	}
	f.api = imp("api", "front", "prod")
	f.synced = imp("synced", "front")
	f.bin = imp("bin")
	return f
}

func listed(body, id string) bool { return strings.Contains(body, `href="/secrets/`+id+`"`) }

func TestSecretListVisibility(t *testing.T) {
	f := newSecretsFixture(t)
	tests := []struct {
		name   string
		client *http.Client
		want   map[string]bool
	}{
		{"alice", f.alice, map[string]bool{f.api: false, f.synced: true, f.bin: false}},
		{"bob", f.bob, map[string]bool{f.api: true, f.synced: true, f.bin: false}},
		{"carol", f.carol, map[string]bool{f.api: true, f.synced: true, f.bin: false}},
		{"admin", f.admin, map[string]bool{f.api: true, f.synced: true, f.bin: true}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, body := f.do(t, tt.client, http.MethodGet, "/", nil)
			for id, want := range tt.want {
				if got := listed(body, id); got != want {
					t.Errorf("secret %s listed = %v, want %v", id, got, want)
				}
			}
			if strings.Contains(body, apiValue) {
				t.Fatal("secret value on list page")
			}
		})
	}

	// Filters.
	_, body := f.do(t, f.carol, http.MethodGet, "/?tag=prod", nil)
	if !listed(body, f.api) || listed(body, f.synced) {
		t.Error("tag filter")
	}
	_, body = f.do(t, f.carol, http.MethodGet, "/?q=SYNC", nil)
	if listed(body, f.api) || !listed(body, f.synced) {
		t.Error("search filter")
	}
	_, body = f.do(t, f.carol, http.MethodGet, "/?ns=other", nil)
	mustContain(t, body, "No secrets match the filter.")
}

func TestSecretViewAndReveal(t *testing.T) {
	f := newSecretsFixture(t)

	// Masked by default.
	resp, body := f.do(t, f.bob, http.MethodGet, "/secrets/"+f.api, nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("view = %d", resp.StatusCode)
	}
	mustContain(t, body, "<code>TOKEN</code>", "Reveal", `href="/static/app.css?v=`, `src="/static/app.js?v=`)
	if strings.Contains(body, apiValue) {
		t.Fatal("value shown before reveal")
	}
	if strings.Contains(body, "/edit") {
		t.Error("edit link shown to read-only user")
	}

	// Unreadable secrets look like they don't exist.
	for _, path := range []string{"/secrets/" + f.api, "/secrets/" + f.bin, "/secrets/999999"} {
		if resp, _ := f.do(t, f.alice, http.MethodGet, path, nil); resp.StatusCode != http.StatusNotFound {
			t.Errorf("alice GET %s = %d, want 404", path, resp.StatusCode)
		}
	}
	if resp, _ := f.post(t, f.alice, "/secrets/"+f.api+"/reveal", url.Values{"key": {"TOKEN"}}); resp.StatusCode != http.StatusNotFound {
		t.Errorf("alice reveal = %d, want 404", resp.StatusCode)
	}

	// Reveal without JavaScript: full page with the value.
	resp, body = f.post(t, f.bob, "/secrets/"+f.api+"/reveal", url.Values{"key": {"TOKEN"}})
	if resp.StatusCode != http.StatusOK || resp.Header.Get("Cache-Control") != "no-store" {
		t.Fatalf("reveal = %d, cache %q", resp.StatusCode, resp.Header.Get("Cache-Control"))
	}
	mustContain(t, body, "<html", "reveal?for=copy&amp;key=TOKEN", ">\n"+apiValue+"</textarea>")

	// Reveal via htmx: fragment only.
	req, _ := http.NewRequestWithContext(t.Context(), http.MethodPost, f.srv.URL+"/secrets/"+f.api+"/reveal",
		strings.NewReader("key=TOKEN"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("HX-Request", "true")
	hresp, err := f.bob.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = hresp.Body.Close() }()
	fragBytes, _ := io.ReadAll(hresp.Body)
	frag := string(fragBytes)
	if strings.Contains(frag, "<html") || !strings.Contains(frag, ">\n"+apiValue+"</textarea>") {
		t.Fatalf("fragment = %s", frag)
	}

	// Unknown key.
	if resp, _ := f.post(t, f.bob, "/secrets/"+f.api+"/reveal", url.Values{"key": {"NOPE"}}); resp.StatusCode != http.StatusNotFound {
		t.Errorf("unknown key = %d", resp.StatusCode)
	}

	// Copy (double-click on a masked field): the raw value as text, never cached; one key only.
	resp, body = f.post(t, f.bob, "/secrets/"+f.api+"/reveal?for=copy", url.Values{"key": {"TOKEN"}})
	if resp.StatusCode != http.StatusOK || body != apiValue || resp.Header.Get("Cache-Control") != "no-store" ||
		!strings.HasPrefix(resp.Header.Get("Content-Type"), "text/plain") {
		t.Errorf("copy = %d %q cache %q type %q", resp.StatusCode, body, resp.Header.Get("Cache-Control"), resp.Header.Get("Content-Type"))
	}
	if resp, _ := f.post(t, f.bob, "/secrets/"+f.api+"/reveal?for=copy", url.Values{"all": {"1"}}); resp.StatusCode == http.StatusOK {
		t.Error("copy of all keys allowed")
	}
	if resp, _ := f.post(t, f.alice, "/secrets/"+f.api+"/reveal?for=copy", url.Values{"key": {"TOKEN"}}); resp.StatusCode != http.StatusNotFound {
		t.Errorf("alice copy = %d, want 404", resp.StatusCode)
	}

	// Audited with the key name, never the value (page, fragment and copy).
	if n := strings.Count(f.audit.String(), `"action":"secret.reveal"`); n != 3 {
		t.Errorf("reveal audit events = %d, want 3", n)
	}
	mustContain(t, f.audit.String(), `"key":"TOKEN"`, `"copy":true`)
	if strings.Contains(f.audit.String(), apiValue) {
		t.Fatal("secret value in audit log")
	}
}

func TestSecretRevealBinary(t *testing.T) {
	f := newSecretsFixture(t)
	_, body := f.post(t, f.admin, "/secrets/"+f.bin+"/reveal", url.Values{"key": {"BLOB"}})
	mustContain(t, body, "//4A", "(binary, base64)")
}

// htmxPost sends a form POST the way htmx does and returns the response body.
func (f *secretsFixture) htmxPost(t *testing.T, c *http.Client, path, form string) (int, string) {
	t.Helper()
	req, _ := http.NewRequestWithContext(t.Context(), http.MethodPost, f.srv.URL+path, strings.NewReader(form))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("HX-Request", "true")
	resp, err := c.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	b, _ := io.ReadAll(resp.Body)
	if cc := resp.Header.Get("Cache-Control"); resp.StatusCode == http.StatusOK && cc != "no-store" {
		t.Errorf("Cache-Control = %q", cc)
	}
	return resp.StatusCode, string(b)
}

func TestSecretRevealAll(t *testing.T) {
	f := newSecretsFixture(t)
	s, _ := f.kube.CoreV1().Secrets("front").Get(t.Context(), "bin", metav1.GetOptions{})
	s.Data["TEXT"] = []byte("\nfirst & <b>")
	if _, err := f.kube.CoreV1().Secrets("front").Update(t.Context(), s, metav1.UpdateOptions{}); err != nil {
		t.Fatal(err)
	}
	path := "/secrets/" + f.bin + "/reveal"

	// View page offers Reveal all plus per-key Reveal.
	_, body := f.do(t, f.admin, http.MethodGet, "/secrets/"+f.bin, nil)
	mustContain(t, body, "data-reveal-all", `class="reveal-toggle"`, `reveal?key=BLOB`, `reveal?key=TEXT`, `data-reveal-target="val-1"`)

	// Without JavaScript: full page with every value.
	_, body = f.post(t, f.admin, path, url.Values{"all": {"1"}})
	mustContain(t, body, "<html", "//4A", "first &amp; &lt;b&gt;")

	// htmx: out-of-band value cells for every key.
	code, frag := f.htmxPost(t, f.admin, path, "all=1")
	if code != http.StatusOK || strings.Contains(frag, "<html") {
		t.Fatalf("reveal all fragment = %d %s", code, frag)
	}
	mustContain(t, frag, `id="val-0" hx-swap-oob="true"`, `id="val-1" hx-swap-oob="true"`, "//4A")

	// Edit mode: textareas prefilled; binary values are skipped (they can't be edited as text).
	code, frag = f.htmxPost(t, f.admin, path+"?for=edit&all=1", "")
	if code != http.StatusOK {
		t.Fatalf("edit reveal all = %d", code)
	}
	mustContain(t, frag, `<textarea id="edit-val-1" name="value" rows="2"`, "hx-swap-oob=\"true\">\n\nfirst &amp; &lt;b&gt;</textarea>")
	if strings.Contains(frag, "edit-val-0") {
		t.Error("binary value offered for text editing")
	}
	code, frag = f.htmxPost(t, f.admin, path+"?for=edit&key=TEXT", "")
	if code != http.StatusOK || !strings.Contains(frag, "edit-val-1") {
		t.Fatalf("edit reveal key = %d %s", code, frag)
	}
	if code, _ = f.htmxPost(t, f.admin, path+"?for=edit&key=BLOB", ""); code != http.StatusNotFound {
		t.Errorf("edit reveal of binary key = %d, want 404", code)
	}

	// Edit page: per-key reveal checkbox only for text keys, plus Reveal all.
	_, body = f.do(t, f.admin, http.MethodGet, "/secrets/"+f.bin+"/edit", nil)
	mustContain(t, body, "for=edit&amp;all=1", "for=edit&amp;key=TEXT", `data-reveal-target="edit-val-1"`, `id="edit-val-0"`)
	if strings.Contains(body, "key=BLOB") {
		t.Error("reveal offered for a binary key on the edit page")
	}

	// No access → not found, nothing audited for it.
	if code, _ := f.htmxPost(t, f.bob, path, "all=1"); code != http.StatusNotFound {
		t.Errorf("bob reveal all = %d", code)
	}

	// Audited with key names, never values.
	mustContain(t, f.audit.String(), `"keys":["BLOB","TEXT"]`, `"keys":["TEXT"]`)
	if strings.Contains(f.audit.String(), "first") {
		t.Fatal("secret value in audit log")
	}
}

var versionRe = regexp.MustCompile(`name="version" value="([^"]*)"`)

func (f *secretsFixture) editVersion(t *testing.T, c *http.Client, id string) string {
	t.Helper()
	resp, body := f.do(t, c, http.MethodGet, "/secrets/"+id+"/edit", nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("edit form = %d", resp.StatusCode)
	}
	if strings.Contains(body, apiValue) {
		t.Fatal("edit form shows a current value")
	}
	m := versionRe.FindStringSubmatch(body)
	if m == nil {
		t.Fatal("no version in edit form")
	}
	return m[1]
}

func (f *secretsFixture) kubeData(t *testing.T, name string) map[string]string {
	t.Helper()
	s, err := f.kube.CoreV1().Secrets("front").Get(t.Context(), name, metav1.GetOptions{})
	if err != nil {
		t.Fatal(err)
	}
	out := map[string]string{}
	for k, v := range s.Data {
		out[k] = string(v)
	}
	return out
}

func TestSecretEdit(t *testing.T) {
	f := newSecretsFixture(t)

	// Read-only users cannot edit.
	if resp, _ := f.do(t, f.bob, http.MethodGet, "/secrets/"+f.api+"/edit", nil); resp.StatusCode != http.StatusForbidden {
		t.Errorf("bob edit form = %d, want 403", resp.StatusCode)
	}
	if resp, _ := f.post(t, f.bob, "/secrets/"+f.api, url.Values{"version": {"1"}}); resp.StatusCode != http.StatusForbidden {
		t.Errorf("bob save = %d, want 403", resp.StatusCode)
	}
	if resp, _ := f.post(t, f.alice, "/secrets/"+f.api, url.Values{"version": {"1"}}); resp.StatusCode != http.StatusNotFound {
		t.Errorf("alice save = %d, want 404", resp.StatusCode)
	}

	// Carol: blank keeps TOKEN, adds two keys (CRLF normalized), one blank new row ignored.
	_, body := f.do(t, f.carol, http.MethodGet, "/secrets/"+f.api, nil)
	mustContain(t, body, `href="/secrets/`+f.api+`/edit"`)
	ver := f.editVersion(t, f.carol, f.api)
	resp, body := f.post(t, f.carol, "/secrets/"+f.api, url.Values{
		"version": {ver},
		"key":     {"TOKEN", "NEW", "CERT", ""},
		"value":   {"", "n1", "line1\r\nline2", ""},
	})
	if resp.URL.Path != "/secrets/"+f.api {
		t.Fatalf("after save: %s", resp.URL)
	}
	mustContain(t, body, "Secret saved.")
	got := f.kubeData(t, "api")
	if got["TOKEN"] != apiValue || got["NEW"] != "n1" || got["CERT"] != "line1\nline2" || len(got) != 3 {
		t.Fatalf("data after add = %v", got)
	}

	// Change one value and delete another.
	ver = f.editVersion(t, f.carol, f.api)
	_, body = f.post(t, f.carol, "/secrets/"+f.api, url.Values{
		"version": {ver},
		"key":     {"TOKEN", "NEW", "CERT"},
		"value":   {"rotated", "", ""},
		"delete":  {"CERT"},
	})
	mustContain(t, body, "Secret saved.")
	got = f.kubeData(t, "api")
	if got["TOKEN"] != "rotated" || got["NEW"] != "n1" || len(got) != 2 {
		t.Fatalf("data after change = %v", got)
	}

	// Nothing changed.
	ver = f.editVersion(t, f.carol, f.api)
	_, body = f.post(t, f.carol, "/secrets/"+f.api, url.Values{"version": {ver}, "key": {"TOKEN"}, "value": {""}})
	mustContain(t, body, "No changes.")

	// Invalid key name is rejected by the provider.
	ver = f.editVersion(t, f.carol, f.api)
	_, body = f.post(t, f.carol, "/secrets/"+f.api, url.Values{"version": {ver}, "key": {"bad key"}, "value": {"x"}})
	mustContain(t, body, "flash-error", "invalid secret data")

	// Audit has key names only.
	mustContain(t, f.audit.String(), `"action":"secret.update"`, `"added":["NEW","CERT"]`, `"changed":["TOKEN"]`, `"removed":["CERT"]`)
	for _, v := range []string{"rotated", "n1", "line1"} {
		if strings.Contains(f.audit.String(), v) {
			t.Fatalf("value %q in audit log", v)
		}
	}
}

func TestSecretEditConflict(t *testing.T) {
	f := newSecretsFixture(t)
	ver := f.editVersion(t, f.carol, f.api)

	// Someone else changes the secret meanwhile.
	s, _ := f.kube.CoreV1().Secrets("front").Get(t.Context(), "api", metav1.GetOptions{})
	s.ResourceVersion = "99"
	s.Data["OTHER"] = []byte("x")
	if _, err := f.kube.CoreV1().Secrets("front").Update(t.Context(), s, metav1.UpdateOptions{}); err != nil {
		t.Fatal(err)
	}

	resp, body := f.post(t, f.carol, "/secrets/"+f.api, url.Values{"version": {ver}, "key": {"TOKEN"}, "value": {"mine"}})
	if !strings.HasSuffix(resp.URL.Path, "/edit") {
		t.Fatalf("after conflict: %s", resp.URL)
	}
	mustContain(t, body, "changed by someone else")
	if got := f.kubeData(t, "api"); got["TOKEN"] != apiValue {
		t.Fatalf("conflicting save was applied: %v", got)
	}
}

func TestSecretExternalAndMissing(t *testing.T) {
	f := newSecretsFixture(t)

	_, body := f.do(t, f.carol, http.MethodGet, "/secrets/"+f.synced+"/edit", nil)
	mustContain(t, body, "managed by <strong>ExternalSecret</strong>")
	ver := f.editVersion(t, f.carol, f.synced)
	_, body = f.post(t, f.carol, "/secrets/"+f.synced, url.Values{"version": {ver}, "key": {"A"}, "value": {"2"}})
	mustContain(t, body, "Secret saved.", "managed by ExternalSecret, which may overwrite")

	if err := f.kube.CoreV1().Secrets("front").Delete(t.Context(), "api", metav1.DeleteOptions{}); err != nil {
		t.Fatal(err)
	}
	resp, body := f.do(t, f.bob, http.MethodGet, "/secrets/"+f.api, nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("missing secret view = %d", resp.StatusCode)
	}
	mustContain(t, body, "no longer exists in its storage")
}

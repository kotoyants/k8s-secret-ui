package auth

import (
	"bytes"
	"io"
	"log/slog"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/kotoyants/secrets-ui/internal/audit"
	"github.com/kotoyants/secrets-ui/internal/auth/authtest"
)

type harness struct {
	t     *testing.T
	idp   *authtest.FakeIDP
	store *authtest.MemStore
	svc   *Service
	app   *httptest.Server
	audit *bytes.Buffer
}

func newHarness(t *testing.T, mutate func(*Config)) *harness {
	t.Helper()
	h := &harness{t: t, idp: authtest.NewFakeIDP(t, "client-id"), store: authtest.NewMemStore(), audit: &bytes.Buffer{}}

	var handler http.Handler
	h.app = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { handler.ServeHTTP(w, r) }))
	t.Cleanup(h.app.Close)
	base, _ := url.Parse(h.app.URL)

	cfg := Config{
		Issuer: h.idp.Issuer(), ClientID: "client-id", ClientSecret: "secret",
		BaseURL: base, SessionSecret: []byte(strings.Repeat("k", 32)), SessionTTL: time.Hour,
	}
	if mutate != nil {
		mutate(&cfg)
	}
	svc, err := New(t.Context(), cfg, h.store, audit.New(slog.New(slog.NewJSONHandler(h.audit, nil))), slog.New(slog.DiscardHandler))
	if err != nil {
		t.Fatal(err)
	}
	h.svc = svc

	mux := http.NewServeMux()
	mux.HandleFunc("GET /auth/login", svc.HandleLogin)
	mux.HandleFunc("GET /auth/callback", svc.HandleCallback)
	mux.HandleFunc("POST /auth/logout", svc.HandleLogout)
	mux.HandleFunc("GET /login", func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, "login page error="+r.URL.Query().Get("error"))
	})
	mux.Handle("/me", RequireUser(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, "me="+FromContext(r.Context()).User.Email)
	})))
	mux.Handle("GET /admin", RequireAdmin(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, "admin")
	})))
	mux.HandleFunc("GET /{$}", func(w http.ResponseWriter, _ *http.Request) { _, _ = io.WriteString(w, "home") })
	handler = svc.LoadPrincipal(mux)
	return h
}

func (h *harness) client() *http.Client {
	jar, _ := cookiejar.New(nil)
	return &http.Client{Jar: jar}
}

// get performs a GET following redirects and returns the final URL and body.
func (h *harness) get(c *http.Client, path string) (*url.URL, int, string) {
	h.t.Helper()
	req, _ := http.NewRequestWithContext(h.t.Context(), http.MethodGet, h.app.URL+path, nil)
	resp, err := c.Do(req)
	if err != nil {
		h.t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	b, _ := io.ReadAll(resp.Body)
	return resp.Request.URL, resp.StatusCode, string(b)
}

func (h *harness) login(c *http.Client, id authtest.Identity, next string) (*url.URL, string) {
	h.t.Helper()
	h.idp.SetIdentity(id)
	path := "/auth/login"
	if next != "" {
		path += "?next=" + url.QueryEscape(next)
	}
	u, _, body := h.get(c, path)
	return u, body
}

var alice = authtest.Identity{Email: "Alice@Corp.com", EmailVerified: true, HostedDomain: "corp.com", Name: "Alice"}

func TestLoginSuccess(t *testing.T) {
	h := newHarness(t, nil)
	c := h.client()

	u, body := h.login(c, alice, "/me?x=1")
	if u.Path != "/me" || body != "me=alice@corp.com" {
		t.Fatalf("final %s body %q", u, body)
	}
	if !strings.Contains(h.audit.String(), `"action":"login"`) || !strings.Contains(h.audit.String(), `"new_user":true`) {
		t.Fatalf("audit = %s", h.audit)
	}
	// Second request uses the session cookie.
	if _, _, body := h.get(c, "/me"); body != "me=alice@corp.com" {
		t.Fatalf("session not kept: %q", body)
	}
	// Not an admin.
	if _, code, _ := h.get(c, "/admin"); code != http.StatusForbidden {
		t.Fatalf("/admin = %d, want 403", code)
	}
}

func TestLoginBootstrapAdmin(t *testing.T) {
	h := newHarness(t, func(c *Config) { c.AdminEmails = []string{"alice@corp.com"} })
	c := h.client()
	h.login(c, alice, "")
	if _, code, body := h.get(c, "/admin"); code != http.StatusOK || body != "admin" {
		t.Fatalf("/admin = %d %q", code, body)
	}
}

func TestLoginIdentityChecks(t *testing.T) {
	tests := []struct {
		name    string
		domains []string
		id      authtest.Identity
		wantErr string
	}{
		{"any domain ok", nil, authtest.Identity{Email: "bob@gmail.com", EmailVerified: true}, ""},
		{"unverified email", nil, authtest.Identity{Email: "bob@gmail.com"}, ErrCodeEmailNotVerified},
		{"allowed domain", []string{"corp.com"}, alice, ""},
		{"one of several domains", []string{"a.com", "corp.com"}, alice, ""},
		{"consumer account without hd", []string{"corp.com"}, authtest.Identity{Email: "bob@gmail.com", EmailVerified: true}, ErrCodeDomainNotAllowed},
		{"other workspace", []string{"corp.com"}, authtest.Identity{Email: "eve@evil.com", EmailVerified: true, HostedDomain: "evil.com"}, ErrCodeDomainNotAllowed},
		{"hd and email mismatch", []string{"corp.com"}, authtest.Identity{Email: "eve@evil.com", EmailVerified: true, HostedDomain: "corp.com"}, ErrCodeDomainNotAllowed},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h := newHarness(t, func(c *Config) { c.AllowedDomains = tt.domains })
			u, body := h.login(h.client(), tt.id, "/me")
			if tt.wantErr == "" {
				if u.Path != "/me" {
					t.Fatalf("expected success, got %s %q", u, body)
				}
				return
			}
			if u.Path != LoginPath || u.Query().Get("error") != tt.wantErr {
				t.Fatalf("final %s, want login error %s", u, tt.wantErr)
			}
			if !strings.Contains(h.audit.String(), `"action":"login_denied"`) {
				t.Fatalf("no login_denied audit: %s", h.audit)
			}
		})
	}
}

func TestLoginSendsHostedDomainHint(t *testing.T) {
	h := newHarness(t, func(c *Config) { c.AllowedDomains = []string{"corp.com"} })
	h.login(h.client(), alice, "")
	q := h.idp.LastAuthQuery
	if q.Get("hd") != "corp.com" || q.Get("code_challenge_method") != "S256" || q.Get("nonce") == "" {
		t.Fatalf("auth query = %v", q)
	}
}

func TestDisabledUser(t *testing.T) {
	h := newHarness(t, nil)
	c := h.client()
	h.login(c, alice, "")
	h.store.SetDisabled("alice@corp.com", true)

	// Existing session is revoked immediately.
	if u, _, _ := h.get(c, "/me"); u.Path != LoginPath {
		t.Fatalf("disabled user still has access: %s", u)
	}
	// New login is denied.
	if u, _ := h.login(c, alice, ""); u.Query().Get("error") != ErrCodeUserDisabled {
		t.Fatalf("final %s, want user_disabled", u)
	}
}

func TestDeletedUserLosesSession(t *testing.T) {
	h := newHarness(t, nil)
	c := h.client()
	h.login(c, alice, "")
	h.store.Delete("alice@corp.com")
	if u, _, _ := h.get(c, "/me"); u.Path != LoginPath {
		t.Fatalf("deleted user still has access: %s", u)
	}
}

func TestSessionExpiresAndTampering(t *testing.T) {
	h := newHarness(t, nil)
	c := h.client()
	h.login(c, alice, "")
	appURL, _ := url.Parse(h.app.URL)

	// Tampered cookie → anonymous.
	cookies := c.Jar.Cookies(appURL)
	for _, ck := range cookies {
		if ck.Name == sessionCookie {
			ck.Value += "x"
		}
	}
	c.Jar.SetCookies(appURL, cookies)
	if u, _, _ := h.get(c, "/me"); u.Path != LoginPath {
		t.Fatalf("tampered session accepted: %s", u)
	}

	// Expired session → anonymous.
	h.login(c, alice, "")
	h.svc.now = func() time.Time { return time.Now().Add(2 * time.Hour) }
	if u, _, _ := h.get(c, "/me"); u.Path != LoginPath {
		t.Fatalf("expired session accepted: %s", u)
	}
}

func TestStateCookieCannotBeUsedAsSession(t *testing.T) {
	h := newHarness(t, nil)
	tok, err := h.svc.sign(stateClaims{State: "s", RegisteredClaims: h.svc.registered(audState, time.Hour)}, h.svc.stateKey)
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/", nil)
	req.AddCookie(&http.Cookie{Name: sessionCookie, Value: tok})
	if _, err := h.svc.sessionUserID(req); err == nil {
		t.Fatal("state token accepted as session")
	}
}

func TestCallbackRejectsBadState(t *testing.T) {
	h := newHarness(t, nil)

	// No state cookie at all.
	if u, _, _ := h.get(h.client(), "/auth/callback?code=x&state=y"); u.Query().Get("error") != ErrCodeInvalidState {
		t.Fatalf("no cookie: final %s", u)
	}

	// Valid state cookie but different state parameter (CSRF on login).
	c := h.client()
	c.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	h.get(c, "/auth/login") // sets the state cookie, stops before the IdP
	c.CheckRedirect = nil
	if u, _, _ := h.get(c, "/auth/callback?code=x&state=forged"); u.Query().Get("error") != ErrCodeInvalidState {
		t.Fatalf("forged state: final %s", u)
	}
	if h.idp.TokenRequests != 0 {
		t.Fatal("code was exchanged despite invalid state")
	}
}

func TestCallbackRejectsWrongNonce(t *testing.T) {
	h := newHarness(t, nil)
	h.idp.NonceOverride = "replayed"
	if u, _ := h.login(h.client(), alice, ""); u.Query().Get("error") != ErrCodeInvalidState {
		t.Fatalf("final %s, want invalid_state", u)
	}
}

func TestOpenRedirectBlocked(t *testing.T) {
	h := newHarness(t, nil)
	u, body := h.login(h.client(), alice, "//evil.com/x")
	if u.Host != strings.TrimPrefix(h.app.URL, "http://") || body != "home" {
		t.Fatalf("final %s body %q", u, body)
	}
}

func TestLogout(t *testing.T) {
	h := newHarness(t, nil)
	c := h.client()
	h.login(c, alice, "")
	req, _ := http.NewRequestWithContext(t.Context(), http.MethodPost, h.app.URL+"/auth/logout", nil)
	resp, err := c.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.Request.URL.Path != LoginPath {
		t.Fatalf("logout redirected to %s", resp.Request.URL)
	}
	if u, _, _ := h.get(c, "/me"); u.Path != LoginPath {
		t.Fatalf("still logged in after logout: %s", u)
	}
	if !strings.Contains(h.audit.String(), `"action":"logout"`) {
		t.Fatalf("no logout audit: %s", h.audit)
	}
}

func TestRequireUserNonGetIs401(t *testing.T) {
	h := newHarness(t, nil)
	req, _ := http.NewRequestWithContext(t.Context(), http.MethodPost, h.app.URL+"/me", nil)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", resp.StatusCode)
	}
}

func TestSafeNext(t *testing.T) {
	tests := map[string]string{
		"":                  "",
		"/":                 "/",
		"/secrets?tag=a":    "/secrets?tag=a",
		"//evil.com":        "",
		"/\\evil.com":       "",
		"https://evil.com/": "",
		"relative":          "",
		"/a\r\nSet-Cookie:": "",
	}
	for in, want := range tests {
		if got := SafeNext(in); got != want {
			t.Errorf("SafeNext(%q) = %q, want %q", in, got, want)
		}
	}
}

package web

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/kotoyants/k8s-secret-ui/internal/audit"
	"github.com/kotoyants/k8s-secret-ui/internal/auth"
	"github.com/kotoyants/k8s-secret-ui/internal/auth/authtest"
)

type testApp struct {
	srv *httptest.Server
	idp *authtest.FakeIDP
}

// newTestApp starts the full router with a fake Google IdP and in-memory users.
func newTestApp(t *testing.T, checks ...ReadinessCheck) *testApp {
	t.Helper()
	idp := authtest.NewFakeIDP(t, "client-id")
	var handler http.Handler
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { handler.ServeHTTP(w, r) }))
	t.Cleanup(srv.Close)
	base, _ := url.Parse(srv.URL)

	log := slog.New(slog.DiscardHandler)
	svc, err := auth.New(t.Context(), auth.Config{
		Issuer: idp.Issuer(), ClientID: "client-id", ClientSecret: "s", BaseURL: base,
		SessionSecret: []byte(strings.Repeat("k", 32)), SessionTTL: time.Hour,
	}, authtest.NewMemStore(), audit.New(log), log)
	if err != nil {
		t.Fatal(err)
	}
	handler = NewRouter(Deps{Logger: log, Readiness: checks, Auth: svc})
	return &testApp{srv: srv, idp: idp}
}

// result is a fully-read response.
type result struct {
	StatusCode int
	Header     http.Header
	URL        *url.URL // final URL after redirects
}

func (a *testApp) do(t *testing.T, c *http.Client, method, path string, hdr map[string]string) (result, string) {
	t.Helper()
	req, _ := http.NewRequestWithContext(t.Context(), method, a.srv.URL+path, nil)
	for k, v := range hdr {
		req.Header.Set(k, v)
	}
	resp, err := c.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	b, _ := io.ReadAll(resp.Body)
	return result{StatusCode: resp.StatusCode, Header: resp.Header, URL: resp.Request.URL}, string(b)
}

func newClient() *http.Client {
	jar, _ := cookiejar.New(nil)
	return &http.Client{Jar: jar}
}

func TestHealthz(t *testing.T) {
	app := newTestApp(t)
	resp, _ := app.do(t, http.DefaultClient, http.MethodGet, "/healthz", nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
}

func TestReadyz(t *testing.T) {
	ok := ReadinessCheck{Name: "ok", Check: func(context.Context) error { return nil }}
	bad := ReadinessCheck{Name: "db", Check: func(context.Context) error { return errors.New("down") }}

	tests := []struct {
		name   string
		checks []ReadinessCheck
		want   int
	}{
		{"no checks", nil, http.StatusOK},
		{"all ok", []ReadinessCheck{ok}, http.StatusOK},
		{"one failing", []ReadinessCheck{ok, bad}, http.StatusServiceUnavailable},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			app := newTestApp(t, tt.checks...)
			resp, _ := app.do(t, http.DefaultClient, http.MethodGet, "/readyz", nil)
			if resp.StatusCode != tt.want {
				t.Fatalf("status = %d, want %d", resp.StatusCode, tt.want)
			}
		})
	}
}

func TestSecurityHeaders(t *testing.T) {
	app := newTestApp(t)
	resp, _ := app.do(t, http.DefaultClient, http.MethodGet, "/login", nil)
	for _, h := range []string{"Content-Security-Policy", "X-Content-Type-Options", "X-Frame-Options", "Referrer-Policy"} {
		if resp.Header.Get(h) == "" {
			t.Errorf("missing header %s", h)
		}
	}
	if resp.Header.Get("Cache-Control") != "no-store" {
		t.Errorf("Cache-Control = %q", resp.Header.Get("Cache-Control"))
	}
}

func TestAnonymousRedirectsToLogin(t *testing.T) {
	app := newTestApp(t)
	resp, body := app.do(t, newClient(), http.MethodGet, "/", nil)
	if resp.URL.Path != "/login" || resp.URL.Query().Get("next") != "/" {
		t.Fatalf("final URL %s", resp.URL)
	}
	if !strings.Contains(body, `href="/auth/login?next=%2f"`) {
		t.Fatalf("login link missing next: %s", body)
	}
}

func TestLoginPageShowsError(t *testing.T) {
	app := newTestApp(t)
	_, body := app.do(t, http.DefaultClient, http.MethodGet, "/login?error="+auth.ErrCodeDomainNotAllowed, nil)
	if !strings.Contains(body, "domain is not allowed") {
		t.Fatalf("body = %s", body)
	}
	_, body = app.do(t, http.DefaultClient, http.MethodGet, "/login?error=<script>", nil)
	if strings.Contains(body, "<script>") || !strings.Contains(body, "Something went wrong") {
		t.Fatalf("unknown error code not handled safely: %s", body)
	}
}

func TestLoginFlowAndHome(t *testing.T) {
	app := newTestApp(t)
	app.idp.SetIdentity(authtest.Identity{Email: "bob@corp.com", EmailVerified: true, Name: "Bob <b>"})
	c := newClient()

	resp, _ := app.do(t, c, http.MethodGet, "/", nil) // → /login
	if resp.URL.Path != "/login" {
		t.Fatalf("expected login page, got %s", resp.URL)
	}
	resp, body := app.do(t, c, http.MethodGet, "/auth/login?next=/", nil) // → IdP → callback → /
	if resp.URL.Path != "/" {
		t.Fatalf("final URL %s", resp.URL)
	}
	for _, want := range []string{"Welcome, Bob &lt;b&gt;", "bob@corp.com", "default (read)", "must grant you a role"} {
		if !strings.Contains(body, want) {
			t.Errorf("home missing %q:\n%s", want, body)
		}
	}

	// Logged-in user visiting /login goes home.
	if resp, _ := app.do(t, c, http.MethodGet, "/login", nil); resp.URL.Path != "/" {
		t.Errorf("/login when logged in → %s", resp.URL)
	}

	// Cross-site logout is blocked (CSRF), same-origin logout works.
	resp, _ = app.do(t, c, http.MethodPost, "/auth/logout", map[string]string{"Sec-Fetch-Site": "cross-site"})
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("cross-site POST status = %d, want 403", resp.StatusCode)
	}
	resp, _ = app.do(t, c, http.MethodPost, "/auth/logout", map[string]string{"Sec-Fetch-Site": "same-origin"})
	if resp.URL.Path != "/login" {
		t.Fatalf("after logout: %s", resp.URL)
	}
	if resp, _ := app.do(t, c, http.MethodGet, "/", nil); resp.URL.Path != "/login" {
		t.Fatalf("still logged in after logout: %s", resp.URL)
	}
}

func TestRecovererReturns500(t *testing.T) {
	h := recoverer(slog.New(slog.DiscardHandler))(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { panic("boom") }))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/", nil))
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500", rec.Code)
	}
}

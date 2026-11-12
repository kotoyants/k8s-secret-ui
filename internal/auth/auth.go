// Package auth implements Google OpenID Connect login and stateless sessions.
//
// Login state (state, nonce, PKCE verifier) and the session itself are kept in
// signed cookies, so no server-side session storage is needed. The user's status
// and roles are re-loaded from the database on every request.
package auth

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"fmt"
	"log/slog"
	"net/url"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"

	"github.com/kotoyants/secrets-ui/internal/audit"
	"github.com/kotoyants/secrets-ui/internal/store"
	"github.com/kotoyants/secrets-ui/internal/store/db"
)

// GoogleIssuer is the OIDC issuer URL of Google accounts.
const GoogleIssuer = "https://accounts.google.com"

const (
	sessionCookie = "sm_session"
	stateCookie   = "sm_oauth" //nolint:gosec // G101: cookie name, not a credential
	stateTTL      = 10 * time.Minute
	tokenIssuer   = "secrets-ui" //nolint:gosec // G101: JWT "iss" value, not a credential
	audSession    = "session"
	audState      = "oauth-state"
	callbackPath  = "/auth/callback"
	// LoginPath is the app's login page; errors are passed as ?error=<code>.
	LoginPath = "/login"
)

// UserStore is the subset of the store used by auth.
type UserStore interface {
	LoginUser(ctx context.Context, p store.LoginProfile, grantAdmin bool) (db.User, bool, error)
	LoadUserWithRoles(ctx context.Context, id int64) (db.User, []db.ListUserRolesRow, error)
}

// Config configures the auth service.
type Config struct {
	Issuer         string // GoogleIssuer in production; a fake IdP in tests
	ClientID       string
	ClientSecret   string
	BaseURL        *url.URL
	SessionSecret  []byte
	SessionTTL     time.Duration
	AllowedDomains []string // lowercase; empty = any Google account
	AdminEmails    []string // lowercase
}

// Service handles login, logout and session validation.
type Service struct {
	cfg        Config
	oauth      *oauth2.Config
	verifier   *oidc.IDTokenVerifier
	store      UserStore
	audit      *audit.Logger
	log        *slog.Logger
	sessionKey []byte
	stateKey   []byte
	secure     bool
	now        func() time.Time
}

// New discovers the OIDC provider and returns a Service. ctx must stay alive for
// the lifetime of the service (it is used to refresh the provider's signing keys).
func New(ctx context.Context, cfg Config, st UserStore, a *audit.Logger, log *slog.Logger) (*Service, error) {
	provider, err := oidc.NewProvider(ctx, cfg.Issuer)
	if err != nil {
		return nil, fmt.Errorf("oidc discovery for %s: %w", cfg.Issuer, err)
	}
	return &Service{
		cfg: cfg,
		oauth: &oauth2.Config{
			ClientID:     cfg.ClientID,
			ClientSecret: cfg.ClientSecret,
			Endpoint:     provider.Endpoint(),
			RedirectURL:  cfg.BaseURL.JoinPath(callbackPath).String(),
			Scopes:       []string{oidc.ScopeOpenID, "email", "profile"},
		},
		verifier:   provider.Verifier(&oidc.Config{ClientID: cfg.ClientID}),
		store:      st,
		audit:      a,
		log:        log,
		sessionKey: deriveKey(cfg.SessionSecret, "session"),
		stateKey:   deriveKey(cfg.SessionSecret, "oauth-state"),
		secure:     cfg.BaseURL.Scheme == "https",
		now:        time.Now,
	}, nil
}

// deriveKey derives a purpose-specific signing key so the session and state
// cookies can never be swapped for each other.
func deriveKey(secret []byte, purpose string) []byte {
	m := hmac.New(sha256.New, secret)
	m.Write([]byte(purpose))
	return m.Sum(nil)
}

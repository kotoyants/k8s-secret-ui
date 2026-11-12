// Package authtest provides test doubles for auth: a fake OpenID Connect
// provider (standing in for Google) and an in-memory user store.
package authtest

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sync"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"

	"github.com/kotoyants/secrets-ui/internal/store"
	"github.com/kotoyants/secrets-ui/internal/store/db"
)

// Identity is the Google account the fake IdP "logs in" as.
type Identity struct {
	Email         string
	EmailVerified bool
	HostedDomain  string
	Name          string
	Picture       string
}

// FakeIDP is a minimal OIDC provider. Its /auth endpoint immediately redirects
// back to the client with a code (as if the user picked an account), and its
// /token endpoint returns an ID token for the configured Identity.
type FakeIDP struct {
	Server   *httptest.Server
	ClientID string
	key      *rsa.PrivateKey

	mu       sync.Mutex
	identity Identity
	codes    map[string]codeInfo
	// LastAuthQuery is the query of the last /auth request (for assertions).
	LastAuthQuery url.Values
	// TokenRequests counts /token calls.
	TokenRequests int
	// NonceOverride, if set, replaces the nonce in issued ID tokens (replay tests).
	NonceOverride string
}

type codeInfo struct {
	nonce     string
	challenge string
}

// NewFakeIDP starts a fake IdP that is closed when the test ends.
func NewFakeIDP(t *testing.T, clientID string) *FakeIDP {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	f := &FakeIDP{ClientID: clientID, key: key, codes: map[string]codeInfo{}}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /.well-known/openid-configuration", f.discovery)
	mux.HandleFunc("GET /keys", f.keys)
	mux.HandleFunc("GET /auth", f.authorize)
	mux.HandleFunc("POST /token", f.token)
	f.Server = httptest.NewServer(mux)
	t.Cleanup(f.Server.Close)
	return f
}

// Issuer returns the issuer URL to configure in auth.Config.
func (f *FakeIDP) Issuer() string { return f.Server.URL }

// SetIdentity sets the account used for the next logins.
func (f *FakeIDP) SetIdentity(id Identity) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.identity = id
}

func (f *FakeIDP) discovery(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, map[string]any{
		"issuer":                                f.Server.URL,
		"authorization_endpoint":                f.Server.URL + "/auth",
		"token_endpoint":                        f.Server.URL + "/token",
		"jwks_uri":                              f.Server.URL + "/keys",
		"response_types_supported":              []string{"code"},
		"subject_types_supported":               []string{"public"},
		"id_token_signing_alg_values_supported": []string{"RS256"},
	})
}

func (f *FakeIDP) keys(w http.ResponseWriter, _ *http.Request) {
	b64 := base64.RawURLEncoding.EncodeToString
	writeJSON(w, map[string]any{"keys": []map[string]string{{
		"kty": "RSA", "alg": "RS256", "use": "sig", "kid": "test",
		"n": b64(f.key.N.Bytes()),
		"e": b64(big.NewInt(int64(f.key.E)).Bytes()),
	}}})
}

func (f *FakeIDP) authorize(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	code := rand.Text()
	f.mu.Lock()
	f.LastAuthQuery = q
	f.codes[code] = codeInfo{nonce: q.Get("nonce"), challenge: q.Get("code_challenge")}
	f.mu.Unlock()

	redirect, err := url.Parse(q.Get("redirect_uri"))
	if err != nil {
		http.Error(w, "bad redirect_uri", http.StatusBadRequest)
		return
	}
	rq := redirect.Query()
	rq.Set("code", code)
	rq.Set("state", q.Get("state"))
	redirect.RawQuery = rq.Encode()
	http.Redirect(w, r, redirect.String(), http.StatusFound)
}

func (f *FakeIDP) token(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad form", http.StatusBadRequest)
		return
	}
	f.mu.Lock()
	f.TokenRequests++
	info, ok := f.codes[r.PostForm.Get("code")]
	delete(f.codes, r.PostForm.Get("code"))
	id := f.identity
	if f.NonceOverride != "" {
		info.nonce = f.NonceOverride
	}
	f.mu.Unlock()

	if !ok {
		w.WriteHeader(http.StatusBadRequest)
		writeJSON(w, map[string]string{"error": "invalid_grant"})
		return
	}
	// Verify PKCE (S256).
	if info.challenge != oauthS256(r.PostForm.Get("code_verifier")) {
		w.WriteHeader(http.StatusBadRequest)
		writeJSON(w, map[string]string{"error": "invalid_grant", "error_description": "pkce"})
		return
	}

	now := time.Now()
	claims := jwt.MapClaims{
		"iss":            f.Server.URL,
		"aud":            f.ClientID,
		"sub":            "sub-" + id.Email,
		"iat":            now.Unix(),
		"exp":            now.Add(time.Hour).Unix(),
		"nonce":          info.nonce,
		"email":          id.Email,
		"email_verified": id.EmailVerified,
		"name":           id.Name,
		"picture":        id.Picture,
	}
	if id.HostedDomain != "" {
		claims["hd"] = id.HostedDomain
	}
	tok := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	tok.Header["kid"] = "test"
	signed, err := tok.SignedString(f.key)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	writeJSON(w, map[string]any{
		"access_token": "fake-access", "token_type": "Bearer", "expires_in": 3600, "id_token": signed,
	})
}

// oauthS256 computes the PKCE S256 code challenge for verifier.
func oauthS256(verifier string) string {
	sum := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}

// MemStore is an in-memory implementation of auth.UserStore.
type MemStore struct {
	mu      sync.Mutex
	nextID  int64
	users   map[int64]*db.User
	byEmail map[string]int64
	roles   map[int64][]db.ListUserRolesRow
}

// NewMemStore returns an empty MemStore.
func NewMemStore() *MemStore {
	return &MemStore{users: map[int64]*db.User{}, byEmail: map[string]int64{}, roles: map[int64][]db.ListUserRolesRow{}}
}

var (
	defaultRole = db.ListUserRolesRow{ID: 2, Name: store.RoleDefault, Permission: db.RolePermissionRead, Builtin: true, Tags: []string{}}
	adminRole   = db.ListUserRolesRow{ID: 1, Name: store.RoleAdmin, Permission: db.RolePermissionReadWrite, Builtin: true, Tags: []string{}}
)

// LoginUser mimics store.Store.LoginUser.
func (m *MemStore) LoginUser(_ context.Context, p store.LoginProfile, grantAdmin bool) (db.User, bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	now := time.Now()
	id, ok := m.byEmail[p.Email]
	created := !ok
	if created {
		m.nextID++
		id = m.nextID
		m.users[id] = &db.User{ID: id, Email: p.Email, CreatedAt: now}
		m.byEmail[p.Email] = id
		m.roles[id] = []db.ListUserRolesRow{defaultRole}
	}
	u := m.users[id]
	u.Name, u.AvatarUrl, u.LastLoginAt = p.Name, p.AvatarURL, &now
	if grantAdmin && !m.hasRole(id, store.RoleAdmin) {
		m.roles[id] = append([]db.ListUserRolesRow{adminRole}, m.roles[id]...)
	}
	return *u, created, nil
}

// LoadUserWithRoles mimics store.Store.LoadUserWithRoles.
func (m *MemStore) LoadUserWithRoles(_ context.Context, id int64) (db.User, []db.ListUserRolesRow, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	u, ok := m.users[id]
	if !ok {
		return db.User{}, nil, store.ErrNotFound
	}
	return *u, append([]db.ListUserRolesRow(nil), m.roles[id]...), nil
}

// SetDisabled disables or enables a user by email.
func (m *MemStore) SetDisabled(email string, disabled bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if id, ok := m.byEmail[email]; ok {
		m.users[id].Disabled = disabled
	}
}

// Delete removes a user by email.
func (m *MemStore) Delete(email string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if id, ok := m.byEmail[email]; ok {
		delete(m.users, id)
		delete(m.byEmail, email)
		delete(m.roles, id)
	}
}

func (m *MemStore) hasRole(id int64, name string) bool {
	for _, r := range m.roles[id] {
		if r.Name == name {
			return true
		}
	}
	return false
}

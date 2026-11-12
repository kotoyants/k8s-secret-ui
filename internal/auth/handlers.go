package auth

import (
	"crypto/rand"
	"crypto/subtle"
	"net/http"
	"net/url"
	"slices"
	"strings"

	"golang.org/x/oauth2"

	"github.com/coreos/go-oidc/v3/oidc"

	"github.com/kotoyants/k8s-secret-ui/internal/audit"
	"github.com/kotoyants/k8s-secret-ui/internal/store"
)

// Login error codes passed to the login page as ?error=<code>.
const (
	ErrCodeInvalidState     = "invalid_state"
	ErrCodeProviderError    = "provider_error"
	ErrCodeEmailNotVerified = "email_not_verified"
	ErrCodeDomainNotAllowed = "domain_not_allowed"
	ErrCodeUserDisabled     = "user_disabled"
	ErrCodeInternal         = "internal"
)

// HandleLogin starts the OAuth flow: GET /auth/login?next=/path
func (s *Service) HandleLogin(w http.ResponseWriter, r *http.Request) {
	sc := stateClaims{
		State:    rand.Text(),
		Nonce:    rand.Text(),
		Verifier: oauth2.GenerateVerifier(),
		Next:     SafeNext(r.URL.Query().Get("next")),
	}
	if err := s.setState(w, sc); err != nil {
		s.log.ErrorContext(r.Context(), "sign oauth state", "err", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	opts := []oauth2.AuthCodeOption{
		oidc.Nonce(sc.Nonce),
		oauth2.S256ChallengeOption(sc.Verifier),
		oauth2.SetAuthURLParam("prompt", "select_account"),
	}
	if len(s.cfg.AllowedDomains) == 1 {
		// Hint Google to show only accounts of this domain (still verified on callback).
		opts = append(opts, oauth2.SetAuthURLParam("hd", s.cfg.AllowedDomains[0]))
	}
	http.Redirect(w, r, s.oauth.AuthCodeURL(sc.State, opts...), http.StatusFound)
}

type googleClaims struct {
	Email         string `json:"email"`
	EmailVerified bool   `json:"email_verified"`
	HostedDomain  string `json:"hd"`
	Name          string `json:"name"`
	Picture       string `json:"picture"`
}

// HandleCallback completes the OAuth flow: GET /auth/callback?code=...&state=...
func (s *Service) HandleCallback(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	sc, err := s.readState(r)
	s.clearCookie(w, stateCookie)
	q := r.URL.Query()

	switch {
	case err != nil:
		s.deny(w, r, "", ErrCodeInvalidState, "state cookie: "+err.Error())
		return
	case q.Get("error") != "":
		s.deny(w, r, "", ErrCodeProviderError, "provider: "+q.Get("error"))
		return
	case subtle.ConstantTimeCompare([]byte(q.Get("state")), []byte(sc.State)) != 1:
		s.deny(w, r, "", ErrCodeInvalidState, "state mismatch")
		return
	}

	tok, err := s.oauth.Exchange(ctx, q.Get("code"), oauth2.VerifierOption(sc.Verifier))
	if err != nil {
		s.deny(w, r, "", ErrCodeProviderError, "code exchange: "+err.Error())
		return
	}
	rawID, _ := tok.Extra("id_token").(string)
	idt, err := s.verifier.Verify(ctx, rawID)
	if err != nil {
		s.deny(w, r, "", ErrCodeProviderError, "id token: "+err.Error())
		return
	}
	if subtle.ConstantTimeCompare([]byte(idt.Nonce), []byte(sc.Nonce)) != 1 {
		s.deny(w, r, "", ErrCodeInvalidState, "nonce mismatch")
		return
	}
	var gc googleClaims
	if err := idt.Claims(&gc); err != nil {
		s.deny(w, r, "", ErrCodeProviderError, "claims: "+err.Error())
		return
	}

	email := strings.ToLower(strings.TrimSpace(gc.Email))
	if code := s.checkIdentity(email, gc.EmailVerified, gc.HostedDomain); code != "" {
		s.deny(w, r, email, code, "identity check failed")
		return
	}

	user, created, err := s.store.LoginUser(ctx, store.LoginProfile{
		Email: email, Name: gc.Name, AvatarURL: gc.Picture,
	}, slices.Contains(s.cfg.AdminEmails, email))
	if err != nil {
		s.log.ErrorContext(ctx, "login user", "err", err)
		s.deny(w, r, email, ErrCodeInternal, "store error")
		return
	}
	if user.Disabled {
		s.deny(w, r, email, ErrCodeUserDisabled, "user disabled")
		return
	}

	if err := s.setSession(w, user.ID); err != nil {
		s.log.ErrorContext(ctx, "sign session", "err", err)
		s.deny(w, r, email, ErrCodeInternal, "session error")
		return
	}
	s.audit.Log(ctx, audit.Event{
		ActorID: user.ID, ActorEmail: user.Email, Action: audit.ActionLogin,
		IP: audit.ClientIP(r), Details: map[string]any{"new_user": created},
	})
	next := sc.Next
	if next == "" {
		next = "/"
	}
	http.Redirect(w, r, next, http.StatusFound)
}

// HandleLogout clears the session: POST /auth/logout
func (s *Service) HandleLogout(w http.ResponseWriter, r *http.Request) {
	if p := FromContext(r.Context()); p != nil {
		s.audit.Log(r.Context(), audit.Event{
			ActorID: p.User.ID, ActorEmail: p.User.Email, Action: audit.ActionLogout, IP: audit.ClientIP(r),
		})
	}
	s.clearCookie(w, sessionCookie)
	http.Redirect(w, r, LoginPath, http.StatusSeeOther)
}

// checkIdentity returns an error code if the Google identity may not log in.
func (s *Service) checkIdentity(email string, verified bool, hd string) string {
	if email == "" || !verified {
		return ErrCodeEmailNotVerified
	}
	if len(s.cfg.AllowedDomains) == 0 {
		return ""
	}
	hd = strings.ToLower(hd)
	// hd is only present for Google Workspace accounts and is the authoritative
	// domain claim; the email must also belong to it.
	if hd == "" || !slices.Contains(s.cfg.AllowedDomains, hd) || !strings.HasSuffix(email, "@"+hd) {
		return ErrCodeDomainNotAllowed
	}
	return ""
}

func (s *Service) deny(w http.ResponseWriter, r *http.Request, email, code, reason string) {
	s.audit.Log(r.Context(), audit.Event{
		ActorEmail: email, Action: audit.ActionLoginDenied, Result: audit.ResultDenied,
		IP: audit.ClientIP(r), Details: map[string]any{"code": code, "reason": reason},
	})
	http.Redirect(w, r, LoginPath+"?error="+url.QueryEscape(code), http.StatusFound)
}

// SafeNext returns p if it is a local absolute path, otherwise "".
// It prevents open redirects via ?next=.
func SafeNext(p string) string {
	if p == "" || !strings.HasPrefix(p, "/") || strings.HasPrefix(p, "//") || strings.ContainsAny(p, "\\\r\n") {
		return ""
	}
	u, err := url.Parse(p)
	if err != nil || u.Scheme != "" || u.Host != "" {
		return ""
	}
	return p
}

package auth

import (
	"context"
	"errors"
	"net/http"
	"net/url"

	"github.com/kotoyants/k8s-secret-ui/internal/store"
	"github.com/kotoyants/k8s-secret-ui/internal/store/db"
)

// Principal is the authenticated user of a request, loaded fresh from the DB.
type Principal struct {
	User  db.User
	Roles []db.ListUserRolesRow
}

// IsAdmin reports whether the user has the built-in admin role.
func (p *Principal) IsAdmin() bool {
	for _, r := range p.Roles {
		if r.Builtin && r.Name == store.RoleAdmin {
			return true
		}
	}
	return false
}

type ctxKey struct{}

// FromContext returns the request's principal, or nil if not logged in.
func FromContext(ctx context.Context) *Principal {
	p, _ := ctx.Value(ctxKey{}).(*Principal)
	return p
}

// WithPrincipal returns ctx carrying p (used by middleware and tests).
func WithPrincipal(ctx context.Context, p *Principal) context.Context {
	return context.WithValue(ctx, ctxKey{}, p)
}

// LoadPrincipal validates the session cookie and loads the user and roles from the DB.
// Requests without a valid session continue anonymously. Disabled or deleted users
// lose their session immediately.
func (s *Service) LoadPrincipal(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id, err := s.sessionUserID(r)
		if err != nil {
			if !errors.Is(err, errNoSession) {
				s.clearCookie(w, sessionCookie) // expired or tampered
			}
			next.ServeHTTP(w, r)
			return
		}

		user, roles, err := s.store.LoadUserWithRoles(r.Context(), id)
		switch {
		case errors.Is(err, store.ErrNotFound) || (err == nil && user.Disabled):
			s.clearCookie(w, sessionCookie)
			next.ServeHTTP(w, r)
			return
		case err != nil:
			s.log.ErrorContext(r.Context(), "load principal", "err", err, "user_id", id)
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}

		p := &Principal{User: user, Roles: roles}
		next.ServeHTTP(w, r.WithContext(WithPrincipal(r.Context(), p)))
	})
}

// RequireUser rejects anonymous requests: GET/HEAD are redirected to the login page,
// other methods get 401.
func RequireUser(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if FromContext(r.Context()) == nil {
			if r.Method == http.MethodGet || r.Method == http.MethodHead {
				http.Redirect(w, r, LoginPath+"?next="+url.QueryEscape(r.URL.RequestURI()), http.StatusFound)
				return
			}
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// RequireAdmin allows only admins (and redirects anonymous users to login).
func RequireAdmin(next http.Handler) http.Handler {
	return RequireUser(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !FromContext(r.Context()).IsAdmin() {
			http.Error(w, "forbidden", http.StatusForbidden)
			return
		}
		next.ServeHTTP(w, r)
	}))
}

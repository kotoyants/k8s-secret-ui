// Package web contains the HTTP router, middleware and handlers.
package web

import (
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"

	"github.com/kotoyants/k8s-secret-ui/internal/auth"
)

// ReadinessCheck reports whether a dependency (e.g. the database) is ready to serve traffic.
type ReadinessCheck struct {
	Name  string
	Check func(ctx context.Context) error
}

// Deps are the dependencies the HTTP layer needs.
type Deps struct {
	Logger    *slog.Logger
	Readiness []ReadinessCheck
	Auth      *auth.Service
	// Secure enables HSTS (set when BASE_URL is https).
	Secure bool
}

type handlers struct {
	log *slog.Logger
}

// NewRouter builds the application's HTTP handler.
func NewRouter(d Deps) http.Handler {
	h := &handlers{log: d.Logger}

	r := chi.NewRouter()
	r.Use(middleware.RequestID)
	r.Use(requestLogger(d.Logger))
	r.Use(recoverer(d.Logger))
	r.Use(securityHeaders(d.Secure))

	r.Get("/healthz", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
	})
	r.Get("/readyz", readyHandler(d.Logger, d.Readiness))

	r.Group(func(r chi.Router) {
		// Rejects cross-origin state-changing requests (CSRF) using
		// Sec-Fetch-Site / Origin headers; no tokens needed.
		r.Use(http.NewCrossOriginProtection().Handler)
		r.Use(d.Auth.LoadPrincipal)

		r.Get(auth.LoginPath, h.loginPage)
		r.Get("/auth/login", d.Auth.HandleLogin)
		r.Get("/auth/callback", d.Auth.HandleCallback)
		r.Post("/auth/logout", d.Auth.HandleLogout)

		r.Group(func(r chi.Router) {
			r.Use(auth.RequireUser)
			r.Get("/", h.home)
		})
	})

	return r
}

func readyHandler(log *slog.Logger, checks []ReadinessCheck) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(r.Context(), 2*time.Second)
		defer cancel()

		status := http.StatusOK
		result := map[string]string{}
		for _, c := range checks {
			if err := c.Check(ctx); err != nil {
				log.WarnContext(ctx, "readiness check failed", "check", c.Name, "err", err)
				result[c.Name] = "fail"
				status = http.StatusServiceUnavailable
				continue
			}
			result[c.Name] = "ok"
		}
		writeJSON(w, status, map[string]any{"status": http.StatusText(status), "checks": result})
	}
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

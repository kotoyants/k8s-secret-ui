package web

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"
)

func newTestRouter(checks ...ReadinessCheck) http.Handler {
	return NewRouter(Deps{
		Logger:    slog.New(slog.DiscardHandler),
		Readiness: checks,
	})
}

func TestHealthz(t *testing.T) {
	rec := httptest.NewRecorder()
	newTestRouter().ServeHTTP(rec, httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/healthz", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
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
			rec := httptest.NewRecorder()
			newTestRouter(tt.checks...).ServeHTTP(rec, httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/readyz", nil))
			if rec.Code != tt.want {
				t.Fatalf("status = %d, want %d", rec.Code, tt.want)
			}
		})
	}
}

func TestRecovererReturns500(t *testing.T) {
	log := slog.New(slog.DiscardHandler)
	h := recoverer(log)(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { panic("boom") }))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/", nil))
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500", rec.Code)
	}
}

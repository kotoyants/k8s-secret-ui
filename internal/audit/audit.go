// Package audit writes security-relevant events as structured JSON lines to stdout.
// Audit events must never contain secret values.
package audit

import (
	"context"
	"log/slog"
	"net"
	"net/http"
)

// Actions.
const (
	ActionLogin       = "login"
	ActionLoginDenied = "login_denied"
	ActionLogout      = "logout"
)

// Results.
const (
	ResultSuccess = "success"
	ResultDenied  = "denied"
	ResultError   = "error"
)

// Event is one audit record.
type Event struct {
	ActorID    int64
	ActorEmail string
	Action     string
	TargetType string
	TargetID   string
	Result     string // defaults to ResultSuccess
	IP         string
	Details    map[string]any // must not contain secret values
}

// Logger writes audit events.
type Logger struct{ l *slog.Logger }

// New returns an audit logger writing through l.
func New(l *slog.Logger) *Logger { return &Logger{l: l} }

// Log writes e as a single "audit" log line with audit=true.
func (a *Logger) Log(ctx context.Context, e Event) {
	if e.Result == "" {
		e.Result = ResultSuccess
	}
	attrs := []slog.Attr{
		slog.Bool("audit", true),
		slog.String("action", e.Action),
		slog.String("result", e.Result),
	}
	if e.ActorID != 0 {
		attrs = append(attrs, slog.Int64("actor_id", e.ActorID))
	}
	if e.ActorEmail != "" {
		attrs = append(attrs, slog.String("actor_email", e.ActorEmail))
	}
	if e.TargetType != "" {
		attrs = append(attrs, slog.String("target_type", e.TargetType), slog.String("target_id", e.TargetID))
	}
	if e.IP != "" {
		attrs = append(attrs, slog.String("ip", e.IP))
	}
	if len(e.Details) > 0 {
		attrs = append(attrs, slog.Any("details", e.Details))
	}
	a.l.LogAttrs(ctx, slog.LevelInfo, "audit", attrs...)
}

// ClientIP returns the client address of r (host part of RemoteAddr).
func ClientIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

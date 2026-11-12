package config

import (
	"log/slog"
	"slices"
	"strings"
	"testing"
	"time"
)

func validEnv() map[string]string {
	return map[string]string{
		"DATABASE_URL":         "postgres://u:p@localhost:5432/db",
		"GOOGLE_CLIENT_ID":     "id",
		"GOOGLE_CLIENT_SECRET": "secret",
		"BASE_URL":             "https://secrets.example.com/",
		"SESSION_SECRET":       strings.Repeat("x", 32),
		"ALLOWED_NAMESPACES":   "front, back",
	}
}

func getenv(m map[string]string) func(string) string {
	return func(k string) string { return m[k] }
}

func TestLoadValid(t *testing.T) {
	env := validEnv()
	env["ALLOWED_DOMAINS"] = " Example.com ,b.org,"
	env["ADMIN_EMAILS"] = "Admin@Example.com"

	cfg, err := Load(getenv(env))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.ListenAddr != ":8080" {
		t.Errorf("ListenAddr = %q, want :8080", cfg.ListenAddr)
	}
	if cfg.SessionTTL != 8*time.Hour {
		t.Errorf("SessionTTL = %v, want 8h", cfg.SessionTTL)
	}
	if got := cfg.BaseURL.String(); got != "https://secrets.example.com" {
		t.Errorf("BaseURL = %q", got)
	}
	if !slices.Equal(cfg.AllowedDomains, []string{"example.com", "b.org"}) {
		t.Errorf("AllowedDomains = %v", cfg.AllowedDomains)
	}
	if !slices.Equal(cfg.AdminEmails, []string{"admin@example.com"}) {
		t.Errorf("AdminEmails = %v", cfg.AdminEmails)
	}
	if !slices.Equal(cfg.AllowedNamespaces, []string{"front", "back"}) {
		t.Errorf("AllowedNamespaces = %v", cfg.AllowedNamespaces)
	}
	if cfg.LogLevel != slog.LevelInfo {
		t.Errorf("LogLevel = %v", cfg.LogLevel)
	}
}

func TestLoadInvalid(t *testing.T) {
	tests := []struct {
		name    string
		key     string
		value   string
		wantErr string
	}{
		{"missing db", "DATABASE_URL", "", "DATABASE_URL is required"},
		{"missing client id", "GOOGLE_CLIENT_ID", "", "GOOGLE_CLIENT_ID is required"},
		{"relative base url", "BASE_URL", "/foo", "absolute http(s) URL"},
		{"short secret", "SESSION_SECRET", "short", "at least 32 bytes"},
		{"bad ttl", "SESSION_TTL", "forever", "SESSION_TTL"},
		{"negative ttl", "SESSION_TTL", "-1h", "must be positive"},
		{"no namespaces", "ALLOWED_NAMESPACES", " , ", "ALLOWED_NAMESPACES is required"},
		{"wildcard namespace", "ALLOWED_NAMESPACES", "a,*", "wildcard"},
		{"bad log level", "LOG_LEVEL", "loud", "LOG_LEVEL"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			env := validEnv()
			env[tt.key] = tt.value
			_, err := Load(getenv(env))
			if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("error = %v, want containing %q", err, tt.wantErr)
			}
		})
	}
}

func TestLoadReportsAllErrors(t *testing.T) {
	_, err := Load(getenv(map[string]string{}))
	if err == nil {
		t.Fatal("expected error")
	}
	for _, key := range []string{"DATABASE_URL", "GOOGLE_CLIENT_ID", "GOOGLE_CLIENT_SECRET", "BASE_URL", "SESSION_SECRET", "ALLOWED_NAMESPACES"} {
		if !strings.Contains(err.Error(), key) {
			t.Errorf("error does not mention %s: %v", key, err)
		}
	}
}

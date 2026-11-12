// Package config loads and validates application configuration from environment variables.
package config

import (
	"errors"
	"fmt"
	"log/slog"
	"net/url"
	"strings"
	"time"
)

const minSessionSecretLen = 32

// Config holds all runtime configuration. It is built once at startup and is read-only afterwards.
type Config struct {
	ListenAddr         string
	BaseURL            *url.URL
	DatabaseURL        string
	GoogleClientID     string
	GoogleClientSecret string
	SessionSecret      []byte
	SessionTTL         time.Duration
	AllowedDomains     []string
	AdminEmails        []string
	AllowedNamespaces  []string
	LogLevel           slog.Level
}

// Load reads configuration using getenv (typically os.Getenv) and validates it.
// All validation errors are returned together.
func Load(getenv func(string) string) (*Config, error) {
	var errs []error
	required := func(key string) string {
		v := strings.TrimSpace(getenv(key))
		if v == "" {
			errs = append(errs, fmt.Errorf("%s is required", key))
		}
		return v
	}

	cfg := &Config{
		ListenAddr:         withDefault(getenv("LISTEN_ADDR"), ":8080"),
		DatabaseURL:        required("DATABASE_URL"),
		GoogleClientID:     required("GOOGLE_CLIENT_ID"),
		GoogleClientSecret: required("GOOGLE_CLIENT_SECRET"),
		AllowedDomains:     lowerAll(splitList(getenv("ALLOWED_DOMAINS"))),
		AdminEmails:        lowerAll(splitList(getenv("ADMIN_EMAILS"))),
		AllowedNamespaces:  splitList(getenv("ALLOWED_NAMESPACES")),
	}

	if raw := required("BASE_URL"); raw != "" {
		u, err := url.Parse(raw)
		switch {
		case err != nil:
			errs = append(errs, fmt.Errorf("BASE_URL: %w", err))
		case u.Scheme != "http" && u.Scheme != "https", u.Host == "":
			errs = append(errs, fmt.Errorf("BASE_URL must be an absolute http(s) URL, got %q", raw))
		default:
			u.Path = strings.TrimRight(u.Path, "/")
			cfg.BaseURL = u
		}
	}

	if s := required("SESSION_SECRET"); s != "" {
		if len(s) < minSessionSecretLen {
			errs = append(errs, fmt.Errorf("SESSION_SECRET must be at least %d bytes", minSessionSecretLen))
		}
		cfg.SessionSecret = []byte(s)
	}

	ttl, err := time.ParseDuration(withDefault(getenv("SESSION_TTL"), "8h"))
	switch {
	case err != nil:
		errs = append(errs, fmt.Errorf("SESSION_TTL: %w", err))
	case ttl <= 0:
		errs = append(errs, errors.New("SESSION_TTL must be positive"))
	default:
		cfg.SessionTTL = ttl
	}

	if len(cfg.AllowedNamespaces) == 0 {
		errs = append(errs, errors.New("ALLOWED_NAMESPACES is required"))
	}
	for _, ns := range cfg.AllowedNamespaces {
		if ns == "*" {
			errs = append(errs, errors.New("ALLOWED_NAMESPACES must not contain a wildcard"))
		}
	}

	if err := cfg.LogLevel.UnmarshalText([]byte(withDefault(getenv("LOG_LEVEL"), "info"))); err != nil {
		errs = append(errs, fmt.Errorf("LOG_LEVEL: %w", err))
	}

	if len(errs) > 0 {
		return nil, fmt.Errorf("invalid configuration: %w", errors.Join(errs...))
	}
	return cfg, nil
}

func withDefault(v, def string) string {
	if v = strings.TrimSpace(v); v == "" {
		return def
	}
	return v
}

// splitList splits a comma-separated value, trimming spaces and dropping empty items.
func splitList(v string) []string {
	var out []string
	for item := range strings.SplitSeq(v, ",") {
		if item = strings.TrimSpace(item); item != "" {
			out = append(out, item)
		}
	}
	return out
}

func lowerAll(in []string) []string {
	for i := range in {
		in[i] = strings.ToLower(in[i])
	}
	return in
}

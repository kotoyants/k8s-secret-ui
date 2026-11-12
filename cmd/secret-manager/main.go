// Command secret-manager runs the k8s-secret-ui web application.
//
// Usage:
//
//	secret-manager           start the web server (applies migrations first)
//	secret-manager migrate   apply database migrations and exit (needs only DATABASE_URL)
package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/kotoyants/k8s-secret-ui/internal/audit"
	"github.com/kotoyants/k8s-secret-ui/internal/auth"
	"github.com/kotoyants/k8s-secret-ui/internal/config"
	"github.com/kotoyants/k8s-secret-ui/internal/store"
	"github.com/kotoyants/k8s-secret-ui/internal/web"
)

const (
	shutdownTimeout = 15 * time.Second
	startupTimeout  = 30 * time.Second
)

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	var err error
	switch cmd := subcommand(); cmd {
	case "", "serve":
		err = serve(ctx)
	case "migrate":
		err = migrate(ctx)
	default:
		err = fmt.Errorf("unknown command %q (use: serve, migrate)", cmd)
	}
	if err != nil {
		slog.Error("fatal", "err", err)
		os.Exit(1)
	}
}

func subcommand() string {
	if len(os.Args) > 1 {
		return os.Args[1]
	}
	return ""
}

func migrate(ctx context.Context) error {
	dsn := os.Getenv("DATABASE_URL")
	if dsn == "" {
		return errors.New("DATABASE_URL is required")
	}
	ctx, cancel := context.WithTimeout(ctx, startupTimeout)
	defer cancel()
	pool, err := store.Open(ctx, dsn)
	if err != nil {
		return err
	}
	defer pool.Close()
	if err := store.Migrate(ctx, pool); err != nil {
		return err
	}
	slog.Info("migrations applied")
	return nil
}

func serve(ctx context.Context) error {
	cfg, err := config.Load(os.Getenv)
	if err != nil {
		return err
	}

	log := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: cfg.LogLevel}))
	slog.SetDefault(log)

	startCtx, cancel := context.WithTimeout(ctx, startupTimeout)
	defer cancel()
	pool, err := store.Open(startCtx, cfg.DatabaseURL)
	if err != nil {
		return err
	}
	defer pool.Close()
	if err := store.Migrate(startCtx, pool); err != nil {
		return err
	}
	st := store.New(pool)

	// ctx (not startCtx) keeps the OIDC key set refreshable for the server's lifetime.
	authSvc, err := auth.New(ctx, auth.Config{
		Issuer:         auth.GoogleIssuer,
		ClientID:       cfg.GoogleClientID,
		ClientSecret:   cfg.GoogleClientSecret,
		BaseURL:        cfg.BaseURL,
		SessionSecret:  cfg.SessionSecret,
		SessionTTL:     cfg.SessionTTL,
		AllowedDomains: cfg.AllowedDomains,
		AdminEmails:    cfg.AdminEmails,
	}, st, audit.New(log), log)
	if err != nil {
		return err
	}

	srv := &http.Server{
		Addr: cfg.ListenAddr,
		Handler: web.NewRouter(web.Deps{
			Logger:    log,
			Readiness: []web.ReadinessCheck{{Name: "database", Check: st.Ping}},
			Auth:      authSvc,
			Secure:    cfg.BaseURL.Scheme == "https",
		}),
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       15 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       60 * time.Second,
		ErrorLog:          slog.NewLogLogger(log.Handler(), slog.LevelWarn),
	}

	errCh := make(chan error, 1)
	go func() {
		log.Info("server starting", "addr", cfg.ListenAddr, "base_url", cfg.BaseURL.String())
		if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			errCh <- err
		}
		close(errCh)
	}()

	select {
	case err := <-errCh:
		return fmt.Errorf("http server: %w", err)
	case <-ctx.Done():
	}

	log.Info("shutting down")
	shutdownCtx, cancelShutdown := context.WithTimeout(context.Background(), shutdownTimeout)
	defer cancelShutdown()
	if err := srv.Shutdown(shutdownCtx); err != nil {
		return fmt.Errorf("shutdown: %w", err)
	}
	log.Info("server stopped")
	return nil
}

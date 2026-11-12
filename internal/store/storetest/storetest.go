// Package storetest provides a real PostgreSQL-backed store for tests in other
// packages. The database is started once per test binary with testcontainers
// (or taken from TEST_DATABASE_URL) and reset for every caller.
package storetest

import (
	"context"
	"os"
	"sync"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
	tcpostgres "github.com/testcontainers/testcontainers-go/modules/postgres"

	"github.com/kotoyants/k8s-secret-ui/internal/store"
)

var (
	once    sync.Once
	pool    *pgxpool.Pool
	initErr error
)

func start() {
	ctx := context.Background()
	dsn := os.Getenv("TEST_DATABASE_URL")
	if dsn == "" {
		// The container is removed by the testcontainers reaper when the test binary exits.
		ctr, err := tcpostgres.Run(ctx, "postgres:17-alpine",
			tcpostgres.WithDatabase("test"), tcpostgres.WithUsername("test"), tcpostgres.WithPassword("test"),
			tcpostgres.BasicWaitStrategies())
		if err != nil {
			initErr = err
			return
		}
		if dsn, err = ctr.ConnectionString(ctx, "sslmode=disable"); err != nil {
			initErr = err
			return
		}
	}
	if pool, initErr = store.Open(ctx, dsn); initErr != nil {
		return
	}
	initErr = store.Migrate(ctx, pool)
}

// New returns a store on a clean database. It skips the test in -short mode.
// Tests using it must not run in parallel with each other.
func New(t *testing.T) *store.Store {
	t.Helper()
	if testing.Short() {
		t.Skip("database tests skipped (-short)")
	}
	once.Do(start)
	if initErr != nil {
		t.Fatalf("test database: %v", initErr)
	}
	if _, err := pool.Exec(t.Context(), `
		TRUNCATE users, secrets RESTART IDENTITY CASCADE;
		DELETE FROM roles WHERE NOT builtin;`); err != nil {
		t.Fatalf("reset test database: %v", err)
	}
	return store.New(pool)
}

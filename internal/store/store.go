// Package store provides PostgreSQL access: connection, migrations and
// transactional operations on top of the sqlc-generated queries in store/db.
package store

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/jackc/pgx/v5/stdlib"
	"github.com/pressly/goose/v3"
	"github.com/pressly/goose/v3/lock"

	"github.com/kotoyants/k8s-secret-ui/internal/store/db"
	"github.com/kotoyants/k8s-secret-ui/internal/tags"
	"github.com/kotoyants/k8s-secret-ui/migrations"
)

// Names of the built-in roles (seeded by the initial migration).
const (
	RoleAdmin   = "admin"
	RoleDefault = "default"
)

var (
	ErrNotFound    = errors.New("not found")
	ErrConflict    = errors.New("already exists")
	ErrBuiltinRole = errors.New("built-in role cannot be modified")
)

// Store wraps a connection pool and exposes the generated queries plus
// multi-statement operations that need a transaction.
type Store struct {
	*db.Queries
	pool *pgxpool.Pool
}

// Open connects to PostgreSQL and verifies the connection.
func Open(ctx context.Context, databaseURL string) (*pgxpool.Pool, error) {
	pool, err := pgxpool.New(ctx, databaseURL)
	if err != nil {
		return nil, fmt.Errorf("connect to database: %w", err)
	}
	if err := pool.Ping(ctx); err != nil {
		pool.Close()
		return nil, fmt.Errorf("ping database: %w", err)
	}
	return pool, nil
}

// New returns a Store backed by pool.
func New(pool *pgxpool.Pool) *Store {
	return &Store{Queries: db.New(pool), pool: pool}
}

// Ping checks database connectivity (used by /readyz).
func (s *Store) Ping(ctx context.Context) error { return s.pool.Ping(ctx) }

// Migrate applies all pending migrations. A Postgres advisory lock makes it safe
// to run from several replicas at the same time.
func Migrate(ctx context.Context, pool *pgxpool.Pool) error {
	p, err := newMigrator(pool)
	if err != nil {
		return err
	}
	if _, err := p.Up(ctx); err != nil {
		return fmt.Errorf("apply migrations: %w", err)
	}
	return nil
}

func newMigrator(pool *pgxpool.Pool) (*goose.Provider, error) {
	locker, err := lock.NewPostgresSessionLocker()
	if err != nil {
		return nil, fmt.Errorf("migration locker: %w", err)
	}
	p, err := goose.NewProvider(goose.DialectPostgres, stdlib.OpenDBFromPool(pool), migrations.FS,
		goose.WithSessionLocker(locker))
	if err != nil {
		return nil, fmt.Errorf("migration provider: %w", err)
	}
	return p, nil
}

// InTx runs fn inside a transaction. It commits if fn returns nil and rolls back otherwise.
func (s *Store) InTx(ctx context.Context, fn func(q *db.Queries) error) error {
	return pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
		return fn(db.New(tx))
	})
}

// LoginProfile is the identity data received from Google on login.
type LoginProfile struct {
	Email     string
	Name      string
	AvatarURL string
}

// LoginUser creates the user on first login (with the default role) or refreshes
// their profile and last-login time. If grantAdmin is true the admin role is added.
// It does not check whether the user is disabled; the caller must do that.
func (s *Store) LoginUser(ctx context.Context, p LoginProfile, grantAdmin bool) (user db.User, created bool, err error) {
	err = s.InTx(ctx, func(q *db.Queries) error {
		user, err = q.InsertUser(ctx, db.InsertUserParams{Email: p.Email, Name: p.Name, AvatarUrl: p.AvatarURL})
		switch {
		case err == nil:
			created = true
			if err := q.AddUserRoleByName(ctx, db.AddUserRoleByNameParams{UserID: user.ID, Name: RoleDefault}); err != nil {
				return fmt.Errorf("assign default role: %w", err)
			}
		case errors.Is(err, pgx.ErrNoRows): // already exists
			existing, err := q.GetUserByEmail(ctx, p.Email)
			if err != nil {
				return fmt.Errorf("get user: %w", err)
			}
			user, err = q.UpdateUserLogin(ctx, db.UpdateUserLoginParams{ID: existing.ID, Name: p.Name, AvatarUrl: p.AvatarURL})
			if err != nil {
				return fmt.Errorf("update user: %w", err)
			}
		default:
			return fmt.Errorf("insert user: %w", err)
		}

		if grantAdmin {
			if err := q.AddUserRoleByName(ctx, db.AddUserRoleByNameParams{UserID: user.ID, Name: RoleAdmin}); err != nil {
				return fmt.Errorf("assign admin role: %w", err)
			}
		}
		return nil
	})
	return user, created, err
}

// SetRoleTags replaces a role's tags. Built-in roles cannot be changed.
func (s *Store) SetRoleTags(ctx context.Context, roleID int64, in []string) error {
	t, err := tags.Normalize(in)
	if err != nil {
		return err
	}
	return s.InTx(ctx, func(q *db.Queries) error {
		role, err := q.GetRole(ctx, roleID)
		if err != nil {
			return mapErr(err)
		}
		if role.Builtin {
			return ErrBuiltinRole
		}
		if err := q.DeleteRoleTags(ctx, roleID); err != nil {
			return err
		}
		return q.InsertRoleTags(ctx, db.InsertRoleTagsParams{RoleID: roleID, Tags: t})
	})
}

// CreateRoleWithTags creates a role with tags.
func (s *Store) CreateRoleWithTags(ctx context.Context, name string, perm db.RolePermission, in []string) (int64, error) {
	t, err := tags.Normalize(in)
	if err != nil {
		return 0, err
	}
	var id int64
	err = s.InTx(ctx, func(q *db.Queries) error {
		role, err := q.CreateRole(ctx, db.CreateRoleParams{Name: name, Permission: perm})
		if err != nil {
			return mapErr(err)
		}
		id = role.ID
		return q.InsertRoleTags(ctx, db.InsertRoleTagsParams{RoleID: id, Tags: t})
	})
	return id, err
}

// ImportSecret registers a provider secret with tags. The locator identifies the
// secret inside the provider (e.g. {"namespace": "x", "name": "y"} for Kubernetes).
func (s *Store) ImportSecret(ctx context.Context, provider string, locator map[string]string, in []string, createdBy *int64) (int64, error) {
	t, err := tags.Normalize(in)
	if err != nil {
		return 0, err
	}
	loc, err := json.Marshal(locator)
	if err != nil {
		return 0, fmt.Errorf("marshal locator: %w", err)
	}
	var id int64
	err = s.InTx(ctx, func(q *db.Queries) error {
		sec, err := q.InsertSecret(ctx, db.InsertSecretParams{Provider: provider, Locator: loc, CreatedBy: createdBy})
		if err != nil {
			return mapErr(err)
		}
		id = sec.ID
		return q.InsertSecretTags(ctx, db.InsertSecretTagsParams{SecretID: id, Tags: t})
	})
	return id, err
}

// SetSecretTags replaces a secret's tags.
func (s *Store) SetSecretTags(ctx context.Context, secretID int64, in []string) error {
	t, err := tags.Normalize(in)
	if err != nil {
		return err
	}
	return s.InTx(ctx, func(q *db.Queries) error {
		if _, err := q.GetSecret(ctx, secretID); err != nil {
			return mapErr(err)
		}
		if err := q.DeleteSecretTags(ctx, secretID); err != nil {
			return err
		}
		return q.InsertSecretTags(ctx, db.InsertSecretTagsParams{SecretID: secretID, Tags: t})
	})
}

// mapErr converts driver errors into store sentinel errors.
func mapErr(err error) error {
	if errors.Is(err, pgx.ErrNoRows) {
		return ErrNotFound
	}
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) && pgErr.Code == "23505" { // unique_violation
		return fmt.Errorf("%w: %s", ErrConflict, pgErr.ConstraintName)
	}
	return err
}

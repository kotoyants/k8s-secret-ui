package store

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"slices"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/testcontainers/testcontainers-go"
	tcpostgres "github.com/testcontainers/testcontainers-go/modules/postgres"

	"github.com/kotoyants/k8s-secret-ui/internal/store/db"
)

// testPool is shared by all tests in this package. Tests run sequentially and
// call reset() to start from a clean state.
var testPool *pgxpool.Pool

// TestMain starts a throwaway Postgres in Docker (testcontainers), or uses
// TEST_DATABASE_URL if set. Use `go test -short` to skip DB tests.
func TestMain(m *testing.M) {
	flag.Parse()
	os.Exit(runTests(m))
}

func runTests(m *testing.M) int {
	ctx := context.Background()
	if testing.Short() {
		return m.Run()
	}

	dsn := os.Getenv("TEST_DATABASE_URL")
	if dsn == "" {
		ctr, err := tcpostgres.Run(ctx, "postgres:17-alpine",
			tcpostgres.WithDatabase("test"),
			tcpostgres.WithUsername("test"),
			tcpostgres.WithPassword("test"),
			tcpostgres.BasicWaitStrategies(),
		)
		if err != nil {
			fmt.Fprintf(os.Stderr, "start postgres container: %v\n", err)
			return 1
		}
		defer func() { _ = testcontainers.TerminateContainer(ctr) }()
		if dsn, err = ctr.ConnectionString(ctx, "sslmode=disable"); err != nil {
			fmt.Fprintf(os.Stderr, "connection string: %v\n", err)
			return 1
		}
	}

	pool, err := Open(ctx, dsn)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	defer pool.Close()
	if err := Migrate(ctx, pool); err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	testPool = pool
	return m.Run()
}

func newStore(t *testing.T) *Store {
	t.Helper()
	if testPool == nil {
		t.Skip("database tests skipped (-short)")
	}
	_, err := testPool.Exec(t.Context(), `
		TRUNCATE users, secrets RESTART IDENTITY CASCADE;
		DELETE FROM roles WHERE NOT builtin;`)
	if err != nil {
		t.Fatalf("reset db: %v", err)
	}
	return New(testPool)
}

func roleNames(t *testing.T, s *Store, userID int64) []string {
	t.Helper()
	roles, err := s.ListUserRoles(t.Context(), userID)
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, r := range roles {
		names = append(names, r.Name)
	}
	return names
}

func TestMigrateIsIdempotentAndReversible(t *testing.T) {
	s := newStore(t)
	ctx := t.Context()
	if err := Migrate(ctx, s.pool); err != nil {
		t.Fatalf("second migrate: %v", err)
	}
	p, err := newMigrator(s.pool)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := p.DownTo(ctx, 0); err != nil {
		t.Fatalf("down: %v", err)
	}
	if err := Migrate(ctx, s.pool); err != nil {
		t.Fatalf("up after down: %v", err)
	}
}

func TestBuiltinRolesSeeded(t *testing.T) {
	s := newStore(t)
	roles, err := s.ListRoles(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	var builtin []string
	for _, r := range roles {
		if r.Builtin {
			builtin = append(builtin, r.Name)
		}
	}
	slices.Sort(builtin)
	if !slices.Equal(builtin, []string{RoleAdmin, RoleDefault}) {
		t.Fatalf("builtin roles = %v", builtin)
	}
}

func TestLoginUser(t *testing.T) {
	s := newStore(t)
	ctx := t.Context()

	u, created, err := s.LoginUser(ctx, LoginProfile{Email: "a@x.com", Name: "A"}, false)
	if err != nil || !created {
		t.Fatalf("first login: created=%v err=%v", created, err)
	}
	if got := roleNames(t, s, u.ID); !slices.Equal(got, []string{RoleDefault}) {
		t.Fatalf("roles after first login = %v, want [default]", got)
	}
	if u.LastLoginAt == nil {
		t.Fatal("last_login_at not set")
	}

	// Admin removes the default role; a later login must not re-add it.
	defRole := mustRoleID(t, s, RoleDefault)
	if _, err := s.RemoveUserRole(ctx, db.RemoveUserRoleParams{UserID: u.ID, RoleID: defRole}); err != nil {
		t.Fatal(err)
	}

	u2, created, err := s.LoginUser(ctx, LoginProfile{Email: "a@x.com", Name: "A2", AvatarURL: "pic"}, false)
	if err != nil || created {
		t.Fatalf("second login: created=%v err=%v", created, err)
	}
	if u2.ID != u.ID || u2.Name != "A2" || u2.AvatarUrl != "pic" {
		t.Fatalf("profile not updated: %+v", u2)
	}
	if got := roleNames(t, s, u.ID); len(got) != 0 {
		t.Fatalf("roles after relogin = %v, want none", got)
	}

	// Bootstrap admin.
	if _, _, err := s.LoginUser(ctx, LoginProfile{Email: "a@x.com"}, true); err != nil {
		t.Fatal(err)
	}
	if got := roleNames(t, s, u.ID); !slices.Equal(got, []string{RoleAdmin}) {
		t.Fatalf("roles = %v, want [admin]", got)
	}
}

func TestLoadUserWithRoles(t *testing.T) {
	s := newStore(t)
	ctx := t.Context()
	u, _, _ := s.LoginUser(ctx, LoginProfile{Email: "l@x.com"}, true)
	got, roles, err := s.LoadUserWithRoles(ctx, u.ID)
	if err != nil || got.Email != "l@x.com" || len(roles) != 2 {
		t.Fatalf("got %+v roles=%v err=%v", got, roles, err)
	}
	if _, _, err := s.LoadUserWithRoles(ctx, 999999); !errors.Is(err, ErrNotFound) {
		t.Fatalf("missing user: err = %v, want ErrNotFound", err)
	}
}

func TestEmailMustBeLowercase(t *testing.T) {
	s := newStore(t)
	if _, _, err := s.LoginUser(t.Context(), LoginProfile{Email: "A@x.com"}, false); err == nil {
		t.Fatal("expected check constraint error for uppercase email")
	}
}

func TestRolesAndTags(t *testing.T) {
	s := newStore(t)
	ctx := t.Context()

	id, err := s.CreateRoleWithTags(ctx, "frontend", db.RolePermissionRead, []string{"Front", "prod", "front"})
	if err != nil {
		t.Fatal(err)
	}
	role, err := s.GetRole(ctx, id)
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(role.Tags, []string{"front", "prod"}) {
		t.Fatalf("tags = %v", role.Tags)
	}

	if _, err := s.CreateRoleWithTags(ctx, "frontend", db.RolePermissionRead, nil); !errors.Is(err, ErrConflict) {
		t.Fatalf("duplicate role: err = %v, want ErrConflict", err)
	}
	if _, err := s.CreateRoleWithTags(ctx, "bad", db.RolePermissionRead, []string{"no spaces!"}); err == nil {
		t.Fatal("expected invalid tag error")
	}

	if err := s.SetRoleTags(ctx, id, []string{"back"}); err != nil {
		t.Fatal(err)
	}
	role, _ = s.GetRole(ctx, id)
	if !slices.Equal(role.Tags, []string{"back"}) {
		t.Fatalf("tags after set = %v", role.Tags)
	}

	if err := s.SetRoleTags(ctx, 999999, nil); !errors.Is(err, ErrNotFound) {
		t.Fatalf("missing role: err = %v", err)
	}
}

func TestUpdateRoleWithTags(t *testing.T) {
	s := newStore(t)
	ctx := t.Context()
	id, _ := s.CreateRoleWithTags(ctx, "r1", db.RolePermissionRead, []string{"a"})
	_, _ = s.CreateRoleWithTags(ctx, "r2", db.RolePermissionRead, nil)

	if err := s.UpdateRoleWithTags(ctx, id, "r1-new", db.RolePermissionReadWrite, []string{"b", "c"}); err != nil {
		t.Fatal(err)
	}
	r, _ := s.GetRole(ctx, id)
	if r.Name != "r1-new" || r.Permission != db.RolePermissionReadWrite || !slices.Equal(r.Tags, []string{"b", "c"}) {
		t.Fatalf("role = %+v", r)
	}
	if err := s.UpdateRoleWithTags(ctx, id, "r2", db.RolePermissionRead, nil); !errors.Is(err, ErrConflict) {
		t.Fatalf("rename to existing: err = %v", err)
	}
	if err := s.UpdateRoleWithTags(ctx, mustRoleID(t, s, RoleAdmin), "x", db.RolePermissionRead, nil); !errors.Is(err, ErrBuiltinRole) {
		t.Fatalf("builtin: err = %v", err)
	}
	if err := s.UpdateRoleWithTags(ctx, 999999, "x", db.RolePermissionRead, nil); !IsNotFound(err) {
		t.Fatalf("missing: err = %v", err)
	}
	if _, err := s.GetUserByID(ctx, 999999); !IsNotFound(err) {
		t.Fatalf("IsNotFound(generated query) = false: %v", err)
	}
}

func TestBuiltinRolesAreProtected(t *testing.T) {
	s := newStore(t)
	ctx := t.Context()
	adminID := mustRoleID(t, s, RoleAdmin)

	if err := s.SetRoleTags(ctx, adminID, []string{"x"}); !errors.Is(err, ErrBuiltinRole) {
		t.Fatalf("set tags: err = %v, want ErrBuiltinRole", err)
	}
	if n, err := s.DeleteRole(ctx, adminID); err != nil || n != 0 {
		t.Fatalf("delete builtin: n=%d err=%v, want 0 rows", n, err)
	}
	if n, err := s.UpdateRole(ctx, db.UpdateRoleParams{ID: adminID, Name: "root", Permission: db.RolePermissionRead}); err != nil || n != 0 {
		t.Fatalf("update builtin: n=%d err=%v, want 0 rows", n, err)
	}
}

func TestListUserRolesIncludesTags(t *testing.T) {
	s := newStore(t)
	ctx := t.Context()
	u, _, _ := s.LoginUser(ctx, LoginProfile{Email: "u@x.com"}, false)
	rid, _ := s.CreateRoleWithTags(ctx, "rw", db.RolePermissionReadWrite, []string{"front", "prod"})
	if err := s.AddUserRole(ctx, db.AddUserRoleParams{UserID: u.ID, RoleID: rid}); err != nil {
		t.Fatal(err)
	}
	roles, err := s.ListUserRoles(ctx, u.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(roles) != 2 {
		t.Fatalf("roles = %+v", roles)
	}
	for _, r := range roles {
		switch r.Name {
		case RoleDefault:
			if len(r.Tags) != 0 {
				t.Errorf("default tags = %v", r.Tags)
			}
		case "rw":
			if r.Permission != db.RolePermissionReadWrite || !slices.Equal(r.Tags, []string{"front", "prod"}) {
				t.Errorf("rw role = %+v", r)
			}
		}
	}
}

func TestSecrets(t *testing.T) {
	s := newStore(t)
	ctx := t.Context()
	loc := map[string]string{"namespace": "front", "name": "api"}

	id, err := s.ImportSecret(ctx, "k8s", loc, []string{"front", "prod"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	// Same locator with different key order is still a duplicate (JSONB equality).
	if _, err := s.ImportSecret(ctx, "k8s", map[string]string{"name": "api", "namespace": "front"}, nil, nil); !errors.Is(err, ErrConflict) {
		t.Fatalf("duplicate import: err = %v, want ErrConflict", err)
	}

	sec, err := s.GetSecret(ctx, id)
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(sec.Tags, []string{"front", "prod"}) {
		t.Fatalf("tags = %v", sec.Tags)
	}

	if err := s.SetSecretTags(ctx, id, nil); err != nil {
		t.Fatal(err)
	}
	sec, _ = s.GetSecret(ctx, id)
	if len(sec.Tags) != 0 {
		t.Fatalf("tags after clear = %v", sec.Tags)
	}

	locs, err := s.ListSecretLocators(ctx, "k8s")
	if err != nil || len(locs) != 1 {
		t.Fatalf("locators = %v err = %v", locs, err)
	}

	if n, err := s.DeleteSecret(ctx, id); err != nil || n != 1 {
		t.Fatalf("delete: n=%d err=%v", n, err)
	}
	if err := s.SetSecretTags(ctx, id, nil); !errors.Is(err, ErrNotFound) {
		t.Fatalf("set tags on deleted: err = %v", err)
	}
}

func TestListTags(t *testing.T) {
	s := newStore(t)
	ctx := t.Context()
	_, _ = s.CreateRoleWithTags(ctx, "r", db.RolePermissionRead, []string{"front", "prod"})
	_, _ = s.ImportSecret(ctx, "k8s", map[string]string{"namespace": "a", "name": "b"}, []string{"prod", "back"}, nil)
	got, err := s.ListTags(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(got, []string{"back", "front", "prod"}) {
		t.Fatalf("tags = %v", got)
	}
}

func mustRoleID(t *testing.T, s *Store, name string) int64 {
	t.Helper()
	roles, err := s.ListRoles(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range roles {
		if r.Name == name {
			return r.ID
		}
	}
	t.Fatalf("role %q not found", name)
	return 0
}

package authz

import (
	"math/rand/v2"
	"slices"
	"testing"

	"github.com/kotoyants/secrets-ui/internal/auth"
	"github.com/kotoyants/secrets-ui/internal/store"
	"github.com/kotoyants/secrets-ui/internal/store/db"
)

const (
	R  = db.RolePermissionRead
	RW = db.RolePermissionReadWrite
)

func role(p db.RolePermission, tags ...string) Role { return Role{Permission: p, Tags: tags} }

func TestCan(t *testing.T) {
	tests := []struct {
		name      string
		admin     bool
		disabled  bool
		roles     []Role
		secret    []string
		wantRead  bool
		wantWrite bool
	}{
		// No roles / default role.
		{name: "no roles", secret: []string{"front"}},
		{name: "role without tags (default)", roles: []Role{role(R)}, secret: []string{"front"}},

		// Single role.
		{name: "read exact match", roles: []Role{role(R, "front")}, secret: []string{"front"}, wantRead: true},
		{name: "read_write exact match", roles: []Role{role(RW, "front")}, secret: []string{"front"}, wantRead: true, wantWrite: true},
		{name: "role has more tags than secret", roles: []Role{role(R, "front", "prod")}, secret: []string{"front"}, wantRead: true},
		{name: "role missing one secret tag", roles: []Role{role(RW, "front")}, secret: []string{"front", "prod"}},
		{name: "no overlap", roles: []Role{role(RW, "back")}, secret: []string{"front"}},

		// Union across roles (SPEC example 1).
		{name: "union of read roles", roles: []Role{role(R, "front"), role(R, "prod")}, secret: []string{"front", "prod"}, wantRead: true},
		{name: "union of read_write roles", roles: []Role{role(RW, "front"), role(RW, "prod")}, secret: []string{"front", "prod"}, wantRead: true, wantWrite: true},
		// Mixed permissions (SPEC example 2): prod only comes from a read role.
		{name: "write needs all tags from read_write roles", roles: []Role{role(RW, "front"), role(R, "prod")}, secret: []string{"front", "prod"}, wantRead: true},
		{name: "union still incomplete", roles: []Role{role(R, "front"), role(R, "prod")}, secret: []string{"front", "prod", "eu"}},

		// Untagged secrets are admin-only.
		{name: "untagged secret, user", roles: []Role{role(RW, "front")}, secret: nil},
		{name: "untagged secret, empty slice", roles: []Role{role(RW, "front")}, secret: []string{}},
		{name: "untagged secret, admin", admin: true, secret: nil, wantRead: true, wantWrite: true},

		// Admin and disabled.
		{name: "admin bypasses tags", admin: true, secret: []string{"anything"}, wantRead: true, wantWrite: true},
		{name: "disabled user", disabled: true, roles: []Role{role(RW, "front")}, secret: []string{"front"}},
		{name: "disabled admin", admin: true, disabled: true, secret: []string{"front"}},

		// Robustness.
		{name: "unknown permission grants nothing", roles: []Role{role("superuser", "front")}, secret: []string{"front"}},
		{name: "tags are case-sensitive (normalized upstream)", roles: []Role{role(RW, "front")}, secret: []string{"Front"}},
		{name: "duplicate secret tags", roles: []Role{role(R, "front")}, secret: []string{"front", "front"}, wantRead: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := NewSubject(tt.admin, tt.disabled, tt.roles)
			if got := s.CanRead(tt.secret); got != tt.wantRead {
				t.Errorf("CanRead = %v, want %v", got, tt.wantRead)
			}
			if got := s.CanWrite(tt.secret); got != tt.wantWrite {
				t.Errorf("CanWrite = %v, want %v", got, tt.wantWrite)
			}
		})
	}
}

func TestUnknownActionDenied(t *testing.T) {
	s := NewSubject(false, false, []Role{role(RW, "a")})
	if s.Can(Action(99), []string{"a"}) {
		t.Fatal("unknown action allowed")
	}
}

func TestFromPrincipal(t *testing.T) {
	if FromPrincipal(nil).CanRead([]string{"a"}) {
		t.Fatal("anonymous can read")
	}

	p := &auth.Principal{Roles: []db.ListUserRolesRow{
		{Name: store.RoleDefault, Builtin: true, Permission: R, Tags: []string{}},
		{Name: "front-rw", Permission: RW, Tags: []string{"front"}},
	}}
	s := FromPrincipal(p)
	if !s.CanWrite([]string{"front"}) || s.IsAdmin() {
		t.Fatal("principal roles not applied")
	}

	p.User.Disabled = true
	if FromPrincipal(p).CanRead([]string{"front"}) {
		t.Fatal("disabled principal can read")
	}

	admin := &auth.Principal{Roles: []db.ListUserRolesRow{{Name: store.RoleAdmin, Builtin: true, Permission: RW}}}
	if !FromPrincipal(admin).IsAdmin() || !FromPrincipal(admin).CanWrite(nil) {
		t.Fatal("admin not recognized")
	}

	// A non-builtin role that happens to be called "admin" grants nothing special.
	fake := &auth.Principal{Roles: []db.ListUserRolesRow{{Name: store.RoleAdmin, Builtin: false, Permission: RW}}}
	if FromPrincipal(fake).IsAdmin() {
		t.Fatal("non-builtin role named admin treated as admin")
	}
}

func TestFilter(t *testing.T) {
	type sec struct {
		name string
		tags []string
	}
	items := []sec{
		{"a", []string{"front"}},
		{"b", []string{"front", "prod"}},
		{"c", []string{"back"}},
		{"d", nil},
	}
	s := NewSubject(false, false, []Role{role(RW, "front"), role(R, "prod")})
	names := func(in []sec) []string {
		var out []string
		for _, i := range in {
			out = append(out, i.name)
		}
		return out
	}
	tagsOf := func(x sec) []string { return x.tags }

	if got := names(Filter(s, Read, items, tagsOf)); !slices.Equal(got, []string{"a", "b"}) {
		t.Errorf("read = %v", got)
	}
	if got := names(Filter(s, Write, items, tagsOf)); !slices.Equal(got, []string{"a"}) {
		t.Errorf("write = %v", got)
	}
}

// TestProperties checks invariants over random inputs against a brute-force reference.
func TestProperties(t *testing.T) {
	universe := []string{"a", "b", "c", "d", "e"}
	rng := rand.New(rand.NewPCG(1, 2))
	randTags := func() []string {
		var out []string
		for _, t := range universe {
			if rng.IntN(3) == 0 {
				out = append(out, t)
			}
		}
		return out
	}
	randRoles := func() []Role {
		n := rng.IntN(4)
		roles := make([]Role, n)
		for i := range roles {
			p := R
			if rng.IntN(2) == 0 {
				p = RW
			}
			roles[i] = role(p, randTags()...)
		}
		return roles
	}
	// Reference implementation written independently from the production code.
	reference := func(roles []Role, secret []string, write bool) bool {
		if len(secret) == 0 {
			return false
		}
		for _, st := range secret {
			found := false
			for _, r := range roles {
				if write && r.Permission != RW {
					continue
				}
				if slices.Contains(r.Tags, st) {
					found = true
				}
			}
			if !found {
				return false
			}
		}
		return true
	}

	for range 5000 {
		roles, secret := randRoles(), randTags()
		s := NewSubject(false, false, roles)
		read, write := s.CanRead(secret), s.CanWrite(secret)

		if read != reference(roles, secret, false) || write != reference(roles, secret, true) {
			t.Fatalf("mismatch with reference: roles=%v secret=%v read=%v write=%v", roles, secret, read, write)
		}
		if write && !read {
			t.Fatalf("write without read: roles=%v secret=%v", roles, secret)
		}
		// Monotonic: adding a role never removes access.
		more := NewSubject(false, false, append(slices.Clone(roles), randRoles()...))
		if (read && !more.CanRead(secret)) || (write && !more.CanWrite(secret)) {
			t.Fatalf("adding a role removed access: roles=%v secret=%v", roles, secret)
		}
		// Adding a tag to the secret never grants new access.
		if extra := append(slices.Clone(secret), randTags()...); !read && s.CanRead(extra) && len(secret) > 0 {
			t.Fatalf("adding secret tags granted access: roles=%v secret=%v extra=%v", roles, secret, extra)
		}
	}
}

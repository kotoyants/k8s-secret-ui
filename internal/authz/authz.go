// Package authz decides who may read or write a secret, based on tags.
//
// Rule (SPEC §4.1): a user's tags are the union of the tags of all their roles.
// A user may read a secret if the secret's tags are a subset of the tags from
// roles with read or read_write permission, and may write it if they are a subset
// of the tags from read_write roles only. Admins may do anything. Secrets without
// tags are admin-only. Disabled users may do nothing.
//
// This package is the single place where access decisions are made.
package authz

import (
	"github.com/kotoyants/k8s-secret-ui/internal/auth"
	"github.com/kotoyants/k8s-secret-ui/internal/store/db"
)

// Action is something a user can do with a secret.
type Action int

const (
	Read Action = iota
	Write
)

// Role is the authorization-relevant part of a role.
type Role struct {
	Permission db.RolePermission
	Tags       []string
}

// Subject is a user as seen by the access rules. Build it once per request.
type Subject struct {
	admin     bool
	disabled  bool
	readTags  map[string]struct{}
	writeTags map[string]struct{}
}

// NewSubject builds a Subject from its admin/disabled flags and roles.
func NewSubject(admin, disabled bool, roles []Role) Subject {
	s := Subject{admin: admin, disabled: disabled, readTags: map[string]struct{}{}, writeTags: map[string]struct{}{}}
	for _, r := range roles {
		switch r.Permission {
		case db.RolePermissionReadWrite:
			for _, t := range r.Tags {
				s.readTags[t] = struct{}{}
				s.writeTags[t] = struct{}{}
			}
		case db.RolePermissionRead:
			for _, t := range r.Tags {
				s.readTags[t] = struct{}{}
			}
		}
		// Unknown permissions grant nothing.
	}
	return s
}

// FromPrincipal builds a Subject for the authenticated user. A nil principal
// (anonymous) gets no access.
func FromPrincipal(p *auth.Principal) Subject {
	if p == nil {
		return NewSubject(false, true, nil)
	}
	roles := make([]Role, len(p.Roles))
	for i, r := range p.Roles {
		roles[i] = Role{Permission: r.Permission, Tags: r.Tags}
	}
	return NewSubject(p.IsAdmin(), p.User.Disabled, roles)
}

// IsAdmin reports whether the subject is an active admin.
func (s Subject) IsAdmin() bool { return s.admin && !s.disabled }

// Can reports whether the subject may perform action on a secret with secretTags.
func (s Subject) Can(action Action, secretTags []string) bool {
	if s.disabled {
		return false
	}
	if s.admin {
		return true
	}
	if len(secretTags) == 0 {
		return false // untagged secrets are admin-only
	}
	have := s.readTags
	switch action {
	case Read:
	case Write:
		have = s.writeTags
	default:
		return false
	}
	for _, t := range secretTags {
		if _, ok := have[t]; !ok {
			return false
		}
	}
	return true
}

// CanRead is shorthand for Can(Read, secretTags).
func (s Subject) CanRead(secretTags []string) bool { return s.Can(Read, secretTags) }

// CanWrite is shorthand for Can(Write, secretTags).
func (s Subject) CanWrite(secretTags []string) bool { return s.Can(Write, secretTags) }

// Filter returns the items the subject may perform action on. tagsOf extracts an item's tags.
func Filter[T any](s Subject, action Action, items []T, tagsOf func(T) []string) []T {
	out := make([]T, 0, len(items))
	for _, it := range items {
		if s.Can(action, tagsOf(it)) {
			out = append(out, it)
		}
	}
	return out
}

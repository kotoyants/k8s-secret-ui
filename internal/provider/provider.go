// Package provider defines the interface to external secret storages
// (Kubernetes now; AWS, GCP, Vault later) and a registry of configured providers.
//
// Provider-specific code lives in sub-packages; the rest of the app only uses
// the types in this package.
package provider

import (
	"context"
	"errors"
	"fmt"
	"maps"
	"slices"
	"strings"
)

var (
	ErrNotFound    = errors.New("secret not found in provider")
	ErrConflict    = errors.New("secret was changed by someone else; reload and try again")
	ErrForbidden   = errors.New("access to this location is not allowed")
	ErrUnsupported = errors.New("secret type is not supported")
	ErrInvalid     = errors.New("invalid secret data")
)

// SecretRef identifies a secret inside a provider. Locator is provider-specific
// (Kubernetes: {"namespace": ..., "name": ...}) and is stored as JSON in the DB.
type SecretRef struct {
	Provider string
	Locator  map[string]string
}

// String returns a stable human-readable form, e.g. "k8s:name=api,namespace=front".
func (r SecretRef) String() string {
	parts := make([]string, 0, len(r.Locator))
	for _, k := range slices.Sorted(maps.Keys(r.Locator)) {
		parts = append(parts, k+"="+r.Locator[k])
	}
	return r.Provider + ":" + strings.Join(parts, ",")
}

// External describes a tool that manages a secret (e.g. External Secrets, Helm).
// Changes made through this app may be overwritten by that tool.
type External struct {
	ManagedBy string // e.g. "ExternalSecret", "Helm", "Argo CD"; empty = not managed
}

// IsExternal reports whether the secret is managed by another tool.
func (e External) IsExternal() bool { return e.ManagedBy != "" }

// SecretInfo is a secret as listed for import (no values).
type SecretInfo struct {
	Ref   SecretRef
	Group string // grouping for the UI (Kubernetes: namespace)
	Name  string
	Keys  []string // sorted key names
	External
}

// SecretData is a secret's content.
type SecretData struct {
	Values  map[string][]byte
	Version string // opaque version for optimistic locking (Kubernetes: resourceVersion)
	External
}

// SortedKeys returns the value keys in sorted order.
func (d *SecretData) SortedKeys() []string { return slices.Sorted(maps.Keys(d.Values)) }

// Provider is a secret storage backend.
type Provider interface {
	// ID is the provider's identifier, stored with imported secrets.
	ID() string
	// Describe returns a display group and name for ref (Kubernetes: namespace, name).
	Describe(ref SecretRef) (group, name string)
	// List returns the secrets available for import.
	List(ctx context.Context) ([]SecretInfo, error)
	// Get reads a secret's values.
	Get(ctx context.Context, ref SecretRef) (*SecretData, error)
	// Update replaces a secret's values. data.Version must be the version from Get;
	// if the secret changed since then, ErrConflict is returned.
	Update(ctx context.Context, ref SecretRef, data *SecretData) error
}

// Registry holds the configured providers by ID.
type Registry struct{ providers map[string]Provider }

// NewRegistry builds a registry. Provider IDs must be unique.
func NewRegistry(ps ...Provider) (*Registry, error) {
	r := &Registry{providers: map[string]Provider{}}
	for _, p := range ps {
		if _, dup := r.providers[p.ID()]; dup {
			return nil, fmt.Errorf("duplicate provider id %q", p.ID())
		}
		r.providers[p.ID()] = p
	}
	return r, nil
}

// Get returns the provider with id.
func (r *Registry) Get(id string) (Provider, error) {
	p, ok := r.providers[id]
	if !ok {
		return nil, fmt.Errorf("unknown provider %q", id)
	}
	return p, nil
}

// All returns all providers sorted by ID.
func (r *Registry) All() []Provider {
	out := make([]Provider, 0, len(r.providers))
	for _, id := range slices.Sorted(maps.Keys(r.providers)) {
		out = append(out, r.providers[id])
	}
	return out
}

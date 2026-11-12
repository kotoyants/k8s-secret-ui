package provider

import (
	"context"
	"testing"
)

type stub struct{ id string }

func (s stub) ID() string                                         { return s.id }
func (stub) List(context.Context) ([]SecretInfo, error)           { return nil, nil }
func (stub) Get(context.Context, SecretRef) (*SecretData, error)  { return nil, nil }
func (stub) Update(context.Context, SecretRef, *SecretData) error { return nil }

func TestRegistry(t *testing.T) {
	r, err := NewRegistry(stub{"k8s"}, stub{"aws"})
	if err != nil {
		t.Fatal(err)
	}
	if p, err := r.Get("k8s"); err != nil || p.ID() != "k8s" {
		t.Fatalf("Get = %v, %v", p, err)
	}
	if _, err := r.Get("gcp"); err == nil {
		t.Fatal("expected unknown provider error")
	}
	if all := r.All(); len(all) != 2 || all[0].ID() != "aws" {
		t.Fatalf("All = %v", all)
	}
	if _, err := NewRegistry(stub{"x"}, stub{"x"}); err == nil {
		t.Fatal("expected duplicate id error")
	}
}

func TestSecretRefString(t *testing.T) {
	r := SecretRef{Provider: "k8s", Locator: map[string]string{"namespace": "a", "name": "b"}}
	if got := r.String(); got != "k8s:name=b,namespace=a" {
		t.Fatalf("String = %q", got)
	}
}

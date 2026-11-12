package k8s

import (
	"errors"
	"slices"
	"testing"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes/fake"
	k8stesting "k8s.io/client-go/testing"

	"github.com/kotoyants/k8s-secret-ui/internal/provider"
)

func secret(ns, name string, typ corev1.SecretType, data map[string]string, mod ...func(*corev1.Secret)) *corev1.Secret {
	s := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Namespace: ns, Name: name, ResourceVersion: "1"},
		Type:       typ,
		Data:       map[string][]byte{},
	}
	for k, v := range data {
		s.Data[k] = []byte(v)
	}
	for _, m := range mod {
		m(s)
	}
	return s
}

func newProvider(objs ...runtime.Object) (*Provider, *fake.Clientset) {
	cs := fake.NewClientset(objs...)
	return New(cs.CoreV1(), []string{"front", "back"}), cs
}

func fixtures() []runtime.Object {
	yes := true
	return []runtime.Object{
		secret("front", "api", corev1.SecretTypeOpaque, map[string]string{"TOKEN": "t", "URL": "u"}),
		secret("front", "tls", corev1.SecretTypeTLS, map[string]string{"tls.crt": "c", "tls.key": "k"}),
		secret("front", "es", corev1.SecretTypeOpaque, map[string]string{"A": "1"}, func(s *corev1.Secret) {
			s.OwnerReferences = []metav1.OwnerReference{{Kind: "ExternalSecret", Name: "es", Controller: &yes}}
		}),
		secret("back", "db", corev1.SecretTypeOpaque, map[string]string{"PASSWORD": "p"}, func(s *corev1.Secret) {
			s.Labels = map[string]string{"app.kubernetes.io/managed-by": "Helm"}
		}),
		secret("kube-system", "hidden", corev1.SecretTypeOpaque, map[string]string{"X": "x"}),
	}
}

func TestList(t *testing.T) {
	p, _ := newProvider(fixtures()...)
	got, err := p.List(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, s := range got {
		names = append(names, s.Group+"/"+s.Name)
	}
	// Sorted; TLS and other-namespace secrets excluded.
	if want := []string{"back/db", "front/api", "front/es"}; !slices.Equal(names, want) {
		t.Fatalf("names = %v, want %v", names, want)
	}
	byName := map[string]provider.SecretInfo{}
	for _, s := range got {
		byName[s.Name] = s
	}
	if !slices.Equal(byName["api"].Keys, []string{"TOKEN", "URL"}) || byName["api"].IsExternal() {
		t.Errorf("api = %+v", byName["api"])
	}
	if byName["es"].ManagedBy != "ExternalSecret" {
		t.Errorf("es ManagedBy = %q", byName["es"].ManagedBy)
	}
	if byName["db"].ManagedBy != "Helm" {
		t.Errorf("db ManagedBy = %q", byName["db"].ManagedBy)
	}
	if byName["api"].Ref.String() != "k8s:name=api,namespace=front" {
		t.Errorf("ref = %s", byName["api"].Ref)
	}
}

func TestListUsesOnlyAllowedNamespaces(t *testing.T) {
	p, cs := newProvider(fixtures()...)
	if _, err := p.List(t.Context()); err != nil {
		t.Fatal(err)
	}
	for _, a := range cs.Actions() {
		if ns := a.GetNamespace(); ns != "front" && ns != "back" {
			t.Errorf("unexpected API call in namespace %q: %v", ns, a)
		}
		if a.GetVerb() != "list" {
			t.Errorf("unexpected verb %s", a.GetVerb())
		}
	}
}

func TestGet(t *testing.T) {
	p, _ := newProvider(fixtures()...)
	ctx := t.Context()

	d, err := p.Get(ctx, Ref("front", "api"))
	if err != nil {
		t.Fatal(err)
	}
	if string(d.Values["TOKEN"]) != "t" || d.Version != "1" || !slices.Equal(d.SortedKeys(), []string{"TOKEN", "URL"}) {
		t.Fatalf("data = %+v", d)
	}

	tests := []struct {
		name string
		ref  provider.SecretRef
		want error
	}{
		{"missing", Ref("front", "nope"), provider.ErrNotFound},
		{"namespace not allowed", Ref("kube-system", "hidden"), provider.ErrForbidden},
		{"tls not supported", Ref("front", "tls"), provider.ErrUnsupported},
		{"wrong provider", provider.SecretRef{Provider: "aws", Locator: Ref("front", "api").Locator}, provider.ErrInvalid},
		{"empty name", Ref("front", ""), provider.ErrInvalid},
		{"extra locator key", provider.SecretRef{Provider: ID, Locator: map[string]string{"namespace": "front", "name": "api", "x": "y"}}, provider.ErrInvalid},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := p.Get(ctx, tt.ref); !errors.Is(err, tt.want) {
				t.Fatalf("err = %v, want %v", err, tt.want)
			}
		})
	}
}

func TestGetReturnsCopy(t *testing.T) {
	p, _ := newProvider(fixtures()...)
	d, _ := p.Get(t.Context(), Ref("front", "api"))
	d.Values["TOKEN"] = []byte("changed")
	d2, _ := p.Get(t.Context(), Ref("front", "api"))
	if string(d2.Values["TOKEN"]) != "t" {
		t.Fatal("Get returned shared map")
	}
}

func TestUpdate(t *testing.T) {
	p, cs := newProvider(fixtures()...)
	ctx := t.Context()

	d, _ := p.Get(ctx, Ref("back", "db"))
	d.Values = map[string][]byte{"PASSWORD": []byte("new"), "USER": []byte("app")}
	if err := p.Update(ctx, Ref("back", "db"), d); err != nil {
		t.Fatal(err)
	}
	s, err := cs.CoreV1().Secrets("back").Get(ctx, "db", metav1.GetOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if string(s.Data["PASSWORD"]) != "new" || string(s.Data["USER"]) != "app" || len(s.Data) != 2 {
		t.Fatalf("data = %v", s.Data)
	}
	if s.Labels["app.kubernetes.io/managed-by"] != "Helm" {
		t.Fatal("metadata not preserved")
	}
}

func TestUpdateRemovesKeys(t *testing.T) {
	p, cs := newProvider(fixtures()...)
	ctx := t.Context()
	d, _ := p.Get(ctx, Ref("front", "api"))
	delete(d.Values, "URL")
	if err := p.Update(ctx, Ref("front", "api"), d); err != nil {
		t.Fatal(err)
	}
	s, _ := cs.CoreV1().Secrets("front").Get(ctx, "api", metav1.GetOptions{})
	if _, ok := s.Data["URL"]; ok || len(s.Data) != 1 {
		t.Fatalf("data = %v", s.Data)
	}
}

func TestUpdateConflict(t *testing.T) {
	p, cs := newProvider(fixtures()...)
	ctx := t.Context()
	d, _ := p.Get(ctx, Ref("front", "api"))

	// Someone else changes the secret.
	s, _ := cs.CoreV1().Secrets("front").Get(ctx, "api", metav1.GetOptions{})
	s.ResourceVersion = "2"
	if _, err := cs.CoreV1().Secrets("front").Update(ctx, s, metav1.UpdateOptions{}); err != nil {
		t.Fatal(err)
	}

	if err := p.Update(ctx, Ref("front", "api"), d); !errors.Is(err, provider.ErrConflict) {
		t.Fatalf("err = %v, want ErrConflict", err)
	}
}

func TestUpdateConflictFromAPIServer(t *testing.T) {
	// The secret changes between our Get and Update: the API server rejects it.
	p, cs := newProvider(fixtures()...)
	cs.PrependReactor("update", "secrets", func(k8stesting.Action) (bool, runtime.Object, error) {
		return true, nil, errConflict()
	})
	d, _ := p.Get(t.Context(), Ref("front", "api"))
	if err := p.Update(t.Context(), Ref("front", "api"), d); !errors.Is(err, provider.ErrConflict) {
		t.Fatalf("err = %v, want ErrConflict", err)
	}
}

func TestUpdateRBACForbidden(t *testing.T) {
	p, cs := newProvider(fixtures()...)
	cs.PrependReactor("update", "secrets", func(k8stesting.Action) (bool, runtime.Object, error) {
		return true, nil, errForbidden()
	})
	d, _ := p.Get(t.Context(), Ref("front", "api"))
	if err := p.Update(t.Context(), Ref("front", "api"), d); !errors.Is(err, provider.ErrForbidden) {
		t.Fatalf("err = %v, want ErrForbidden", err)
	}
}

func TestUpdateValidation(t *testing.T) {
	p, _ := newProvider(fixtures()...)
	ctx := t.Context()
	d, _ := p.Get(ctx, Ref("front", "api"))

	bad := &provider.SecretData{Values: map[string][]byte{"bad key!": nil}, Version: d.Version}
	if err := p.Update(ctx, Ref("front", "api"), bad); !errors.Is(err, provider.ErrInvalid) {
		t.Fatalf("bad key: err = %v", err)
	}
	noVer := &provider.SecretData{Values: map[string][]byte{"A": nil}}
	if err := p.Update(ctx, Ref("front", "api"), noVer); !errors.Is(err, provider.ErrInvalid) {
		t.Fatalf("no version: err = %v", err)
	}
	if err := p.Update(ctx, Ref("kube-system", "hidden"), d); !errors.Is(err, provider.ErrForbidden) {
		t.Fatalf("forbidden ns: err = %v", err)
	}
	if err := p.Update(ctx, Ref("front", "tls"), d); !errors.Is(err, provider.ErrUnsupported) {
		t.Fatalf("tls: err = %v", err)
	}
}

func TestDetectExternal(t *testing.T) {
	yes := true
	tests := []struct {
		name string
		mod  func(*corev1.Secret)
		want string
	}{
		{"plain", func(*corev1.Secret) {}, ""},
		{"controller owner", func(s *corev1.Secret) {
			s.OwnerReferences = []metav1.OwnerReference{{Kind: "Foo"}, {Kind: "SealedSecret", Controller: &yes}}
		}, "SealedSecret"},
		{"non-controller owner", func(s *corev1.Secret) { s.OwnerReferences = []metav1.OwnerReference{{Kind: "Deployment"}} }, "Deployment"},
		{"argo cd", func(s *corev1.Secret) { s.Annotations = map[string]string{"argocd.argoproj.io/tracking-id": "x"} }, "Argo CD"},
		{"flux kustomize", func(s *corev1.Secret) { s.Labels = map[string]string{"kustomize.toolkit.fluxcd.io/name": "x"} }, "Flux"},
		{"flux helm", func(s *corev1.Secret) { s.Labels = map[string]string{"helm.toolkit.fluxcd.io/name": "x"} }, "Flux"},
		{"helm", func(s *corev1.Secret) { s.Labels = map[string]string{"app.kubernetes.io/managed-by": "Helm"} }, "Helm"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := secret("front", "x", corev1.SecretTypeOpaque, nil, tt.mod)
			if got := detectExternal(s).ManagedBy; got != tt.want {
				t.Fatalf("ManagedBy = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestNewClientRequiresContextOutsideCluster(t *testing.T) {
	t.Setenv("KUBERNETES_SERVICE_HOST", "")
	if _, _, err := NewClient(""); err == nil {
		t.Fatal("expected error without KUBE_CONTEXT outside a cluster")
	}
}

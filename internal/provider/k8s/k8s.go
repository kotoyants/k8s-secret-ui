// Package k8s implements provider.Provider for Kubernetes Secrets in the
// cluster the app runs in, limited to an allow-list of namespaces.
package k8s

import (
	"context"
	"errors"
	"fmt"
	"maps"
	"slices"
	"strings"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/validation"
	corev1client "k8s.io/client-go/kubernetes/typed/core/v1"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"

	"github.com/kotoyants/secrets-ui/internal/provider"
)

// ID is the provider ID stored with imported Kubernetes secrets.
const ID = "k8s"

const (
	locNamespace = "namespace"
	locName      = "name"
)

// Provider accesses Opaque Secrets in allowed namespaces.
type Provider struct {
	client     corev1client.SecretsGetter
	namespaces []string
}

var _ provider.Provider = (*Provider)(nil)

// New returns a Kubernetes provider limited to namespaces.
func New(client corev1client.SecretsGetter, namespaces []string) *Provider {
	return &Provider{client: client, namespaces: slices.Sorted(slices.Values(namespaces))}
}

// NewClient returns a client for the cluster the app runs in. Outside a cluster
// (local development) kubeContext must name a kubeconfig context explicitly, so
// the app never silently uses whatever context is current (e.g. production).
// Only the core/v1 client is built (all-group clients add ~40 MB to the binary).
func NewClient(kubeContext string) (corev1client.SecretsGetter, string, error) {
	cfg, err := rest.InClusterConfig()
	where := "in-cluster"
	if errors.Is(err, rest.ErrNotInCluster) {
		if kubeContext == "" {
			return nil, "", errors.New("not running in a cluster: set KUBE_CONTEXT to the kubeconfig context to use")
		}
		cfg, err = clientcmd.NewNonInteractiveDeferredLoadingClientConfig(
			clientcmd.NewDefaultClientConfigLoadingRules(),
			&clientcmd.ConfigOverrides{CurrentContext: kubeContext},
		).ClientConfig()
		where = "kubeconfig context " + kubeContext
	}
	if err != nil {
		return nil, "", fmt.Errorf("kubernetes config: %w", err)
	}
	client, err := corev1client.NewForConfig(cfg)
	if err != nil {
		return nil, "", fmt.Errorf("kubernetes client: %w", err)
	}
	return client, where, nil
}

// ID implements provider.Provider.
func (p *Provider) ID() string { return ID }

// Describe implements provider.Provider.
func (p *Provider) Describe(ref provider.SecretRef) (string, string) {
	return ref.Locator[locNamespace], ref.Locator[locName]
}

// Ref builds a SecretRef for namespace/name.
func Ref(namespace, name string) provider.SecretRef {
	return provider.SecretRef{Provider: ID, Locator: map[string]string{locNamespace: namespace, locName: name}}
}

// List implements provider.Provider. Only Opaque secrets in allowed namespaces are returned.
func (p *Provider) List(ctx context.Context) ([]provider.SecretInfo, error) {
	var out []provider.SecretInfo
	for _, ns := range p.namespaces {
		list, err := p.client.Secrets(ns).List(ctx, metav1.ListOptions{
			FieldSelector: "type=" + string(corev1.SecretTypeOpaque),
		})
		if err != nil {
			return nil, fmt.Errorf("list secrets in %s: %w", ns, mapErr(err))
		}
		for i := range list.Items {
			s := &list.Items[i]
			if s.Type != corev1.SecretTypeOpaque && s.Type != "" {
				continue // field selector is not honored by every client (e.g. fakes)
			}
			out = append(out, provider.SecretInfo{
				Ref:      Ref(s.Namespace, s.Name),
				Group:    s.Namespace,
				Name:     s.Name,
				Keys:     slices.Sorted(maps.Keys(s.Data)),
				External: detectExternal(s),
			})
		}
	}
	slices.SortFunc(out, func(a, b provider.SecretInfo) int {
		return strings.Compare(a.Group+"/"+a.Name, b.Group+"/"+b.Name)
	})
	return out, nil
}

// Get implements provider.Provider.
func (p *Provider) Get(ctx context.Context, ref provider.SecretRef) (*provider.SecretData, error) {
	ns, name, err := p.locate(ref)
	if err != nil {
		return nil, err
	}
	s, err := p.get(ctx, ns, name)
	if err != nil {
		return nil, err
	}
	return &provider.SecretData{
		Values:   maps.Clone(s.Data),
		Version:  s.ResourceVersion,
		External: detectExternal(s),
	}, nil
}

// Update implements provider.Provider. It replaces all data keys and keeps the
// secret's metadata. The update is rejected if the secret changed since data.Version.
func (p *Provider) Update(ctx context.Context, ref provider.SecretRef, data *provider.SecretData) error {
	ns, name, err := p.locate(ref)
	if err != nil {
		return err
	}
	if data.Version == "" {
		return fmt.Errorf("%w: missing version", provider.ErrInvalid)
	}
	for k := range data.Values {
		if errs := validation.IsConfigMapKey(k); len(errs) > 0 {
			return fmt.Errorf("%w: key %q: %s", provider.ErrInvalid, k, strings.Join(errs, "; "))
		}
	}

	s, err := p.get(ctx, ns, name)
	if err != nil {
		return err
	}
	if s.ResourceVersion != data.Version {
		return provider.ErrConflict
	}
	updated := s.DeepCopy()
	updated.Data = maps.Clone(data.Values)
	updated.StringData = nil
	// The API server also rejects the update if resourceVersion changed in between.
	if _, err := p.client.Secrets(ns).Update(ctx, updated, metav1.UpdateOptions{}); err != nil {
		return fmt.Errorf("update secret %s/%s: %w", ns, name, mapErr(err))
	}
	return nil
}

func (p *Provider) get(ctx context.Context, ns, name string) (*corev1.Secret, error) {
	s, err := p.client.Secrets(ns).Get(ctx, name, metav1.GetOptions{})
	if err != nil {
		return nil, fmt.Errorf("get secret %s/%s: %w", ns, name, mapErr(err))
	}
	if s.Type != corev1.SecretTypeOpaque && s.Type != "" {
		return nil, fmt.Errorf("%w: %s/%s has type %s", provider.ErrUnsupported, ns, name, s.Type)
	}
	return s, nil
}

// locate validates ref and returns its namespace and name.
func (p *Provider) locate(ref provider.SecretRef) (string, string, error) {
	if ref.Provider != ID {
		return "", "", fmt.Errorf("%w: ref for provider %q", provider.ErrInvalid, ref.Provider)
	}
	ns, name := ref.Locator[locNamespace], ref.Locator[locName]
	if ns == "" || name == "" || len(ref.Locator) != 2 {
		return "", "", fmt.Errorf("%w: locator must have exactly namespace and name", provider.ErrInvalid)
	}
	if _, ok := slices.BinarySearch(p.namespaces, ns); !ok {
		return "", "", fmt.Errorf("%w: namespace %q", provider.ErrForbidden, ns)
	}
	return ns, name, nil
}

func mapErr(err error) error {
	switch {
	case apierrors.IsNotFound(err):
		return fmt.Errorf("%w: %w", provider.ErrNotFound, err)
	case apierrors.IsConflict(err):
		return fmt.Errorf("%w: %w", provider.ErrConflict, err)
	case apierrors.IsForbidden(err):
		return fmt.Errorf("%w: %w", provider.ErrForbidden, err)
	}
	return err
}

// detectExternal recognizes secrets that are managed by another tool, which would
// overwrite changes made here.
func detectExternal(s *corev1.Secret) provider.External {
	for _, o := range s.OwnerReferences {
		if o.Controller != nil && *o.Controller {
			return provider.External{ManagedBy: o.Kind} // e.g. ExternalSecret, SealedSecret
		}
	}
	if len(s.OwnerReferences) > 0 {
		return provider.External{ManagedBy: s.OwnerReferences[0].Kind}
	}
	if _, ok := s.Annotations["argocd.argoproj.io/tracking-id"]; ok {
		return provider.External{ManagedBy: "Argo CD"}
	}
	if _, ok := s.Labels["kustomize.toolkit.fluxcd.io/name"]; ok {
		return provider.External{ManagedBy: "Flux"}
	}
	if _, ok := s.Labels["helm.toolkit.fluxcd.io/name"]; ok {
		return provider.External{ManagedBy: "Flux"}
	}
	if m := s.Labels["app.kubernetes.io/managed-by"]; m != "" {
		return provider.External{ManagedBy: m} // e.g. Helm
	}
	return provider.External{}
}

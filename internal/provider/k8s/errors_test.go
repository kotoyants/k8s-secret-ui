package k8s

import (
	"errors"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/runtime/schema"
)

var secretsGR = schema.GroupResource{Resource: "secrets"}

func errConflict() error {
	return apierrors.NewConflict(secretsGR, "api", errors.New("object was modified"))
}

func errForbidden() error {
	return apierrors.NewForbidden(secretsGR, "api", errors.New("rbac"))
}

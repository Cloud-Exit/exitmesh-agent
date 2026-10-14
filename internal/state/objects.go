package state

import (
	"context"
	"fmt"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/fields"
	"k8s.io/client-go/dynamic"

	"github.com/cloud-exit/exitmesh-agent/internal/redact"
)

const lastAppliedAnnotation = "kubectl.kubernetes.io/last-applied-configuration"

// LiveObject reads one object from the API server and returns it redacted by RedactObject; nil means it does not exist.
func (c *Collector) LiveObject(ctx context.Context, kind, namespace, name string) (map[string]any, error) {
	n := c.o.Tracker.Normalizer()
	s := n.kindSpec(kind)
	if s == nil {
		return nil, fmt.Errorf("kind %s is not collected", kind)
	}
	var ri dynamic.ResourceInterface = c.o.Dynamic.Resource(s.GVR)
	if s.Namespaced {
		ri = c.o.Dynamic.Resource(s.GVR).Namespace(namespace)
	}
	// The collector is granted list and watch only, so a named list stands in for get.
	list, err := ri.List(ctx, metav1.ListOptions{FieldSelector: fields.OneTermEqualSelector("metadata.name", name).String()})
	if err != nil {
		return nil, err
	}
	for i := range list.Items {
		u := &list.Items[i]
		if u.GetName() == name && (!s.Namespaced || u.GetNamespace() == namespace) {
			if u.GetKind() == "" {
				u.SetAPIVersion(s.GVR.GroupVersion().String())
				u.SetKind(s.APIKind)
			}
			return RedactObject(n.red, kind, u.Object), nil
		}
	}
	return nil, nil
}

// RedactObject replaces Secret and ConfigMap values, environment values, and secret-named fields with redact.Placeholder in place.
func RedactObject(red *redact.Redactor, kind string, obj map[string]any) map[string]any {
	if red == nil {
		red = redact.Default()
	}
	unstructured.RemoveNestedField(obj, "metadata", "managedFields")
	if ann := nestedMap(obj, "metadata", "annotations"); ann != nil {
		for k := range ann {
			if kind == KindSecret || k == lastAppliedAnnotation {
				ann[k] = redact.Placeholder
			}
		}
	}
	var valueMaps []string
	switch kind {
	case KindSecret:
		valueMaps = []string{"data", "stringData"}
	case KindConfigMap:
		valueMaps = []string{"data", "binaryData"}
	}
	for _, f := range valueMaps {
		m := nestedMap(obj, f)
		for k := range m {
			m[k] = redact.Placeholder
		}
	}
	redactTree(red, obj)
	return obj
}

func redactTree(red *redact.Redactor, m map[string]any) {
	for k, v := range m {
		switch x := v.(type) {
		case string:
			if red.IsSecretField(k) {
				m[k] = redact.Placeholder
			} else {
				m[k] = red.String(x)
			}
		case map[string]any:
			redactTree(red, x)
		case []any:
			if k == "env" {
				eachMap(x, func(e map[string]any) {
					if _, ok := e["value"]; ok {
						e["value"] = redact.Placeholder
					}
				})
			}
			redactList(red, x)
		}
	}
}

func redactList(red *redact.Redactor, l []any) {
	for i, v := range l {
		switch x := v.(type) {
		case string:
			l[i] = red.String(x)
		case map[string]any:
			redactTree(red, x)
		case []any:
			redactList(red, x)
		}
	}
}

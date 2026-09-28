package state

import (
	"context"
	"fmt"
	"sort"
	"strings"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes"
)

// Placement describes where the coordinator spool volume lives (PRD A8).
type Placement struct {
	Claim        string
	Volume       string
	StorageClass string
	AccessModes  []string
	Driver       string
	NodeAffinity string
	// PinnedNodes lists hostnames the volume is restricted to when affinity uses kubernetes.io/hostname.
	PinnedNodes []string
	Pinned      bool
	// Zonal reports affinity to a topology zone without pinning to one node.
	Zonal       bool
	Limitations []string
}

// Placement limitations reported on the connector.
const (
	LimitationPinned       = "volume is node-local (nodeAffinity): the coordinator is pinned to its node"
	LimitationZonal        = "volume is zonal (nodeAffinity): the coordinator can only be rescheduled within its zone"
	LimitationRWO          = "ReadWriteOnce without ReadWriteOncePod: single writer relies on the spool file lock"
	LimitationRWX          = "ReadWriteMany is not supported for the coordinator spool"
	LimitationNoAccessMode = "no access mode reported"
)

// ReadPlacement reads the coordinator's own claim and its bound PersistentVolume with get requests only.
func ReadPlacement(ctx context.Context, cs kubernetes.Interface, namespace, claim string) (Placement, error) {
	pvc, err := cs.CoreV1().PersistentVolumeClaims(namespace).Get(ctx, claim, metav1.GetOptions{})
	if err != nil {
		return Placement{}, fmt.Errorf("state: read claim %s/%s: %w", namespace, claim, err)
	}
	if pvc.Spec.VolumeName == "" {
		return Placement{}, fmt.Errorf("state: claim %s/%s is not bound", namespace, claim)
	}
	pv, err := cs.CoreV1().PersistentVolumes().Get(ctx, pvc.Spec.VolumeName, metav1.GetOptions{})
	if err != nil {
		return Placement{}, fmt.Errorf("state: read volume %s: %w", pvc.Spec.VolumeName, err)
	}
	p := PlacementFromVolume(pv)
	p.Claim = namespace + "/" + claim
	return p, nil
}

// PlacementFromVolume derives placement from a PersistentVolume.
func PlacementFromVolume(pv *corev1.PersistentVolume) Placement {
	p := Placement{Volume: pv.Name, StorageClass: pv.Spec.StorageClassName, AccessModes: accessModes(pv.Spec.AccessModes)}
	if m, err := runtime.DefaultUnstructuredConverter.ToUnstructured(pv); err == nil {
		p.Driver = pvDriver(&unstructured.Unstructured{Object: m})
	}
	p.NodeAffinity = NodeAffinitySummary(pv.Spec.NodeAffinity)
	if na := pv.Spec.NodeAffinity; na != nil && na.Required != nil {
		for _, t := range na.Required.NodeSelectorTerms {
			for _, r := range t.MatchExpressions {
				if r.Operator != corev1.NodeSelectorOpIn {
					continue
				}
				switch {
				case r.Key == corev1.LabelHostname:
					p.PinnedNodes = append(p.PinnedNodes, r.Values...)
				case strings.HasSuffix(r.Key, "/zone"):
					p.Zonal = true
				}
			}
			for _, r := range t.MatchFields {
				if r.Operator == corev1.NodeSelectorOpIn && r.Key == "metadata.name" {
					p.PinnedNodes = append(p.PinnedNodes, r.Values...)
				}
			}
		}
	}
	p.PinnedNodes = sortedUnique(p.PinnedNodes)
	p.Pinned = len(p.PinnedNodes) > 0
	if p.Pinned {
		p.Limitations = append(p.Limitations, LimitationPinned)
	} else if p.Zonal {
		p.Limitations = append(p.Limitations, LimitationZonal)
	}
	modes := map[string]bool{}
	for _, m := range p.AccessModes {
		modes[m] = true
	}
	switch {
	case modes[string(corev1.ReadWriteMany)]:
		p.Limitations = append(p.Limitations, LimitationRWX)
	case modes[string(corev1.ReadWriteOncePod)]:
	case modes[string(corev1.ReadWriteOnce)]:
		p.Limitations = append(p.Limitations, LimitationRWO)
	case len(modes) == 0:
		p.Limitations = append(p.Limitations, LimitationNoAccessMode)
	}
	sort.Strings(p.Limitations)
	return p
}

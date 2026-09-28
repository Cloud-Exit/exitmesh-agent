package state

import (
	"context"
	"slices"
	"testing"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/fake"

	"github.com/cloud-exit/exitmesh-agent/internal/config"
	"github.com/cloud-exit/exitmesh-agent/internal/redact"
)

func TestPlacementDetectsNodeAffinityPinning(t *testing.T) {
	pv := fixturePV()
	claim := &corev1.PersistentVolumeClaim{ObjectMeta: metav1.ObjectMeta{Name: "data-coordinator-0", Namespace: "exitmesh"},
		Spec: corev1.PersistentVolumeClaimSpec{VolumeName: pv.Name}}
	unbound := &corev1.PersistentVolumeClaim{ObjectMeta: metav1.ObjectMeta{Name: "pending", Namespace: "exitmesh"}}
	cs := fake.NewClientset(pv, claim, unbound)
	p, err := ReadPlacement(context.Background(), cs, "exitmesh", "data-coordinator-0")
	if err != nil {
		t.Fatal(err)
	}
	if !p.Pinned || !slices.Equal(p.PinnedNodes, []string{"node-a"}) || p.Driver != "local" || p.Volume != "pv-data" ||
		p.Claim != "exitmesh/data-coordinator-0" || p.NodeAffinity != "kubernetes.io/hostname in (node-a)" || p.StorageClass != "fast" {
		t.Fatalf("placement %+v", p)
	}
	if !slices.Equal(p.Limitations, []string{LimitationPinned}) {
		t.Fatalf("limitations %v", p.Limitations)
	}
	if _, err := ReadPlacement(context.Background(), cs, "exitmesh", "pending"); err == nil {
		t.Fatal("unbound claim accepted")
	}
	if _, err := ReadPlacement(context.Background(), cs, "exitmesh", "missing"); err == nil {
		t.Fatal("missing claim accepted")
	}
	for _, a := range cs.Actions() {
		if a.GetVerb() != "get" {
			t.Fatalf("placement used verb %s", a.GetVerb())
		}
	}
}

func TestPlacementAccessModes(t *testing.T) {
	cases := []struct {
		modes []corev1.PersistentVolumeAccessMode
		want  []string
	}{
		{[]corev1.PersistentVolumeAccessMode{corev1.ReadWriteOncePod}, nil},
		{[]corev1.PersistentVolumeAccessMode{corev1.ReadWriteOnce}, []string{LimitationRWO}},
		{[]corev1.PersistentVolumeAccessMode{corev1.ReadWriteMany, corev1.ReadWriteOnce}, []string{LimitationRWX}},
		{nil, []string{LimitationNoAccessMode}},
	}
	for _, c := range cases {
		pv := &corev1.PersistentVolume{ObjectMeta: metav1.ObjectMeta{Name: "v"}, Spec: corev1.PersistentVolumeSpec{AccessModes: c.modes,
			PersistentVolumeSource: corev1.PersistentVolumeSource{CSI: &corev1.CSIPersistentVolumeSource{Driver: "ebs.csi.aws.com", VolumeHandle: "vol-1"}}}}
		p := PlacementFromVolume(pv)
		if !slices.Equal(p.Limitations, c.want) || p.Pinned || p.Driver != "ebs.csi.aws.com" {
			t.Fatalf("%v: %+v", c.modes, p)
		}
	}
	affinity := func(terms ...corev1.NodeSelectorTerm) *corev1.PersistentVolume {
		return &corev1.PersistentVolume{Spec: corev1.PersistentVolumeSpec{AccessModes: []corev1.PersistentVolumeAccessMode{corev1.ReadWriteOncePod},
			NodeAffinity: &corev1.VolumeNodeAffinity{Required: &corev1.NodeSelector{NodeSelectorTerms: terms}}}}
	}
	zoneTerm := corev1.NodeSelectorTerm{MatchExpressions: []corev1.NodeSelectorRequirement{{Key: corev1.LabelTopologyZone, Operator: corev1.NodeSelectorOpIn, Values: []string{"b", "a"}}}}
	p := PlacementFromVolume(affinity(zoneTerm))
	if p.Pinned || !p.Zonal || !slices.Equal(p.Limitations, []string{LimitationZonal}) || p.NodeAffinity != "topology.kubernetes.io/zone in (a,b)" {
		t.Fatalf("zonal %+v", p)
	}
	p = PlacementFromVolume(affinity(zoneTerm, corev1.NodeSelectorTerm{MatchFields: []corev1.NodeSelectorRequirement{{Key: "metadata.name", Operator: corev1.NodeSelectorOpIn, Values: []string{"node-c"}}}}))
	if !p.Pinned || !slices.Equal(p.PinnedNodes, []string{"node-c"}) || !slices.Equal(p.Limitations, []string{LimitationPinned}) ||
		p.NodeAffinity != "field:metadata.name in (node-c) || topology.kubernetes.io/zone in (a,b)" {
		t.Fatalf("field pinned %+v", p)
	}
}

func TestOptionsFromConfig(t *testing.T) {
	o := OptionsFromConfig(config.Kubernetes{LabelAllowlist: []string{"team"}, AnnotationAllowlist: []string{"a/*"}}, redact.Default())
	n, err := NewNormalizer(o)
	if err != nil {
		t.Fatal(err)
	}
	if !n.labelAllowed("team") || n.labelAllowed("app") || !n.annotationAllowed("a/b") {
		t.Fatal("config allowlists not applied")
	}
	d, _ := NewNormalizer(OptionsFromConfig(config.Kubernetes{}, nil))
	if !d.labelAllowed("app") || !d.labelAllowed("node-role.kubernetes.io/control-plane") || d.annotationAllowed("x") {
		t.Fatal("default allowlists")
	}
}

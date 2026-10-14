package state

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"

	"github.com/cloud-exit/exitmesh-agent/internal/redact"
)

func TestLiveObjectRedacts(t *testing.T) {
	sm := meta("web-secret", "shop", "sec-1")
	sm.Annotations["meta.helm.sh/release-name"] = "web"
	secret := &corev1.Secret{
		TypeMeta:   metav1.TypeMeta{APIVersion: "v1", Kind: "Secret"},
		ObjectMeta: sm, Type: corev1.SecretTypeOpaque,
		Data:       map[string][]byte{"token": []byte(secretLiteral)},
		StringData: map[string]string{"password": secretLiteral},
	}
	objs := append(fixtureObjects(t), toU(t, secret))
	env := newTestEnv(t, objs)
	col, err := NewCollector(CollectorOptions{Dynamic: env.dyn, Metadata: env.meta, Discovery: env.disc, Tracker: NewTracker(TrackerOptions{})})
	if err != nil {
		t.Fatal(err)
	}
	get := func(kind, ns, name string) (map[string]any, string) {
		t.Helper()
		obj, err := col.LiveObject(context.Background(), kind, ns, name)
		if err != nil {
			t.Fatal(err)
		}
		b, _ := json.Marshal(obj)
		for _, leak := range []string{secretLiteral, secretCMValue, "hunter2", "managedFields"} {
			if strings.Contains(string(b), leak) {
				t.Fatalf("%s %s leaks %q: %s", kind, name, leak, b)
			}
		}
		return obj, string(b)
	}

	pod, raw := get(KindPod, "shop", "web-abc-1")
	if pod["kind"] != "Pod" || !strings.Contains(raw, `"image":"nginx:1.25"`) || !strings.Contains(raw, `"secretName":"web-secret"`) ||
		!strings.Contains(raw, `"name":"API_TOKEN","valueFrom"`) || !strings.Contains(raw, `"example.com/owner":"alice"`) {
		t.Fatalf("pod structure lost: %s", raw)
	}
	env0, _, _ := unstructured.NestedSlice(pod, "spec", "containers")
	if e := env0[0].(map[string]any)["env"].([]any)[0].(map[string]any); e["name"] != "DB_PASSWORD" || e["value"] != redact.Placeholder {
		t.Fatalf("env value %v", e)
	}
	if v, _, _ := unstructured.NestedString(pod, "metadata", "annotations", lastAppliedAnnotation); v != redact.Placeholder {
		t.Fatalf("last-applied %q", v)
	}

	cm, _ := get(KindConfigMap, "shop", "web-config")
	if d, _, _ := unstructured.NestedStringMap(cm, "data"); d["mode"] != redact.Placeholder || d["db.password"] != redact.Placeholder {
		t.Fatalf("configmap data %v", d)
	}
	if d, _, _ := unstructured.NestedStringMap(cm, "binaryData"); d["cert.der"] != redact.Placeholder {
		t.Fatalf("configmap binaryData %v", d)
	}

	sec, _ := get(KindSecret, "shop", "web-secret")
	if d, _, _ := unstructured.NestedStringMap(sec, "data"); len(d) != 1 || d["token"] != redact.Placeholder {
		t.Fatalf("secret data %v", d)
	}
	if d, _, _ := unstructured.NestedStringMap(sec, "metadata", "annotations"); d["meta.helm.sh/release-name"] != redact.Placeholder {
		t.Fatalf("secret annotations %v", d)
	}
	if typ, _, _ := unstructured.NestedString(sec, "type"); typ != "Opaque" {
		t.Fatalf("secret type %q", typ)
	}

	if obj, err := col.LiveObject(context.Background(), KindPod, "other", "web-abc-1"); err != nil || obj != nil {
		t.Fatalf("other namespace %v %v", obj, err)
	}
	if _, err := col.LiveObject(context.Background(), "example.com/Unknown", "shop", "x"); err == nil {
		t.Fatal("unknown kind accepted")
	}
	for _, a := range env.dyn.Actions() {
		if a.GetVerb() != "list" {
			t.Fatalf("verb %s", a.GetVerb())
		}
	}
}

func TestRedactObjectSecretFields(t *testing.T) {
	obj := map[string]any{"spec": map[string]any{
		"clientSecret": "abc", "secretName": "keep", "args": []any{"--token=abcdef"},
		"template": map[string]any{"env": []any{map[string]any{"name": "X", "value": "v"}}},
	}}
	RedactObject(nil, "example.com/Widget", obj)
	var buf strings.Builder
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(obj); err != nil {
		t.Fatal(err)
	}
	b := strings.TrimSpace(buf.String())
	want := `{"spec":{"args":["--token=<redacted>"],"clientSecret":"<redacted>","secretName":"keep","template":{"env":[{"name":"X","value":"<redacted>"}]}}}`
	if b != want {
		t.Fatalf("got %s", b)
	}
}

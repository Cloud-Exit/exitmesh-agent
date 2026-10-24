package node

import (
	"errors"
	"testing"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/cloud-exit/exitmesh-agent/internal/config"
	"github.com/cloud-exit/exitmesh-agent/internal/kv"
)

func TestFactCachePrunesDeletedPodsDurably(t *testing.T) {
	s := kv.NewMemory()
	keys := []string{"container/ns/live/app", "container/ns/deleted/app", "container/ns/replaced/app", "node/node-a"}
	for _, k := range keys {
		if err := s.Put(k, []byte(`{"metric.cpu.p95_cores":1}`)); err != nil {
			t.Fatal(err)
		}
	}
	if err := s.Put(factUIDPrefix+keys[2], []byte("old-uid")); err != nil {
		t.Fatal(err)
	}
	a := &Agent{pods: newPodWatch(nil, "node-a", newNSScope(config.Kubernetes{}), func() {})}
	a.pods.upsert(&corev1.Pod{ObjectMeta: metav1.ObjectMeta{Namespace: "ns", Name: "live", UID: "live-uid"}, Spec: corev1.PodSpec{NodeName: "node-a"}})
	a.pods.upsert(&corev1.Pod{ObjectMeta: metav1.ObjectMeta{Namespace: "ns", Name: "replaced", UID: "new-uid"}, Spec: corev1.PodSpec{NodeName: "node-a"}})
	if err := a.facts.load(s); err != nil {
		t.Fatal(err)
	}
	if err := a.pruneFacts(); err != nil {
		t.Fatal(err)
	}
	if _, ok, _ := s.Get(keys[1]); !ok {
		t.Fatal("unsynced pod watch removed persisted facts")
	}
	a.pods.ready.Store(true)
	a.facts.store = failingFactStore{s}
	if err := a.pruneFacts(); err == nil {
		t.Fatal("failed persistence was ignored")
	}
	if len(a.facts.last) != len(keys) {
		t.Fatal("failed persistence changed the live cache")
	}
	a.facts.store = s
	if err := a.pruneFacts(); err != nil {
		t.Fatal(err)
	}
	var restored factState
	if err := restored.load(s); err != nil {
		t.Fatal(err)
	}
	if len(restored.last) != 2 || restored.last[keys[0]] == nil || restored.last[keys[3]] == nil || len(restored.lastUID) != 0 {
		t.Fatal("restart did not preserve only live pod and node facts")
	}
}

type failingFactStore struct{ kv.Store }

func (failingFactStore) Batch(map[string][]byte) error { return errors.New("write failed") }

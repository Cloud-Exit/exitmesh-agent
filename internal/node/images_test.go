package node

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/cloud-exit/exitmesh-agent/internal/imagesbom"
	"github.com/cloud-exit/exitmesh-agent/internal/imagesbom/imagesbomtest"
	"github.com/cloud-exit/exitmesh-agent/internal/nodeapi"
)

func (h *harness) setImageID(ns, name, container, imageID string) {
	h.t.Helper()
	ctx := context.Background()
	p, err := h.kube.CoreV1().Pods(ns).Get(ctx, name, metav1.GetOptions{})
	if err != nil {
		h.t.Fatal(err)
	}
	for i := range p.Status.ContainerStatuses {
		if p.Status.ContainerStatuses[i].Name == container {
			p.Status.ContainerStatuses[i].ImageID = imageID
		}
	}
	if _, err := h.kube.CoreV1().Pods(ns).UpdateStatus(ctx, p, metav1.UpdateOptions{}); err != nil {
		h.t.Fatal(err)
	}
}

func (h *harness) imageTask(id string, payload string) nodeapi.TaskResult {
	h.t.Helper()
	h.coord.addTask(nodeapi.Task{ID: id, Kind: nodeapi.TaskImageSBOM, Payload: []byte(payload), DeadlineMs: time.Now().Add(time.Minute).UnixMilli()})
	var res nodeapi.TaskResult
	h.waitFor("task "+id, func() bool {
		var ok bool
		res, ok = h.coord.result(id)
		return ok
	})
	return res
}

func (h *harness) imageResult(id, digest string) imagesbom.Result {
	h.t.Helper()
	res := h.imageTask(id, fmt.Sprintf(`{"digest":%q}`, digest))
	if res.Error != "" {
		h.t.Fatalf("task %s: %s", id, res.Error)
	}
	var out imagesbom.Result
	if err := json.Unmarshal(res.Payload, &out); err != nil {
		h.t.Fatal(err)
	}
	return out
}

func TestImageSBOMTask(t *testing.T) {
	store := imagesbomtest.ContentStore(t, t.TempDir())
	digest := imagesbomtest.AlpineImage(t, store)
	h := newHarness(t, options{realClock: true, extraTop: "imageInventory:\n  contentStore: " + store + "\n"})
	h.setImageID("prod", "web-1", "app", "registry.example/app@"+digest)
	h.setImageID("prod", "db-1", "db", "registry.example/db@sha256:"+strings.Repeat("b", 64))
	a := h.start()
	h.waitFor("pods observed", func() bool {
		return !strings.Contains(a.images.Get(digest).Reason, "has not listed its pods")
	})

	if r := h.imageResult("img-other", "sha256:"+strings.Repeat("b", 64)); r.Status != imagesbom.StatusUnavailable || r.Reason != "No running pod on node "+testNode+" uses image sha256:"+strings.Repeat("b", 64)+"." {
		t.Fatalf("pod on another node %+v", r)
	}
	var ready imagesbom.Result
	for i := 0; ; i++ {
		ready = h.imageResult(fmt.Sprintf("img-%d", i), digest)
		if ready.Status == imagesbom.StatusReady {
			break
		}
		if ready.Status != imagesbom.StatusPending || i > 500 {
			t.Fatalf("image result %+v", ready)
		}
		time.Sleep(20 * time.Millisecond)
	}
	if len(ready.Packages) != 1 || ready.Packages[0].Ecosystem != imagesbomtest.AlpineEcosystem || ready.Packages[0].Name != imagesbomtest.AlpinePackage ||
		ready.Labels.Source != imagesbomtest.AlpineSource || ready.Digest != digest || ready.Truncated {
		t.Fatalf("ready %+v", ready)
	}
	if res := h.imageTask("img-bad", `{"digest":"sha256:x","extra":1}`); res.Error == "" {
		t.Fatalf("malformed payload accepted: %s", res.Payload)
	}
}

func TestImageSBOMTaskDisabled(t *testing.T) {
	h := newHarness(t, options{realClock: true, extraTop: "imageInventory:\n  enabled: false\n"})
	a := h.start()
	if a.images != nil {
		t.Fatal("inventory opened while disabled")
	}
	d := "sha256:" + strings.Repeat("c", 64)
	if r := h.imageResult("img-off", d); r.Status != imagesbom.StatusUnavailable || r.Reason != "Image inventory is disabled on node "+testNode+"." {
		t.Fatalf("disabled %+v", r)
	}
}

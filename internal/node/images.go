package node

import (
	"context"
	"encoding/json"
	"fmt"
	"path/filepath"
	"slices"
	"strings"

	corev1 "k8s.io/api/core/v1"

	"github.com/cloud-exit/exitmesh-agent/internal/imagesbom"
	"github.com/cloud-exit/exitmesh-agent/internal/nodeapi"
)

func (a *Agent) openImages() error {
	ii := a.cfg.ImageInventory
	if !ii.Active() {
		return nil
	}
	inv, err := imagesbom.New(imagesbom.Options{
		Node: a.node, ContentStore: ii.ContentStore, Dir: filepath.Join(a.cfg.StateDir, "sbom"),
		Limits: imagesbom.Limits{
			MaxLayerBytes: int64(ii.MaxLayerBytes), MaxFiles: ii.MaxFiles, MaxStagedBytes: int64(ii.MaxStagedBytes),
			MaxPackages: ii.MaxPackages, Timeout: ii.Timeout.D(),
		},
		CacheEntries: ii.CacheEntries, CacheBytes: int64(ii.CacheBytes),
		Redactor: a.red, Logger: a.log.With("component", "imagesbom"), Clock: a.clock,
	})
	if err != nil {
		return fmt.Errorf("node: image inventory: %w", err)
	}
	a.images = inv
	return nil
}

// podDigests returns the image digests the node's in-scope pods run.
func podDigests(pods []*corev1.Pod) []string {
	var out []string
	for _, p := range pods {
		for _, list := range [][]corev1.ContainerStatus{p.Status.InitContainerStatuses, p.Status.ContainerStatuses, p.Status.EphemeralContainerStatuses} {
			for _, s := range list {
				if d, ok := imagesbom.DigestFromImageID(s.ImageID); ok {
					out = append(out, d)
				}
			}
		}
	}
	slices.Sort(out)
	return slices.Compact(out)
}

// imageExecutor answers image_sbom tasks from the inventory and passes every other task on.
type imageExecutor struct {
	next   TaskExecutor
	images *imagesbom.Inventory
	node   string
}

func (e imageExecutor) Execute(ctx context.Context, t nodeapi.Task) nodeapi.TaskResult {
	if t.Kind != nodeapi.TaskImageSBOM {
		return e.next.Execute(ctx, t)
	}
	var req imagesbom.TaskRequest
	dec := json.NewDecoder(strings.NewReader(string(t.Payload)))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&req); err != nil {
		return nodeapi.TaskResult{ID: t.ID, Error: "invalid image_sbom payload: " + err.Error()}
	}
	if _, err := imagesbom.ParseDigest(req.Digest); err != nil {
		return nodeapi.TaskResult{ID: t.ID, Error: err.Error()}
	}
	res := imagesbom.Unavailable(req.Digest, fmt.Sprintf("Image inventory is disabled on node %s.", e.node))
	if e.images != nil {
		res = e.images.Get(req.Digest)
	}
	// Reserve space for the task ID and CBOR framing.
	res, err := imagesbom.Bound(res, 0, nodeapi.MaxRequestBytes-1024)
	if err != nil {
		return nodeapi.TaskResult{ID: t.ID, Error: err.Error()}
	}
	b, err := json.Marshal(res)
	if err != nil {
		return nodeapi.TaskResult{ID: t.ID, Error: err.Error()}
	}
	return nodeapi.TaskResult{ID: t.ID, Payload: b}
}

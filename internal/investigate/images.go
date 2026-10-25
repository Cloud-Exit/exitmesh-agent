package investigate

import (
	"cmp"
	"context"
	"encoding/json"
	"fmt"
	"slices"
	"strconv"
	"strings"
	"sync"

	"github.com/cloud-exit/exitmesh-agent/internal/imagesbom"
	"github.com/cloud-exit/exitmesh-agent/internal/nodeapi"
	"github.com/cloud-exit/exitmesh-agent/pkg/protocol"
)

// imageArgs carries the digest; the investigation envelope is optional and an absent scope is cluster-wide.
type imageArgs struct {
	RequestID string `json:"request_id,omitempty"`
	Requester string `json:"requester,omitempty"`
	Purpose   string `json:"purpose,omitempty"`
	Scope     *Scope `json:"scope,omitempty"`
	Limits    Limits `json:"limits"`
	Digest    string `json:"digest"`
}

type imagePart struct {
	node string
	res  imagesbom.Result
	// reason is set when the node gave no usable answer.
	reason string
}

func (s *Service) imageSBOM(ctx context.Context, raw json.RawMessage, rec *AuditRecord) (any, error) {
	var a imageArgs
	if err := decodeStrict(raw, &a); err != nil {
		return nil, err
	}
	rec.RequestID, rec.Requester, rec.Purpose = a.RequestID, a.Requester, a.Purpose
	if _, err := imagesbom.ParseDigest(a.Digest); err != nil {
		return nil, errorf(ClassInvalid, "%v", err)
	}
	req := Request{
		RequestID: a.RequestID, Requester: cmp.Or(a.Requester, "control plane"), Purpose: cmp.Or(a.Purpose, ToolImageSBOM),
		Scope: Scope{Cluster: true},
	}
	if a.Scope != nil {
		req.Scope = *a.Scope
	}
	if err := req.validate(); err != nil {
		return nil, err
	}
	rec.RequestID, rec.Scope = req.RequestID, req.Scope
	lim, err := clampLimits(a.Limits, s.o.Limits)
	if err != nil {
		return nil, err
	}
	rec.Limits = lim
	var st *protocol.State
	if s.o.State != nil {
		st = s.o.State()
	}
	scope, err := resolveScope(req.Scope, st)
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(ctx, lim.timeout())
	defer cancel()
	res := imagesbom.Redact(s.locateImage(ctx, req.RequestID, a.Digest, scope, st), s.o.Redactor)
	if res.Truncated && res.Reason == "" {
		res.Reason = "The image inventory is truncated, so the package list is incomplete."
	}
	res, err = imagesbom.Bound(res, lim.MaxLines, lim.MaxBytes)
	if err != nil {
		return nil, errorf(ClassInvalid, "%v", err)
	}
	rec.Truncated = res.Truncated
	if res.Reason != "" {
		rec.Limitations = 1
	}
	return res, nil
}

// runningOn returns the nodes whose in-scope pods run digest according to the current state.
func runningOn(st *protocol.State, digest string, scope *resolvedScope) []string {
	if st == nil {
		return nil
	}
	set := map[string]bool{}
	for _, r := range st.Resources {
		if r.Kind != kindPod || !scope.contains(r) {
			continue
		}
		for k, v := range r.Fields {
			id, ok := v.(string)
			if !ok || !isImageIDField(k) {
				continue
			}
			if d, ok := imagesbom.DigestFromImageID(id); ok && d == digest {
				node, _ := r.Fields["nodeName"].(string)
				set[node] = true
			}
		}
	}
	return setKeys(set)
}

func isImageIDField(k string) bool {
	return strings.HasSuffix(k, ".imageID") && (strings.HasPrefix(k, "containers.") || strings.HasPrefix(k, "initContainers."))
}

func (s *Service) locateImage(ctx context.Context, requestID, digest string, scope *resolvedScope, st *protocol.State) imagesbom.Result {
	var connected []string
	if s.o.Nodes != nil {
		connected = s.o.Nodes.Nodes()
	}
	running := runningOn(st, digest, scope)
	unscoped := scope.cluster && len(scope.namespaces)+len(scope.nodes)+len(scope.uids) == 0
	var targets []string
	switch {
	case len(running) == 0 && !unscoped:
		return imagesbom.Unavailable(digest, fmt.Sprintf("No pod inside the request scope runs image %s.", digest))
	case len(connected) == 0:
		return imagesbom.Unavailable(digest, fmt.Sprintf("No node agent is connected, so image %s cannot be read.", digest))
	case len(running) == 0:
		targets = connected
	default:
		for _, n := range running {
			if slices.Contains(connected, n) {
				targets = append(targets, n)
			}
		}
		if len(targets) == 0 {
			return imagesbom.Unavailable(digest, fmt.Sprintf("No node agent is connected on node %s, which runs image %s.", strings.Join(running, ", "), digest))
		}
	}
	parts := s.askImageNodes(ctx, requestID, digest, targets)
	var ready, truncated *imagesbom.Result
	pending := false
	reason := ""
	for i := range parts {
		p := &parts[i]
		switch {
		case p.reason != "":
			reason = cmp.Or(reason, p.reason)
		case p.res.Status == imagesbom.StatusReady && !p.res.Truncated:
			ready = cmp.Or(ready, &p.res)
		case p.res.Status == imagesbom.StatusReady:
			truncated = cmp.Or(truncated, &p.res)
		case p.res.Status == imagesbom.StatusPending:
			pending = true
		default:
			reason = cmp.Or(reason, p.res.Reason)
		}
	}
	switch {
	case ready != nil:
		return *ready
	case truncated != nil:
		return *truncated
	case pending:
		return imagesbom.Pending(digest)
	case len(running) == 0:
		return imagesbom.Unavailable(digest, fmt.Sprintf("No running pod in the cluster uses image %s, and no node agent holds its inventory.", digest))
	}
	return imagesbom.Unavailable(digest, cmp.Or(reason, fmt.Sprintf("No node agent returned an inventory of image %s.", digest)))
}

func (s *Service) askImageNodes(ctx context.Context, requestID, digest string, targets []string) []imagePart {
	payload, _ := json.Marshal(imagesbom.TaskRequest{Digest: digest})
	parts := make([]imagePart, len(targets))
	var wg sync.WaitGroup
	sem := make(chan struct{}, fanoutWorkers)
	for i, n := range targets {
		wg.Add(1)
		sem <- struct{}{}
		go func() {
			defer func() { <-sem; wg.Done() }()
			t := nodeapi.Task{ID: requestID + ".img." + strconv.Itoa(i), Kind: nodeapi.TaskImageSBOM, Payload: payload}
			if dl, ok := ctx.Deadline(); ok {
				t.DeadlineMs = dl.UnixMilli()
			}
			parts[i] = s.imagePart(ctx, n, digest, t)
		}()
	}
	wg.Wait()
	return parts
}

func (s *Service) imagePart(ctx context.Context, node, digest string, t nodeapi.Task) imagePart {
	p := imagePart{node: node}
	tr, err := s.o.Nodes.Run(ctx, node, t)
	switch {
	case err != nil:
		p.reason = fmt.Sprintf("The node agent on %s did not answer: %s.", node, strings.TrimSuffix(s.o.Redactor.String(err.Error()), "."))
		return p
	case tr.Error != "":
		p.reason = fmt.Sprintf("The node agent on %s cannot read images: %s.", node, strings.TrimSuffix(s.o.Redactor.String(tr.Error), "."))
		return p
	}
	if err := json.Unmarshal(tr.Payload, &p.res); err != nil || p.res.Digest != digest || !validImageStatus(p.res.Status) {
		p.reason = fmt.Sprintf("The node agent on %s returned an invalid image inventory.", node)
		return p
	}
	if p.res.Packages == nil {
		p.res.Packages = []imagesbom.Package{}
	}
	return p
}

func validImageStatus(s string) bool {
	return s == imagesbom.StatusReady || s == imagesbom.StatusPending || s == imagesbom.StatusUnavailable
}

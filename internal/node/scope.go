package node

import (
	"context"
	"encoding/json"
	"fmt"
	"regexp"
	"sort"
	"strings"

	"github.com/prometheus/prometheus/model/labels"

	"github.com/cloud-exit/exitmesh-agent/internal/config"
	"github.com/cloud-exit/exitmesh-agent/internal/investigate"
	"github.com/cloud-exit/exitmesh-agent/internal/nodeapi"
)

// nsScope is the administrator's namespace scope: the allowlist of the namespaces profile and the exclusions.
type nsScope struct {
	allow   []string // nil admits every namespace
	exclude []string
}

func newNSScope(k config.Kubernetes) nsScope {
	var s nsScope
	if k.Scope == "namespaces" {
		s.allow = sortedUnique(k.Namespaces)
	}
	s.exclude = sortedUnique(k.ExcludeNamespaces)
	return s
}

func sortedUnique(in []string) []string {
	out := make([]string, 0, len(in))
	seen := map[string]bool{}
	for _, v := range in {
		if v != "" && !seen[v] {
			seen[v] = true
			out = append(out, v)
		}
	}
	sort.Strings(out)
	return out
}

func (s nsScope) restricted() bool { return s.allow != nil || len(s.exclude) > 0 }

func (s nsScope) allows(ns string) bool {
	for _, x := range s.exclude {
		if x == ns {
			return false
		}
	}
	if s.allow == nil {
		return true
	}
	for _, x := range s.allow {
		if x == ns {
			return true
		}
	}
	return false
}

// watched is the namespaces the pod watch lists, or nil for one cluster-wide watch.
func (s nsScope) watched() []string {
	if s.allow == nil {
		return nil
	}
	out := []string{}
	for _, ns := range s.allow {
		if s.allows(ns) {
			out = append(out, ns)
		}
	}
	return out
}

// matchers express the scope as stream selector matchers on the namespace label.
func (s nsScope) matchers() ([]*labels.Matcher, error) {
	alt := func(ns []string) string {
		q := make([]string, len(ns))
		for i, n := range ns {
			q[i] = regexp.QuoteMeta(n)
		}
		return strings.Join(q, "|")
	}
	var out []*labels.Matcher
	if s.allow != nil {
		// An allowlist left empty by exclusions admits no stream; a NUL namespace never exists.
		v := "\x00"
		if w := s.watched(); len(w) > 0 {
			v = alt(w)
		}
		m, err := labels.NewMatcher(labels.MatchRegexp, investigate.NamespaceLabel, v)
		if err != nil {
			return nil, err
		}
		out = append(out, m)
	}
	if len(s.exclude) > 0 {
		m, err := labels.NewMatcher(labels.MatchNotRegexp, investigate.NamespaceLabel, alt(s.exclude))
		if err != nil {
			return nil, err
		}
		out = append(out, m)
	}
	return out, nil
}

// scopedExecutor bounds on-demand log and evidence reads on the node by the administrator's namespace scope.
type scopedExecutor struct {
	next  TaskExecutor
	scope nsScope
}

func (e scopedExecutor) Execute(ctx context.Context, t nodeapi.Task) nodeapi.TaskResult {
	if !e.scope.restricted() {
		return e.next.Execute(ctx, t)
	}
	switch t.Kind {
	case nodeapi.TaskLogQLQuery, nodeapi.TaskLogRead:
		p, err := e.scopeQuery(t.Payload)
		if err != nil {
			return nodeapi.TaskResult{ID: t.ID, Error: err.Error()}
		}
		t.Payload = p
		return e.next.Execute(ctx, t)
	case nodeapi.TaskEvidence:
		return e.filterEvidence(e.next.Execute(ctx, t))
	}
	return e.next.Execute(ctx, t)
}

// scopeQuery ANDs the scope into every stream selector, so out-of-scope streams are never opened.
func (e scopedExecutor) scopeQuery(payload []byte) ([]byte, error) {
	var q investigate.TaskQuery
	if err := json.Unmarshal(payload, &q); err != nil {
		return nil, fmt.Errorf("invalid task payload: %w", err)
	}
	m, err := e.scope.matchers()
	if err != nil {
		return nil, err
	}
	if q.Query, err = investigate.InjectLogQL(q.Query, m); err != nil {
		return nil, err
	}
	return json.Marshal(q)
}

func (e scopedExecutor) filterEvidence(res nodeapi.TaskResult) nodeapi.TaskResult {
	if res.Error != "" {
		return res
	}
	var resp investigate.TaskResponse
	if err := json.Unmarshal(res.Payload, &resp); err != nil {
		return nodeapi.TaskResult{ID: res.ID, Error: "evidence response not filtered by namespace scope: " + err.Error()}
	}
	keep := resp.Data.Lines[:0]
	for _, l := range resp.Data.Lines {
		if e.scope.allows(l.Labels[investigate.NamespaceLabel]) {
			keep = append(keep, l)
		}
	}
	resp.Data.Lines = keep
	b, err := json.Marshal(resp)
	if err != nil {
		return nodeapi.TaskResult{ID: res.ID, Error: err.Error()}
	}
	res.Payload = b
	return res
}

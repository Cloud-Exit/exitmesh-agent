package protocol

import (
	"encoding/base64"
	"sort"
)

// Readable renders a record with named fields for support and export inspection (PRD 7.4).
func Readable(r *Record, chainHash *Hash) map[string]any {
	out := map[string]any{
		"record_id":   r.ID().String(),
		"type":        r.Type.String(),
		"target_id":   r.TargetID,
		"epoch":       r.Epoch.String(),
		"seq":         r.Seq,
		"parent":      r.Parent,
		"base":        r.Base,
		"writer_id":   r.Writer.String(),
		"incarnation": r.Incarnation,
		"time_ms":     r.Time,
		"schema":      r.Schema,
		"record_hash": r.Hash().String(),
		"size_bytes":  len(r.Bytes()),
	}
	if chainHash != nil {
		out["chain_hash"] = chainHash.String()
	}
	if len(r.Ext) > 0 {
		keys := make([]uint64, 0, len(r.Ext))
		for k := range r.Ext {
			keys = append(keys, k)
		}
		sort.Slice(keys, func(i, j int) bool { return keys[i] < keys[j] })
		out["extension_keys"] = keys
	}
	switch r.Type {
	case TypeCheckpoint:
		c := r.Checkpoint
		res := make([]any, len(c.Resources))
		for i, x := range c.Resources {
			res[i] = map[string]any{"uid": x.UID, "kind": x.Kind, "namespace": x.Namespace, "name": x.Name, "fields": readableValue(x.Fields)}
		}
		edges := make([]any, len(c.Edges))
		for i, e := range c.Edges {
			edges[i] = map[string]any{"from": e.From, "type": e.Type, "to": e.To, "attrs": readableValue(e.Attrs)}
		}
		body := map[string]any{
			"reason": checkpointReasonName(c.Reason), "interval": []uint64{c.Interval.Start, c.Interval.End},
			"resources": res, "edges": edges, "scopes": readableScopes(c.Scopes), "capabilities": c.Capabilities,
			"state_hash": c.StateHash.String(),
		}
		if c.PrevEpoch != nil {
			body["prev_epoch"] = c.PrevEpoch.String()
		}
		if c.PrevHead != nil {
			body["prev_head"] = *c.PrevHead
		}
		out["checkpoint"] = body
	case TypeDelta:
		body := map[string]any{"ops": readableOps(r.Delta.Ops), "flags": r.Delta.Flags}
		if r.Delta.Uncertain != nil {
			body["uncertain"] = []uint64{r.Delta.Uncertain.Start, r.Delta.Uncertain.End}
		}
		out["delta"] = body
	case TypeRange:
		g := r.Range
		fs := make([]any, len(g.Findings))
		for i, f := range g.Findings {
			fs[i] = map[string]any{"seq": f.Seq, "finding": readableFinding(&f.Finding)}
		}
		body := map[string]any{"span": []uint64{g.From, g.To}, "ops": readableOps(g.Ops), "findings": fs, "flags": g.Flags}
		if g.From < g.To {
			body["unavailable"] = []uint64{g.From, g.To - 1}
		}
		out["range"] = body
	case TypeFinding:
		out["finding"] = readableFinding(r.Finding)
	}
	return out
}

func checkpointReasonName(r CheckpointReason) string {
	switch r {
	case ReasonInitial:
		return "initial"
	case ReasonAnchor:
		return "anchor"
	case ReasonRebaseline:
		return "rebaseline"
	case ReasonWriterChange:
		return "writer_change"
	case ReasonReplayAnchor:
		return "replay_anchor"
	}
	return "unknown"
}

func readableScopes(s map[string]ScopeStatus) map[string]any {
	out := make(map[string]any, len(s))
	for k, v := range s {
		out[k] = readableScope(v)
	}
	return out
}

func readableScope(v ScopeStatus) map[string]any {
	names := []string{"complete", "partial", "unavailable"}
	m := map[string]any{"state": "unknown"}
	if int(v.State) < len(names) {
		m["state"] = names[v.State]
	}
	if v.Reason != "" {
		m["reason"] = v.Reason
	}
	if v.Since != 0 {
		m["since_ms"] = v.Since
	}
	return m
}

func readableOps(ops []Op) []any {
	out := make([]any, len(ops))
	for i, o := range ops {
		m := map[string]any{"op": o.Kind.String()}
		switch o.Kind {
		case OpCreate:
			m["uid"], m["kind"], m["namespace"], m["name"], m["fields"] = o.UID, o.ResourceKind, o.Namespace, o.Name, readableValue(o.Fields)
		case OpUpdate:
			m["uid"], m["changes"] = o.UID, readableValue(o.Fields)
		case OpDelete:
			m["uid"] = o.UID
			m["reason"] = map[DeleteReason]string{DeleteDeleted: "deleted", DeleteScopeRemoved: "scope_removed"}[o.DeleteReason]
		case OpEdgeAdd, OpEdgeRemove, OpEdgeReplace:
			m["from"], m["type"], m["to"], m["attrs"] = o.UID, o.EdgeType, o.To, readableValue(o.Attrs)
			if o.Kind == OpEdgeReplace {
				m["prev_attrs"] = readableValue(o.PrevAttrs)
			}
		case OpScopeSet:
			m["scope"], m["status"] = o.ScopeKey, readableScope(o.Scope)
		}
		out[i] = m
	}
	return out
}

func readableFinding(f *Finding) map[string]any {
	prov := map[string]any{}
	if f.Provenance.Kind == ProvenanceQuery {
		prov["kind"], prov["query_hash"], prov["requester"] = "query", f.Provenance.QueryHash.String(), f.Provenance.Requester
	} else {
		prov["kind"], prov["rule_id"], prov["rule_version"], prov["bundle_version"] = "rule", f.Provenance.RuleID, f.Provenance.RuleVersion, f.Provenance.BundleVersion
	}
	ev := make([]any, len(f.Evidence))
	for i, e := range f.Evidence {
		m := map[string]any{"source": e.Source, "time_ms": e.Time, "text": e.Text}
		if e.Count != 0 {
			m["count"] = e.Count
		}
		if len(e.Labels) > 0 {
			m["labels"] = e.Labels
		}
		if e.Truncated {
			m["truncated"] = true
		}
		if e.Context {
			m["context"] = true
		}
		ev[i] = m
	}
	m := map[string]any{
		"finding_id": f.ID, "dedup_key": f.DedupKey, "transition": f.Transition.String(), "provenance": prov,
		"category": f.Category, "severity": f.Severity.String(), "eval_time_ms": f.EvalTime, "first_seen_ms": f.FirstSeen,
		"last_seen_ms": f.LastSeen, "count": f.Count, "resources": f.Resources, "evidence": ev, "flags": f.Flags,
	}
	for k, v := range map[string]any{"facts": f.Facts, "labels": f.Labels, "coverage": f.Coverage} {
		switch x := v.(type) {
		case map[string]any:
			if len(x) > 0 {
				m[k] = readableValue(x)
			}
		case map[string]string:
			if len(x) > 0 {
				m[k] = x
			}
		case []string:
			if len(x) > 0 {
				m[k] = x
			}
		}
	}
	for k, v := range map[string]string{"node": f.Node, "summary": f.Summary} {
		if v != "" {
			m[k] = v
		}
	}
	if len(f.Suggestions) > 0 {
		ss := make([]any, len(f.Suggestions))
		for i, s := range f.Suggestions {
			ss[i] = map[string]any{"language": s.Language, "query": s.Query, "source": s.Source}
		}
		m["suggestions"] = ss
	}
	return m
}

// readableValue renders byte strings as base64 text; everything else is JSON-compatible already.
func readableValue(v any) any {
	switch x := v.(type) {
	case []byte:
		return map[string]any{"base64": base64.StdEncoding.EncodeToString(x)}
	case []any:
		out := make([]any, len(x))
		for i, e := range x {
			out[i] = readableValue(e)
		}
		return out
	case map[string]any:
		out := make(map[string]any, len(x))
		for k, e := range x {
			if e == nil {
				out[k] = nil
				continue
			}
			out[k] = readableValue(e)
		}
		return out
	}
	return v
}

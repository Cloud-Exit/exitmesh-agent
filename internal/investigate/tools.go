package investigate

import "encoding/json"

func str(desc string) map[string]any { return map[string]any{"type": "string", "description": desc} }

func integer(desc string) map[string]any {
	return map[string]any{"type": "integer", "minimum": 0, "description": desc}
}

func strList(desc string) map[string]any {
	return map[string]any{"type": "array", "items": map[string]any{"type": "string"}, "description": desc}
}

func object(props map[string]any, required ...string) map[string]any {
	o := map[string]any{"type": "object", "properties": props, "additionalProperties": false}
	if len(required) > 0 {
		o["required"] = required
	}
	return o
}

var resourceRefSchema = object(map[string]any{
	"uid": str("resource UID"), "kind": str("resource kind, for example Pod or apps/Deployment"),
	"namespace": str("namespace of a namespaced resource"), "name": str("resource name"),
})

func commonProps() map[string]any {
	return map[string]any{
		"request_id": str("caller request id, 1 to 64 characters of [A-Za-z0-9_.:-]; generated when absent"),
		"requester":  str("identity of the user or AI agent issuing the request"),
		"purpose":    str("why the request is made; recorded in the audit trail"),
		"scope": object(map[string]any{
			"cluster":    map[string]any{"type": "boolean", "description": "the requester's scope is cluster-wide; required when no namespaces, resources, or nodes are named"},
			"namespaces": strList("namespaces the request is bound to"),
			"resources":  map[string]any{"type": "array", "items": resourceRefSchema, "description": "resources the request is bound to"},
			"nodes":      strList("nodes the request is bound to"),
		}),
		"window": object(map[string]any{"start": integer("start, Unix milliseconds"), "end": integer("end, Unix milliseconds")}, "start", "end"),
		"limits": object(map[string]any{
			"max_lines": integer("maximum lines or items"), "max_bytes": integer("maximum result bytes"),
			"max_series": integer("maximum series"), "max_samples": integer("maximum samples"),
			"timeout_ms": integer("call timeout in milliseconds"),
		}),
	}
}

func toolSchema(props map[string]any, required ...string) json.RawMessage {
	all := commonProps()
	for k, v := range props {
		all[k] = v
	}
	b, err := json.Marshal(object(all, append([]string{"requester", "purpose", "scope"}, required...)...))
	if err != nil {
		panic(err)
	}
	return b
}

var (
	stepProp      = integer("range query resolution in milliseconds; zero evaluates an instant query at window.end")
	directionProp = map[string]any{"type": "string", "enum": []string{"backward", "forward"}, "description": "line order; backward returns newest first"}
	sourceProp    = str("name of a configured lookback source")
)

const (
	stateDesc    = "Filter the current normalized state by kind, namespace, name, and field values, within the request scope."
	graphDesc    = "Traverse change-graph edges touching the given resources, by edge type and direction, depth-limited and within the request scope."
	promqlDesc   = "Run a scope-injected PromQL instant or range query against node agent TSDBs and coordinator series (or the host TSDB)."
	logqlDesc    = "Run a scope-injected LogQL query over on-demand bounded reads of node agent or host logs; streams need not be tailed by any rule."
	logsqlDesc   = "Run native LogsQL, parsed and scope-injected, against a configured VictoriaLogs lookback source."
	lookbackDesc = "Run the same validated PromQL, MetricsQL, or LogQL query against a configured external lookback source."
	evidenceDesc = "Read the redacted matched-line evidence that node agents (or the host) hold in memory for a rule, within the request scope and window, without consuming it."
	findingDesc  = "Re-run a validated query and save its result as a query-generated finding with query hash and requester provenance."
)

var (
	stateSchema = toolSchema(map[string]any{
		"kind": str("resource kind"), "namespace": str("namespace"), "name": str("resource name"),
		"fields": map[string]any{"type": "object", "description": "field path (dot separated) to required value"},
	})
	graphSchema = toolSchema(map[string]any{
		"from":       map[string]any{"type": "array", "items": resourceRefSchema, "description": "start resources; defaults to scope resources"},
		"edge_types": strList("edge types to follow; all when empty"),
		"depth":      map[string]any{"type": "integer", "minimum": 1, "maximum": maxGraphDepth, "description": "traversal depth"},
		"direction":  map[string]any{"type": "string", "enum": []string{"out", "in", "both"}},
	})
	promqlSchema   = toolSchema(map[string]any{"query": str("PromQL expression"), "step_ms": stepProp}, "query", "window")
	logqlSchema    = toolSchema(map[string]any{"query": str("LogQL expression in the published subset"), "step_ms": stepProp, "direction": directionProp}, "query", "window")
	logsqlSchema   = toolSchema(map[string]any{"source": sourceProp, "query": str("native LogsQL query"), "step_ms": stepProp}, "source", "query", "window")
	lookbackSchema = toolSchema(map[string]any{
		"source":   sourceProp,
		"language": map[string]any{"type": "string", "enum": []string{LangPromQL, LangMetricsQL, LangLogQL}},
		"query":    str("query in the given language"), "step_ms": stepProp, "direction": directionProp,
	}, "source", "language", "query", "window")
	evidenceSchema = toolSchema(map[string]any{"rule_id": str("rule whose evidence to read")}, "rule_id", "window")
	findingSchema  = toolSchema(map[string]any{
		"tool":      map[string]any{"type": "string", "enum": []string{ToolPromQL, ToolLogQL, ToolLogsQL, ToolLookback}},
		"query":     str("query to re-run"),
		"language":  map[string]any{"type": "string", "enum": []string{LangPromQL, LangMetricsQL, LangLogQL}, "description": "lookback.query language"},
		"source":    sourceProp,
		"step_ms":   stepProp,
		"direction": directionProp,
		"severity":  map[string]any{"type": "string", "enum": []string{"info", "low", "medium", "high", "critical"}},
		"summary":   str("finding summary"),
		"category":  str("finding category; defaults to investigation"),
		"labels":    map[string]any{"type": "object", "additionalProperties": map[string]any{"type": "string"}},
	}, "tool", "query", "window", "severity", "summary")
)

# Investigation

The coordinator (and the host agent) serves bounded investigation tools to ExitMesh as MCP tools over the reverse tunnel (SPEC 9.5) and to the local CLI through `POST /v1/investigate` on the admin socket. The implementation is `internal/investigate`. Results are returned and never retained, except when `finding.save` turns one into a query-generated finding.

## Request

Every tool call carries these fields; unknown fields are rejected.

|Field|Meaning|
|---|---|
|`request_id`|Optional, 1 to 64 characters of `[A-Za-z0-9_.:-]`; generated when absent. Node task IDs derive from it.|
|`requester`|Identity of the user or AI agent. Required.|
|`purpose`|Why the request is made. Required, recorded in the audit trail.|
|`scope`|`namespaces`, `resources` (each a `uid` or `kind`, `namespace`, `name`), `nodes`, and `cluster`. A scope with no namespaces, resources, or nodes is rejected unless `cluster` is true, which asserts that the requester's scope is cluster-wide.|
|`window`|`start` and `end` in Unix milliseconds, `start <= end`, at most `investigation.maxWindow` long, ending no more than five minutes in the future. Required for telemetry tools.|
|`limits`|`max_lines`, `max_bytes`, `max_series`, `max_samples`, `timeout_ms`. Zero means the configured maximum; larger values are clamped to `investigation.*` and the effective limits are returned with the result. Negative values are rejected.|

AI-generated queries take exactly this path: there is no separate validation mode, so an AI requester cannot widen scope, limits, or endpoints (PRD I9).

Resources are resolved in the current state; a resource that is not in state is rejected. For telemetry queries a resource binds its namespace (a `Namespace` resource binds its own name, a `Node` resource binds a node), so resource scope is namespace-granular for metrics and logs and exact for `state.query` and `graph.query`.

## Result

```json
{"source": "live", "window": {"start": 0, "end": 0}, "limits": {}, "truncated": false,
 "limitations": [], "query_hash": "...", "language": "promql", "query": "...",
 "executed_query": "...", "retention_ms": 0, "data": {}}
```

`query` is the scope-injected, re-serialized query; `query_hash` is `protocol.QueryHash(language, query, source)` and is the provenance of a saved finding. `executed_query` is present when the executed text differs (LogQL translated to LogsQL, LogsQL with the window filter). `retention_ms` is the in-cluster TSDB retention (the shortest reported by the node agents) or the lookback source retention. Telemetry `data` is `{result_type, series[], lines[], nodes[]}`: every series and line carries its `source` (`node/<name>`, `coordinator`, `host`, or the lookback source name), sample values are `[unix_ms, "value"]` so non-finite values survive JSON, and `nodes` lists each fan-out target as `ok`, `failed`, or `uncovered`.

## Tools

|Tool|Arguments beyond the request|Behavior|
|---|---|---|
|`state.query`|`kind`, `namespace`, `name`, `fields` (dot path to required value)|Filters the current normalized state to resources inside the scope. Items are bounded by `max_lines` and `max_bytes`. Collection scopes that are partial or unavailable for the asked kind and namespaces are limitations. A `namespace` outside the scope is rejected.|
|`graph.query`|`from`, `edge_types`, `depth` (1 to 5), `direction` (`out`, `in`, `both`)|Breadth-first traversal of change-graph edges from in-scope resources. Edges whose other end is outside the scope are omitted and counted as a limitation.|
|`promql.query`|`query`, `step_ms`|Coordinator: fan-out to node agents (`promql_query` tasks) and evaluation over the coordinator's `kube_*` and pushed series. Host: the local TSDB. Zero `step_ms` is an instant query at `window.end`; a range query has at most 11000 points per series.|
|`logql.query`|`query`, `step_ms` (metric queries), `direction`|Node agents perform on-demand bounded reads of `/var/log/pods` whether or not a rule tails the stream (PRD I1a); a bare stream selector runs as a `log_read` task. Host: allowlisted log files and the journal.|
|`logsql.query`|`source`, `query`, `step_ms` (stats queries)|Native LogsQL against a configured VictoriaLogs source, after parsing and scope injection.|
|`lookback.query`|`source`, `language` (`promql`, `metricsql`, `logql`), `query`, `step_ms`, `direction`|The same validated query against a configured external store.|
|`finding.save`|`tool`, `query`, `language`, `source`, `step_ms`, `direction`, `severity`, `summary`, `category`, `labels`|Re-runs the named query tool with identical validation and saves the result as a query-generated finding (provenance: query hash and requester) with up to 10 evidence samples. A query with no data is not saved.|

`Service.Tools()` returns the JSON schemas; every schema requires `requester`, `purpose`, and `scope` and forbids additional properties.

## Scope injection

Every query is parsed with its language's parser, scope is added at the AST, the AST is re-serialized, and the result is re-parsed and verified. A query the parser rejects is rejected. Nothing is concatenated into the user's query text. Scope never replaces a matcher; it is always ANDed, so a query naming another namespace returns nothing.

Scope labels are `namespace` and `node`. One value is an equality matcher; several are an anchored alternation of quoted literals (`namespace=~"a|b"`).

|Language|Parser|Injection|
|---|---|---|
|PromQL|`prometheus/promql/parser`|Matchers appended to every `VectorSelector`, which covers matrix selectors, subqueries, function arguments, and both binary operands. The `@` modifier is rejected. Offsets, ranges, and subquery ranges together may reach at most `maxWindow` before the evaluation time.|
|MetricsQL|`metricsql.Parse` (lookback to VictoriaMetrics only)|Filters appended to every or-group of every metric expression after `WITH` expansion, re-serialized with `AppendString`.|
|LogQL|`internal/rules/logql`|`logql.InjectScope` ANDs the matchers into every stream selector.|
|LogsQL|`logstorage.ParseQuery`|Stream filters `{namespace in (...)}` and `{node in (...)}` are built from quoted literals, parsed with `logstorage.ParseFilter`, and attached with `AddExtraFilters`, which ANDs them with the whole query and every subquery (`in(...)`, `union`, `join`). The window is attached with `AddTimeFilter`. The serialization must be a parser fixpoint.|

Node agents re-verify that every selector of a task carries the task's scope matchers and reject the task otherwise.

On a host the only node is the host itself: `nodes` may name only the host (no node matcher is injected), and `namespaces` are rejected.

## Limits and isolation

- A semaphore of `investigation.maxConcurrency` bounds concurrent calls; a call that cannot start before its timeout fails as `busy`. Every call has the effective `timeout_ms`.
- Node agent executors have their own semaphore and honor the task deadline. Node fan-out runs at most 16 tasks at once.
- PromQL runs on a per-query engine with `MaxSamples` and `Timeout` from the limits; exceeding the sample limit is a truncated result with a limitation.
- LogQL runs `logql.RunQuery` with line, byte, series, sample, and timeout limits. On-demand reads hold at most 50000 lines and 16 MiB and scan at most 256 MiB per task before the pipeline runs; lines cut by those bounds are disclosed as truncation. Host log files without a timestamp prefix (RFC 3339 or classic syslog) inherit the previous line's timestamp or the file modification time, which is disclosed.
- Series are sorted by source and labels, then cut at `max_series`, `max_samples`, and `max_bytes`; lines are ordered by direction and cut at `max_lines` and `max_bytes`.
- Investigation runs on the tunnel or admin request goroutines and on node agent task goroutines, never on the rule evaluation path.
- Log line text and label values are redacted with `internal/redact` before they leave the node and again before a result leaves the service.

Fan-out evaluates the query independently on each source. When a query aggregates or matches vectors and more than one source answered, the result says that series are per source and not combined across nodes.

## Lookback adapters

Sources come only from `lookback` configuration. A request naming an unconfigured source is rejected (`unauthorized`); redirects are never followed. Requests are read-only `GET`s with the configured credentials: a bearer token file or basic auth username and password files, reread on every request, and an optional CA file. Each source has its configured timeout (default 30 s) and at most 2 concurrent requests; responses are capped at four times `max_bytes` (at least 1 MiB, at most 64 MiB). URLs with embedded credentials are refused at startup.

|Type|Queries|Tenant|
|---|---|---|
|`prometheus`|PromQL: `/api/v1/query`, `/api/v1/query_range`|none|
|`mimir`|PromQL: `/prometheus/api/v1/query`, `/prometheus/api/v1/query_range`|`X-Scope-OrgID: <tenant>`|
|`victoriametrics`|PromQL or MetricsQL: single-node `/api/v1/query[_range]`; with `accountID`, cluster `/select/<accountID>[:<projectID>]/prometheus/api/v1/query[_range]`|path|
|`loki`|LogQL: `/loki/api/v1/query_range` for log and range metric queries, `/loki/api/v1/query` for instant metric queries|`X-Scope-OrgID: <tenant>`|
|`victorialogs`|LogsQL: `/select/logsql/query` for log queries, `/select/logsql/stats_query` and `/select/logsql/stats_query_range` for stats queries|`AccountID`, `ProjectID` headers|

LogQL sent to VictoriaLogs is first scope-injected as LogQL, then translated with `logql.ToLogsQL` (line filters become substring filters, parsers map only where semantics match, stream labels become stream fields and extracted labels become log fields), then scope and window are injected again at the LogsQL AST. Constructs without an exact mapping are rejected with the translator's reason. Range metric LogQL is rejected for VictoriaLogs because the translation yields instant stats queries.

Source retention is reported with every result: the configured `retention` when set, otherwise discovered once and cached (Prometheus `/api/v1/status/flags` `storage.tsdb.retention.time`; VictoriaMetrics single-node and VictoriaLogs `/flags` `retentionPeriod`, where a bare number is months). Mimir, Loki, and VictoriaMetrics cluster retention is unknown unless configured.

## Limitations

Missing sources, expired retention, unavailable endpoints, and insufficient authorization are limitations on a returned result, never an empty success.

|Condition|Limitation text|
|---|---|
|In-cluster window exceeded, no compatible lookback source|`the query reaches before the in-cluster window (retention <d>); historical search requires connecting the customer's own monitoring stack as a lookback source`|
|In-cluster window exceeded, lookback configured|`the query reaches before the in-cluster window (retention <d>); extend it with lookback.query against [<sources>]`|
|No lookback source configured|`no lookback source is configured; historical search requires connecting the customer's own monitoring stack as a lookback source`|
|Lookback retention exceeded|`the query reaches before the retention of lookback source <s> (<d>); older data has expired`|
|Lookback retention unknown|`the retention of lookback source <s> is unknown; expired data cannot be reported`|
|Endpoint failure|`lookback source <s>: endpoint unreachable: ...`, `endpoint unavailable (HTTP <code>)`, `redirect (HTTP <code>) not followed; only the configured endpoint is used`, `request timed out`|
|Authorization|`lookback source <s>: insufficient authorization (HTTP 401 or 403)`, or unreadable credential files|
|Upstream rejection|`lookback source <s>: query rejected (HTTP <code>): <message>`|
|Node failure|`node/<n>: query failed: <error>`|
|Uncovered node|`node <n> is not covered by a node agent; its data is missing`|
|No sources|`no node agents are connected and no coordinator series apply; no data was read`|
|Truncation|`series limit`, `sample limit`, `byte limit`, `line limit`, on-demand read bounds, response cap|
|State|`collection scope <scope key> is partial: <reason>` (or `unavailable`); `state.query answers from current state; the requested window is not reconstructed`|

## Audit

Every call, including rejected ones, produces one `AuditRecord` through `Options.Audit`, sent as `investigation.audit`: request id, time, requester, purpose, tool, language, query hash, scope, window, effective limits, source, outcome (`ok`, `limited`, `rejected`, `error`), truncation, number of limitations, error class (`invalid_request`, `unauthorized`, `unavailable`, `timeout`, `busy`, `source_rejected`, `internal`), duration, and whether a finding was retained. Records never contain query text, credentials, or result bodies.

## Node tasks

The coordinator sends `nodeapi.Task` values of kind `promql_query`, `logql_query`, or `log_read` whose payload is JSON `TaskQuery` (`query`, `start_ms`, `end_ms`, `step_ms`, `forward`, `namespaces`, `nodes`, `limits`). The node agent answers with JSON `TaskResponse` (`data`, `truncated`, `limitations`, `retention_ms`) in `TaskResult.Payload`, or `TaskResult.Error`. `Executor.Execute` retains nothing after the response.

## evidence.query

Reads the redacted matched-line evidence that node agents (or the host agent) hold in memory for a rule (PRD I1), filtered by the request scope's namespaces and nodes and by the window, newest first, bounded by `max_lines` and `max_bytes`. The read never consumes the evidence a finding will carry. Arguments: `rule_id` plus the common fields; `window` is required.

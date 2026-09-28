# PromQL rules

PromQL alerting rules use upstream Prometheus rule-group YAML unchanged. This page is the published reference for what the agent accepts (PRD R7, M3, M4, M7, M8) and how it evaluates it. Validation lives in `internal/rules/engine` (`ValidatePromQL`, `SplitPromQL`); a bundle containing a rule that fails validation is rejected as a whole and the last known good bundle stays active.

## Alerting semantics

Evaluation follows Prometheus `AlertingRule` exactly:

- A sample in the result starts a pending instance with `ActiveAt` set to the evaluation time. It fires once `for` has elapsed since `ActiveAt` (immediately when `for` is 0).
- A pending instance whose sample disappears is dropped without an event.
- A firing instance whose sample disappears keeps firing while less than `keep_firing_for` has passed since the first evaluation without the sample; the timer resets whenever the sample returns. After that it resolves.
- Instance labels are the sample labels without `__name__`, plus the rule labels, plus `alertname`. Two samples with the same resulting label set fail the evaluation.
- Label and annotation values substitute `{{ $labels.name }}`, `{{ .Labels.name }}`, `{{ $value }}`, and `{{ .Value }}`. Other template actions are left verbatim. The event summary is the rule metadata `summary`, or else the `summary` annotation.

Events carry the transitions `firing`, `update` (a firing instance whose annotations, summary, affected resources, or completeness changed, or that is seen again after being stale), `resolved`, and `stale`. Loss of inputs never resolves an instance:

- When the node's coverage (`Options.Coverage`) is warming or uncovered, observed samples still fire, but events are flagged incomplete and firing instances without a sample become `stale` instead of resolving.
- A rule that calls `absent` or `absent_over_time` is not evaluated at all while coverage is not complete, so an uncovered or warming node never produces an absent match.
- A rule that fails, or exceeds its budget, marks its firing instances stale.

Alert state is persisted in the key-value store after every cycle and restored on start. Firing instances are always restored. Pending instances keep the pending time accrued before the restart (their `ActiveAt` moves forward by the downtime) unless the downtime exceeds `OutageTolerance` (default 1h). A rule with `for` that has no resumed state reports `warming_up` until `for` has elapsed since it was loaded.

## Budgets

Each rule has a budget (`budget` in the rule metadata), with defaults and local policy caps applied:

|Field|Default|Enforced as|
|---|---|---|
|`max_eval_time`|10s|query context deadline and PromQL engine timeout|
|`max_samples`|1,000,000|PromQL engine sample limit|
|`max_series`|1,000|maximum result samples|
|`max_complexity`|500|maximum PromQL AST nodes, checked at validation|

A rule that exceeds its budget is skipped for `BudgetBackoff` (default 5m) and reported `budget_limited`; other rules continue.

## Grammar restrictions for every rule

- The expression must return a vector or a scalar.
- Every selector names its metric literally (`name{...}` or `{__name__="name"}`).
- The `@` modifier and negative offsets are rejected.
- Experimental functions are rejected by the parser.
- `kube_*` metrics must be in the published subset synthesized by the coordinator (see the field catalog). Any other `kube_*` metric is rejected with a pointer to the equivalent state rule, for example `kube_deployment_status_observed_generation is not in the published kube_* subset; express it as a state rule with kinds: [Deployment]`.

## Node-local rules

`scope: node` (the default) rules are evaluated by every node agent over its own TSDB and the node-scoped `kube_*` subset the coordinator pushes to it. Only pod-scoped `kube_pod_*` and that node's `kube_node_*` series are node-scoped, so a node-local rule may join only those. For example:

```promql
container_memory_working_set_bytes / on(namespace, pod, container) kube_pod_container_resource_limits > 0.9
```

A node-local rule referencing another `kube_*` family (such as `kube_deployment_*`) is rejected; express it as a cluster rule over `kube_*` series only, or as a state rule. On a host agent every rule is node-local.

## Cluster rules

`scope: cluster` rules take one of two forms.

**Coordinator-only.** Every selector is a published `kube_*` metric. The coordinator evaluates the expression as written over its synthesized series; any PromQL form is allowed except `absent` and `absent_over_time`.

**Decomposable.** The rule aggregates node telemetry across nodes. Node agents evaluate a node part and push pre-aggregated series; the coordinator evaluates the outer aggregation. The accepted shape is:

```
[scalar ops] OUTER [by (...) | without (...)] (INNER(selector[range]))
[scalar ops] histogram_quantile(φ, sum by (le, ...) (INNER(bucket_selector[range])))
```

- `OUTER` is `sum`, `count`, `min`, `max`, or `avg`.
- `INNER` is `rate`, `increase`, or any `*_over_time` function other than `absent_over_time`, applied directly to a range selector (no subqueries). Other `INNER` parameters, such as the quantile of `quantile_over_time`, must not select series.
- `scalar ops` is any chain of arithmetic or comparison operators (with or without `bool`) whose other operand selects no series.
- For `histogram_quantile`, the buckets must be summed per bucket: the grouping must keep `le`.

Rejected with a precise reason: `quantile`, `topk` and `bottomk` over raw series, `stddev`, `stdvar`, `group`, `count_values`, other aggregations, nested aggregations, binary operations between two vectors, raw series without an outer aggregation, `absent`, `absent_over_time`, functions other than `histogram_quantile` around the aggregation, and joins between node series and `kube_*` series.

### Decomposition

`SplitPromQL` returns `Split{NodeExpr, CoordExpr, Outer, Grouping, Without}`. Pushed series are named `exitmesh_split` and labeled `__exitmesh_rule__`, `__exitmesh_rule_version__`, and `__exitmesh_node__` (`PartSeries` adds them), so contributions from different nodes stay distinct and only contributions from the same rule version are combined.

|Outer|Node part|Coordinator|
|---|---|---|
|`sum`|`sum G (inner)`|`sum G (pushed)`|
|`count`|`count G (inner)`|`sum G (pushed)`|
|`min`|`min G (inner)`|`min G (pushed)`|
|`max`|`max G (inner)`|`max G (pushed)`|
|`avg`|`sum G (inner)` and `count G (inner)`, told apart by `__exitmesh_part__`|`sum G (sum part) / sum G (count part)`|

`G` is the rule's grouping; for `without` groupings the coordinator also drops the helper labels. Scalar operations and `histogram_quantile` are applied at the coordinator. Pushed parts carry float samples only, so histogram rules use classic `_bucket` series.

For example, `sum by (namespace) (rate(x[5m])) > 10` becomes:

```promql
# node
sum by (namespace) (rate(x[5m]))
# coordinator
(sum by (namespace) (exitmesh_split{__exitmesh_rule__="id",__exitmesh_rule_version__="1"})) > (10)
```

At the coordinator, `Options.ClusterCoverage` reports whether every connected node contributes on a compatible bundle version. When it does not, the rule still evaluates over the contributions it has, events are flagged incomplete, firing instances without a sample become stale, and the rule reports `converging` when the cause is version skew.

## Per-rule states

`RuleStates()` reports, in order of precedence: `disabled` (rule metadata or local policy), `unsupported` (needs a newer engine, an unavailable capability, or flagged by bundle validation), `budget_limited`, `failed`, `converging`, `stale` (last evaluation incomplete), `warming_up`, `evidence_limited`, and `active`.

## Missing input telemetry

Absence of data is never healthy (PRD G8). For every node-local or host PromQL rule, the engine records the scraped metric names it reads outside `absent` calls. When an evaluation finds no series for one of them within the lookback window, the rule state is `stale` with reason `no input series for <names>`, and firing instances become `stale` instead of `resolved`. A rule resolves only when its inputs are present and the condition no longer holds. Synthesized `kube_*` series are excluded, because their absence means the object or condition does not exist.

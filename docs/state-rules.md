# State rules

State rules are CEL predicates over the normalized state and change graph (PRD R3). The coordinator evaluates them (a host agent evaluates them over host state); node agents do not. Each rule is compiled when its bundle is loaded, and `ValidateCEL` performs the same compilation during bundle validation.

## Rule file

```yaml
- id: deployment-unavailable
  version: 1
  kinds: [Deployment]
  expr: field(r, "status.availableReplicas", 0) < field(r, "spec.replicas", 1)
  for: 10m
  keep_firing_for: 0s
  interval: 1m
  labels:
    team: platform                      # literal
    wanted: '=string(field(r, "spec.replicas", 0))'   # CEL expression
```

The rule is evaluated against every resource whose kind is listed in `kinds`. A true result is an alert instance keyed by the resource UID, with the `for` and `keep_firing_for` semantics of PromQL rules (see `docs/promql-rules.md`). Instance labels are `kind`, `namespace` (when set), and `name`, then the rule labels. A label value starting with `=` is a CEL expression evaluated in the same environment and rendered as a string; any other value is a literal. The event summary is the rule metadata `summary`, with `{{ $labels.x }}` substituted. `ResourceUIDs` holds the resource UID.

## Environment

|Name|Type|Meaning|
|---|---|---|
|`r`|`map(string, dyn)`|The resource: `uid`, `kind`, `namespace`, `name`, `fields` (the normalized field map).|
|`now`|`timestamp`|The evaluation time, UTC.|
|`field(r, path, default)`|`dyn`|The field at `path`: an exact key in `r.fields` first, then a dotted path through nested maps; `default` when absent or when the path crosses a non-map value.|
|`out(r, edgeType)`|`list(map(string, dyn))`|Resources that `r` has an outgoing edge of `edgeType` to, ordered by UID.|
|`in(r, edgeType)`|`list(map(string, dyn))`|Resources with an edge of `edgeType` to `r`, ordered by UID.|

Edge types and field names come from the field catalog (`docs/field-catalog.md`); `scheduled_on` below is illustrative. Related resources have the same shape as `r`, plus `edge`, the edge attributes. Edges to resources absent from state are skipped. `in` is a CEL keyword, so calls spelled `in(r, t)` are rewritten to an internal function name before compilation; the membership operator (`x in list`) and string literals are left untouched.

The standard CEL library is available with macros (`has`, `all`, `exists`, `exists_one`, `map`, `filter`), cross-type numeric comparisons (fields may be int, uint, or double), and the `strings` and `math` extensions. Timestamps and durations use `timestamp("...")`, `duration("...")`, and arithmetic with `now`.

## Budgets

|Field|Default|Enforced as|
|---|---|---|
|`max_eval_time`|10s|context deadline over the whole rule, checked by CEL interrupts|
|`max_samples`|1,000,000|CEL cost limit for each resource and for the sum over all resources in a cycle|
|`max_series`|1,000|maximum matching resources|
|`max_complexity`|500|CEL AST nodes of the expression plus all label expressions, checked at compile time|

A rule exceeding its budget is skipped for the backoff period and reported `budget_limited`; other rules continue.

## Incomplete evaluation

A state predicate that cannot be evaluated never resolves an instance; a firing instance becomes `stale` instead:

- a resource lacks one of the rule's `required_fields`;
- the scope covering the resource is `unavailable` (scope keys `[group/]Kind[|namespace]` by default, or `Options.ScopeMatch`);
- a firing instance's resource is gone while its scope is `partial` or `unavailable`;
- the CEL expression or a label expression errors for that resource (for example a missing map key without `has()` or `field()`);
- no state snapshot is available.

A resource that is gone while its scope is complete, or whose predicate is false, resolves normally after `keep_firing_for`. An expression that returns a non-bool value fails the rule.

## Examples

```cel
// CrashLoopBackOff waiting reason (kinds: [Pod])
field(r, "status.containerStatuses", []).exists(c, has(c.state.waiting) && c.state.waiting.reason == "CrashLoopBackOff")

// OOMKilled last termination (kinds: [Pod])
field(r, "status.containerStatuses", []).exists(c, has(c.lastState.terminated) && c.lastState.terminated.reason == "OOMKilled")

// Available replicas below desired, with for: 10m and required_fields: [spec.replicas] (kinds: [Deployment])
field(r, "status.availableReplicas", 0) < field(r, "spec.replicas", 1)

// PVC pending for more than 5 minutes (kinds: [PersistentVolumeClaim])
field(r, "status.phase", "") == "Pending" && now - timestamp(field(r, "metadata.creationTimestamp", "1970-01-01T00:00:00Z")) > duration("5m")

// Node Ready condition not True (kinds: [Node])
field(r, "status.conditions", []).exists(c, c.type == "Ready" && c.status != "True")

// Pod scheduled on a node that is not Ready (kinds: [Pod])
out(r, "scheduled_on").exists(n, field(n, "status.conditions", []).exists(c, c.type == "Ready" && c.status != "True"))

// Node hosting at least two pods (kinds: [Node])
size(in(r, "scheduled_on")) >= 2
```

Label expression naming the crash-looping container:

```yaml
labels:
  container: '=field(r, "status.containerStatuses", []).filter(c, has(c.state.waiting) && c.state.waiting.reason == "CrashLoopBackOff")[0].name'
```

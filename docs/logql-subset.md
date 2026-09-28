# Supported LogQL subset

This is the published grammar reference for LogQL in ExitMesh rule bundles and investigation queries (PRD L4, R7). It is implemented in `internal/rules/logql` without Loki code: the Loki engine and parser are never imported or linked. Queries outside this subset are rejected at bundle validation (rules) or before execution (investigation) with an error that names the construct and points to this document:

```
logql: unsupported construct pipeline stage "line_format" at position 12; see docs/logql-subset.md for the supported subset
```

Malformed input fails with `logql: parse error at position N: ...`. Semantics follow Loki; every difference known to the implementation is listed in [Differences from Loki](#differences-from-loki). The package is verified against a real Loki by `TestLokiDifferential`, which runs when `LOKI_URL` is set.

## Grammar

```ebnf
query          = log_query | metric_expr ;

log_query      = selector { pipeline_stage } | "(" log_query ")" ;
selector       = "{" matcher { "," matcher } [ "," ] "}" ;
matcher        = label_name ( "=" | "!=" | "=~" | "!~" ) string ;

pipeline_stage = line_filter
               | "|" "json" [ json_param { "," json_param } ]
               | "|" "logfmt"
               | "|" "pattern" string
               | "|" "regexp" string
               | "|" label_filter ;
line_filter    = ( "|=" | "!=" | "|~" | "!~" ) string ;
json_param     = label_name [ "=" string ] ;

label_filter   = label_and { "or" label_and } ;
label_and      = label_primary { [ "and" | "," ] label_primary } ;
label_primary  = "(" label_filter ")"
               | label_name ( "=" | "!=" | "=~" | "!~" ) string
               | label_name ( "==" | "=" | "!=" | ">" | ">=" | "<" | "<=" ) [ "-" | "+" ] ( number | duration | bytes ) ;

metric_expr    = operand { binary_op [ "bool" ] operand } ;
operand        = [ "-" | "+" ] number | "(" metric_expr ")" | range_agg | vector_agg ;
range_agg      = ( "count_over_time" | "rate" | "bytes_over_time" ) "(" log_range ")" ;
log_range      = selector { pipeline_stage } range
               | selector range { pipeline_stage }
               | "(" log_query ")" range ;
range          = "[" duration "]" ;
vector_agg     = agg_op [ grouping ] "(" [ integer "," ] metric_expr ")" [ grouping ] ;
agg_op         = "sum" | "count" | "min" | "max" | "avg" | "topk" ;
grouping       = ( "by" | "without" ) "(" [ label_name { "," label_name } [ "," ] ] ")" ;
binary_op      = "^" | "*" | "/" | "%" | "+" | "-" | "==" | "!=" | ">" | ">=" | "<" | "<=" ;
```

- Strings are double-quoted with Go escapes or backtick-quoted raw strings.
- `label_name` is `[a-zA-Z_][a-zA-Z0-9_]*`.
- `duration` is a Go duration (`250ms`, `1h30m`, `1.5s`, `250us`) or a Prometheus duration (`1d`, `1w`, `1y`).
- `bytes` is a number with a byte unit, parsed like go-humanize: `B`, `kB`/`KB`/`K` (1000), `KiB`/`Ki` (1024), and the same for M, G, T, P, E. Units are case-insensitive.
- A bare number after `=` or `==` is a numeric comparison; a string after `=` is a string match.
- `topk` requires a positive integer parameter; the other aggregations take none.
- Operator precedence, from loosest: comparisons, `+ -`, `* / %`, `^` (right-associative). A leading sign binds to the number literal, as in Loki. Label filters bind `and` (also written `,` or by juxtaposition) tighter than `or`.
- A binary operation needs at least one scalar side. Comparisons between two scalars need `bool`.
- A query must select log streams: a scalar-only expression is rejected.

## Canonical form

`Expr.String()` prints a canonical form that re-parses to an identical AST and that Loki accepts (checked by `TestLokiAcceptsCanonicalForms`): matchers separated by `", "`, strings double-quoted, `and` for every label conjunction, numeric equality as `==`, durations in Prometheus form when whole milliseconds (`1m30s`, `1d`) and Go form otherwise (`250µs`), byte sizes as an integer with `B` (`10KB` prints `10000B`), the range after the pipeline (`count_over_time({a="b"} |= "x" [5m])`), grouping before the arguments (`sum by (a) (...)`), and the minimum parentheses needed for precedence. `ParseExpr` returns the AST; `InjectScope` uses the printer to re-serialize.

## Semantics

### Stream selectors

Matchers have Prometheus semantics: regular expressions are fully anchored and `.` matches newlines; an absent label equals the empty string. Every selector needs at least one `=` or `=~` matcher that does not match the empty string, so `{app=~".*"}` is rejected and `{app=~".+"}` is accepted. Several matchers on the same label are all applied (AND).

### Line filters

`|= "s"` keeps lines containing the substring `s` (case-sensitive, byte-wise); `!= "s"` keeps lines that do not. `|= ""` keeps every line and `!= ""` keeps none. `|~ "re"` keeps lines matched anywhere by the RE2 regular expression `re` (unanchored, `.` does not match newlines unless the expression enables `(?s)`); `!~` keeps the others. Filters chain as AND and apply to the original line wherever they appear in the pipeline.

### Parsers and labels

Each line carries its stream labels and the labels extracted by parsers. An extracted label whose name is already a stream label is renamed with the `_extracted` suffix, so stream labels are never overwritten. A later parser overwrites labels extracted by an earlier one.

- `json` extracts every string, number and boolean value of a top-level JSON object (leading whitespace allowed). Nested object keys are joined with `_` (`{"resp":{"code":1}}` gives `resp_code`). Arrays and nulls are skipped. Keys are sanitized: characters outside `[a-zA-Z0-9_]` become `_` and a leading digit gets a `_` prefix. Strings are unescaped; numbers keep their literal text. An empty string value yields a label with an empty value. A line that is not a JSON object sets `__error__="JSONParserErr"` and extracts nothing.
- `json label="path", ...` extracts only the given paths (`a.b`, `a[0]`, `a["key with space"]`; a bare `label` means `label="label"`). The line must start with `{`, `[` or `"` and be valid JSON, otherwise `__error__="JSONParserErr"`. A missing path or null yields an empty value; objects yield their JSON text; arrays yield their JSON text with escapes decoded.
- `logfmt` extracts `key=value` pairs; quoted values are unescaped. Pairs with empty values and bare keys are skipped. A malformed pair (a key containing `"`, a key starting with `=`, an unquoted value containing `=` or `"`) is skipped up to the next whitespace; an unterminated quoted value ends the line. Keys are sanitized as for `json`. `logfmt` never sets `__error__`.
- `pattern "..."` uses `<name>` captures and `<_>` placeholders; every other character is literal. At least one named capture is required, captures cannot be adjacent, and names are unique. A leading literal must start the line. Each capture ends at the first occurrence of the following literal; when that literal is missing, a named capture takes the rest of the line and matching stops. A capture may be empty.
- `regexp "..."` applies an RE2 expression with at least one named group; names must be unique label names. When the expression matches (leftmost-first, unanchored), every named group sets its label (a non-participating group sets an empty value); otherwise nothing is extracted.

A label with an empty value is distinct from an absent label in results and series identity, as in Loki, but string matchers treat both as the empty string.

### Label filters

String filters (`=`, `!=`, `=~`, `!~`) use Prometheus matcher semantics on the current label value (absent labels are empty). Numeric filters parse the value as a float (`strconv.ParseFloat`), duration filters with Go `time.ParseDuration`, and byte filters with go-humanize rules. A missing label drops the line. A present value that does not parse keeps the line and sets `__error__="LabelFilterErr"` unless an error is already set. `and` evaluates both sides; `or` stops at the first true side.

`__error__` is filterable like any label: `| __error__=""` drops lines with parser or label filter errors, `| __error__!=""` keeps only those.

### Metric expressions

- `count_over_time(q [r])` counts lines per label set in the window `(t - r, t]`; `rate` is that count divided by `r` in seconds; `bytes_over_time` sums line lengths in bytes. The label set of each series is the stream labels plus extracted labels plus `__error__` when set. Series without lines in the window are absent.
- `sum`, `count` (number of series), `min`, `max`, `avg` group by the `by` labels (or all labels except the `without` labels); no grouping aggregates everything into one series with no labels. `topk(k, v)` keeps the k highest values per group (NaN lowest); ties are broken by label order.
- Arithmetic between a vector and a scalar applies to every sample. A comparison without `bool` keeps the samples for which it holds and their values; with `bool` it keeps every sample with value 1 or 0. Division by zero follows IEEE 754.
- Pipeline errors: a metric evaluation fails with `logql: pipeline error "JSONParserErr" ...` when a sample in the window carries `__error__`, unless the range aggregation sits directly under a `sum` (not `sum without`) whose grouping or label filters reference `__error__`. Error messages never contain label values or line content.

## Rules

`CompileRule(expr, budget)` accepts only metric queries (with a range of at least 1s) and evaluates them over per-series time-bucketed counters; lines are never retained (PRD R11, L5).

- Bucket width is `max(range / 60, 1s)`; the counter ring holds `ceil(range / width) + 1` buckets. Each bucket stores its index, a line count and a byte count (24 bytes).
- Counter memory is estimated as `buckets x MaxSeries x 24` bytes, with `MaxSeries` defaulting to 1000 and the budget `CounterBytes` defaulting to 4 MiB. A rule whose estimate exceeds its budget is rejected with a `BudgetError` naming the numbers. `MemoryBytes()` reports the estimate; `Budget.MaxComplexity`, when set, bounds the number of AST nodes.
- When a range aggregation sits directly under `sum`, counters are keyed by the summed labels, so `sum by (namespace) (...)` needs one series per namespace.
- A new series beyond `MaxSeries` is not created: its lines still report a match (for evidence) but are counted in `Status().DroppedLines`, and `Status().BudgetLimited` stays true while such a drop lies within the window (PRD R9). Lines older than the window are counted in `LateLines`. Series with no bucket in the window are removed, freeing cardinality.
- `Eval(t)` sums the buckets overlapping `(t - range, t]`, so the older edge of the window is rounded down to a bucket boundary: a line up to one bucket width older than `t - range` can still count. Rates divide by the exact range.
- `Matches(streamLabels)` applies the stream selector, for the tailer's stream filter (PRD L3).

## Investigation queries

`RunQuery(ctx, query, src, limits)` evaluates a query over a `LineSource`, which receives the stream matchers and the time range it must cover (PRD I1a). Nothing read is retained beyond the result.

- Log queries return lines in `[Start, End)` with their labels, newest first (`Backward`, default) or oldest first (`Forward`), keeping the lines nearest the chosen end within `MaxLines` (default 1000) and `MaxBytes` of line text (default 1 MiB).
- Metric queries are evaluated at `End` (instant) or at `Start, Start+Step, ...` up to `End` (range). Counter cells (series times steps) are bounded by `MaxSamples` (default 50000) and series by `MaxSeries` (default 500); more steps than `MaxSamples` is an error.
- `Timeout` bounds the scan through the context. A timeout returns the partial result; a caller cancellation returns an error.
- Every cut sets `Truncated` and lists the limits in `Limited`: `max_lines`, `max_bytes`, `max_series`, `max_samples`, `timeout`.

## Scope injection

`InjectScope(query, matchers)` parses the query, appends the matchers to every stream selector in the AST, and prints the canonical form (PRD I2). Existing matchers are never replaced: `{namespace="other"}` scoped to `namespace="shop"` becomes `{namespace="other", namespace="shop"}` and selects nothing. Label filters after parsers cannot widen the selected streams, and extracted labels never overwrite stream labels. A query the parser rejects is rejected.

## Rejected constructs

Everything not in the grammar is rejected. Constructs recognized and reported by name:

| Construct | Error names |
|---|---|
| `line_format`, `label_format`, `unwrap`, `drop`, `keep`, `decolorize`, `unpack`, `distinct` | `pipeline stage "..."` |
| `logfmt --strict`, `logfmt --keep-empty` | `logfmt flags` |
| `logfmt key="field"` | `logfmt extraction parameters` |
| `\|> "pattern"`, `!> "pattern"` | `pattern line filter` |
| `\|= "a" or "b"` | `line filter or-chain` |
| `ip("...")` in line or label filters | `ip line filter`, `ip label filter` |
| `sum_over_time`, `avg_over_time`, `max_over_time`, `min_over_time`, `first_over_time`, `last_over_time`, `stdvar_over_time`, `stddev_over_time`, `quantile_over_time`, `absent_over_time`, `bytes_rate`, `rate_counter` | `range aggregation "..."` |
| `bottomk`, `stddev`, `stdvar`, `sort`, `sort_desc`, `approx_topk`, `group`, `quantile`, `count_values` | `vector aggregation "..."` |
| `label_replace`, `vector`, `absent` and any other function | `function "..."` |
| `offset` | `offset modifier` |
| `[5m:1m]` | `subquery` |
| grouping on a range aggregation, `count_over_time(...) by (x)` | `grouping on range aggregation "..."` |
| binary operations between two vectors | `binary operation "..." between two vectors` |
| `and`, `or`, `unless` between vectors | `set operator "..."` |
| `on`, `ignoring`, `group_left`, `group_right` | `vector matching "..."` |
| unary minus on an expression other than a number | `unary "-" on a non-literal expression` |

## LogsQL translation

`ToLogsQL(query)` translates the subset to VictoriaLogs LogsQL for lookback investigation (PRD I6b). It assumes the ingestion mapping in which LogQL stream labels are VictoriaLogs stream fields and the log line is `_msg`. Translations are checked in `TestToLogsQL` by parsing with the VictoriaLogs parser (including that `|=` yields a `*substr*` filter and not a word filter) and in `TestLogsQLEngine*` by running both sides on the same fixture with the VictoriaLogs storage engine.

| LogQL | LogsQL |
|---|---|
| `{a="x", b!="y", c=~"r", d!~"s"}` | `_stream:{"a"="x","b"!="y","c"=~"r","d"!~"s"}` |
| `\|= "s"` | `*"s"*` (substring, not the default word filter) |
| `!= "s"` | `!*"s"*` |
| `\|= ""` / `!= ""` | omitted / `!~".*"` |
| `\|~ "re"` / `!~ "re"` | `~"(?-s:re)"` / `!~"(?-s:re)"` (LogsQL regexp filters let `.` match newlines) |
| `\| json` | `copy _msg as "exitmesh.json" \| replace_regexp ("^[ \t\r\n]+", "") at "exitmesh.json" \| unpack_json from "exitmesh.json" keep_original_fields \| delete "exitmesh.json"` |
| `\| logfmt` | `unpack_logfmt keep_original_fields` |
| `\| pattern "p"` | `extract` with `<plain:...>` placeholders, guarded by `if (_msg:="lead"*)` for a leading literal, plus one conditional `extract` per named capture followed by a literal, reproducing LogQL's rest-of-line capture when that literal is missing; `<_>` becomes a temporary field that is deleted |
| `\| regexp "re"` | `extract_regexp "(?-s:re)" keep_original_fields` |
| label `l="v"`, `!=`, `=~`, `!~` | `"l":="v"`, `!"l":="v"`, `"l":~"^(?s:re)$"`, `!"l":~"^(?s:re)$"`; after a parser inside `\| filter ...` |
| `and`, `or`, parentheses | juxtaposition, `or`, parentheses |
| `count_over_time(q [r])` (no parser) | `_time:(now-r,now] ... \| stats by (_stream) count() as value` |
| `bytes_over_time` | `sum_len(_msg)` |
| `rate` | the count, then `math (value / r_seconds) as value` |
| `sum by (l) (range_agg)` | `stats by ("l") ... as value` (parsers allowed) |
| `min`, `max`, `avg`, `count` over a range aggregation (no parser) | `stats by (_stream, "l") ... as value \| stats by ("l") max(value) as value` |
| aggregation over an aggregation | a further `stats by (...)` pipe over `value` |
| aggregation without grouping | `stats count() as "exitmesh.rows", ... \| filter "exitmesh.rows":>0 \| delete "exitmesh.rows"` (LogQL returns no sample for no input) |
| `v + s`, `v - s`, `v * s`, `v / s`, `s + v`, `s - v`, `s * v` | `math (value op s) as value` (scalar sides constant-folded) |
| `v > s`, `>=`, `<`, `<=`, `==`, `!=` | `filter value:>s`, ..., `filter value:>=s value:<=s`, `filter !(value:>=s value:<=s)` |

The value of a translated metric query is the `value` field; `_time:(now-r,now]` is exactly LogQL's window when the query is evaluated at time `now`.

Rejected with a `TranslationError` naming the construct and the reason:

| LogQL | Reason |
|---|---|
| `json` extraction parameters | no JSON path extraction into renamed fields |
| a second parser stage | chained parsers overwrite earlier labels differently |
| after `json` or `logfmt`, a reference to a label containing `_` that the selector does not pin | sanitization and nested keys map several LogsQL fields to one label |
| labels beginning with `_`, or named `value` | reserved LogsQL fields or the translated value field |
| numeric, duration and byte label filters | LogQL keeps unparsable values with `__error__`; LogsQL range filters drop them and parse other units |
| `__error__` label filters | LogsQL records no parser errors |
| a range aggregation with a parser and no enclosing `sum` | series identity includes every extracted label |
| `min`, `max`, `avg`, `count` over a range aggregation with a parser | same |
| `topk` | no top-k with LogQL tie semantics |
| `without` grouping | LogsQL groups by listed fields only |
| `bool` | LogsQL filters rows |
| `%`, `^`, division by a vector or by zero | no verified LogsQL math equivalent |

Data-dependent differences that the translation cannot exclude (pinned by `TestLogsQLDocumentedDifferences`):

- JSON array values: LogQL extracts nothing, `unpack_json` stores the array text.
- Malformed logfmt pairs: LogQL skips `x=y=z` and stops at an unterminated quote; `unpack_logfmt` keeps `y=z` and the raw quoted text.
- Parser errors: LogQL fails a metric query when a line fails JSON parsing (unless `__error__` is handled); LogsQL counts the line without extracted fields.
- Empty values: LogQL keeps an extracted label with an empty value as a separate series from an absent label; LogsQL groups both as empty.

## Differences from Loki

- `__error_details__` is not produced, and structured metadata is not modeled.
- On a JSON syntax error no labels are extracted; Loki may keep labels parsed before the error. With duplicate JSON keys the last value wins.
- Rule counters round the older window edge to a bucket boundary (see [Rules](#rules)); investigation queries use exact windows.
- Range query steps start exactly at `Start`; Loki's query frontend may align them to multiples of the step.

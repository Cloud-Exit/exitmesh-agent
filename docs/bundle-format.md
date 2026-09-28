# Rule bundle format

This document specifies the ExitMesh rule bundle: the archive the agent receives, the metadata that binds rules to their evaluation policy, the signatures that protect integrity, the key manifest that carries signing keys, and the activation, rollback, and air-gap semantics. The format is open. Any operator can build, sign, inspect, and verify bundles with `exitmesh-bundle` (built from `cmd/exitmesh-bundle`), and the implementation lives in `internal/rules/bundle`.

Bundle contents are inspectable by customers. Nothing in a bundle is encrypted or obfuscated. Signing protects integrity and origin, not secrecy: a signature proves that a bundle was issued by a holder of a valid signing key and has not been altered, and it hides nothing.

## Archive layout

A bundle is a gzip-compressed tar archive, conventionally `bundle.tar.gz`.

```
bundle.yaml              manifest (required)
state/<name>.yaml        state rules (CEL predicates over normalized state)
prometheus/<name>.yaml   PromQL alerting rules, upstream Prometheus rule-group format
loki/<name>.yaml         LogQL alerting rules, upstream Prometheus rule-group format
```

Rule files use the `.yaml` or `.yml` extension and live exactly one level below their directory. Directory entries for `state/`, `prometheus/`, and `loki/` and a leading `./` on member names are accepted. Anything else is rejected.

Extraction is strict. The agent rejects the whole archive when any of these hold:

|Check|Limit or rule|
|---|---|
|Compressed archive size|16 MiB|
|Total decompressed member bytes|16 MiB|
|Single member size|4 MiB|
|Member count, directories included|512|
|Member type|regular files and directories only; symbolic links, hard links, devices, FIFOs, and global headers are rejected|
|Member path|no absolute paths, no `..` or `.` segments, no backslashes or NUL bytes, no non-canonical paths|
|Duplicates|a member name may appear once (after removing a leading `./`)|
|Unexpected content|members outside the layout above, nested directories, hidden files, data after the gzip stream|

YAML documents are decoded with unknown fields rejected, and a file may hold only one YAML document.

`exitmesh-bundle build -dir DIR -out bundle.tar.gz` produces a reproducible archive: members sorted by path, mode `0644`, owner 0, modification time 0, and a gzip header without name or time. Building the same directory twice with the same tool version gives identical bytes.

The bundle digest reported by the agent and by `exitmesh-bundle` is the SHA-256 of the archive bytes.

## bundle.yaml

```yaml
version: "2026.09.1"
engine_version: 1
schema_version: 1
target_type: kubernetes
created_at: 2026-09-01T00:00:00Z
rules:
  - id: node-high-cpu
    version: 2
    class: promql
    target: kubernetes
    scope: node
    file: prometheus/node.yaml
    group: node
    alert: NodeHighCPU
    category: saturation
    severity: medium
    capabilities: [metrics]
    dedup_key: node
    resolution: recovery
    resource_labels: {kind: Node, name: node}
    evidence: {max_samples: 5, max_bytes: 8192}
    budget: {max_eval_time: 2s, max_series: 10000}
    summary: Node CPU saturated
```

### Manifest fields

|Field|Type|Required|Meaning|
|---|---|---|---|
|`version`|string|yes|Bundle version. Letters, digits, `.`, `_`, `+`, `-`; starts with a letter or digit; at most 64 bytes. A version identifies exactly one archive: storing the same version with different content is rejected.|
|`engine_version`|integer|yes|Highest rule engine version any rule in the bundle needs. At least 1.|
|`schema_version`|integer|yes|Version of this `bundle.yaml` schema. This agent implements schema 1 and rejects any other value.|
|`target_type`|string|yes|`kubernetes` or `host`. Every rule must declare the same target (PRD H7), and an agent rejects a bundle for another target type.|
|`created_at`|RFC 3339 time|yes|Creation time, informational.|
|`rules`|list|yes|Rule metadata entries, one per rule. At most 2000 by default (local policy).|

### Rule metadata fields

|Field|Type|Required|Meaning|
|---|---|---|---|
|`id`|string|yes|Unique rule identifier. Letters, digits, `.`, `_`, `:`, `-`; starts with a letter or digit; at most 128 bytes.|
|`version`|integer|yes|Rule version, at least 1. Carried in every finding.|
|`class`|string|yes|`state`, `promql`, or `logql`.|
|`target`|string|yes|Must equal `target_type`.|
|`scope`|string|yes|`node` (evaluated by each node agent over local data) or `cluster` (evaluated by the coordinator). Host bundles allow only `node`.|
|`file`|string|promql, logql|Archive path of the rule-group file, for example `prometheus/node.yaml`.|
|`group`|string|promql, logql|Rule group name in that file.|
|`alert`|string|promql, logql|Alert name in that group.|
|`match`|map|no|Static label values that select one alerting rule when several rules in a group share the alert name (for example a warning and a critical variant).|
|`category`|string|yes|Finding category, single line, at most 128 bytes.|
|`severity`|string|yes|`info`, `low`, `medium`, `high`, or `critical`.|
|`capabilities`|list|yes|Capabilities the rule needs: `inventory`, `metrics`, `logs`. A state rule must list `inventory`, a PromQL rule `metrics`, a LogQL rule `logs`.|
|`required_fields`|list|no|Normalized state fields the rule reads, used for coverage reporting.|
|`evidence`|map|no|`max_samples`, `max_bytes`, `context_lines`. Missing values take the local defaults; values above the local maximum are capped.|
|`dedup_key`|string|no|Comma-separated alert label names that form the deduplication key. When empty, every label except volatile ones (such as `value`) is used.|
|`resolution`|string|no|`recovery` (default: the finding resolves when the rule stops firing past `keep_firing_for` or the predicate stops holding) or `manual` (resolved by an administrative action in ExitMesh).|
|`resource_labels`|map|no|`kind`, `namespace`, `name`: the alert labels that identify the affected resource.|
|`budget`|map|no|`max_eval_time` (duration), `max_samples`, `max_series`, `max_complexity`, `counter_bytes`. Missing values take the local defaults; values above the local maximum are capped.|
|`min_engine`|integer|no|Minimum rule engine version. Defaults to 1 and must not exceed `engine_version`.|
|`disabled`|boolean|no|Per-rule disablement (PRD R10). A disabled rule is validated structurally but not evaluated, and its expression is not checked.|
|`summary`|string|no|Human summary, at most 1024 bytes.|

Durations use Go duration syntax (`30s`, `5m`, `1h`).

## State rules

Files under `state/` hold a YAML list of state rules. Each rule carries its identity inline and must also have an entry of class `state` with the same `id` in `bundle.yaml`, which supplies the rest of the metadata.

```yaml
- id: pod-crashloop
  version: 1
  target: kubernetes
  kinds: [Pod]
  expr: object.status.restarts > 5
  for: 5m
  keep_firing_for: 10m
  interval: 1m
  labels:
    team: platform
```

|Field|Type|Required|Meaning|
|---|---|---|---|
|`id`|string|yes|Matches the metadata entry.|
|`version`|integer|yes|Must equal the metadata `version`.|
|`target`|string|yes|Must equal the metadata `target`.|
|`kinds`|list|yes|Normalized resource kinds the predicate applies to. Unique, non-empty.|
|`expr`|string|yes|CEL predicate over normalized state and the change graph.|
|`for`|duration|no|How long the predicate must hold before firing.|
|`keep_firing_for`|duration|no|How long a firing rule keeps firing after the predicate stops holding.|
|`interval`|duration|no|Evaluation interval; defaults to the local default (1 minute).|
|`labels`|map|no|Static labels added to findings. Keys are label names.|

State rule metadata entries must not set `group`, `alert`, or `match`.

## PromQL and LogQL rules

Files under `prometheus/` and `loki/` use the upstream Prometheus rule-group format unchanged, so existing rule files and mixins can be copied into a bundle as they are:

```yaml
groups:
  - name: node
    interval: 30s
    labels:
      team: infra
    rules:
      - alert: NodeHighCPU
        expr: avg by (node) (rate(node_cpu_seconds_total{mode!="idle"}[5m])) > 0.9
        for: 10m
        keep_firing_for: 5m
        labels:
          severity: warning
        annotations:
          summary: "CPU high on {{ $labels.node }}"
```

The files are parsed with the upstream `rulefmt` package, so the structural rules of Prometheus apply (group names unique per file, one of `alert` or `record`, valid label names, parseable templates). In addition:

- Every alerting rule must be bound to exactly one metadata entry in `bundle.yaml` by `file`, `group`, and `alert` (plus `match` when needed), and every PromQL or LogQL metadata entry must resolve to exactly one alerting rule. An unbound or ambiguous rule rejects the bundle.
- Recording rules are rejected.
- The group fields `query_offset` and `limit` are not supported and reject the bundle.
- Group labels are merged into each rule's labels, rule labels winning, as in Prometheus.
- A group without `interval` uses the local default interval (1 minute).
- PromQL expressions are parsed by the Prometheus PromQL parser and then checked against the agent's supported subset and budgets. LogQL expressions are not PromQL; they are checked by the agent's LogQL subset validator, including the per-rule counter memory budget (PRD R11). Unsupported constructs reject the bundle.
- Label and annotation templates may format labels and values. Template functions and fields that run queries or reference external destinations (`query`, `graphLink`, `tableLink`, `externalURL`, `pathPrefix`, `$externalURL`, `.ExternalURL`) are rejected.

## Validation and engine compatibility

Validation is all or nothing, with one exception for engine compatibility (PRD U4):

- A rule whose `min_engine` is above the agent's engine version does not fail the bundle. It is reported as `unsupported: agent upgrade required` and not evaluated. Only its identity (`id`, `version`, `target`, `min_engine`) is checked, so a newer bundle may use classes, capabilities, and expression grammar this agent does not know for such rules.
- A bundle whose `engine_version` is above the agent's engine version loads the rules within the agent's engine and reports the others as unsupported.
- Any other error (manifest fields, a rule's metadata, durations, expressions, binding, archive structure) rejects the whole bundle, and the agent keeps its last known good bundle.

Every rule gets one verdict: active, disabled, unsupported with a reason, or rejected with a reason.

Checks applied to supported rules:

|Check|Rule|
|---|---|
|Target|rule `target` equals `target_type`; bundle `target_type` equals the agent's|
|Identity|valid, unique `id`; `version` at least 1|
|Metadata|known `class`, `scope`, `severity`, `capabilities`, `resolution`; required `category`; valid `dedup_key`, `match`, `resource_labels` label names|
|Durations|`for` and `keep_firing_for` between 0 and 24 hours; intervals between 10 seconds and 1 hour (local policy)|
|Budgets and evidence|non-negative; defaults applied; capped at the local maximum|
|Expressions|PromQL, LogQL, and CEL validators for enabled rules|
|No code, no destinations|unknown fields rejected everywhere; forbidden template functions rejected (PRD R7)|

### Local policy is an upper bound

The agent's local policy defines default and maximum budgets, evidence limits, intervals, the longest `for`, and the rule count. A bundle can lower these per rule but never raise them: a value above the local maximum is capped to it. A bundle cannot grant permissions, expand scope, add network destinations, or override data minimization limits. No field in the format is ever used by the agent as a network destination or executed as code; there is no shell, no embedded program, and no plugin mechanism.

Default local policy:

|Limit|Default|Maximum|
|---|---|---|
|`max_eval_time`|2s|10s|
|`max_samples`|500000|5000000|
|`max_series`|10000|100000|
|`max_complexity`|200|1000|
|`counter_bytes`|1 MiB|8 MiB|
|evidence `max_samples`|5|20|
|evidence `max_bytes`|8 KiB|64 KiB|
|evidence `context_lines`|0|5|

## Signatures

All signatures are Ed25519 over a SHA-256 digest with a domain separator:

```
bundle digest       = SHA-256("EMBv1/bundle"      || 0x00 || archive bytes)
key manifest digest = SHA-256("EMBv1/keymanifest" || 0x00 || manifest bytes)
signature           = Ed25519(private key, digest)
```

The domain separator prevents a signature over one kind of document from being accepted as the other.

A bundle signature file (`bundle.sig`) is JSON; binary values are standard base64:

```json
{"key_id": "sign-2026a", "signature": "<base64 64-byte signature>"}
```

## Key manifest

Bundle signing keys are published in a key manifest signed by the root key set (PRD R2a). The manifest body is JSON:

```json
{
  "sequence": 7,
  "issued_at": "2026-09-01T00:00:00Z",
  "signing_keys": [
    {"id": "sign-2026a", "public_key": "<base64>", "not_before": "2026-01-01T00:00:00Z", "not_after": "2026-10-01T00:00:00Z"},
    {"id": "sign-2026b", "public_key": "<base64>", "not_before": "2026-09-01T00:00:00Z", "not_after": "2027-04-01T00:00:00Z"},
    {"id": "sign-2025x", "public_key": "<base64>", "not_before": "2025-01-01T00:00:00Z", "not_after": "2026-12-01T00:00:00Z", "revoked_at": "2026-08-15T00:00:00Z"}
  ],
  "successor_roots": [
    {"id": "root-2027", "public_key": "<base64>", "not_before": "2027-01-01T00:00:00Z"}
  ]
}
```

It is delivered wrapped, with the exact signed bytes carried in base64 so no re-serialization is involved:

```json
{"manifest": "<base64 manifest bytes>", "signatures": [{"key_id": "root-2026", "signature": "<base64>"}]}
```

Verification rules:

- Root keys belong to the ExitMesh deployment, not to agent releases: every self-hosted deployment has its own root key set. Agents are configured with it (`trust.roots` as `<id>:<base64 ed25519 public key>` entries and optional `trust.threshold`, or `trust.rootsFile` pointing at a roots document with `keys` (`id`, `public_key`) and an optional `threshold`, the number of distinct root signatures required, default 1). The deployment's onboarding page shows the values next to the enrollment token. An agent without roots verifies nothing and fails closed with an error naming the setting.
- The trusted root set is the configured roots plus every adopted successor root whose `not_before` has passed.
- A manifest is accepted when at least `threshold` distinct trusted roots signed it. Signatures by unknown keys are ignored.
- The agent persists the highest verified `sequence` and its digest. A manifest with a lower sequence is rejected. A manifest with an equal sequence is accepted only if it is byte-identical to the verified one. This holds for manifests received over the tunnel and out of band alike.
- Successor roots in an accepted manifest are adopted and persisted. They sign later manifests once their `not_before` has passed, so roots rotate without an agent upgrade. A successor root that reuses a trusted root id with a different key rejects the manifest.
- A bundle signature is accepted only when its key is listed in the latest verified manifest, the current time is within `[not_before, not_after)`, and the key is not revoked (`revoked_at` absent or in the future).
- Root key compromise requires the deployment operator to replace `trust.roots` on its agents (see SECURITY.md).
- Delivery carries the latest manifest and, in `key_manifest_chain`, earlier manifests in ascending sequence, so an agent that only knows an older root (for example one installed from old onboarding values) follows every rotation. Air-gap delivery places the chain in a `keymanifests/` subdirectory.

Rotation and revocation:

- Signing key rotation publishes a manifest in which the outgoing and incoming keys have overlapping validity windows. During the overlap bundles signed by either key are accepted; after the outgoing key's `not_after`, only the incoming key is.
- Revocation publishes a manifest with a higher sequence that sets `revoked_at` on the key. From `revoked_at` on, new bundles signed by that key are rejected, and stored bundles signed by it can no longer be loaded as last known good or rolled back to. Removing a key from the manifest also stops new bundles signed by it from being accepted, but only `revoked_at` disqualifies stored bundles.
- Root rotation publishes, signed by the current roots, a manifest listing the successor under `successor_roots`; later manifests may then be signed by the successor.

## Activation, last known good, and rollback

- The agent activates a bundle only after the signature verifies, the archive parses, and validation passes. Activation is atomic per component and happens between evaluation cycles (PRD R5).
- Each activated bundle is stored with its archive, signature, digest, and signing key id, keyed by version, and becomes the last known good. The five most recent versions are retained; the current one is never pruned.
- An invalid or untrusted bundle is rejected and the last known good stays active (acceptance 15).
- On restart the agent reloads the last known good from local storage, checks it against its stored digest, and validates it again against the current local policy. Signing key expiry is not re-checked for stored bundles, so rules keep running through long disconnections; revocation is.
- Rollback makes a retained version current again by version string, subject to the same checks (PRD R10).
- The bundle version is carried in every finding (PRD R8).

## Air-gap delivery

In the air-gap profile the key manifest and bundles are delivered out of band as files in one directory:

```
keymanifest.json   signed key manifest (optional when the current manifest is already trusted)
bundle.tar.gz      bundle archive
bundle.sig         bundle signature
```

The agent verifies these files exactly as it verifies tunnel delivery: the same root set, sequence rules, validity windows, and revocation. An older manifest delivered out of band is rejected. Files must be regular files within the size limits; symbolic links are rejected.

## Operator tool

```
exitmesh-bundle keygen   -id ID -out PREFIX                     writes PREFIX.key (0600) and PREFIX.pub
exitmesh-bundle roots    -pub root.pub [-threshold N] -out roots.json
exitmesh-bundle manifest -seq N [-issued-at T] -key PUB,NOT_BEFORE,NOT_AFTER[,REVOKED_AT] \
                         [-successor PUB,NOT_BEFORE] -root root.key -out keymanifest.json
exitmesh-bundle build    -dir DIR -out bundle.tar.gz
exitmesh-bundle sign     -bundle bundle.tar.gz -key sign.key -out bundle.sig
exitmesh-bundle verify   -bundle bundle.tar.gz -sig bundle.sig -manifest keymanifest.json [-roots roots.json | -root-pub root.pub] [-at T]
exitmesh-bundle verify   -dir DIR [-roots roots.json | -root-pub root.pub] [-at T]
exitmesh-bundle inspect  -bundle bundle.tar.gz
```

`inspect` prints the manifest, every rule with its class, target, scope, minimum engine, source, and verdict for this agent. `verify` requires `-roots` or `-root-pub` with the deployment's root keys. Private key files contain the raw key in base64 and must be kept offline.

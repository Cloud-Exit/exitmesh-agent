# Insight coverage of the default rule bundles

ExitMesh ships two default rule bundles whose sources are open and inspectable: `rules/kubernetes/` and `rules/host/`, in the layout of `docs/bundle-format.md`. They are embedded in the agent (`internal/rulesdefault`, which also builds their archives byte for byte as `exitmesh-bundle build -dir rules/<target>` does). The sources are unsigned; each ExitMesh deployment signs the archives it distributes.

This page maps every current ExitMesh insight to the rules that retain it (PRD G2, 13.1), or to a documented unsupported case with the reason. The rule category of every mapped rule is the insight name, so findings carry the insight they retain. Every rule listed here validates with the agent's real validators and is exercised by a fixture test in `internal/rulesdefault` that makes it fire after its `for`, resolve after recovery plus its `keep_firing_for`, and stay silent on a healthy fixture.

Classes:

|Class|Evaluated by|Input|
|---|---|---|
|state|coordinator (Kubernetes), host agent (host)|CEL over normalized state (`docs/field-catalog.md`, `docs/host-facts.md`), including `events.warning.<reason>` facts|
|PromQL node-local|each node agent, or the host agent|its own TSDB|
|PromQL join|each node agent|its TSDB joined with the node-scoped `kube_pod_*` and `kube_node_*` series (`docs/kube-series.md`)|
|PromQL cluster|coordinator|decomposable aggregation over node parts; no current insight needs one|
|LogQL|each node agent, or the host agent|per-rule counters over tailed pod logs or journal streams (`docs/logql-subset.md`)|

## Kubernetes insights

|Insight|Behavior|Rule IDs|Class|Notes|
|---|---|---|---|---|
|`log.process_failure`|Crash or fatal lines (panic, fatal error, segfault, SIGSEGV or SIGABRT, core dumped, out of memory, OOM kill) for a workload|`log.process_failure`|LogQL|Grouped by namespace, workload kind, workload, and container.|
|`log.error_rate_spike`|Error-level log rate of a workload well above its recent level|`log.error_rate_spike`|LogQL|Gap: fires on more than one error line per second sustained for 5 minutes, an absolute level. A comparison with the workload's own recent rate needs a binary operation between two vectors or an `offset`, both rejected by the LogQL subset.|
|`log.severity_mix_shift`|Share of warning and error lines shifts sharply|`log.severity_mix_shift`|LogQL|Gap: fires when warning and error lines exceed 600 in 15 minutes. Their share of all lines needs a division of two vectors, which the subset rejects.|
|`log.new_fingerprint_burst`|Burst of previously unseen message patterns|`log.new_fingerprint_burst`|LogQL|Gap: a message fingerprint is the first run of three consecutive words of at least three letters in a line (`regexp` capture), which skips numbers, identifiers, and punctuation; the rule fires when a workload emits more than 50 distinct fingerprints in 10 minutes. Novelty against the whole history of a workload needs state the counter model cannot hold. Fingerprints live only in the in-memory counters; the outer `count` removes them from alert labels.|
|`log.dominant_fingerprint`|One message pattern dominates a workload's output|`log.dominant_fingerprint`|LogQL|Gap: fires when the most frequent fingerprint exceeds 1200 lines in 15 minutes, an absolute count rather than a share of the output (vector division is rejected). The fingerprint text stays out of the alert labels.|
|`metric.saturation`|Usage over limit at or above 0.9 is high, at or above 0.97 critical (CPU and memory)|`metric.saturation.cpu.high`, `metric.saturation.cpu.critical`, `metric.saturation.memory.high`, `metric.saturation.memory.critical`|PromQL join|cadvisor usage joined `on (namespace, pod, container)` with `kube_pod_container_resource_limits`. The high rules cover the band from 0.9 to below 0.97, so one severity fires at a time. Containers without a limit have no ratio.|
|`metric.active_series_spike`|Sudden growth in active series of a scrape target|`metric.active_series_spike`|PromQL node-local|`scrape_samples_scraped` more than twice its average over the hour ending 10 minutes ago, and at least 1000 series above it.|
|`metric.slope_change`|Sustained trend change over a window, for example memory growth rate|`metric.slope_change.memory`|PromQL node-local|Fires when the 30 minute memory growth rate of a container exceeds twice its growth rate over the preceding 2 hours plus 1 MiB per minute, for 15 minutes. Only container memory is covered by default.|
|`metric.volume_saturation`|Persistent volume usage at or above 0.9 of capacity|`metric.volume_saturation`|PromQL node-local|kubelet volume stats of the node that mounts the claim.|
|`metric.volume_fill_trend`|Volume predicted to fill within hours at the current rate|`metric.volume_fill_trend`|PromQL node-local|Less than 40% available and `predict_linear` over 1 hour reaching zero within 4 hours. The window stays within the 6 hour TSDB retention ceiling (PRD R11).|
|`event.warning_spike`|Burst of Warning events|`event.warning_spike`|state|At least 20 Warning events within the event window (1 hour by default) on one involved object, summed over its reason counters. Gap: evaluated per involved object; a cluster-wide total is not available to a per-resource predicate.|
|`event.reason_spike`|Burst of Warning events of one reason|`event.reason_spike`|state|One reason at least 10 times on an object within the event window. The `reason` label is the lexicographically first reason over the threshold.|
|`event.new_reason`|A Warning reason not seen before for an object|`event.new_reason`|state|Gap: novelty is relative to the event window. The rule fires when an object first has a Warning reason; a further new reason on a firing object is an `update` transition carrying the new `reason_count`.|
|`event.backoff_loop`|BackOff events repeating for a container|`event.backoff_loop`|state|At least 3 BackOff events with a container waiting in CrashLoopBackOff or ImagePullBackOff, for 5 minutes. Events carry no container in the catalog, so the `container` label comes from the waiting status.|
|`event.scheduling_failure`|FailedScheduling persisting across windows|`event.scheduling_failure`|state|FailedScheduling events on a Pending pod that is not scheduled, for 15 minutes; severity high.|
|`event.image_pull_failure`|ErrImagePull or ImagePullBackOff|`event.image_pull_failure`|state|Pull related Warning reasons (Failed, BackOff, ErrImageNeverPull, InspectFailed) on a pod whose container waits on an image pull reason. The kubelet reason Failed is shared with other failures; the waiting reason pins it to image pulls.|
|`event.volume_failure`|FailedMount, FailedAttachVolume|`event.volume_failure`|state|FailedMount, FailedAttachVolume, or FailedMapVolume on a Pending pod, and ProvisioningFailed or FailedBinding on a Pending claim, for 5 minutes.|
|`event.node_pressure`|Node MemoryPressure, DiskPressure, PIDPressure|`event.node_pressure`|state|Read from the node conditions, which the kubelet sets together with the pressure events; the `pressure` label lists the conditions that are True.|
|`manifest.pod_status_failure`|CrashLoopBackOff, image pull failures, OOMKilled or exit code 137, CreateContainerError and CreateContainerConfigError|`manifest.pod_status_failure.crashloop`, `manifest.pod_status_failure.image_pull`, `manifest.pod_status_failure.oom_killed`, `manifest.pod_status_failure.create_container`|state|Over containers and init containers. The `container` label is the lexicographically first matching container. The OOM rule reads the current and last termination, and the last termination persists in the pod status until the container terminates again or the pod is replaced.|
|`manifest.sveltos_feature_failure`|Sveltos ClusterSummary feature failures|none|unsupported|ClusterSummary receives the default custom-resource identity and condition projection. This specific insight still needs a selected projection for `config.projectsveltos.io/ClusterSummary` feature summaries and a corresponding rule.|
|`cross_signal_correlation`|Correlation across signals|none|control plane|Not an agent rule: correlation runs in the ExitMesh control plane over findings from every rule and the change graph. Rules keep their inputs local to one evaluation.|

## Host rules

Host bundles contain only node-scoped rules (PRD H7). The host rules retain the insights that apply to a Linux host and add the classic node-exporter alerts, which evaluate unchanged over the in-process node_exporter collectors (`docs/host-facts.md`).

|Rule ID|Retains|Class|Behavior|
|---|---|---|---|
|`host.filesystem_almost_full.high`|`metric.volume_saturation`|PromQL node-local|Filesystem usage from 0.9 to below 0.97 for 15 minutes, excluding pseudo filesystems and read-only mounts.|
|`host.filesystem_almost_full.critical`|`metric.volume_saturation`|PromQL node-local|Filesystem usage at or above 0.97 for 5 minutes.|
|`host.filesystem_predicted_full`|`metric.volume_fill_trend`|PromQL node-local|Less than 40% available and `predict_linear` over 1 hour reaching zero within 4 hours.|
|`host.cpu_saturation.high`|`metric.saturation`|PromQL node-local|Non-idle, non-iowait CPU from 0.9 to below 0.97 for 15 minutes.|
|`host.cpu_saturation.critical`|`metric.saturation`|PromQL node-local|Non-idle, non-iowait CPU at or above 0.97 for 15 minutes.|
|`host.memory_saturation.high`|`metric.saturation`|PromQL node-local|Memory in use (1 minus MemAvailable over MemTotal) from 0.9 to below 0.97 for 15 minutes.|
|`host.memory_saturation.critical`|`metric.saturation`|PromQL node-local|Memory in use at or above 0.97 for 5 minutes.|
|`host.memory_pressure`|host only|PromQL node-local|Pressure stall information: tasks wait on memory more than 10% of the time for 10 minutes.|
|`host.high_load`|host only|PromQL node-local|`node_load1` above twice the CPU count for 15 minutes.|
|`host.disk_io_saturation`|host only|PromQL node-local|Weighted IO time rate (average queue) above 10 for 30 minutes.|
|`host.clock_skew`|host only|PromQL node-local|Clock offset beyond 50 ms and not converging for 10 minutes. Needs the node_exporter `timex` collector, which is not in the host's default collector set; until it is collected the rule has no input.|
|`host.systemd_unit_failed`|host only|state|A `host/Unit` whose `active_state` is `failed` for 2 minutes.|
|`host.log.oom_kill`|`log.process_failure`|LogQL|Kernel or systemd-oomd journal entries reporting an OOM kill.|
|`host.log.process_failure`|`log.process_failure`|LogQL|Journal entries reporting a segfault, general protection fault, trap, core dump, panic, or fatal error, per unit and syslog identifier.|
|`host.log.error_rate_spike`|`log.error_rate_spike`|LogQL|Journal entries with priority 0 to 3 at more than 0.5 per second for 5 minutes, per unit and syslog identifier. Same absolute-level gap as the Kubernetes rule.|

## Operational notes

- The Kubernetes LogQL rules select every pod stream (`{namespace=~".+"}`), so the node agent tails every pod log while they are active. Disabling the five `log.*` rules (per-rule disablement, PRD R10) stops that.
- LogQL counter budgets: the fingerprint rules reserve 3000 series per node (about 4.4 MB of counters each); the other LogQL rules reserve 1000 series. A workload or fingerprint beyond that is dropped from the counters and the rule reports `budget_limited` (PRD R9).
- State rules that iterate over every field of every pod raise their CEL cost budget to the local maximum (`max_samples: 5000000`), which bounds the cycle cost over roughly ten thousand pods.
- Warning event counters are kept for the tracker's event window (1 hour by default), so event rules gated only on counts would stay true for up to that window after the last event. Every event rule except `event.warning_spike`, `event.reason_spike`, and `event.new_reason` is also gated on the current object status so that it resolves on recovery.

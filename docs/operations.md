# Operations runbook

Commands assume the default namespaces (`exitmesh-node` for node agents, `exitmesh` for the coordinator) and release name `exitmesh-agent`.

## Health at a glance

```sh
kubectl -n exitmesh get statefulset,pod,pvc -o wide
kubectl -n exitmesh-node get daemonset exitmesh-agent-node
kubectl -n exitmesh logs statefulset/exitmesh-agent-coordinator --tail=200
kubectl -n exitmesh-node logs -l app.kubernetes.io/component=node --prefix --tail=50
```

The connector page is the primary view: agent versions per node, last checkpoint and last applied delta, coverage per node, namespace, resource type, and capability, bundle convergence, rule states, coordinator storage placement, spool use, and the projected outage window. The agent logs in JSON through a redaction handler; logs never carry raw payloads, credentials, or tokens.

## Never force-delete the coordinator pod

Do not run `kubectl delete pod --force --grace-period=0` on the coordinator, and do not remove its finalizers. Kubernetes documents that force-deleting a StatefulSet pod can leave two instances running, and the coordinator relies on at-most-one pod (together with `ReadWriteOncePod` or the spool file lock, and writer ownership checks in ExitMesh) for its single-writer guarantee. A normal `kubectl delete pod` is safe: the StatefulSet recreates the pod only after the old one has terminated, and the new process takes the spool lock, increments its incarnation, resumes its epoch, and reconciles through relist and diff. Node agents spool meanwhile.

## Coordinator node unreachable

When the node running `exitmesh-agent-coordinator-0` becomes `NotReady` or unreachable, the pod stays `Terminating` or `Unknown` and no replacement is created until Kubernetes knows the old pod is gone. Node agents keep spooling; nothing is lost while their queues have room.

1. Confirm the node is powered off or otherwise can no longer run workloads (cloud console, BMC, hypervisor). Do not skip this step: a partitioned but running node could still be writing.
2. Then either delete the Node object:

   ```sh
   kubectl delete node <node>
   ```

   or, to keep the Node object, apply the out-of-service taint so Kubernetes force-detaches volumes and deletes the pods safely:

   ```sh
   kubectl taint nodes <node> node.kubernetes.io/out-of-service=nodeshutdown:NoExecute
   ```

3. The StatefulSet recreates the coordinator on a healthy node. Remove the taint once the node is repaired and rejoins, or after it is decommissioned:

   ```sh
   kubectl taint nodes <node> node.kubernetes.io/out-of-service=nodeshutdown:NoExecute-
   ```

If the coordinator volume is node-local (the bound PV has `nodeAffinity`), the coordinator can only run on that node and stays `Pending` until it returns; the connector shows this limitation. Permanent loss of such a node is PVC loss: after deleting the pending PVC, the coordinator starts with a new spool and a new writer ID, opens a new epoch at the committed head of the previous one, and node agent queues deliver the findings from the gap. The boundary is recorded and shown.

## Node agent failures

- **Restart:** tailing resumes from persisted offsets and alert state resumes from `/var/lib/exitmesh`; any gap is disclosed.
- **Node reimaged or `/var/lib/exitmesh` lost:** `for` rules warm up again from agent start, and the gap is disclosed.
- **Node drained or removed:** the node is marked uncovered, its node-local rule state expires, and findings from it are not auto-resolved.
- **Disk cap:** the agent enforces `node.diskCap` (1 GiB) across queue, TSDB, and offsets, because kubelet eviction does not see hostPath usage.
- **Rolling updates** never surge (`maxSurge: 0`), so only one agent per node ever holds the `/var/lib/exitmesh` lock.

## Spool window

The coordinator spool on the PVC holds every checkpoint, delta, range record, metric fact, finding, and capped evidence until ExitMesh commits it.

|Setting|Default|Meaning|
|---|---|---|
|`coordinator.spool.capacity`|10Gi (PVC 12Gi)|Hard budget for record bodies; sized for about 7 days of outage at the reference workload.|
|`coordinator.spool.window`|8Mi|Transmitted-unconfirmed window.|
|`coordinator.spool.coalesceAt`|0.90|Fill ratio at which coalescing starts.|

Under pressure the coordinator relieves the spool in a fixed order: evict evidence, then compact finding samples to counts, then coalesce the oldest never-transmitted range into a range record whose interior is marked unavailable for exact reconstruction. Transmitted records are never coalesced and the chain stays unbroken. A finding is raised on the cluster before capacity is reached, and the projected window (how long the spool lasts at the current rate) is reported. At a ten times heavier workload the window is roughly one day before coalescing. To extend it, raise `coordinator.persistence.size` and `coordinator.spool.capacity` together; the air-gap profile uses 60Gi and 50Gi.

When ExitMesh is unreachable, evaluation continues with the last valid rules, everything is spooled, and on reconnect the coordinator resumes and drains in order with no gap in the delta chain.

If the tunnel is cut without a clean close (a proxy or control plane restart, logged as `history session` warnings ending in `502`), ExitMesh can still hold the old session for up to the 60 second keepalive. Each agent process presents a random instance ID on every hello, so a reconnect of the same process replaces that stale session instead of being refused. A control plane that does not yet implement instances answers `identity_conflict` until the stale session expires; the agent keeps spooling and retries with backoff, and delivery resumes on its own within about a minute. An `identity_conflict` that persists means two writers really share one identity, for example a copied `/var/lib/exitmesh` (see [install-host.md](install-host.md)) or a restored coordinator PVC snapshot running next to the original.

Until a rule bundle is published for the target type, the coordinator logs `bundle fetch failed` once, retries with backoff up to one minute, and logs `bundle fetch recovered` when the control plane answers again. A control plane that answers "nothing published" with an empty version (SPEC 9.4) is not a failure: the coordinator logs `no rule bundle is published for this target yet` once and waits for the `bundle.available` notification.

Each successful connection logs `history session established` with the session ID, decision, epoch, and committed head, so a recovered tunnel is visible next to the warnings of the failed attempts.

## Log lines at steady state

Node agents re-register every 30 seconds as a heartbeat. The coordinator logs `node agent registered` at info only when a node first appears, returns after the node timeout, or changes version, bundle, warming state, coverage, capabilities, or process identity; the heartbeats are logged at debug. Records a node submits while a restarted coordinator is still synchronizing cluster state are answered with HTTP 503 and `Retry-After: 1`, logged at debug, and retried by the node from its queue. Kubernetes client library messages (for example client-side throttling) are emitted through the agent's own structured, redacted log handler with `component: client-go`; the coordinator allows 25 API requests per second with a burst of 50.

## Convergence

A rule bundle rollout converges when every node agent runs the target bundle. Until then the cluster reports **converging**, cross-node rules treat missing nodes as incomplete, and a disconnected node agent keeps its last good bundle and receives the target on reconnect. An invalid bundle is rejected and the last known good bundle stays active. Rules that need a newer engine are reported **unsupported: agent upgrade required**, never skipped silently.

## Coverage states

Absence of data is never shown as healthy. The agent reports coverage per node and per source, and each rule reports its own state.

|Coverage|Meaning|Typical cause and action|
|---|---|---|
|covered|The node or source is reporting within its interval.|None.|
|stale|No report within the expected interval.|Node agent down or partitioned; check the DaemonSet pod on that node.|
|uncovered|The node left the cluster or was drained.|Expected after a drain; findings from it are not auto-resolved.|
|incomplete|Part of the scope could not be collected.|A scrape target blocked by NetworkPolicy, a watch interruption (recorded as uncertain until relist completes), or a disabled capability.|
|unavailable|The permission or source is missing.|RBAC removed or narrowed (a disappearance is never read as deletion), a lookback source down, or a host fact not collectible as non-root.|

|Rule state|Meaning|
|---|---|
|active|Evaluating normally.|
|warming up|A `for` rule within its duration since agent start without persisted state.|
|converging|Not yet running on every node in the target bundle.|
|stale|Inputs stopped arriving.|
|unsupported|Needs a newer engine or a missing capability.|
|disabled|Disabled by `policy.disabledRules`.|
|failed|Evaluation error; isolated from other rules.|
|budget-limited|Exceeded a `policy` budget; isolated and reported.|
|evidence-limited|Evidence exceeded its share of the 16 MiB ring; oldest samples evicted, evaluation unaffected.|

## Access failures

A forbidden API call is reported once and backed off; the agent never retries forbidden operations at high frequency. Fix RBAC by changing chart values (`capabilities`, `rbac.inventory`, `rbac.clusterReads`), never by granting write verbs.

## Credential rotation

ExitMesh rotates the tunnel credential over the tunnel; the coordinator persists the new credential durably before acknowledging. To rotate the node API serving certificate generated by the chart, delete the `exitmesh-agent-coordinator-tls` Secret, run the same `helm upgrade`, then restart both workloads so they load the new certificate and CA:

```sh
kubectl -n exitmesh rollout restart statefulset/exitmesh-agent-coordinator
kubectl -n exitmesh-node rollout restart daemonset/exitmesh-agent-node
```

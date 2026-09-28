# Uninstall and removal

Removal always stops every writer before its state is deleted, and never revokes the credential implicitly. Credentials are revoked only by explicit de-enrollment: an administrator action in ExitMesh, or the agent's `deenroll` command on a host. A disconnect, restart, outage, uninstall, or package removal never revokes.

## Kubernetes

### De-enroll first (optional)

To revoke the cluster's credential, de-enroll the cluster in ExitMesh before uninstalling. The running coordinator receives the de-enrollment, stops, and deletes its credential. If you uninstall without de-enrolling, the cluster shows as offline in ExitMesh until an administrator de-enrolls it there.

### Uninstall with Helm

```sh
helm uninstall exitmesh-agent --namespace default --cascade foreground --wait --timeout 10m
```

The chart performs the removal sequence:

1. **Workloads stop.** Helm deletes the DaemonSet and StatefulSet. With `--cascade foreground --wait`, Helm returns from the deletion only after their pods have terminated.
2. **Node state is removed.** A post-delete hook creates the `exitmesh-agent-cleanup` DaemonSet in the node namespace. On every node its init container runs `exitmesh-agent cleanup --dir /var/lib/exitmesh`, which takes the `/var/lib/exitmesh` file lock and deletes the state. If the lock is held (a node agent is still running) it refuses, reports it in the pod log, and exits non-zero; the kubelet retries with backoff until the lock is free. The main container then runs `exitmesh-agent cleanup --dir /var/lib/exitmesh --wait`, which confirms the directory is clean and keeps the pod Running and Ready as the per-node completion signal. The cleanup pods have no ServiceAccount token and no capabilities, and nothing in the chart needs write RBAC.
3. **Coordinator storage is removed.** The StatefulSet's `persistentVolumeClaimRetentionPolicy: whenDeleted: Delete` deletes the coordinator PVC. PVC protection holds it until the coordinator pod has terminated, so it is never deleted under a running writer.

The two namespaces carry `helm.sh/resource-policy: keep` so the hook can run after the release is gone.

### Confirm completion per node

```sh
kubectl -n exitmesh-node rollout status daemonset/exitmesh-agent-cleanup --timeout 5m
kubectl -n exitmesh-node get pods -l app.kubernetes.io/component=cleanup -o wide
kubectl -n exitmesh-node logs -l app.kubernetes.io/component=cleanup -c cleanup --prefix
```

|Cleanup pod state|Meaning|
|---|---|
|`Running`, `1/1` ready|State removed on that node.|
|`Init:Error` or `Init:CrashLoopBackOff`|The lock is held; a writer is still running on that node. The log reports the refusal. It retries automatically.|
|`Pending` or missing for a node|The node is unreachable or not schedulable. It is listed by the command below and on the connector.|

List nodes without a completed cleanup pod:

```sh
comm -23 <(kubectl get nodes -o name | sed 's#node/##' | sort) \
  <(kubectl -n exitmesh-node get pods -l app.kubernetes.io/component=cleanup \
      -o jsonpath='{range .items[?(@.status.containerStatuses[0].ready==true)]}{.spec.nodeName}{"\n"}{end}' | sort)
```

Inside the pods the directory is the hostPath mount point, so the cleanup removes all of its contents and an empty `/var/lib/exitmesh` directory remains on each node. A node administrator may remove it with `rmdir /var/lib/exitmesh`.

### Finish

```sh
kubectl -n exitmesh-node delete daemonset exitmesh-agent-cleanup
kubectl delete namespace exitmesh-node exitmesh
```

Delete the cleanup DaemonSet before reinstalling; a new install refuses to proceed while it exists, because a cleanup pod restarting on a node could otherwise remove a new agent's state.

### Manual cleanup for GitOps tools without hooks

Tools that do not run Helm post-delete hooks perform the same sequence with these commands (Argo CD runs the hook itself as a `PostDelete` hook; Flux and Sveltos run Helm hooks):

```sh
# 1. Stop the writers and wait for their pods to terminate (after removing the app from Git or pausing sync).
kubectl -n exitmesh-node delete daemonset exitmesh-agent-node --cascade=foreground --wait=true
kubectl -n exitmesh delete statefulset exitmesh-agent-coordinator --cascade=foreground --wait=true
kubectl -n exitmesh-node wait --for=delete pod -l app.kubernetes.io/component=node --timeout=5m
kubectl -n exitmesh wait --for=delete pod -l app.kubernetes.io/component=coordinator --timeout=5m

# 2. Run the cleanup DaemonSet rendered from the same chart version and values.
helm template exitmesh-agent oci://ghcr.io/cloud-exit/charts/exitmesh-agent --version <version> \
  --namespace default -f exitmesh-values.yaml --show-only templates/cleanup.yaml | kubectl apply -f -
kubectl -n exitmesh-node rollout status daemonset/exitmesh-agent-cleanup --timeout 5m

# 3. Confirm the coordinator PVC is gone (deleted by the StatefulSet retention policy).
kubectl -n exitmesh get pvc

# 4. Remove the cleanup DaemonSet, the remaining chart objects, and the namespaces.
kubectl -n exitmesh-node delete daemonset exitmesh-agent-cleanup
kubectl delete clusterrole,clusterrolebinding -l app.kubernetes.io/instance=exitmesh-agent
kubectl delete namespace exitmesh-node exitmesh
```

Add `--set createNamespaces=false --set namespaces.skipLookupValidation=true` to the `helm template` command if you installed into pre-created namespaces.

## Hosts

### De-enroll (optional, before purge)

```sh
sudo systemctl stop exitmesh-agent
sudo -u exitmesh exitmesh-agent deenroll --config /etc/exitmesh/agent.yaml
```

`deenroll` takes the state lock, asks ExitMesh to revoke the host's credential, and deletes the credential locally. Package removal and purge only offer this step; they never perform it.

### Remove, keeping state

```sh
sudo apt remove exitmesh-agent        # Debian, Ubuntu
sudo dnf remove exitmesh-agent        # RHEL family
sudo ./uninstall.sh                   # tarball
```

The service is stopped before any file is deleted. `/var/lib/exitmesh` and `/etc/exitmesh` are kept, so reinstalling resumes the same target, writer ID, and epoch.

### Purge

```sh
sudo apt purge exitmesh-agent                  # Debian, Ubuntu
sudo EXITMESH_PURGE=1 dnf remove exitmesh-agent  # RHEL family (or create /etc/exitmesh/purge-on-remove first)
sudo ./uninstall.sh --purge                    # tarball
```

Purge stops the service, then runs `exitmesh-agent purge-state --dir /var/lib/exitmesh`, which takes the directory lock and deletes the state. If the lock is held by a running agent it refuses and the purge fails with a message, leaving everything in place. On Debian and Ubuntu, removal keeps a root-owned copy of the binary in `/usr/libexec/exitmesh-agent-purge` for this step, because package files are gone by the time the purge runs; the purge deletes it. The tarball `--purge` offers de-enrollment interactively (default no) when run from a terminal.

A purged host that was not de-enrolled shows as offline in ExitMesh until an administrator de-enrolls it. Reinstalling after a purge is a new enrollment with a new `target_id`, unless an administrator binds it to the previous target.

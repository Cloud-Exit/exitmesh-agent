#!/usr/bin/env bash
# Installs the chart into an existing kind cluster against exitmesh-refcp, then checks enrollment, delivery, PSA, RBAC, host state, TLS reuse, and the uninstall sequence.
# env: IMAGE_REF (a pullable image@digest to test; default builds with ko), CHART (chart directory or .tgz), REFCP (exitmesh-refcp binary)
set -euo pipefail
cd "$(git rev-parse --show-toplevel)"

cluster=${KIND_CLUSTER_NAME:-exitmesh}
chart=${CHART:-deploy/helm/exitmesh-agent}
release=exitmesh-agent
nodens=exitmesh-node
coordns=exitmesh
port=${REFCP_PORT:-18443}
work=$(mktemp -d)

fail() {
	echo "FAIL: $*" >&2
	kubectl get pods -A -o wide >&2 || true
	kubectl -n "$coordns" logs statefulset/$release-coordinator --all-containers --tail=100 >&2 || true
	kubectl -n "$nodens" logs daemonset/$release-node --all-containers --tail=100 >&2 || true
	cat "$work/refcp.log" >&2 || true
	exit 1
}

if [ -n "${IMAGE_REF:-}" ]; then
	docker pull "$IMAGE_REF"
	repo=${IMAGE_REF%@*}
	digest=${IMAGE_REF##*@}
	docker tag "$IMAGE_REF" "$repo:kind"
	kind load docker-image "$repo:kind" --name "$cluster"
	image=(--set image.repository="$repo" --set image.tag=kind --set image.pullPolicy=Never)
	echo "testing $repo@$digest"
else
	VERSION=${VERSION:-dev} KO_DOCKER_REPO=ko.local ko build --base-import-paths --tags ci --platform "linux/$(go env GOARCH)" ./cmd/exitmesh-agent
	kind load docker-image ko.local/exitmesh-agent:ci --name "$cluster"
	image=(--set image.repository=ko.local/exitmesh-agent --set image.tag=ci --set image.pullPolicy=Never)
fi

refcp=${REFCP:-$work/exitmesh-refcp}
[ -x "$refcp" ] || go build -o "$refcp" ./cmd/exitmesh-refcp
# Newer Docker lists the IPv6 subnet first and may omit gateways, so fall back to the node's default route.
gw=$(docker network inspect kind -f '{{range .IPAM.Config}}{{.Gateway}} {{end}}' | tr ' ' '\n' | grep -m1 -E '^[0-9]+(\.[0-9]+){3}$' || true)
[ -n "$gw" ] || gw=$(docker exec "$cluster-control-plane" ip -4 route show default | awk '{print $3; exit}')
[ -n "$gw" ] || fail "no IPv4 gateway on the kind network"
echo "control plane reachable from the cluster at $gw:$port"
"$refcp" -listen "0.0.0.0:$port" -hostnames "$gw" -create-cluster -cert-dir "$work" -trust-dir "$work/trust" -bundle-kubernetes rules/kubernetes -status >"$work/refcp.out" 2>"$work/refcp.log" &
refcp_pid=$!
trap 'kill $refcp_pid 2>/dev/null || true' EXIT
for _ in $(seq 1 50); do
	grep -q '^bundle kubernetes' "$work/refcp.out" && break
	sleep 0.2
done
grep -q '^bundle kubernetes' "$work/refcp.out" || fail "refcp did not start"
ca=$(awk '$1=="ca"{print $2}' "$work/refcp.out")
token=$(awk '$1=="target" && $2=="kubernetes"{print $5}' "$work/refcp.out")
bundle_version=$(awk '$1=="bundle" && $2=="kubernetes"{print $3}' "$work/refcp.out")
root=$(cat "$work/trust/roots.txt")
status() { curl -fsS --cacert "$ca" "https://127.0.0.1:$port/_refcp/status"; }

common=(--namespace default
	--set endpoint="https://$gw:$port"
	--set-file endpointCA="$ca"
	--set enrollment.token="$token"
	--set-json "trust.roots=[\"$root\"]"
	"${image[@]}"
	--set coordinator.persistence.accessMode=ReadWriteOnce
	# kind kubelets serve self-signed certificates that the cluster CA does not sign.
	--set node.kubeletTLS=skip)

echo "== createNamespaces=false validation against the live cluster"
kubectl create namespace "$nodens"
kubectl create namespace "$coordns"
if out=$(helm install "$release" "$chart" "${common[@]}" --set createNamespaces=false --dry-run=server 2>&1); then
	fail "install into unlabelled namespaces succeeded"
fi
grep -q 'pod-security.kubernetes.io/enforce' <<<"$out" || fail "unexpected error: $out"
kubectl label namespace "$nodens" pod-security.kubernetes.io/enforce=privileged
kubectl label namespace "$coordns" pod-security.kubernetes.io/enforce=restricted
helm install "$release" "$chart" "${common[@]}" --set createNamespaces=false --dry-run=server >/dev/null || fail "install into labelled namespaces failed"
kubectl delete namespace "$nodens" "$coordns" --wait=true
if out=$(helm install "$release" "$chart" "${common[@]}" --set createNamespaces=false --dry-run=server 2>&1); then
	fail "install into missing namespaces succeeded"
fi
grep -q 'does not exist' <<<"$out" || fail "unexpected error: $out"

echo "== install"
helm install "$release" "$chart" "${common[@]}" --wait --timeout 5m || fail "helm install"
kubectl -n "$coordns" rollout status statefulset/$release-coordinator --timeout 3m || fail "coordinator not ready"
kubectl -n "$nodens" rollout status daemonset/$release-node --timeout 3m || fail "node agents not ready"
[ "$(kubectl get ns "$nodens" -o jsonpath='{.metadata.labels.pod-security\.kubernetes\.io/enforce}')" = privileged ] || fail "node namespace PSA label"
[ "$(kubectl get ns "$coordns" -o jsonpath='{.metadata.labels.pod-security\.kubernetes\.io/enforce}')" = restricted ] || fail "coordinator namespace PSA label"

echo "== enrollment, delivery, and node agent registration"
nodes=$(kind get nodes --name "$cluster" | wc -l)
ok=
for _ in $(seq 1 90); do
	if st=$(status) && jq -e --argjson n "$nodes" --arg bv "$bundle_version" '.targets[0] | .committed >= 1 and (.epochs | length) == 1 and .health_reports >= 1 and ((.last_health.nodes // []) | length) == $n and all((.last_health.nodes // [])[]; .bundle_version == $bv)' >/dev/null <<<"$st"; then
		ok=1
		break
	fi
	sleep 3
done
[ -n "$ok" ] || fail "coordinator did not commit, or node agents did not converge on bundle $bundle_version: $(status || true)"

echo "== node agents read logs and metrics as UID 65532 with only CAP_DAC_READ_SEARCH"
ok=
for _ in $(seq 1 40); do
	if st=$(status) && jq -e '.targets[0].last_health | (.nodes | length) > 0 and all(.nodes[];
		(.coverage.logs | startswith("unavailable") | not) and (.coverage.metrics | startswith("unavailable") | not) and
		.process.uid == 65532 and .process.gid == 65532 and .process.capabilities == ["CAP_DAC_READ_SEARCH"])' >/dev/null <<<"$st"; then
		ok=1
		break
	fi
	sleep 3
done
[ -n "$ok" ] || fail "node agent coverage or identity: $(status | jq -c '.targets[0].last_health.nodes[] | {name, coverage, process}' || true)"
forbidden=$(status | jq -c '[.targets[0].last_health.coverage[] | select(.reason == "forbidden") | .key]')
[ "$forbidden" = "[]" ] || fail "the coordinator lacks RBAC for $forbidden"

echo "== RBAC is read-only"
coordsa=system:serviceaccount:$coordns:$release-coordinator
nodesa=system:serviceaccount:$nodens:$release-node
can() {
	local who=$1 verb=$2 res=$3 sub=${4:-}
	kubectl auth can-i "$verb" "$res" ${sub:+--subresource "$sub"} --as "$who" -A >/dev/null 2>&1
}
for check in "$coordsa create pods" "$coordsa get secrets" "$coordsa create pods exec" "$coordsa get nodes proxy" "$coordsa create tokenreviews" \
	"$coordsa patch statefulsets" "$nodesa get secrets" "$nodesa get nodes log" "$nodesa create pods portforward" "$nodesa delete pods" "$nodesa update daemonsets"; do
	read -r who verb res sub <<<"$check"
	if can "$who" "$verb" "$res" "$sub"; then
		fail "$who can $verb $res${sub:+/$sub}"
	fi
done
can "$nodesa" list pods || fail "node agent cannot list pods"
can "$nodesa" get nodes metrics || fail "node agent cannot get nodes/metrics"
can "$coordsa" get persistentvolumes || fail "coordinator cannot get persistentvolumes"

echo "== host state directory"
for node in $(kind get nodes --name "$cluster"); do
	got=$(docker exec "$node" stat -c '%a %u' /var/lib/exitmesh)
	[ "$got" = "700 65532" ] || fail "$node /var/lib/exitmesh is $got"
done

echo "== upgrade reuses the node API certificate"
before=$(kubectl -n "$coordns" get secret $release-coordinator-tls -o jsonpath='{.data.tls\.crt}')
helm upgrade "$release" "$chart" "${common[@]}" --wait --timeout 5m || fail "helm upgrade"
after=$(kubectl -n "$coordns" get secret $release-coordinator-tls -o jsonpath='{.data.tls\.crt}')
[ "$before" = "$after" ] || fail "serving certificate regenerated on upgrade"

echo "== uninstall"
helm uninstall "$release" --namespace default --cascade foreground --wait --timeout 5m || fail "helm uninstall"
kubectl -n "$nodens" get daemonset $release-node >/dev/null 2>&1 && fail "node DaemonSet still present"
kubectl -n "$nodens" rollout status daemonset/$release-cleanup --timeout 3m || fail "cleanup did not complete on every node"
for node in $(kind get nodes --name "$cluster"); do
	left=$(docker exec "$node" sh -c 'ls -A /var/lib/exitmesh 2>/dev/null' || true)
	[ -z "$left" ] || fail "$node still holds state: $left"
done
for _ in $(seq 1 60); do
	[ -z "$(kubectl -n "$coordns" get pvc -o name)" ] && break
	sleep 2
done
[ -z "$(kubectl -n "$coordns" get pvc -o name)" ] || fail "coordinator PVC not deleted"
kubectl -n "$nodens" delete daemonset $release-cleanup --wait=true
kubectl delete namespace "$nodens" "$coordns" --wait=true
echo "integration passed"

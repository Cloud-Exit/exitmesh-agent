#!/usr/bin/env bash
# Renders the chart with several value sets and validates every object with kubeconform across Kubernetes versions.
set -euo pipefail
cd "$(git rev-parse --show-toplevel)"

chart=${CHART:-deploy/helm/exitmesh-agent}
versions=${KUBE_VERSIONS:-1.27.0 1.30.0 1.34.0 1.37.0}
root="ci-root:$(printf '%032d' 0 | head -c 32 | base64 -w0)"
base=(--namespace default --set endpoint=https://cp.example.com --set enrollment.token=emx1_c_t-ci_abcdefghijklmnop --set-json "trust.roots=[\"$root\"]")
out=$(mktemp -d)

declare -A sets=(
	[default]=""
	[namespaces]="--set kubernetes.scope=namespaces --set kubernetes.namespaces={team-a,team-b}"
	[airgap]="--set airgap.enabled=true --set airgap.bundles.configMap=exitmesh-bundles"
	[precreated]="--set createNamespaces=false --set namespaces.skipLookupValidation=true"
	[inventory]="--set capabilities.metrics=false --set capabilities.logs=false"
)
for name in "${!sets[@]}"; do
	# shellcheck disable=SC2086
	helm template exitmesh-agent "$chart" "${base[@]}" ${sets[$name]} >"$out/$name.yaml"
done
for v in $versions; do
	echo "== Kubernetes $v"
	kubeconform -strict -summary -kubernetes-version "$v" -schema-location default "$out"/*.yaml
done

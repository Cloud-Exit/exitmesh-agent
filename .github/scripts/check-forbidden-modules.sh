#!/usr/bin/env bash
# Fails when the module graph contains Loki, Grafana AGPL projects, or other known copyleft modules.
set -euo pipefail
cd "$(git rev-parse --show-toplevel)"

deny='^(github\.com/grafana/(loki|grafana|mimir|tempo|pyroscope|alloy|agent|oncall|phlare|k6)|go\.k6\.io/k6)(/|$)'
mods=$(go list -m -f '{{.Path}}' all)
bad=$(printf '%s\n' "$mods" | grep -E "$deny" || true)
if [ -n "$bad" ]; then
	echo "forbidden modules in the build graph:" >&2
	printf '  %s\n' $bad >&2
	exit 1
fi
if grep -Eq '(^|[[:space:]/])loki([/[:space:]]|$)' go.mod; then
	echo "go.mod references a Loki module" >&2
	exit 1
fi
# Only the tsdb, promql, textparse, and labels packages of Prometheus may be imported directly (the tsdb itself pulls config transitively).
direct=$(go list -f '{{join .Imports "\n"}}' ./... | grep -E '^github\.com/prometheus/prometheus/(discovery|scrape|notifier|rules|web|cmd)(/|$)' | sort -u || true)
if [ -n "$direct" ]; then
	echo "forbidden direct Prometheus imports:" >&2
	printf '  %s\n' $direct >&2
	exit 1
fi
echo "no forbidden modules ($(printf '%s\n' "$mods" | wc -l) modules checked)"

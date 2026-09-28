#!/usr/bin/env bash
# Runs every native Go fuzz target for a short time; FUZZTIME overrides the per-target budget.
set -euo pipefail
cd "$(git rev-parse --show-toplevel)"

fuzztime=${FUZZTIME:-15s}
count=0
while read -r pkg; do
	targets=$(go test -list '^Fuzz' "$pkg" | grep -E '^Fuzz' || true)
	for target in $targets; do
		echo "::group::$pkg $target"
		go test -run '^$' -fuzz "^${target}\$" -fuzztime "$fuzztime" "$pkg"
		echo "::endgroup::"
		count=$((count + 1))
	done
done < <(grep -rl --include='*_test.go' -E '^func Fuzz[A-Za-z0-9_]*\(' . | xargs -r -n1 dirname | sort -u)
echo "ran $count fuzz targets for $fuzztime each"

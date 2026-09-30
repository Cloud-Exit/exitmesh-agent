#!/usr/bin/env bash
# Reserves the next version by pushing annotated tag vX.Y.Z on COMMIT; tags cannot be overwritten, so concurrent runs always get distinct versions.
# usage: reserve-version.sh LEVEL COMMIT (prints the version)
set -euo pipefail
cd "$(git rev-parse --show-toplevel)"

level=${1:?usage: reserve-version.sh LEVEL COMMIT}
commit=$(git rev-parse --verify "${2:?usage: reserve-version.sh LEVEL COMMIT}^{commit}")
here=$(cd "$(dirname "$0")" && pwd)
run="${GITHUB_SERVER_URL:-local}/${GITHUB_REPOSITORY:-}/actions/runs/${GITHUB_RUN_ID:-$$}"

for attempt in $(seq 1 10); do
	git fetch -q --force --prune --prune-tags --tags origin
	version=$("$here/next-version.sh" "$level")
	tag="v$version"
	# The nonce makes each run's tag object unique; an identical object would push as "up to date" for two runs on one commit.
	git -c user.name="github-actions[bot]" -c user.email="41898282+github-actions[bot]@users.noreply.github.com" \
		tag -f -a "$tag" -m "$tag" -m "Reserved by $run (nonce $(od -An -N8 -tx8 /dev/urandom | tr -d ' '))" "$commit"
	mine=$(git rev-parse "refs/tags/$tag")
	out=$(git push -q origin "refs/tags/$tag" 2>&1) || true
	remote=$(git ls-remote --tags origin "refs/tags/$tag" | cut -f1)
	if [ "$remote" = "$mine" ]; then
		echo "$version"
		exit 0
	fi
	git tag -d "$tag" >/dev/null
	if [ -z "$remote" ]; then
		echo "reserve-version: pushing $tag failed: $out" >&2
		exit 1
	fi
	echo "reserve-version: $tag was taken by a concurrent release (attempt $attempt)" >&2
	sleep "$attempt"
done
echo "reserve-version: no free version after 10 attempts" >&2
exit 1

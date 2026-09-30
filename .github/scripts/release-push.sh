#!/usr/bin/env bash
# Commits the Chart.yaml bump to VERSION on the release branch with [skip ci], unless the branch already records the same or a newer version.
set -euo pipefail
cd "$(git rev-parse --show-toplevel)"

version=${1:?usage: release-push.sh VERSION}
branch=${RELEASE_BRANCH:-main}
chart=deploy/helm/exitmesh-agent/Chart.yaml
work=$(mktemp -d)
trap 'git worktree remove --force "$work" >/dev/null 2>&1 || true' EXIT

for attempt in 1 2 3 4 5; do
	git fetch -q origin "$branch"
	git worktree remove --force "$work" >/dev/null 2>&1 || true
	git worktree add -q --detach "$work" FETCH_HEAD
	current=$(sed -n 's/^version:[[:space:]]*"\{0,1\}\([0-9][0-9.]*\)"\{0,1\}[[:space:]]*$/\1/p' "$work/$chart")
	if [ "$(printf '%s\n%s\n' "$current" "$version" | sort -V | tail -n1)" != "$version" ] || [ "$current" = "$version" ]; then
		echo "$branch already records version $current"
		exit 0
	fi
	sed -i -E "s/^version:.*/version: $version/; s/^appVersion:.*/appVersion: \"$version\"/" "$work/$chart"
	git -C "$work" -c user.name="github-actions[bot]" -c user.email="41898282+github-actions[bot]@users.noreply.github.com" \
		commit -q -m "release: v$version [skip ci]" -- "$chart"
	if git -C "$work" push -q origin "HEAD:refs/heads/$branch"; then
		echo "recorded v$version on $branch"
		exit 0
	fi
	echo "push rejected (attempt $attempt), retrying on the new $branch" >&2
	sleep $((attempt * 3))
done
echo "release-push: could not record v$version after 5 attempts" >&2
exit 1

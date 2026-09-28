#!/usr/bin/env bash
# Commits the Chart.yaml bump for VERSION with [skip ci], tags vVERSION (on TAG_COMMIT, the built commit, when set), and pushes both atomically, rebasing on races.
set -euo pipefail
cd "$(git rev-parse --show-toplevel)"

version=${1:?usage: release-push.sh VERSION}
branch=${RELEASE_BRANCH:-main}
chart=deploy/helm/exitmesh-agent/Chart.yaml
tag="v$version"

git config user.name "github-actions[bot]"
git config user.email "41898282+github-actions[bot]@users.noreply.github.com"

bump() {
	sed -i -E "s/^version:.*/version: $version/; s/^appVersion:.*/appVersion: \"$version\"/" "$chart"
	git add "$chart"
	if git diff --cached --quiet; then
		return 0
	fi
	git commit -q -m "release: $tag [skip ci]"
}

bump
for attempt in 1 2 3 4 5; do
	git tag -f "$tag" "${TAG_COMMIT:-HEAD}" >/dev/null
	if git push --atomic origin "HEAD:refs/heads/$branch" "refs/tags/$tag"; then
		echo "pushed $tag"
		exit 0
	fi
	echo "push rejected (attempt $attempt), rebasing onto origin/$branch" >&2
	git fetch -q origin "$branch"
	git rebase -q "origin/$branch" || { git rebase --abort; git reset -q --hard "origin/$branch"; bump; }
	sleep $((attempt * 3))
done
echo "release-push: could not push $tag after 5 attempts" >&2
exit 1

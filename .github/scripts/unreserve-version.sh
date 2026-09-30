#!/usr/bin/env bash
# Deletes tag vVERSION from origin when it still tags COMMIT, releasing the version reserved by a run that published nothing.
# usage: unreserve-version.sh VERSION COMMIT
set -euo pipefail
cd "$(git rev-parse --show-toplevel)"

version=${1:?usage: unreserve-version.sh VERSION COMMIT}
commit=${2:?usage: unreserve-version.sh VERSION COMMIT}
tag="v$version"

if ! git fetch -q --depth=1 origin "+refs/tags/$tag:refs/tags/$tag" 2>/dev/null; then
	if git ls-remote --exit-code --tags origin "refs/tags/$tag" >/dev/null; then
		echo "unreserve-version: $tag exists on origin but could not be fetched" >&2
		exit 1
	fi
	echo "$tag is not on origin"
	exit 0
fi
at=$(git rev-parse "refs/tags/$tag^{commit}")
if [ "$at" != "$(git rev-parse "$commit^{commit}" 2>/dev/null || echo "$commit")" ]; then
	echo "unreserve-version: $tag tags $at, not $commit; left in place" >&2
	exit 0
fi
git push -q origin --delete "refs/tags/$tag"
git tag -d "$tag" >/dev/null
echo "released $tag"

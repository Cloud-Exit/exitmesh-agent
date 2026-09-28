#!/usr/bin/env bash
# Prints the next release version: max(Chart.yaml version, latest vX.Y.Z tag) bumped by patch, minor, or major.
set -euo pipefail
cd "$(git rev-parse --show-toplevel)"

level=${1:-patch}
chart=deploy/helm/exitmesh-agent/Chart.yaml
semver='^[0-9]+\.[0-9]+\.[0-9]+$'

chart_version=$(sed -n 's/^version:[[:space:]]*"\{0,1\}\([0-9][0-9.]*\)"\{0,1\}[[:space:]]*$/\1/p' "$chart")
[[ $chart_version =~ $semver ]] || { echo "next-version: $chart has no X.Y.Z version" >&2; exit 1; }
tag_version=$(git tag --list 'v[0-9]*.[0-9]*.[0-9]*' | sed 's/^v//' | grep -E "$semver" | sort -V | tail -n1 || true)
base=$(printf '%s\n%s\n' "$chart_version" "${tag_version:-0.0.0}" | sort -V | tail -n1)

IFS=. read -r major minor patch <<<"$base"
case "$level" in
patch) patch=$((patch + 1)) ;;
minor) minor=$((minor + 1)); patch=0 ;;
major) major=$((major + 1)); minor=0; patch=0 ;;
*) echo "next-version: level must be patch, minor, or major" >&2; exit 2 ;;
esac
echo "$major.$minor.$patch"

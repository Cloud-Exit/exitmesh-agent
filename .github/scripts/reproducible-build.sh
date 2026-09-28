#!/usr/bin/env bash
# Builds the agent twice from two checkouts at different paths and fails if any binary differs.
set -euo pipefail
cd "$(git rev-parse --show-toplevel)"

version=${VERSION:-$(git describe --tags --always --dirty)}
commit=$(git rev-parse HEAD)
date=$(git log -1 --format=%cI)
export SOURCE_DATE_EPOCH=$(git log -1 --format=%ct)
export CGO_ENABLED=0
work=$(mktemp -d)
trap 'git worktree remove --force "$work/b" >/dev/null 2>&1 || true; rm -rf "$work"' EXIT
git worktree add --detach "$work/b" "$commit" >/dev/null

build() {
	local src=$1 out=$2 arch
	for arch in amd64 arm64; do
		(cd "$src" && GOOS=linux GOARCH=$arch go build -trimpath \
			-ldflags "-s -w -buildid= -X main.version=$version -X main.commit=$commit -X main.date=$date" \
			-o "$out/exitmesh-agent-linux-$arch" ./cmd/exitmesh-agent)
	done
}
build "$PWD" "$work/out-a"
build "$work/b" "$work/out-b"
(cd "$work/out-a" && sha256sum ./*) >"$work/a.sum"
(cd "$work/out-b" && sha256sum ./*) >"$work/b.sum"
cat "$work/a.sum"
if ! diff -u "$work/a.sum" "$work/b.sum"; then
	echo "builds are not reproducible" >&2
	exit 1
fi
if go version -m "$work/out-a/exitmesh-agent-linux-amd64" | grep -q 'CGO_ENABLED=1'; then
	echo "binary built with cgo" >&2
	exit 1
fi
echo "reproducible: identical checksums from two checkouts"

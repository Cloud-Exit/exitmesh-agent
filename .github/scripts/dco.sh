#!/usr/bin/env bash
# Verifies that every commit in BASE..HEAD carries a Signed-off-by trailer matching its author.
set -euo pipefail
cd "$(git rev-parse --show-toplevel)"

base=${1:?usage: dco.sh <base-ref> [head-ref]}
head=${2:-HEAD}
fail=0
for c in $(git rev-list --no-merges "$base..$head"); do
	author=$(git log -1 --format='%an <%ae>' "$c")
	if ! git log -1 --format='%(trailers:key=Signed-off-by,valueonly)' "$c" | grep -Fqx "$author"; then
		echo "commit $(git log -1 --format='%h %s' "$c") lacks 'Signed-off-by: $author'" >&2
		fail=1
	fi
done
if [ "$fail" -ne 0 ]; then
	echo "sign off with: git commit --amend --signoff (or git rebase --signoff $base)" >&2
	exit 1
fi
echo "all commits signed off"

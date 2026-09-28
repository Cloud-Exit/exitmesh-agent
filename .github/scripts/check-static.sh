#!/usr/bin/env bash
# Fails unless every given ELF binary is statically linked (no program interpreter, no dynamic section).
set -euo pipefail
[ $# -gt 0 ] || { echo "usage: check-static.sh BINARY..." >&2; exit 2; }
for bin in "$@"; do
	if readelf -lW "$bin" | grep -q 'Requesting program interpreter'; then
		echo "FAIL: $bin requests a program interpreter" >&2
		exit 1
	fi
	if readelf -dW "$bin" 2>/dev/null | grep -q '(NEEDED)'; then
		echo "FAIL: $bin needs shared libraries:" >&2
		readelf -dW "$bin" | grep '(NEEDED)' >&2
		exit 1
	fi
	echo "static: $bin ($(readelf -hW "$bin" | sed -n 's/^ *Machine: *//p'))"
done

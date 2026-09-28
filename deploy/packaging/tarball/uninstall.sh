#!/bin/sh
# Removes the ExitMesh host agent installed by install.sh; --purge also deletes /var/lib/exitmesh after taking its lock.
set -eu

PREFIX=${PREFIX:-/usr/local}
UNIT=exitmesh-agent.service
STATE=/var/lib/exitmesh
BIN=$PREFIX/bin/exitmesh-agent
purge=0

for arg in "$@"; do
	case "$arg" in
	--purge) purge=1 ;;
	-h | --help)
		echo "usage: uninstall.sh [--purge]"
		exit 0
		;;
	*)
		echo "unknown argument: $arg" >&2
		exit 2
		;;
	esac
done
if [ "$(id -u)" -ne 0 ]; then
	echo "uninstall.sh must run as root" >&2
	exit 1
fi

systemctl stop "$UNIT" 2>/dev/null || true
systemctl disable "$UNIT" >/dev/null 2>&1 || true

if [ "$purge" -eq 1 ] && [ -d "$STATE" ]; then
	if [ -t 0 ] && [ -x "$BIN" ]; then
		printf 'De-enroll this host now, revoking its credential in ExitMesh? [y/N] '
		read -r answer || answer=n
		case "$answer" in
		y | Y | yes | YES)
			if command -v runuser >/dev/null 2>&1; then
				runuser -u exitmesh -- "$BIN" deenroll --config /etc/exitmesh/agent.yaml
			else
				"$BIN" deenroll --config /etc/exitmesh/agent.yaml
			fi
			;;
		*) echo "Not de-enrolled. The host shows as offline in ExitMesh until an administrator de-enrolls it there." ;;
		esac
	else
		echo "Not de-enrolled. The host shows as offline in ExitMesh until an administrator de-enrolls it there."
	fi
	if ! "$BIN" purge-state --dir "$STATE"; then
		echo "refusing to delete $STATE: its lock is held by a running agent. Stop it and run uninstall.sh --purge again." >&2
		exit 1
	fi
fi

rm -f /etc/systemd/system/$UNIT "$BIN" /etc/sysusers.d/exitmesh-agent.conf
rm -rf /etc/systemd/system/exitmesh-agent.service.d
if [ "$purge" -eq 1 ]; then
	rm -rf /etc/exitmesh
	echo "exitmesh-agent purged."
else
	echo "exitmesh-agent removed. $STATE and /etc/exitmesh were kept; reinstalling resumes the same target. Run uninstall.sh --purge to delete them."
fi
systemctl daemon-reload

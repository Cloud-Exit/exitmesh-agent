#!/bin/sh
# Installs or upgrades the ExitMesh host agent from an extracted release tarball.
set -eu

PREFIX=${PREFIX:-/usr/local}
UNIT=exitmesh-agent.service
STATE=/var/lib/exitmesh
DROPIN=/etc/systemd/system/exitmesh-agent.service.d
here=$(cd "$(dirname "$0")" && pwd)

if [ "$(id -u)" -ne 0 ]; then
	echo "install.sh must run as root" >&2
	exit 1
fi
if ! [ -d /run/systemd/system ]; then
	echo "install.sh requires systemd" >&2
	exit 1
fi
for f in exitmesh-agent systemd/exitmesh-agent.service sysusers.d/exitmesh-agent.conf config/agent.yaml; do
	if ! [ -f "$here/$f" ]; then
		echo "install.sh: $f missing next to the script" >&2
		exit 1
	fi
done

upgrade=0
[ -e /etc/systemd/system/$UNIT ] && upgrade=1

install -d -m 0755 "$PREFIX/bin" /etc/sysusers.d /etc/exitmesh
install -m 0755 "$here/exitmesh-agent" "$PREFIX/bin/exitmesh-agent"
install -m 0644 "$here/sysusers.d/exitmesh-agent.conf" /etc/sysusers.d/exitmesh-agent.conf
if ! getent passwd exitmesh >/dev/null; then
	if command -v systemd-sysusers >/dev/null 2>&1; then
		systemd-sysusers /etc/sysusers.d/exitmesh-agent.conf
	else
		useradd --system --user-group --home-dir "$STATE" --no-create-home --shell /usr/sbin/nologin --comment "ExitMesh agent" exitmesh
	fi
fi
install -d -m 0700 -o exitmesh -g exitmesh "$STATE"
[ -e /etc/exitmesh/agent.yaml ] || install -m 0644 "$here/config/agent.yaml" /etc/exitmesh/agent.yaml
sed "s#/usr/bin/exitmesh-agent#$PREFIX/bin/exitmesh-agent#" "$here/systemd/exitmesh-agent.service" >/etc/systemd/system/$UNIT
chmod 0644 /etc/systemd/system/$UNIT
if getent group adm >/dev/null; then
	mkdir -p "$DROPIN"
	printf '[Service]\nSupplementaryGroups=adm\n' >"$DROPIN/10-adm.conf"
else
	rm -f "$DROPIN/10-adm.conf"
fi
systemctl daemon-reload
if [ "$upgrade" -eq 1 ]; then
	systemctl try-restart "$UNIT"
	echo "exitmesh-agent upgraded; state in $STATE was kept."
else
	systemctl enable "$UNIT" >/dev/null
	systemctl start "$UNIT" || true
	if [ ! -e /etc/exitmesh/enrollment-token ]; then
		echo "exitmesh-agent installed. Set endpoint in /etc/exitmesh/agent.yaml, write the enrollment token to /etc/exitmesh/enrollment-token (mode 0640, group exitmesh), then run: systemctl start $UNIT"
	fi
fi

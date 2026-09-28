#!/usr/bin/env bash
# Installs the host .deb on this systemd machine, runs the agent against exitmesh-refcp, and checks enrollment, delivery, hardening, and purge.
# usage: host-smoke.sh AGENT_DEB REFCP_BINARY
set -euo pipefail
cd "$(git rev-parse --show-toplevel)"

deb=$(realpath "${1:?usage: host-smoke.sh AGENT_DEB REFCP_BINARY}")
refcp=$(realpath "${2:?usage: host-smoke.sh AGENT_DEB REFCP_BINARY}")
work=$(mktemp -d)
port=${REFCP_PORT:-18443}

fail() {
	echo "FAIL: $*" >&2
	sudo journalctl -u exitmesh-agent --no-pager -n 200 >&2 || true
	cat "$work/refcp.log" >&2 || true
	exit 1
}

"$refcp" -listen "127.0.0.1:$port" -create-host -cert-dir "$work" -trust-dir "$work/trust" -bundle-host rules/host -status >"$work/refcp.out" 2>"$work/refcp.log" &
refcp_pid=$!
trap 'kill $refcp_pid 2>/dev/null || true' EXIT
for _ in $(seq 1 50); do
	grep -q '^bundle host' "$work/refcp.out" && break
	sleep 0.2
done
grep -q '^bundle host' "$work/refcp.out" || fail "refcp did not start"
ca=$(awk '$1=="ca"{print $2}' "$work/refcp.out")
token=$(awk '$1=="target" && $2=="host"{print $5}' "$work/refcp.out")
root=$(cat "$work/trust/roots.txt")
status() { curl -fsS --cacert "$ca" "https://127.0.0.1:$port/_refcp/status"; }

echo "== install $deb"
sudo DEBIAN_FRONTEND=noninteractive apt-get install -y -q --no-install-recommends "$deb"
sudo install -m 0644 "$ca" /etc/exitmesh/endpoint-ca.pem
sudo tee /etc/exitmesh/agent.yaml >/dev/null <<YAML
role: host
endpoint: https://127.0.0.1:$port
endpointCAFile: /etc/exitmesh/endpoint-ca.pem
enrollmentTokenFile: /etc/exitmesh/enrollment-token
stateDir: /var/lib/exitmesh
capabilities: [inventory, metrics, logs]
trust:
  roots: ["$root"]
host:
  journal: true
logging:
  level: info
YAML
printf '%s\n' "$token" | sudo install -m 0640 -o root -g exitmesh /dev/stdin /etc/exitmesh/enrollment-token
sudo systemctl daemon-reload
sudo systemctl start exitmesh-agent

echo "== enrollment and delivery"
ok=
for _ in $(seq 1 90); do
	if st=$(status) && jq -e '.targets[0] | .committed >= 1 and .health_reports >= 1 and (.epochs | length) == 1' >/dev/null <<<"$st"; then
		ok=1
		break
	fi
	sleep 2
done
[ -n "$ok" ] || fail "no committed records or health reports: $(status || true)"
jq -e '.targets[0].last_health.bundle' >/dev/null <<<"$st" || true

echo "== hardening"
pid=$(systemctl show -p MainPID --value exitmesh-agent)
[ "$pid" != 0 ] || fail "service not running"
[ "$(ps -o user= -p "$pid" | tr -d ' ')" = exitmesh ] || fail "service does not run as exitmesh"
[ "$(systemctl show -p ProtectSystem --value exitmesh-agent)" = strict ] || fail "ProtectSystem is not strict"
[ "$(systemctl show -p NoNewPrivileges --value exitmesh-agent)" = yes ] || fail "NoNewPrivileges is not set"
[ -z "$(systemctl show -p CapabilityBoundingSet --value exitmesh-agent)" ] || fail "capability bounding set is not empty"
systemd-analyze security exitmesh-agent --no-pager | tail -n 1 || true
outside=$(sudo find / -xdev \( -path /proc -o -path /sys -o -path /run -o -path /tmp \) -prune -o -user exitmesh -print | grep -v '^/var/lib/exitmesh' || true)
[ -z "$outside" ] || fail "files owned by exitmesh outside /var/lib/exitmesh: $outside"

echo "== admin socket"
sudo -u exitmesh /usr/bin/exitmesh-agent status --config /etc/exitmesh/agent.yaml | jq -e . >/dev/null || fail "status over the admin socket"

echo "== restart resumes the same target and epoch"
before=$(status | jq '.targets[0].health_reports')
sudo systemctl restart exitmesh-agent
for _ in $(seq 1 60); do
	st=$(status)
	[ "$(jq '.targets[0].health_reports' <<<"$st")" -gt "$before" ] && break
	sleep 2
done
jq -e '.targets[0] | (.epochs | length) == 1 and .divergences == 0 and .rejected == 0' >/dev/null <<<"$st" || fail "restart changed the epoch or was rejected: $st"

echo "== graceful stop"
sudo systemctl stop exitmesh-agent
[ "$(systemctl show -p ExecMainStatus --value exitmesh-agent)" = 0 ] || fail "agent did not exit cleanly"
if sudo journalctl -u exitmesh-agent --no-pager | grep -q 'panic:'; then
	fail "agent panicked"
fi

echo "== purge"
sudo DEBIAN_FRONTEND=noninteractive apt-get purge -y -q exitmesh-agent
[ ! -e /var/lib/exitmesh ] || fail "/var/lib/exitmesh left after purge"
echo "host smoke passed"

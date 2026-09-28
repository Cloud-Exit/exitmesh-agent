#!/bin/sh
# Runs as root inside a distribution container: install (optionally upgrading from an older package), verify, remove, purge.
# usage: package-smoke.sh NEW_PACKAGE_DIR [OLD_PACKAGE_DIR]
set -eu

new=${1:?usage: package-smoke.sh NEW_PACKAGE_DIR [OLD_PACKAGE_DIR]}
old=${2:-}
arch=$(uname -m)
state=/var/lib/exitmesh

fail() {
	echo "FAIL: $*" >&2
	exit 1
}

if command -v apt-get >/dev/null 2>&1; then
	fmt=deb
	pkgarch=$(dpkg --print-architecture)
elif command -v zypper >/dev/null 2>&1; then
	fmt=zypper
	pkgarch=$arch
elif command -v dnf >/dev/null 2>&1 || command -v microdnf >/dev/null 2>&1 || command -v yum >/dev/null 2>&1; then
	fmt=rpm
	pkgarch=$arch
else
	fail "no supported package manager"
fi
pm=$(command -v dnf || command -v microdnf || command -v yum || true)

pkg_in() {
	case $fmt in
	deb) ls "$1"/exitmesh-agent_*_"$pkgarch".deb 2>/dev/null | head -n1 ;;
	*) ls "$1"/exitmesh-agent-*."$pkgarch".rpm 2>/dev/null | head -n1 ;;
	esac
}

install_pkg() {
	case $fmt in
	deb) DEBIAN_FRONTEND=noninteractive apt-get install -y -q --no-install-recommends "$1" ;;
	zypper) zypper --non-interactive install --allow-unsigned-rpm --no-recommends "$1" ;;
	rpm) "$pm" install -y --setopt=install_weak_deps=False "$1" ;;
	esac
}

remove_pkg() {
	case $fmt in
	deb) DEBIAN_FRONTEND=noninteractive apt-get remove -y -q exitmesh-agent ;;
	zypper) zypper --non-interactive remove exitmesh-agent ;;
	rpm) "$pm" remove -y exitmesh-agent ;;
	esac
}

purge_pkg() {
	case $fmt in
	deb) DEBIAN_FRONTEND=noninteractive apt-get purge -y -q exitmesh-agent ;;
	zypper) EXITMESH_PURGE=1 zypper --non-interactive remove exitmesh-agent ;;
	rpm) EXITMESH_PURGE=1 "$pm" remove -y exitmesh-agent ;;
	esac
}

pkg_version() {
	case $fmt in
	deb) dpkg-query -W -f '${Version}' exitmesh-agent ;;
	*) rpm -q --qf '%{VERSION}' exitmesh-agent ;;
	esac
}

mode_owner() { stat -c '%a %U:%G' "$1"; }

verify_installed() {
	id exitmesh >/dev/null 2>&1 || fail "user exitmesh missing"
	[ -x /usr/bin/exitmesh-agent ] || fail "binary missing"
	[ "$(mode_owner /usr/bin/exitmesh-agent)" = "755 root:root" ] || fail "binary mode $(mode_owner /usr/bin/exitmesh-agent)"
	[ -f /usr/lib/systemd/system/exitmesh-agent.service ] || fail "systemd unit missing"
	[ -f /usr/lib/sysusers.d/exitmesh-agent.conf ] || fail "sysusers file missing"
	[ -f /etc/exitmesh/agent.yaml ] || fail "default configuration missing"
	[ "$(mode_owner "$state")" = "700 exitmesh:exitmesh" ] || fail "$state is $(mode_owner "$state")"
	/usr/bin/exitmesh-agent version | grep -q "protocol" || fail "version output"
	if out=$(/usr/bin/exitmesh-agent run --config /etc/exitmesh/agent.yaml 2>&1); then
		fail "the default configuration must not start an agent"
	fi
	echo "$out" | grep -q "trust.roots" || fail "missing trust roots not reported clearly: $out"
	if command -v systemd-analyze >/dev/null 2>&1; then
		systemd-analyze verify /usr/lib/systemd/system/exitmesh-agent.service || fail "systemd-analyze verify"
	fi
}

case $fmt in
deb)
	apt-get update -q >/dev/null
	;;
esac

newpkg=$(pkg_in "$new")
[ -n "$newpkg" ] || fail "no $fmt package for $pkgarch in $new"

if [ -n "$old" ]; then
	oldpkg=$(pkg_in "$old")
	[ -n "$oldpkg" ] || fail "no $fmt package for $pkgarch in $old"
	echo "== install $oldpkg"
	install_pkg "$oldpkg"
	verify_installed
	before=$(pkg_version)
	echo "# local edit" >>/etc/exitmesh/agent.yaml
	echo keep >"$state/marker"
	chown exitmesh:exitmesh "$state/marker"
	echo "== upgrade to $newpkg"
	install_pkg "$newpkg"
	[ "$(pkg_version)" != "$before" ] || fail "version did not change on upgrade"
	grep -q "# local edit" /etc/exitmesh/agent.yaml || fail "configuration replaced on upgrade"
	[ "$(cat "$state/marker")" = keep ] || fail "state lost on upgrade"
else
	echo "== install $newpkg"
	install_pkg "$newpkg"
	echo keep >"$state/marker"
	chown exitmesh:exitmesh "$state/marker"
fi
verify_installed

echo "== remove keeps state"
remove_pkg
[ ! -e /usr/bin/exitmesh-agent ] || fail "binary left after remove"
[ -f "$state/marker" ] || fail "state deleted on remove"

echo "== reinstall resumes, purge deletes state"
install_pkg "$newpkg"
[ -f "$state/marker" ] || fail "reinstall lost state"
purge_pkg
[ ! -e "$state" ] || fail "$state left after purge: $(ls -A "$state")"
echo "package smoke passed ($fmt, $pkgarch)"

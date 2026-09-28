#!/usr/bin/env bash
# Adds release packages to a signed APT and YUM repository tree (served from GitHub Pages) and prunes old versions.
# usage: package-repo.sh REPO_DIR PACKAGE_DIR    env: GPG_KEY_ID (required), GPG_PASSPHRASE, REPO_URL, KEEP (default 10)
set -euo pipefail

repo=$(realpath "${1:?usage: package-repo.sh REPO_DIR PACKAGE_DIR}")
pkgs=$(realpath "${2:?usage: package-repo.sh REPO_DIR PACKAGE_DIR}")
key=${GPG_KEY_ID:?GPG_KEY_ID is required}
keep=${KEEP:-10}
url=${REPO_URL:-}

gpgs() {
	if [ -n "${GPG_PASSPHRASE:-}" ]; then
		gpg --batch --yes --pinentry-mode loopback --passphrase "$GPG_PASSPHRASE" --local-user "$key" "$@"
	else
		gpg --batch --yes --local-user "$key" "$@"
	fi
}

# prune keeps the newest $keep versions of files matching a glob in a directory.
prune() {
	local dir=$1 pattern=$2
	mapfile -t files < <(find "$dir" -maxdepth 1 -name "$pattern" -printf '%f\n' | sort -V)
	local n=${#files[@]}
	if [ "$n" -gt "$keep" ]; then
		for f in "${files[@]:0:n-keep}"; do rm -f "$dir/$f"; done
	fi
}

echo "== apt"
pool=$repo/apt/pool/main/e/exitmesh-agent
mkdir -p "$pool"
cp "$pkgs"/*.deb "$pool/"
for arch in amd64 arm64; do
	prune "$pool" "exitmesh-agent_*_$arch.deb"
	bin=$repo/apt/dists/stable/main/binary-$arch
	mkdir -p "$bin"
	(cd "$repo/apt" && dpkg-scanpackages --arch "$arch" pool/main >"$bin/Packages")
	gzip -9nkf "$bin/Packages"
done
(
	cd "$repo/apt/dists/stable"
	apt-ftparchive \
		-o APT::FTPArchive::Release::Origin="ExitMesh" \
		-o APT::FTPArchive::Release::Label="exitmesh-agent" \
		-o APT::FTPArchive::Release::Suite="stable" \
		-o APT::FTPArchive::Release::Codename="stable" \
		-o APT::FTPArchive::Release::Architectures="amd64 arm64" \
		-o APT::FTPArchive::Release::Components="main" \
		release . >Release
	gpgs --clearsign -o InRelease Release
	gpgs --armor --detach-sign -o Release.gpg Release
)

echo "== yum"
for arch in x86_64 aarch64; do
	dir=$repo/rpm/$arch
	mkdir -p "$dir"
	cp "$pkgs"/exitmesh-agent-*."$arch".rpm "$dir/"
	prune "$dir" "exitmesh-agent-*.$arch.rpm"
	createrepo_c --update --quiet "$dir"
	gpgs --armor --detach-sign -o "$dir/repodata/repomd.xml.asc" "$dir/repodata/repomd.xml"
done

echo "== keys and client configuration"
gpg --batch --armor --export "$key" >"$repo/exitmesh-archive-keyring.asc"
gpg --batch --export "$key" >"$repo/exitmesh-archive-keyring.gpg"
if [ -n "$url" ]; then
	cat >"$repo/exitmesh-agent.repo" <<REPO
[exitmesh-agent]
name=ExitMesh agent
baseurl=$url/rpm/\$basearch
enabled=1
gpgcheck=1
repo_gpgcheck=1
gpgkey=$url/exitmesh-archive-keyring.asc
REPO
	cat >"$repo/exitmesh-agent.sources" <<SOURCES
Types: deb
URIs: $url/apt
Suites: stable
Components: main
Signed-By: /etc/apt/keyrings/exitmesh-archive-keyring.gpg
SOURCES
fi
touch "$repo/.nojekyll"
echo "repository updated in $repo"

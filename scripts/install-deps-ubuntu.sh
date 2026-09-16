#!/usr/bin/env bash
#
# install-deps-ubuntu.sh — install everything the checks and tests need on
# Ubuntu 24.04 (a GitHub-hosted runner, or the ubuntu:24.04 container the README
# uses). Skips apt entirely when every tool is already present.
#
#   curl        downloads                       jq           JSON parsing
#   openssl     firewall image signature        fdisk        sfdisk (partition table)
#   squashfs-tools  unsquashfs                  tar, gzip    tarball checks
#   gh          GitHub CLI                      sudo         root steps when not root
#   ca-certificates  HTTPS trust                and the linter used in CI (package: shellcheck)

set -euo pipefail

declare -A package_for=(
	[curl]=curl
	[jq]=jq
	[openssl]=openssl
	[sfdisk]=fdisk
	[unsquashfs]=squashfs-tools
	[tar]=tar
	[gzip]=gzip
	[gh]=gh
	[shellcheck]=shellcheck
)

missing=()
for tool in "${!package_for[@]}"; do
	command -v "$tool" >/dev/null 2>&1 || missing+=("${package_for[$tool]}")
done
if [ "$(id -u)" -ne 0 ] && ! command -v sudo >/dev/null 2>&1; then
	echo "not root and sudo is not installed; run this as root" >&2
	exit 1
fi

if [ "${#missing[@]}" -eq 0 ]; then
	echo "all tools already installed"
	exit 0
fi

run_root() {
	if [ "$(id -u)" -eq 0 ]; then "$@"; else sudo -- "$@"; fi
}

echo "installing: ${missing[*]} ca-certificates"
# DPkg::Lock::Timeout makes apt FAIL on a held lock instead of waiting forever;
# DEBIAN_FRONTEND stops it from waiting on a prompt no one will answer.
run_root env DEBIAN_FRONTEND=noninteractive apt-get update -qq -o DPkg::Lock::Timeout=120
run_root env DEBIAN_FRONTEND=noninteractive apt-get install -y -qq --no-install-recommends \
	-o DPkg::Lock::Timeout=120 ca-certificates "${missing[@]}"

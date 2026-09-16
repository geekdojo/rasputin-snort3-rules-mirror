#!/usr/bin/env bash
#
# fetch-upstream.sh WORK_DIR — Check 1: download the upstream tarball twice,
# over two separate HTTPS connections, and require both to hash identical.
#
# On success:
#   WORK_DIR/snort3-community-rules.tar.gz   the downloaded bytes
#   WORK_DIR/sha256                          their SHA-256, one line
# and the SHA-256 is printed on stdout (and written as the `sha256` step output
# inside GitHub Actions).
#
# Why twice: a single download proves only that SOMETHING arrived. Two separate
# curl processes (separate TCP + TLS sessions) that agree rule out a truncated
# or corrupted transfer, and make a response that varies per request visible.
# If Talos republishes between the two downloads this fails; the next run
# simply fetches the new tarball twice.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
# shellcheck source=scripts/lib.sh
. "$SCRIPT_DIR/lib.sh"

[ "$#" -eq 1 ] || die "usage: $0 WORK_DIR"
work_dir="$1"
mkdir -p -- "$work_dir"

download() {
	# --proto =https: refuse anything but HTTPS, including after redirects.
	# --max-time bounds a single transfer so a stalled server cannot hang the run.
	curl --proto '=https' --tlsv1.2 --fail --silent --show-error --location \
		--retry 3 --retry-delay 5 --max-time 300 \
		--output "$2" -- "$1"
}

first="$work_dir/download-1.tar.gz"
second="$work_dir/download-2.tar.gz"
rm -f -- "$first" "$second"

echo "download 1 of 2: $UPSTREAM_URL" >&2
download "$UPSTREAM_URL" "$first" || die "download 1 of $UPSTREAM_URL failed"
echo "download 2 of 2: $UPSTREAM_URL" >&2
download "$UPSTREAM_URL" "$second" || die "download 2 of $UPSTREAM_URL failed"

sha="$(compare_download_hashes "$first" "$second")" || die "check 1 (two downloads hash identical) FAILED"
is_sha256 "$sha" || die "computed hash is malformed: '$sha'"

mv -f -- "$first" "$work_dir/$ASSET_NAME"
rm -f -- "$second"
printf '%s\n' "$sha" >"$work_dir/sha256"
write_output sha256 "$sha"

echo "check 1 passed: both downloads hash to $sha" >&2
printf '%s\n' "$sha"

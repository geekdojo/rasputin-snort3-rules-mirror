#!/usr/bin/env bash
#
# publish.sh WORK_DIR — publish a verified tarball as a new mirror entry.
#
# WORK_DIR must be the directory verify-upstream.sh filled, with every check
# passed: it holds snort3-community-rules.tar.gz, sha256 and verification.env.
#
# Creates ONE immutable GitHub release:
#   tag    sha256-<SHA>
#   asset  snort3-community-rules.tar.gz   (byte-identical to upstream)
# and then proves the result from the outside: the release is intact
# (mirror-status.sh) and the public download URL serves bytes with that SHA.
#
# Never deletes, edits or overwrites a release. If the entry already exists it
# says so and exits 0. With DRY_RUN=1 it does everything except create the
# release, and says exactly what it would have published.
#
# Needs: gh with write access to the mirror repo (not for DRY_RUN=1), jq, curl.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
# shellcheck source=scripts/lib.sh
. "$SCRIPT_DIR/lib.sh"

[ "$#" -eq 1 ] || die "usage: $0 WORK_DIR"
work_dir="$1"
dry_run="${DRY_RUN:-0}"

tarball="$work_dir/$ASSET_NAME"
[ -s "$tarball" ] || die "no tarball at $tarball"
[ -s "$work_dir/sha256" ] || die "no sha256 file in $work_dir"
[ -s "$work_dir/verification.env" ] || die "no verification.env in $work_dir; refusing to publish anything verify-upstream.sh did not fully verify"

sha="$(head -n 1 -- "$work_dir/sha256")"
tag="$(tag_for_sha "$sha")" || die "invalid sha256 file"
actual="$(sha256_file "$tarball")"
[ "$actual" = "$sha" ] || die "tarball hashes to $actual but was verified as $sha; refusing to publish"

env_value() {
	local value
	value="$(sed -n "s/^$1=//p" "$work_dir/verification.env" | head -n 1)"
	[ -n "$value" ] || die "verification.env has no $1"
	printf '%s\n' "$value"
}
[ "$(env_value sha256)" = "$sha" ] || die "verification.env describes a different tarball than $sha"
active_rules="$(env_value active_rules)"
firewall_tag="$(env_value firewall_tag)"
snort_version="$(env_value snort_version)"
verified_at="$(env_value verified_at)"

download_url="https://github.com/$MIRROR_REPO/releases/download/$tag/$ASSET_NAME"

status="$("$SCRIPT_DIR/mirror-status.sh" "$sha")"
if [ "$status" = "mirrored" ]; then
	echo "$tag is already mirrored; nothing to publish ($download_url)"
	write_output published false
	exit 0
fi

if [ "$dry_run" = "1" ]; then
	echo "DRY RUN: every check passed and $tag is not mirrored yet, so a real run WOULD publish:"
	echo "  release  $tag in $MIRROR_REPO"
	echo "  asset    $ASSET_NAME ($(wc -c <"$tarball" | tr -d ' ') bytes, sha256 $sha)"
	echo "  url      $download_url"
	echo "DRY RUN: nothing was published."
	write_output published false
	exit 0
fi

run_url=""
if [ -n "${GITHUB_RUN_ID:-}" ]; then
	run_url="${GITHUB_SERVER_URL:-https://github.com}/${GITHUB_REPOSITORY:-$MIRROR_REPO}/actions/runs/$GITHUB_RUN_ID"
fi

notes="$(mktemp)"
trap 'rm -f -- "$notes"' EXIT
cat >"$notes" <<EOF
Snort3 Community Rules tarball, mirrored byte-for-byte from
$UPSTREAM_URL

- sha256: \`$sha\`
- download: $download_url
- verified: $verified_at${run_url:+ by $run_url}

Checks passed before publishing:

1. Two separate HTTPS downloads hashed identical.
2. Exactly the five expected members under \`snort3-community-rules/\`.
3. $active_rules active rules (within the sane bounds in README.md).
4. \`snort-mgr -v check\` loaded all $active_rules rules under Snort $snort_version in Rasputin firewall \`$firewall_tag\`.

The rules are Cisco Talos's, under the licences shipped inside the tarball
(\`LICENSE\`, \`VRT-License.txt\`, \`AUTHORS\`). This release is immutable and is
never overwritten.
EOF

echo "publishing $tag to $MIRROR_REPO"
gh release create "$tag" "$tarball" \
	--repo "$MIRROR_REPO" \
	--title "$tag" \
	--notes-file "$notes" ||
	die "gh release create $tag failed"

# Prove it from the outside, the way a firewall build will see it.
status="$("$SCRIPT_DIR/mirror-status.sh" "$sha")" || die "published $tag but it does not verify as intact"
[ "$status" = "mirrored" ] || die "published $tag but mirror-status reports '$status'"

check="$(mktemp)"
trap 'rm -f -- "$notes" "$check"' EXIT
curl --proto '=https' --tlsv1.2 --fail --silent --show-error --location \
	--retry 5 --retry-delay 10 --retry-all-errors --max-time 300 \
	--output "$check" -- "$download_url" || die "published $tag but $download_url does not download"
served="$(sha256_file "$check")"
[ "$served" = "$sha" ] || die "published $tag but $download_url serves $served"

write_output published true
echo "published $tag: $download_url serves sha256 $sha"

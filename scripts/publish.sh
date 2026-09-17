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
# The tag is created on TARGET_SHA, the commit this run checked out, never on
# whatever main points at when gh runs. scripts/release-target-guard.sh checks
# the tag before the release is created (refuse a tag already on another
# commit) and after (prove where it landed). A tag that lands anywhere else
# fails the run but is not deleted: releases here are immutable, so deleting
# one burns the name sha256-<SHA> for good, and that is a person's decision.
#
# Needs: gh with write access to the mirror repo (not for DRY_RUN=1), jq, curl,
# git, and TARGET_SHA (not for DRY_RUN=1).

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

target="${TARGET_SHA:-}"
[[ "$target" =~ ^[0-9a-f]{40}$ ]] ||
	die "TARGET_SHA must be the full commit SHA this run checked out (got '$target'); refusing to publish"
# Overridable only so tests/unit.sh can stand in for the remote and the guard.
mirror_remote="${MIRROR_REMOTE:-https://github.com/$MIRROR_REPO.git}"
guard="${RELEASE_TARGET_GUARD:-$SCRIPT_DIR/release-target-guard.sh}"

# Before publishing: a tag already on another commit would make gh ignore
# --target. Status 3 (absent) is the normal case; 0 cannot happen after the
# mirror-status check above (a bare tag fails it) but would be harmless.
guard_rc=0
"$guard" "$mirror_remote" "$tag" "$target" || guard_rc=$?
case "$guard_rc" in
0 | 3) ;;
*) die "refusing to publish $tag: release-target-guard status $guard_rc (tag on another commit, or unreadable)" ;;
esac

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
	--target "$target" \
	--title "$tag" \
	--notes-file "$notes" ||
	die "gh release create $tag failed"

guard_rc=0
"$guard" "$mirror_remote" "$tag" "$target" || guard_rc=$?
[ "$guard_rc" -eq 0 ] ||
	die "published $tag but its tag is not on the built commit $target (release-target-guard status $guard_rc). Not deleting it: the release is immutable and deleting it burns the name $tag"

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

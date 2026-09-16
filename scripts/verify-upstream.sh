#!/usr/bin/env bash
#
# verify-upstream.sh WORK_DIR — fetch the current upstream tarball and run every
# verification check on it. Publishes nothing; see publish.sh for that.
#
#   Check 1  two separate HTTPS downloads hash identical      fetch-upstream.sh
#   (status) is that SHA already mirrored?                     mirror-status.sh
#   Check 2  the tarball layout is exactly as expected         verify-tarball.sh
#   Check 3  the active rule count is sane                     verify-tarball.sh
#   Check 4  the rules load under Snort in the latest stable   fetch-firewall-image.sh
#            Rasputin firewall image                           extract-firewall-root.sh
#                                                              snort-check.sh
#
# When the SHA is already mirrored, checks 2-4 are skipped (there is nothing to
# publish) UNLESS DRY_RUN=1, in which case everything runs anyway: a dry run is
# how pull requests prove the checks still work against the real upstream.
#
# On success writes WORK_DIR/verification.env (only when checks 2-4 ran) and
# prints a summary. Any failed check exits non-zero naming the check.
#
# Needs: Linux, GNU tar, curl, gh, jq, openssl, sfdisk, unsquashfs, and root or
# passwordless sudo for check 4.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
# shellcheck source=scripts/lib.sh
. "$SCRIPT_DIR/lib.sh"

[ "$#" -eq 1 ] || die "usage: $0 WORK_DIR"
mkdir -p -- "$1"
work_dir="$(cd "$1" && pwd)"
dry_run="${DRY_RUN:-0}"

sha="$("$SCRIPT_DIR/fetch-upstream.sh" "$work_dir")"
tag="$(tag_for_sha "$sha")"

status="$("$SCRIPT_DIR/mirror-status.sh" "$sha")"
write_output mirror_status "$status"
rm -f -- "$work_dir/verification.env"

if [ "$status" = "mirrored" ] && [ "$dry_run" != "1" ]; then
	echo "upstream is $sha, already mirrored as $tag; nothing to do"
	write_output verified false
	exit 0
fi
if [ "$status" = "mirrored" ]; then
	echo "upstream is $sha, already mirrored as $tag; DRY_RUN=1, so verifying anyway"
fi

tarball="$work_dir/$ASSET_NAME"
count="$("$SCRIPT_DIR/verify-tarball.sh" "$tarball")"

rules="$work_dir/candidate.rules"
extract_rules "$tarball" "$rules" || die "could not extract the candidate rules"

fw_dir="$work_dir/firewall"
# A previous run leaves root-owned files behind; clear them the same way.
as_root rm -rf -- "$fw_dir"
fw_tag="$("$SCRIPT_DIR/fetch-firewall-image.sh" "$fw_dir")"
as_root "$SCRIPT_DIR/extract-firewall-root.sh" "$fw_dir/firewall-image.img.gz" "$fw_dir/root"

report="$work_dir/snort-report.env"
rm -f -- "$report"
as_root env SNORT_CHECK_REPORT="$report" "$SCRIPT_DIR/snort-check.sh" "$fw_dir/root" "$rules" ||
	die "check 4 (rules load under Snort in firewall $fw_tag) FAILED"
snort_version="$(sed -n 's/^snort_version=//p' "$report")"
as_root rm -rf -- "$fw_dir"

{
	echo "sha256=$sha"
	echo "active_rules=$count"
	echo "firewall_tag=$fw_tag"
	echo "snort_version=$snort_version"
	echo "verified_at=$(date -u +%Y-%m-%dT%H:%M:%SZ)"
} >"$work_dir/verification.env"

write_output verified true
echo "ALL CHECKS PASSED for $tag: $count active rules, loaded by Snort $snort_version in firewall $fw_tag"

#!/usr/bin/env bash
#
# verify-tarball.sh TARBALL — Checks 2 and 3, offline.
#
#   Check 2: the layout is exactly the five known members under
#            snort3-community-rules/, all regular files.
#   Check 3: the active rule count is within the sane bounds in lib.sh.
#
# Prints the active rule count on stdout when both pass. Needs GNU tar.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
# shellcheck source=scripts/lib.sh
. "$SCRIPT_DIR/lib.sh"

[ "$#" -eq 1 ] || die "usage: $0 TARBALL"
tarball="$1"

check_layout "$tarball" || die "check 2 (tarball layout) FAILED for $tarball"
echo "check 2 passed: exactly the five expected members under $TOP_DIR/" >&2

tmp="$(mktemp -d)"
trap 'rm -rf -- "$tmp"' EXIT
extract_rules "$tarball" "$tmp/rules" || die "check 3 could not read the rules file"
count="$(count_active_rules "$tmp/rules")" || die "check 3 could not count rules"
check_rule_count "$count" || die "check 3 (rule count is sane) FAILED"
echo "check 3 passed: $count active rules (bounds $MIN_ACTIVE_RULES..$MAX_ACTIVE_RULES)" >&2

write_output active_rules "$count"
printf '%s\n' "$count"

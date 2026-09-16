# shellcheck shell=bash
#
# lib.sh — shared constants and pure checks for the Snort3 Community Rules mirror.
#
# Sourced, never executed. Everything here is deterministic and offline so that
# tests/unit.sh can exercise it against fixture tarballs. Anything that talks to
# the network or needs root lives in its own script under scripts/.
#
# Every check prints what failed to stderr and RETURNS non-zero. Callers run
# under `set -euo pipefail`, so a failed check stops the run; nothing here ever
# converts a failure into a default value.

# --- The contract -----------------------------------------------------------
#
# These values are the URL contract rasputin-openwrt-firewall depends on. Do not
# change them without changing that repo's scripts/fetch-snort-rules.sh in step.
#
# Some constants are used only by the scripts that source this file.
# shellcheck disable=SC2034

UPSTREAM_URL="https://www.snort.org/downloads/community/snort3-community-rules.tar.gz"
ASSET_NAME="snort3-community-rules.tar.gz"
MIRROR_REPO="${MIRROR_REPO:-geekdojo/rasputin-snort3-rules-mirror}"
FIREWALL_REPO="${FIREWALL_REPO:-geekdojo/rasputin-openwrt-firewall}"

# The exact tarball layout, unchanged since the firewall switched to this
# ruleset on 2026-06-08. One top-level directory holding exactly these files.
TOP_DIR="snort3-community-rules"
EXPECTED_MEMBERS=(
	"snort3-community.rules"
	"sid-msg.map"
	"VRT-License.txt"
	"LICENSE"
	"AUTHORS"
)
RULES_MEMBER="$TOP_DIR/snort3-community.rules"

# Rule-count bounds. See "Check 3: the rule count is sane" in README.md for why
# these numbers. Overridable from the environment ONLY so the unit tests can
# probe the boundaries; the workflows never set them.
MIN_ACTIVE_RULES="${MIN_ACTIVE_RULES:-3600}"
MAX_ACTIVE_RULES="${MAX_ACTIVE_RULES:-8000}"

# --- Output helpers ---------------------------------------------------------

# fail MESSAGE... — print a failure to stderr. Inside GitHub Actions, also emit
# an ::error:: annotation so the reason shows on the run summary page.
fail() {
	if [ -n "${GITHUB_ACTIONS:-}" ]; then
		printf '::error::%s\n' "$*" >&2
	else
		printf 'FAIL: %s\n' "$*" >&2
	fi
}

# die MESSAGE... — fail and exit 1. For use in scripts, not in the checks below.
die() {
	fail "$@"
	exit 1
}

# --- Primitive helpers ------------------------------------------------------

# sha256_file FILE — print the lowercase hex SHA-256 of FILE.
sha256_file() {
	local file="$1"
	local out
	if [ ! -f "$file" ]; then
		fail "sha256_file: no such file: $file"
		return 1
	fi
	if command -v sha256sum >/dev/null 2>&1; then
		out="$(sha256sum -- "$file")" || return 1
	elif command -v shasum >/dev/null 2>&1; then
		out="$(shasum -a 256 -- "$file")" || return 1
	else
		fail "neither sha256sum nor shasum is installed"
		return 1
	fi
	printf '%s\n' "${out%% *}"
}

# is_sha256 STRING — true when STRING is exactly 64 lowercase hex characters.
is_sha256() {
	[[ "$1" =~ ^[0-9a-f]{64}$ ]]
}

# tag_for_sha SHA — the release tag for a tarball with this SHA-256.
tag_for_sha() {
	if ! is_sha256 "$1"; then
		fail "not a lowercase 64-hex sha256: '$1'"
		return 1
	fi
	printf 'sha256-%s\n' "$1"
}

# require_gnu_tar — the layout check parses `tar -tv` output, whose format
# differs between GNU tar and the BSD tar that ships on macOS. Refuse to guess.
require_gnu_tar() {
	local version
	version="$(tar --version 2>/dev/null | head -n 1)" || true
	case "$version" in
	*"GNU tar"*) return 0 ;;
	esac
	fail "GNU tar is required (found: '${version:-no tar}'). On macOS, run the checks in a Linux container; see README.md."
	return 1
}

# --- Check 1: two downloads hash identical ----------------------------------

# compare_download_hashes FILE1 FILE2 — print the shared SHA-256 when both files
# hash identical; fail naming both hashes when they differ.
compare_download_hashes() {
	local first second
	first="$(sha256_file "$1")" || return 1
	second="$(sha256_file "$2")" || return 1
	if [ "$first" != "$second" ]; then
		fail "the two independent downloads differ: first=$first second=$second"
		return 1
	fi
	printf '%s\n' "$first"
}

# --- Check 2: tarball layout -------------------------------------------------

# check_layout TARBALL — the tarball is valid gzip, and contains exactly the
# directory "$TOP_DIR/" plus the five EXPECTED_MEMBERS as regular files, each
# exactly once. Anything else (an extra file, a missing file, a symlink, a
# nested directory, a "./" prefix, a different top directory) fails.
check_layout() {
	local tarball="$1"
	require_gnu_tar || return 1

	if [ ! -s "$tarball" ]; then
		fail "layout: tarball missing or empty: $tarball"
		return 1
	fi
	if ! gzip -t -- "$tarball" 2>/dev/null; then
		fail "layout: not a valid gzip file: $tarball"
		return 1
	fi

	# Names and verbose listings come from two separate passes over the same
	# archive, so their line N always describes the same member. GNU tar escapes
	# newlines in member names, so one member is always one line.
	local -a names=() long=()
	local listing
	if ! listing="$(tar --quoting-style=escape -tzf "$tarball")"; then
		fail "layout: tar could not list $tarball"
		return 1
	fi
	mapfile -t names <<<"$listing"
	if ! listing="$(tar --quoting-style=escape -tvzf "$tarball")"; then
		fail "layout: tar could not list $tarball verbosely"
		return 1
	fi
	mapfile -t long <<<"$listing"
	if [ "${#names[@]}" -ne "${#long[@]}" ]; then
		fail "layout: tar listings disagree on member count (${#names[@]} vs ${#long[@]})"
		return 1
	fi

	local -A seen=()
	local -a problems=()
	local i name type base expected ok
	for i in "${!names[@]}"; do
		name="${names[$i]}"
		type="${long[$i]:0:1}"
		if [ "$name" = "$TOP_DIR/" ]; then
			if [ "$type" != "d" ]; then
				problems+=("'$name' is not a directory (type '$type')")
			fi
			seen["$name"]=$((${seen["$name"]:-0} + 1))
			continue
		fi
		base="${name#"$TOP_DIR"/}"
		ok=0
		if [ "$base" != "$name" ]; then
			for expected in "${EXPECTED_MEMBERS[@]}"; do
				if [ "$base" = "$expected" ]; then
					ok=1
					break
				fi
			done
		fi
		if [ "$ok" -ne 1 ]; then
			problems+=("unexpected member '$name'")
			continue
		fi
		if [ "$type" != "-" ]; then
			problems+=("'$name' is not a regular file (type '$type')")
		fi
		seen["$name"]=$((${seen["$name"]:-0} + 1))
	done

	for expected in "${EXPECTED_MEMBERS[@]}"; do
		case "${seen["$TOP_DIR/$expected"]:-0}" in
		1) ;;
		0) problems+=("missing member '$TOP_DIR/$expected'") ;;
		*) problems+=("member '$TOP_DIR/$expected' appears ${seen["$TOP_DIR/$expected"]} times") ;;
		esac
	done
	if [ "${seen["$TOP_DIR/"]:-0}" -gt 1 ]; then
		problems+=("directory '$TOP_DIR/' appears ${seen["$TOP_DIR/"]} times")
	fi

	if [ "${#problems[@]}" -gt 0 ]; then
		local p
		for p in "${problems[@]}"; do
			fail "layout: $p"
		done
		return 1
	fi
	return 0
}

# --- Check 3: rule count -----------------------------------------------------

# count_active_rules FILE — print the number of active (uncommented) rules,
# using the same expression rasputin-openwrt-firewall's fetch script reports.
count_active_rules() {
	local file="$1" count rc
	if [ ! -f "$file" ]; then
		fail "count: no such rules file: $file"
		return 1
	fi
	# grep -c exits 1 when the count is zero; that is a valid answer (0), not
	# an error. Exit 2 is a real error and must not be swallowed.
	rc=0
	count="$(grep -cE '^(alert|drop|block|reject)' -- "$file")" || rc=$?
	if [ "$rc" -gt 1 ]; then
		fail "count: grep failed on $file (exit $rc)"
		return 1
	fi
	printf '%s\n' "$count"
}

# check_rule_count COUNT — COUNT is an integer within [MIN_ACTIVE_RULES, MAX_ACTIVE_RULES].
check_rule_count() {
	local count="$1"
	if ! [[ "$count" =~ ^[0-9]+$ ]]; then
		fail "count: not an integer: '$count'"
		return 1
	fi
	if [ "$count" -lt "$MIN_ACTIVE_RULES" ]; then
		fail "count: $count active rules is below the floor of $MIN_ACTIVE_RULES (truncated or gutted ruleset?)"
		return 1
	fi
	if [ "$count" -gt "$MAX_ACTIVE_RULES" ]; then
		fail "count: $count active rules is above the ceiling of $MAX_ACTIVE_RULES (is this still the Community ruleset?)"
		return 1
	fi
	return 0
}

# extract_rules TARBALL DEST — write the rules member of TARBALL to DEST.
extract_rules() {
	local tarball="$1" dest="$2"
	if ! tar -xzf "$tarball" -O -- "$RULES_MEMBER" >"$dest"; then
		fail "could not extract $RULES_MEMBER from $tarball"
		return 1
	fi
}

# as_root CMD... — run CMD as root: directly when already root, else via sudo.
as_root() {
	if [ "$(id -u)" -eq 0 ]; then
		"$@"
	else
		sudo -- "$@"
	fi
}

# write_output KEY VALUE — append KEY=VALUE to $GITHUB_OUTPUT when running in
# Actions; a no-op elsewhere.
write_output() {
	if [ -n "${GITHUB_OUTPUT:-}" ]; then
		printf '%s=%s\n' "$1" "$2" >>"$GITHUB_OUTPUT"
	fi
}

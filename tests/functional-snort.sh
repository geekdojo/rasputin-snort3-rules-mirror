#!/usr/bin/env bash
#
# tests/functional-snort.sh — prove check 4 (snort-check.sh) against the REAL
# Snort in the latest stable Rasputin firewall image: good rules must pass and
# broken rules must fail, for the right reason.
#
# A parse check that never fails is worse than none, because it looks like
# protection. So most cases here are negative: each must exit non-zero AND print
# "check 4 FAILED" (not, say, the harness-broken message), so a case cannot pass
# by accident.
#
# Usage:
#   tests/functional-snort.sh [WORK_DIR]
#
# WORK_DIR defaults to a temporary directory. Set FIREWALL_IMAGE_DIR to a
# directory that fetch-firewall-image.sh already filled to skip the download
# (useful in a container without gh). Needs Linux and root or passwordless sudo.

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
SCRIPTS="$REPO_ROOT/scripts"
# shellcheck source=scripts/lib.sh
. "$SCRIPTS/lib.sh"

if [ "$#" -ge 1 ]; then
	mkdir -p -- "$1"
	W="$(cd "$1" && pwd)"
	cleanup_work=0
else
	W="$(mktemp -d)"
	cleanup_work=1
fi
root="$W/root"
cleanup() {
	as_root rm -rf -- "$root"
	if [ "$cleanup_work" -eq 1 ]; then
		as_root rm -rf -- "$W"
	fi
}
trap cleanup EXIT

if [ -n "${FIREWALL_IMAGE_DIR:-}" ]; then
	image_dir="$FIREWALL_IMAGE_DIR"
	echo "using the already-verified image in $image_dir ($(cat "$image_dir/firewall-tag"))"
else
	image_dir="$W/image"
	"$SCRIPTS/fetch-firewall-image.sh" "$image_dir" >/dev/null
fi
[ -s "$image_dir/firewall-image.img.gz" ] || die "no firewall-image.img.gz in $image_dir"
fw_tag="$(cat "$image_dir/firewall-tag")"

as_root rm -rf -- "$root"
as_root "$SCRIPTS/extract-firewall-root.sh" "$image_dir/firewall-image.img.gz" "$root"

# --- Rules files ----------------------------------------------------------------

rules="$W/rules"
mkdir -p -- "$rules"

# The ruleset the image itself shipped with: real Talos rules, already known to
# load on hardware. Copied out before any case overwrites it.
as_root cat -- "$root/etc/snort/rules/snort3-community.rules" >"$rules/shipped.rules"
shipped_count="$(count_active_rules "$rules/shipped.rules")"
[ "$shipped_count" -gt 0 ] || die "the image's shipped rules file has no active rules"

# A small ruleset written for this test, using ordinary Snort 3 syntax and the
# variables Rasputin's generated config defines.
cat >"$rules/small-good.rules" <<'EOF'
alert tcp $EXTERNAL_NET any -> $HOME_NET 22 ( msg:"RASPUTIN TEST ssh banner"; flow:to_server,established; content:"SSH-",depth 4; sid:9000001; rev:1; )
alert http ( msg:"RASPUTIN TEST uri"; http_uri; content:"/rasputin-functional-test",fast_pattern,nocase; sid:9000002; rev:1; )
# alert udp any any -> any 53 ( msg:"RASPUTIN TEST commented out, must not count"; sid:9000003; rev:1; )
alert icmp any any -> $HOME_NET any ( msg:"RASPUTIN TEST icmp"; itype:8; sid:9000004; rev:1; )
EOF

invented_keyword='alert tcp any any -> any 80 ( msg:"RASPUTIN TEST invented keyword"; flarbnozzle:1; sid:9000101; rev:1; )'
unbalanced='alert tcp any any -> any 80 ( msg:"RASPUTIN TEST missing close paren"; sid:9000102; rev:1;'
# Snort 2 era keyword placement: the failure mode that took down the first
# hardware bring-up, when ET Open's "snort-3.0.0" rules produced 212,249 errors.
snort2_syntax='alert tcp any any -> any 80 (msg:"RASPUTIN TEST snort2 syntax"; content:"abc"; within:10; distance:0; sid:9000103; rev:1;)'
# shellcheck disable=SC2016 # the $ is Snort's variable syntax, not the shell's
undefined_var='alert tcp $NOT_A_RASPUTIN_NET any -> any 80 ( msg:"RASPUTIN TEST undefined variable"; sid:9000104; rev:1; )'
bad_pcre='alert tcp any any -> any 80 ( msg:"RASPUTIN TEST bad pcre"; pcre:"/(unclosed/"; sid:9000105; rev:1; )'

{ cat -- "$rules/small-good.rules"; echo "$invented_keyword"; } >"$rules/small-invented-keyword.rules"
{ cat -- "$rules/shipped.rules"; echo "$invented_keyword"; } >"$rules/shipped-plus-invented-keyword.rules"
{ echo "$unbalanced"; cat -- "$rules/small-good.rules"; } >"$rules/small-unbalanced.rules"
{ cat -- "$rules/small-good.rules"; echo "$snort2_syntax"; } >"$rules/small-snort2-syntax.rules"
{ cat -- "$rules/small-good.rules"; echo "$undefined_var"; } >"$rules/small-undefined-variable.rules"
{ cat -- "$rules/small-good.rules"; echo "$bad_pcre"; } >"$rules/small-bad-pcre.rules"
# Two rules with the same gid:sid. Snort keeps only one and still exits 0, so
# this case exists to prove the loaded-count comparison, not just the exit code.
{ cat -- "$rules/small-good.rules"; sed -n '1p' "$rules/small-good.rules"; } >"$rules/small-duplicate-sid.rules"

# --- Cases ------------------------------------------------------------------------

passed=0
failed=0
failures=()

check_case() {
	# check_case NAME EXPECT(pass|fail) PATTERN RULES_FILE [CHECK_SCRIPT]
	local name="$1" expect="$2" pattern="$3" file="$4" script="${5:-$SCRIPTS/snort-check.sh}" rc=0 ok=1
	local out="$W/case.out"
	as_root "$script" "$root" "$file" >"$out" 2>&1 || rc=$?
	if [ "$expect" = "pass" ] && [ "$rc" -ne 0 ]; then ok=0; fi
	if [ "$expect" = "fail" ] && [ "$rc" -eq 0 ]; then ok=0; fi
	if ! grep -qF -- "$pattern" "$out"; then ok=0; fi
	if [ "$ok" -eq 1 ]; then
		passed=$((passed + 1))
		printf 'ok    %s\n' "$name"
		grep -E 'check 4 (passed|FAILED)' "$out" | sed 's/^/      | /' || true
	else
		failed=$((failed + 1))
		failures+=("$name")
		printf 'FAIL  %s (expected %s with "%s", exit %s)\n' "$name" "$expect" "$pattern" "$rc"
		sed 's/^/      | /' "$out"
	fi
}

echo "functional tests against firewall $fw_tag"
check_case "good: the ruleset shipped in the image loads, all $shipped_count rules" pass "loaded all $shipped_count rules" "$rules/shipped.rules"
check_case "good: a small hand-written ruleset loads, 3 active rules" pass "loaded all 3 rules" "$rules/small-good.rules"
check_case "broken: an invented rule keyword fails" fail "check 4 FAILED: snort-mgr -v check rejected" "$rules/small-invented-keyword.rules"
check_case "broken: the invented keyword names the offending line" fail "unknown rule keyword: flarbnozzle" "$rules/small-invented-keyword.rules"
check_case "broken: one invented keyword among the shipped rules fails" fail "check 4 FAILED: snort-mgr -v check rejected" "$rules/shipped-plus-invented-keyword.rules"
check_case "broken: an unbalanced parenthesis fails" fail "check 4 FAILED: snort-mgr -v check rejected" "$rules/small-unbalanced.rules"
check_case "broken: Snort 2 era keyword placement (the ET Open failure) fails" fail "check 4 FAILED: snort-mgr -v check rejected" "$rules/small-snort2-syntax.rules"
check_case "broken: an undefined variable fails" fail "check 4 FAILED: snort-mgr -v check rejected" "$rules/small-undefined-variable.rules"
check_case "broken: an invalid pcre fails" fail "check 4 FAILED: snort-mgr -v check rejected" "$rules/small-bad-pcre.rules"
check_case "broken: a rule Snort silently drops (duplicate sid) fails the loaded-count check" fail "check 4 FAILED: Snort loaded 3 rules" "$rules/small-duplicate-sid.rules"

# --- Ways snort-mgr exits 0 WITHOUT checking the rules ----------------------------
#
# Each of these makes `snort-mgr ... check` succeed while proving nothing. The
# check must fail on every one, even though the rules themselves are fine.

# 1. Run without -v: snort-mgr generates a config with no rules at all. Proven on
#    a copy of snort-check.sh with only the -v removed; the grep guards make sure
#    the copy really differs, so this case cannot silently test the original.
mutant="$W/mutant-no-v/scripts"
mkdir -p -- "$mutant"
cp -- "$SCRIPTS/lib.sh" "$mutant/lib.sh"
sed 's|/usr/bin/snort-mgr -v check|/usr/bin/snort-mgr check|' "$SCRIPTS/snort-check.sh" >"$mutant/snort-check.sh"
chmod +x "$mutant/snort-check.sh"
[ "$(grep -c 'snort-mgr -v check' "$SCRIPTS/snort-check.sh")" -ge 1 ] || die "snort-check.sh no longer runs 'snort-mgr -v check'; update this test"
! grep -q '/usr/bin/snort-mgr -v check' "$mutant/snort-check.sh" || die "the no -v mutant still runs -v"
check_case "no-op: snort-mgr check WITHOUT -v fails (good rules)" fail "check 4 FAILED" "$rules/small-good.rules" "$mutant/snort-check.sh"

# 2. snort.snort.manual=1 (the package default): check returns 0 before running
#    Snort. Simulated by flipping the image's own 99-rasputin, then restored.
uci_defaults="$root/etc/uci-defaults/99-rasputin"
as_root cp -- "$uci_defaults" "$W/99-rasputin.orig"
as_root sed -i "s/^set snort\.snort\.manual='0'\$/set snort.snort.manual='1'/" "$uci_defaults"
as_root grep -qx "set snort.snort.manual='1'" "$uci_defaults" || die "could not set manual='1' in the image's 99-rasputin; update this test"
check_case "no-op: snort.snort.manual=1 fails (good rules)" fail "check 4 FAILED" "$rules/small-good.rules"
as_root cp -- "$W/99-rasputin.orig" "$uci_defaults"
as_root grep -qx "set snort.snort.manual='0'" "$uci_defaults" || die "could not restore the image's 99-rasputin"

# 3. An empty ruleset validates clean: Snort still loads the image's own 219
#    built-in rules. Also a file whose only rules are commented out.
: >"$rules/empty.rules"
printf '# alert tcp any any -> any 80 ( msg:"RASPUTIN TEST disabled"; sid:9000201; rev:1; )\n' >"$rules/only-comments.rules"
check_case "no-op: an empty rules file fails" fail "check 4 FAILED" "$rules/empty.rules"
check_case "no-op: a rules file with only commented-out rules fails" fail "check 4 FAILED" "$rules/only-comments.rules"

# After the no-op cases, good rules must still pass (the restore worked).
check_case "good: the shipped ruleset still loads after the no-op cases" pass "loaded all $shipped_count rules" "$rules/shipped.rules"

echo
echo "functional tests: $passed passed, $failed failed"
if [ "$failed" -gt 0 ]; then
	printf '  failed: %s\n' "${failures[@]}"
	exit 1
fi

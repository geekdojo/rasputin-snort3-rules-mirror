#!/usr/bin/env bash
#
# tests/unit.sh — unit tests for the verification and publishing logic.
#
# Offline and unprivileged: every tarball is a fixture built here, and `curl`
# and `gh` are replaced by fakes on PATH, so no test touches snort.org or
# GitHub. Needs Linux with GNU tar, jq and sha256sum (see README.md for running
# it in a container on macOS).
#
# Usage: tests/unit.sh        exits 0 only when every case passes.

# Many cases run `bash -c '<script>' _ ARGS`, where single quotes are the point:
# the script expands its own positional arguments.
# shellcheck disable=SC2016

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
SCRIPTS="$REPO_ROOT/scripts"
# shellcheck source=scripts/lib.sh
. "$SCRIPTS/lib.sh"

require_gnu_tar
for tool in jq sha256sum gzip; do
	command -v "$tool" >/dev/null 2>&1 || {
		echo "unit tests need $tool" >&2
		exit 1
	}
done

T="$(mktemp -d)"
trap 'rm -rf -- "$T"' EXIT

# Never let a test reach the real mirror or annotate a real Actions run.
export MIRROR_REPO="example/test-mirror"
unset GITHUB_OUTPUT GITHUB_RUN_ID

passed=0
failed=0
failures=()

# run_case NAME EXPECT(pass|fail) PATTERN CMD... — run CMD, capturing stdout and
# stderr. A "pass" case must exit 0; a "fail" case must exit non-zero AND print
# PATTERN (a fixed string), so a case cannot pass by failing for the wrong reason.
# For "pass" cases PATTERN, when non-empty, must appear in the output too.
run_case() {
	local name="$1" expect="$2" pattern="$3"
	shift 3
	local out="$T/case.out" rc=0
	("$@") >"$out" 2>&1 || rc=$?
	local ok=1
	if [ "$expect" = "pass" ] && [ "$rc" -ne 0 ]; then ok=0; fi
	if [ "$expect" = "fail" ] && [ "$rc" -eq 0 ]; then ok=0; fi
	if [ -n "$pattern" ] && ! grep -qF -- "$pattern" "$out"; then ok=0; fi
	if [ "$ok" -eq 1 ]; then
		passed=$((passed + 1))
		printf 'ok    %s\n' "$name"
	else
		failed=$((failed + 1))
		failures+=("$name")
		printf 'FAIL  %s (expected %s%s, exit %s)\n' "$name" "$expect" "${pattern:+ with '$pattern'}" "$rc"
		sed 's/^/      | /' "$out"
	fi
}

# --- Fixtures ------------------------------------------------------------------

# make_rules FILE ACTIVE [COMMENTED] — ACTIVE `alert` rules plus COMMENTED
# commented-out ones, the way Talos ships disabled rules.
make_rules() {
	local file="$1" active="$2" commented="${3:-0}" i
	: >"$file"
	for ((i = 1; i <= active; i++)); do
		printf 'alert tcp $EXTERNAL_NET any -> $HOME_NET any ( msg:"fixture %d"; sid:%d; rev:1; )\n' "$i" "$((1000000 + i))"
	done >>"$file"
	for ((i = 1; i <= commented; i++)); do
		printf '# alert tcp any any -> any any ( msg:"disabled %d"; sid:%d; rev:1; )\n' "$i" "$((2000000 + i))"
	done >>"$file"
}

# make_tree DIR [ACTIVE] — DIR/snort3-community-rules/ with the five members.
make_tree() {
	local dir="$1" active="${2:-4017}"
	mkdir -p -- "$dir/$TOP_DIR"
	make_rules "$dir/$TOP_DIR/snort3-community.rules" "$active" 5
	printf '1000001 || fixture\n' >"$dir/$TOP_DIR/sid-msg.map"
	printf 'VRT license fixture\n' >"$dir/$TOP_DIR/VRT-License.txt"
	printf 'GPLv2 fixture\n' >"$dir/$TOP_DIR/LICENSE"
	printf 'authors fixture\n' >"$dir/$TOP_DIR/AUTHORS"
}

# pack DIR OUT [PATHS...] — deterministic gzip tarball of PATHS (default: the
# top directory) relative to DIR.
pack() {
	local dir="$1" out="$2"
	shift 2
	[ "$#" -gt 0 ] || set -- "$TOP_DIR"
	tar --sort=name --owner=0 --group=0 --numeric-owner --mtime=@0 -C "$dir" -czf "$out" -- "$@"
}

fixture() {
	# fixture NAME — a fresh empty directory for building one fixture.
	local d="$T/fx/$1"
	rm -rf -- "$d"
	mkdir -p -- "$d"
	printf '%s\n' "$d"
}

# --- Check 2 + 3: verify-tarball.sh --------------------------------------------

d="$(fixture good)"
make_tree "$d/src"
pack "$d/src" "$d/good.tar.gz"
run_case "layout+count: upstream-shaped tarball passes and reports 4017" pass "check 3 passed: 4017 active rules" \
	"$SCRIPTS/verify-tarball.sh" "$d/good.tar.gz"
run_case "layout+count: stdout is exactly the count" pass "" \
	bash -c '[ "$("$1" "$2" 2>/dev/null)" = 4017 ]' _ "$SCRIPTS/verify-tarball.sh" "$d/good.tar.gz"

d="$(fixture nodirentry)"
make_tree "$d/src"
pack "$d/src" "$d/t.tar.gz" "$TOP_DIR/snort3-community.rules" "$TOP_DIR/sid-msg.map" "$TOP_DIR/VRT-License.txt" "$TOP_DIR/LICENSE" "$TOP_DIR/AUTHORS"
run_case "layout: the five files without a directory entry still pass" pass "check 2 passed" \
	"$SCRIPTS/verify-tarball.sh" "$d/t.tar.gz"

d="$(fixture extra)"
make_tree "$d/src"
printf 'surprise\n' >"$d/src/$TOP_DIR/README"
pack "$d/src" "$d/t.tar.gz"
run_case "layout: an extra member fails" fail "unexpected member 'snort3-community-rules/README'" \
	"$SCRIPTS/verify-tarball.sh" "$d/t.tar.gz"

d="$(fixture missing)"
make_tree "$d/src"
rm -f -- "$d/src/$TOP_DIR/AUTHORS"
pack "$d/src" "$d/t.tar.gz"
run_case "layout: a missing member fails" fail "missing member 'snort3-community-rules/AUTHORS'" \
	"$SCRIPTS/verify-tarball.sh" "$d/t.tar.gz"

d="$(fixture flat)"
make_tree "$d/src"
pack "$d/src/$TOP_DIR" "$d/t.tar.gz" snort3-community.rules sid-msg.map VRT-License.txt LICENSE AUTHORS
run_case "layout: members at the archive root (no top directory) fail" fail "unexpected member 'snort3-community.rules'" \
	"$SCRIPTS/verify-tarball.sh" "$d/t.tar.gz"

d="$(fixture renamed)"
make_tree "$d/src"
mv -- "$d/src/$TOP_DIR" "$d/src/snort3-community-rules-2026"
pack "$d/src" "$d/t.tar.gz" snort3-community-rules-2026
run_case "layout: a renamed top directory fails" fail "unexpected member 'snort3-community-rules-2026/'" \
	"$SCRIPTS/verify-tarball.sh" "$d/t.tar.gz"

d="$(fixture dotslash)"
make_tree "$d/src"
pack "$d/src" "$d/t.tar.gz" "./$TOP_DIR"
run_case "layout: a ./ prefix on member names fails" fail "unexpected member './snort3-community-rules/'" \
	"$SCRIPTS/verify-tarball.sh" "$d/t.tar.gz"

d="$(fixture nested)"
make_tree "$d/src"
mkdir -p -- "$d/src/$TOP_DIR/extra"
printf 'x\n' >"$d/src/$TOP_DIR/extra/snort3-community.rules"
pack "$d/src" "$d/t.tar.gz"
run_case "layout: a nested directory fails" fail "unexpected member 'snort3-community-rules/extra/'" \
	"$SCRIPTS/verify-tarball.sh" "$d/t.tar.gz"

d="$(fixture symlink)"
make_tree "$d/src"
rm -f -- "$d/src/$TOP_DIR/LICENSE"
ln -s /etc/passwd "$d/src/$TOP_DIR/LICENSE"
pack "$d/src" "$d/t.tar.gz"
run_case "layout: a member that is a symlink fails" fail "'snort3-community-rules/LICENSE' is not a regular file (type 'l')" \
	"$SCRIPTS/verify-tarball.sh" "$d/t.tar.gz"

d="$(fixture hardlink)"
make_tree "$d/src"
rm -f -- "$d/src/$TOP_DIR/LICENSE"
ln -- "$d/src/$TOP_DIR/AUTHORS" "$d/src/$TOP_DIR/LICENSE"
pack "$d/src" "$d/t.tar.gz"
run_case "layout: a member that is a hard link fails" fail "is not a regular file (type 'h')" \
	"$SCRIPTS/verify-tarball.sh" "$d/t.tar.gz"

d="$(fixture duplicate)"
make_tree "$d/src"
tar --owner=0 --group=0 --mtime=@0 -C "$d/src" -cf "$d/t.tar" -- "$TOP_DIR"
tar --owner=0 --group=0 --mtime=@0 -C "$d/src" -rf "$d/t.tar" -- "$TOP_DIR/snort3-community.rules"
gzip -n -- "$d/t.tar"
run_case "layout: a member that appears twice fails" fail "member 'snort3-community-rules/snort3-community.rules' appears 2 times" \
	"$SCRIPTS/verify-tarball.sh" "$d/t.tar.gz"

d="$(fixture notgzip)"
make_tree "$d/src"
tar -C "$d/src" -cf "$d/t.tar.gz" -- "$TOP_DIR"
run_case "layout: an uncompressed tar fails" fail "not a valid gzip file" \
	"$SCRIPTS/verify-tarball.sh" "$d/t.tar.gz"

d="$(fixture truncated)"
make_tree "$d/src"
pack "$d/src" "$d/full.tar.gz"
head -c 2000 -- "$d/full.tar.gz" >"$d/t.tar.gz"
run_case "layout: a truncated download fails" fail "not a valid gzip file" \
	"$SCRIPTS/verify-tarball.sh" "$d/t.tar.gz"

d="$(fixture empty)"
: >"$d/t.tar.gz"
run_case "layout: an empty file fails" fail "tarball missing or empty" \
	"$SCRIPTS/verify-tarball.sh" "$d/t.tar.gz"

for n in 3599 8001; do
	d="$(fixture "count$n")"
	make_tree "$d/src" "$n"
	pack "$d/src" "$d/t.tar.gz"
	run_case "count: $n active rules fails" fail "count: $n active rules is" \
		"$SCRIPTS/verify-tarball.sh" "$d/t.tar.gz"
done
for n in 3600 8000; do
	d="$(fixture "count$n")"
	make_tree "$d/src" "$n"
	pack "$d/src" "$d/t.tar.gz"
	run_case "count: $n active rules (a bound) passes" pass "check 3 passed: $n active rules" \
		"$SCRIPTS/verify-tarball.sh" "$d/t.tar.gz"
done

d="$(fixture gutted)"
make_tree "$d/src" 50
make_rules "$d/src/$TOP_DIR/snort3-community.rules" 50 4000
pack "$d/src" "$d/t.tar.gz"
run_case "count: 4000 commented-out rules do not count as active" fail "count: 50 active rules is below the floor" \
	"$SCRIPTS/verify-tarball.sh" "$d/t.tar.gz"

d="$(fixture actions)"
{
	echo 'alert tcp any any -> any any ( sid:1; )'
	echo 'drop tcp any any -> any any ( sid:2; )'
	echo 'block tcp any any -> any any ( sid:3; )'
	echo 'reject tcp any any -> any any ( sid:4; )'
	echo '#alert tcp any any -> any any ( sid:5; )'
	echo '# drop tcp any any -> any any ( sid:6; )'
	echo ''
} >"$d/rules"
run_case "count: alert/drop/block/reject count, comments do not" pass "" \
	bash -c '. "$1"; [ "$(count_active_rules "$2")" = 4 ]' _ "$SCRIPTS/lib.sh" "$d/rules"
: >"$d/none"
run_case "count: a file with no rules counts 0, not an error" pass "" \
	bash -c '. "$1"; [ "$(count_active_rules "$2")" = 0 ]' _ "$SCRIPTS/lib.sh" "$d/none"
run_case "count: a non-integer count fails" fail "not an integer" \
	bash -c '. "$1"; check_rule_count "4017abc"' _ "$SCRIPTS/lib.sh"

# --- SHA handling ----------------------------------------------------------------

good_sha="c50913e2153c926fa32bfb897494d1f92ba70d01bfc202e4b22bdbd362c8f9d3"
run_case "sha: a lowercase 64-hex sha gives sha256-<sha>" pass "sha256-$good_sha" \
	bash -c '. "$1"; tag_for_sha "$2"' _ "$SCRIPTS/lib.sh" "$good_sha"
run_case "sha: an uppercase sha is rejected" fail "not a lowercase 64-hex sha256" \
	bash -c '. "$1"; tag_for_sha "$2"' _ "$SCRIPTS/lib.sh" "C50913E2153C926FA32BFB897494D1F92BA70D01BFC202E4B22BDBD362C8F9D3"
run_case "sha: a short sha is rejected" fail "not a lowercase 64-hex sha256" \
	bash -c '. "$1"; tag_for_sha "$2"' _ "$SCRIPTS/lib.sh" "c50913e2153c"
run_case "sha: a sha with a trailing path is rejected" fail "not a lowercase 64-hex sha256" \
	bash -c '. "$1"; tag_for_sha "$2"' _ "$SCRIPTS/lib.sh" "$good_sha/../x"

d="$(fixture hashes)"
printf 'same bytes\n' >"$d/a"
printf 'same bytes\n' >"$d/b"
printf 'other bytes\n' >"$d/c"
run_case "check 1: identical downloads print their shared sha" pass "$(sha256sum "$d/a" | cut -d' ' -f1)" \
	bash -c '. "$1"; compare_download_hashes "$2" "$3"' _ "$SCRIPTS/lib.sh" "$d/a" "$d/b"
run_case "check 1: mismatched downloads fail naming both hashes" fail "first=$(sha256sum "$d/a" | cut -d' ' -f1) second=$(sha256sum "$d/c" | cut -d' ' -f1)" \
	bash -c '. "$1"; compare_download_hashes "$2" "$3"' _ "$SCRIPTS/lib.sh" "$d/a" "$d/c"

# --- Fakes for curl and gh ------------------------------------------------------

FAKE_BIN="$T/fakebin"
mkdir -p -- "$FAKE_BIN"

# Fake curl: serves the files listed in FAKE_CURL_FILES (colon-separated), one
# per call, in order; FAKE_CURL_FAIL=1 makes every call fail like a 404.
cat >"$FAKE_BIN/curl" <<'FAKE'
#!/usr/bin/env bash
set -euo pipefail
printf '%s\n' "$*" >>"$FAKE_LOG"
[ "${FAKE_CURL_FAIL:-0}" != "1" ] || { echo "curl: (22) The requested URL returned error: 404" >&2; exit 22; }
out=""
while [ "$#" -gt 0 ]; do
	case "$1" in
	--output) out="$2"; shift 2 ;;
	*) shift ;;
	esac
done
[ -n "$out" ] || { echo "fake curl: no --output" >&2; exit 2; }
n="$(cat "$FAKE_STATE/curl-calls" 2>/dev/null || echo 0)"
n=$((n + 1))
echo "$n" >"$FAKE_STATE/curl-calls"
IFS=: read -r -a files <<<"$FAKE_CURL_FILES"
src="${files[$((n - 1))]:-${files[$((${#files[@]} - 1))]}}"
cp -- "$src" "$out"
FAKE

# Fake gh: answers the few API calls the scripts make, per FAKE_RELEASE and
# FAKE_TAG, and records `release create` in FAKE_STATE so later calls see it.
cat >"$FAKE_BIN/gh" <<'FAKE'
#!/usr/bin/env bash
set -euo pipefail
printf '%s\n' "$*" >>"$FAKE_LOG"
not_found() { echo '{"message":"Not Found","status":"404"}'; echo "gh: Not Found (HTTP 404)" >&2; exit 1; }
release_json() {
	# release_json DRAFT IMMUTABLE ASSETS_JSON
	jq -n --argjson draft "$1" --argjson immutable "$2" --argjson assets "$3" \
		'{draft: $draft, immutable: $immutable, assets: $assets}'
}
asset() { jq -n --arg name "$1" --arg digest "$2" --arg state "${3:-uploaded}" '{name: $name, digest: $digest, state: $state}'; }
case "$1" in
api)
	case "$2" in
	*/releases/tags/*)
		scenario="$FAKE_RELEASE"
		[ ! -f "$FAKE_STATE/created" ] || scenario="${FAKE_AFTER_CREATE:-good}"
		good="$(asset snort3-community-rules.tar.gz "sha256:$FAKE_SHA")"
		case "$scenario" in
		absent) not_found ;;
		error) echo "gh: Server Error (HTTP 502)" >&2; exit 1 ;;
		good) release_json false true "[$good]" ;;
		draft) release_json true true "[$good]" ;;
		mutable) release_json false false "[$good]" ;;
		baddigest) release_json false true "[$(asset snort3-community-rules.tar.gz "sha256:0000000000000000000000000000000000000000000000000000000000000000")]" ;;
		wrongname) release_json false true "[$(asset rules.tar.gz "sha256:$FAKE_SHA")]" ;;
		twoassets) release_json false true "[$good, $(asset extra.txt sha256:00)]" ;;
		noassets) release_json false true "[]" ;;
		pending) release_json false true "[$(asset snort3-community-rules.tar.gz "sha256:$FAKE_SHA" starter)]" ;;
		*) echo "fake gh: unknown FAKE_RELEASE '$scenario'" >&2; exit 99 ;;
		esac
		;;
	*/git/ref/tags/*)
		case "${FAKE_TAG:-absent}" in
		absent) not_found ;;
		present) echo '{"ref":"refs/tags/x"}' ;;
		esac
		;;
	*) echo "fake gh: unexpected api call $2" >&2; exit 99 ;;
	esac
	;;
release)
	[ "$2" = "create" ] || { echo "fake gh: unexpected release $2" >&2; exit 99; }
	touch "$FAKE_STATE/created"
	exit "${FAKE_CREATE_RC:-0}"
	;;
*) echo "fake gh: unexpected command $*" >&2; exit 99 ;;
esac
FAKE
chmod +x "$FAKE_BIN/curl" "$FAKE_BIN/gh"

# with_fakes VAR=VALUE... -- CMD... — run CMD with the fakes first on PATH and a
# fresh log and state directory.
with_fakes() {
	local -a vars=()
	while [ "$1" != "--" ]; do
		vars+=("$1")
		shift
	done
	shift
	rm -rf -- "$T/state" && mkdir -p -- "$T/state"
	: >"$T/fake.log"
	env PATH="$FAKE_BIN:$PATH" FAKE_LOG="$T/fake.log" FAKE_STATE="$T/state" "${vars[@]}" "$@"
}

# --- Check 1: fetch-upstream.sh --------------------------------------------------

d="$(fixture fetch)"
make_tree "$d/src"
pack "$d/src" "$d/one.tar.gz"
make_tree "$d/src2" 4016
pack "$d/src2" "$d/two.tar.gz"
one_sha="$(sha256sum "$d/one.tar.gz" | cut -d' ' -f1)"

run_case "fetch: two identical downloads pass and print the sha" pass "$one_sha" \
	with_fakes FAKE_CURL_FILES="$d/one.tar.gz:$d/one.tar.gz" -- "$SCRIPTS/fetch-upstream.sh" "$d/work-ok"
run_case "fetch: the tarball and sha file are left in WORK_DIR" pass "" \
	bash -c '[ "$(cat "$1/sha256")" = "$2" ] && [ "$(sha256sum "$1/snort3-community-rules.tar.gz" | cut -d" " -f1)" = "$2" ] && [ ! -e "$1/download-2.tar.gz" ]' _ "$d/work-ok" "$one_sha"
run_case "fetch: curl is called twice, HTTPS-only, on the upstream URL" pass "" \
	bash -c '[ "$(grep -c -- "--proto =https .*https://www.snort.org/downloads/community/snort3-community-rules.tar.gz$" "$1")" = 2 ]' _ "$T/fake.log"
run_case "fetch: two downloads that differ fail" fail "the two independent downloads differ" \
	with_fakes FAKE_CURL_FILES="$d/one.tar.gz:$d/two.tar.gz" -- "$SCRIPTS/fetch-upstream.sh" "$d/work-differ"
run_case "fetch: differing downloads leave no tarball to publish" pass "" \
	bash -c '[ ! -e "$1/snort3-community-rules.tar.gz" ] && [ ! -e "$1/sha256" ]' _ "$d/work-differ"
run_case "fetch: a failed download fails" fail "download 1 of https://www.snort.org" \
	with_fakes FAKE_CURL_FAIL=1 FAKE_CURL_FILES="$d/one.tar.gz" -- "$SCRIPTS/fetch-upstream.sh" "$d/work-404"

# --- mirror-status.sh --------------------------------------------------------------

ms() { with_fakes FAKE_SHA="$good_sha" "$@" -- "$SCRIPTS/mirror-status.sh" "$good_sha"; }
run_case "status: no release and no tag is 'absent'" pass "absent" ms FAKE_RELEASE=absent
run_case "status: an intact release is 'mirrored'" pass "mirrored" ms FAKE_RELEASE=good
run_case "status: an API error is an error, not 'absent'" fail "GitHub API call failed" ms FAKE_RELEASE=error
run_case "status: a bare tag with no release fails" fail "has no published release" ms FAKE_RELEASE=absent FAKE_TAG=present
run_case "status: a draft release fails" fail "the release is a draft" ms FAKE_RELEASE=draft
run_case "status: a mutable release fails" fail "the release is not immutable" ms FAKE_RELEASE=mutable
run_case "status: an asset digest that is not the tag's sha fails" fail "asset digest is 'sha256:0000" ms FAKE_RELEASE=baddigest
run_case "status: a wrongly named asset fails" fail "asset is named 'rules.tar.gz'" ms FAKE_RELEASE=wrongname
run_case "status: two assets fail" fail "expected exactly 1 asset, found 2" ms FAKE_RELEASE=twoassets
run_case "status: no assets fail" fail "expected exactly 1 asset, found 0" ms FAKE_RELEASE=noassets
run_case "status: an asset still uploading fails" fail "asset state is 'starter'" ms FAKE_RELEASE=pending
run_case "status: a malformed sha is rejected before any API call" fail "not a lowercase 64-hex sha256" \
	with_fakes FAKE_RELEASE=good -- "$SCRIPTS/mirror-status.sh" "not-a-sha"

# --- publish.sh ------------------------------------------------------------------

# verified_workdir DIR — a work dir as verify-upstream.sh leaves it after a pass.
verified_workdir() {
	local dir="$1"
	rm -rf -- "$dir"
	mkdir -p -- "$dir"
	cp -- "$d/one.tar.gz" "$dir/$ASSET_NAME"
	printf '%s\n' "$one_sha" >"$dir/sha256"
	printf 'sha256=%s\nactive_rules=4017\nfirewall_tag=2026.09.3\nsnort_version=3.10.0.0\nverified_at=2026-09-16T00:00:00Z\n' "$one_sha" >"$dir/verification.env"
}
pub() { with_fakes FAKE_SHA="$one_sha" FAKE_CURL_FILES="$d/one.tar.gz" "$@" -- "$SCRIPTS/publish.sh" "$d/pub"; }

verified_workdir "$d/pub"
run_case "publish: DRY_RUN=1 on a new sha says what it would publish" pass "WOULD publish" \
	pub DRY_RUN=1 FAKE_RELEASE=absent
run_case "publish: DRY_RUN=1 names the contract URL" pass "https://github.com/example/test-mirror/releases/download/sha256-$one_sha/snort3-community-rules.tar.gz" \
	pub DRY_RUN=1 FAKE_RELEASE=absent
run_case "publish: DRY_RUN=1 never calls gh release create" pass "" \
	bash -c '! grep -q "^release create" "$1"' _ "$T/fake.log"
run_case "publish: an already-mirrored sha is a no-op" pass "already mirrored" \
	pub FAKE_RELEASE=good
run_case "publish: the no-op never calls gh release create" pass "" \
	bash -c '! grep -q "^release create" "$1"' _ "$T/fake.log"
run_case "publish: a new sha is published as sha256-<sha> with the tarball as its only asset" pass "published sha256-$one_sha" \
	pub FAKE_RELEASE=absent
run_case "publish: gh release create got the contract tag, asset and repo" pass "" \
	bash -c 'grep -qF -- "release create sha256-$2 $3/snort3-community-rules.tar.gz --repo example/test-mirror" "$1"' _ "$T/fake.log" "$one_sha" "$d/pub"
run_case "publish: a release that does not verify after creation fails" fail "does not verify as intact" \
	pub FAKE_RELEASE=absent FAKE_AFTER_CREATE=baddigest
run_case "publish: a download URL serving other bytes fails" fail "serves $(sha256sum "$d/two.tar.gz" | cut -d' ' -f1)" \
	with_fakes FAKE_SHA="$one_sha" FAKE_CURL_FILES="$d/two.tar.gz" FAKE_RELEASE=absent -- "$SCRIPTS/publish.sh" "$d/pub"
run_case "publish: a failing gh release create fails" fail "gh release create sha256-$one_sha failed" \
	pub FAKE_RELEASE=absent FAKE_CREATE_RC=1

verified_workdir "$d/pub"
printf 'tampered\n' >>"$d/pub/$ASSET_NAME"
run_case "publish: a tarball that changed after verification is refused" fail "refusing to publish" \
	pub FAKE_RELEASE=absent
run_case "publish: the refusal happens before any GitHub call" pass "" \
	bash -c '[ ! -s "$1" ]' _ "$T/fake.log"

verified_workdir "$d/pub"
rm -f -- "$d/pub/verification.env"
run_case "publish: a work dir without verification.env is refused" fail "did not fully verify" \
	pub FAKE_RELEASE=absent

verified_workdir "$d/pub"
sed -i "s/^sha256=.*/sha256=$good_sha/" "$d/pub/verification.env"
run_case "publish: verification.env for a different sha is refused" fail "describes a different tarball" \
	pub FAKE_RELEASE=absent

# --- Summary ----------------------------------------------------------------------

echo
echo "unit tests: $passed passed, $failed failed"
if [ "$failed" -gt 0 ]; then
	printf '  failed: %s\n' "${failures[@]}"
	exit 1
fi

#!/usr/bin/env bash
#
# mirror-status.sh SHA — is the tarball with this SHA-256 already mirrored?
#
# Prints exactly one word on stdout and exits 0:
#   mirrored   a release tagged sha256-<SHA> exists and is intact: published
#              (not a draft), immutable, and carrying exactly one asset named
#              snort3-community-rules.tar.gz whose GitHub-computed digest is SHA.
#   absent     there is no release and no tag named sha256-<SHA>.
#
# Anything else exits non-zero and says why: an API error, a release that exists
# but is not intact, or a bare tag with no release. Those are never reported as
# "absent", because "absent" leads to a publish attempt and "mirrored" leads to
# doing nothing; an error must not be able to pick either.
#
# Needs: gh (authenticated, or GH_TOKEN set), jq.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
# shellcheck source=scripts/lib.sh
. "$SCRIPT_DIR/lib.sh"

[ "$#" -eq 1 ] || die "usage: $0 SHA256"
sha="$1"
tag="$(tag_for_sha "$sha")" || die "invalid SHA-256"

tmp="$(mktemp -d)"
trap 'rm -rf -- "$tmp"' EXIT

# gh_get ENDPOINT — print "found", "missing" (HTTP 404), or fail. The body of a
# found response is left in $tmp/body.
gh_get() {
	local rc=0
	gh api "$1" >"$tmp/body" 2>"$tmp/err" || rc=$?
	if [ "$rc" -eq 0 ]; then
		echo found
	elif grep -qF '(HTTP 404)' "$tmp/err"; then
		echo missing
	else
		cat -- "$tmp/err" >&2
		fail "GitHub API call failed (exit $rc): $1"
		return 1
	fi
}

release="$(gh_get "repos/$MIRROR_REPO/releases/tags/$tag")" || die "could not determine whether $tag is mirrored"

if [ "$release" = "missing" ]; then
	ref="$(gh_get "repos/$MIRROR_REPO/git/ref/tags/$tag")" || die "could not determine whether tag $tag exists"
	if [ "$ref" = "found" ]; then
		die "tag $tag exists in $MIRROR_REPO but has no published release; a human must look at it (never delete or overwrite a mirror entry)"
	fi
	echo absent
	exit 0
fi

body="$tmp/body"
problems=()
[ "$(jq -r '.draft' "$body")" = "false" ] || problems+=("the release is a draft")
[ "$(jq -r '.immutable' "$body")" = "true" ] || problems+=("the release is not immutable")
asset_count="$(jq -r '.assets | length' "$body")"
if [ "$asset_count" != "1" ]; then
	problems+=("expected exactly 1 asset, found $asset_count")
else
	name="$(jq -r '.assets[0].name' "$body")"
	digest="$(jq -r '.assets[0].digest' "$body")"
	state="$(jq -r '.assets[0].state' "$body")"
	[ "$name" = "$ASSET_NAME" ] || problems+=("asset is named '$name', expected '$ASSET_NAME'")
	[ "$state" = "uploaded" ] || problems+=("asset state is '$state', expected 'uploaded'")
	[ "$digest" = "sha256:$sha" ] || problems+=("asset digest is '$digest', expected 'sha256:$sha'")
fi

if [ "${#problems[@]}" -gt 0 ]; then
	for p in "${problems[@]}"; do
		fail "mirror entry $tag: $p"
	done
	die "mirror entry $tag exists but is not intact; a human must look at it (never delete or overwrite a mirror entry)"
fi

echo mirrored

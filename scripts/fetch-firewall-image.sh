#!/usr/bin/env bash
#
# fetch-firewall-image.sh OUT_DIR — download the A/B disk image of the latest
# STABLE Rasputin firewall release and verify its signature.
#
# Check 4 (the rules load under Snort) must run against the Snort build, config
# and UCI defaults that customers actually get, so it uses the real image rather
# than a Snort from some other distribution.
#
# "Latest stable" is GitHub's `releases/latest` for rasputin-openwrt-firewall,
# which never returns a draft or a prerelease (dev builds are prereleases); the
# script re-checks both flags anyway. Set FIREWALL_TAG to use a specific release
# instead, e.g. to reproduce an old result.
#
# The image is CMS-signed by the Rasputin release pipeline. We verify that
# signature against trust/rasputin-root-ca.pem (the same public root CA that is
# published at https://rasputin.geekdojo.com/rasputin-root-ca.pem) before any
# byte of the image is unpacked, because a later step runs its binaries as root.
#
# On success:
#   OUT_DIR/firewall-image.img.gz   the verified image
#   OUT_DIR/firewall-tag            the release tag it came from
#
# Needs: gh (authenticated, or GH_TOKEN set), openssl, jq.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
# shellcheck source=scripts/lib.sh
. "$SCRIPT_DIR/lib.sh"

[ "$#" -eq 1 ] || die "usage: $0 OUT_DIR"
out_dir="$1"
mkdir -p -- "$out_dir"
root_ca="$REPO_ROOT/trust/rasputin-root-ca.pem"
[ -s "$root_ca" ] || die "missing trust anchor: $root_ca"

for tool in gh jq openssl; do
	command -v "$tool" >/dev/null 2>&1 || die "$tool is required but not installed"
done

if [ -n "${FIREWALL_TAG:-}" ]; then
	endpoint="repos/$FIREWALL_REPO/releases/tags/$FIREWALL_TAG"
else
	endpoint="repos/$FIREWALL_REPO/releases/latest"
fi
release_json="$(gh api "$endpoint")" || die "could not read $endpoint"

tag="$(jq -er '.tag_name' <<<"$release_json")" || die "release has no tag_name"
draft="$(jq -r '.draft' <<<"$release_json")"
prerelease="$(jq -r '.prerelease' <<<"$release_json")"
[ "$draft" = "false" ] || die "release $tag is a draft"
[ "$prerelease" = "false" ] || die "release $tag is a prerelease, not a stable release"

images="$(jq -r '.assets[].name | select(endswith("-ab.img.gz"))' <<<"$release_json")"
[ -n "$images" ] || die "release $tag has no *-ab.img.gz asset"
[ "$(wc -l <<<"$images")" -eq 1 ] || die "release $tag has more than one *-ab.img.gz asset: $images"
image="$images"
jq -e --arg sig "$image.sig" '[.assets[].name] | index($sig) != null' <<<"$release_json" >/dev/null ||
	die "release $tag has no signature asset $image.sig"

dl="$out_dir/download"
rm -rf -- "$dl"
mkdir -p -- "$dl"
echo "downloading $image (+ .sig) from $FIREWALL_REPO release $tag" >&2
gh release download "$tag" --repo "$FIREWALL_REPO" --dir "$dl" \
	--pattern "$image" --pattern "$image.sig" || die "download of $image from $tag failed"

if ! openssl cms -verify -binary -inform DER \
	-in "$dl/$image.sig" -content "$dl/$image" \
	-CAfile "$root_ca" -out /dev/null 2>"$dl/cms.err"; then
	cat -- "$dl/cms.err" >&2
	die "signature verification FAILED for $image from $tag; refusing to use it"
fi
echo "signature verified against $(basename -- "$root_ca"): $image" >&2

mv -f -- "$dl/$image" "$out_dir/firewall-image.img.gz"
rm -rf -- "$dl"
printf '%s\n' "$tag" >"$out_dir/firewall-tag"
write_output firewall_tag "$tag"
printf '%s\n' "$tag"

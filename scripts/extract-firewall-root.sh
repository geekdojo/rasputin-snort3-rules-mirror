#!/usr/bin/env bash
#
# extract-firewall-root.sh IMAGE_GZ ROOT_DIR — unpack the firewall's slot-A root
# filesystem so snort-check.sh can chroot into it. Run as root.
#
# The firewall disk is a GPT image with partitions esp, seed, rootfs-0, rootfs-1
# and rootfs_data (see image/genimage.cfg in rasputin-openwrt-firewall). rootfs-0
# is a squashfs holding the whole OpenWrt userland, including /usr/bin/snort,
# /usr/bin/snort-mgr, /etc/snort and /etc/uci-defaults/99-rasputin. We find the
# partition by its GPT name, never by number, and unsquash it into ROOT_DIR.
#
# Needs: gunzip, sfdisk (util-linux), jq, dd, unsquashfs (squashfs-tools).

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
# shellcheck source=scripts/lib.sh
. "$SCRIPT_DIR/lib.sh"

[ "$#" -eq 2 ] || die "usage: $0 IMAGE_GZ ROOT_DIR"
image_gz="$1"
root_dir="$2"

[ "$(id -u)" -eq 0 ] || die "must run as root (unsquashfs must preserve ownership for the chroot)"
[ -s "$image_gz" ] || die "no such image: $image_gz"
[ ! -e "$root_dir" ] || die "ROOT_DIR already exists, refusing to unpack over it: $root_dir"
for tool in gunzip sfdisk jq dd unsquashfs; do
	command -v "$tool" >/dev/null 2>&1 || die "$tool is required but not installed"
done

scratch="$(dirname -- "$root_dir")/.extract.$$"
mkdir -p -- "$scratch"
trap 'rm -rf -- "$scratch"' EXIT

echo "decompressing $image_gz" >&2
gunzip -c -- "$image_gz" >"$scratch/disk.img" || die "gunzip failed on $image_gz"

table="$(sfdisk -J "$scratch/disk.img")" || die "sfdisk could not read a partition table from the image"
sector="$(jq -er '.partitiontable.sectorsize // 512' <<<"$table")"
matches="$(jq -r '[.partitiontable.partitions[] | select(.name == "rootfs-0")] | length' <<<"$table")"
[ "$matches" = "1" ] || die "expected exactly one partition named rootfs-0, found $matches"
start="$(jq -er '.partitiontable.partitions[] | select(.name == "rootfs-0") | .start' <<<"$table")"
size="$(jq -er '.partitiontable.partitions[] | select(.name == "rootfs-0") | .size' <<<"$table")"

dd if="$scratch/disk.img" of="$scratch/rootfs-0" bs="$sector" skip="$start" count="$size" status=none ||
	die "dd could not copy rootfs-0"
rm -f -- "$scratch/disk.img"

magic="$(head -c 4 -- "$scratch/rootfs-0")"
[ "$magic" = "hsqs" ] || die "rootfs-0 is not a squashfs (magic '$magic')"

unsquashfs -no-progress -quiet -dest "$root_dir" "$scratch/rootfs-0" >/dev/null ||
	die "unsquashfs failed on rootfs-0"

for path in usr/bin/snort usr/bin/snort-mgr sbin/uci etc/uci-defaults/99-rasputin etc/snort/rules; do
	[ -e "$root_dir/$path" ] || die "unpacked root has no /$path; the firewall image layout changed"
done
echo "unpacked rootfs-0 into $root_dir" >&2

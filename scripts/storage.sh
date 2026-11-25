#!/usr/bin/env bash
# How much disk Bridgekeep uses, as key=value lines (plain integers, bytes):
#
#   bridge_bytes=…      Bridge's data (the synced mailbox, its vault and keys)
#   analyzer_bytes=…    the analyzer's decision log and health file
#   portal_bytes=…      the admin portal's data
#   images_bytes=…      Bridgekeep's Docker images (proton-bridge, proton-analyzer, bridgekeep-portal)
#   disk_path=…         where that data lives (Docker's data folder, or the TrueNAS dataset)
#   disk_free_bytes=…   free space there
#   disk_total_bytes=…  size of that filesystem
#   low=yes|no          yes when free space is under 10% or under 5 GiB
#   ts=…                Unix time of this measurement
#
# A size that can't be measured (volume not created yet) is 0.
# ./bridgekeep status formats these; health-watch writes them to
# /var/lib/bridgekeep/status/storage.env for the admin portal.
# Needs root (or sudo) to read the volumes' sizes.
set -euo pipefail
cd "$(dirname "$0")/.."

as_root() { if [[ $(id -u) == 0 ]]; then "$@"; else sudo -n "$@"; fi; }
data=""
[[ -f .env ]] && data=$(sed -n 's/^BRIDGEKEEP_DATA=//p' .env | tail -n1)

size_of() { # a folder's size in bytes, or 0
  if [[ -z $1 ]] || ! as_root test -d "$1"; then echo 0; return; fi
  as_root du -sb -- "$1" 2>/dev/null | awk '{print $1+0}' || echo 0
}
volume_dir() { docker volume inspect -f '{{.Mountpoint}}' "proton-bridge_$1" 2>/dev/null || true; }
where() { # the folder holding piece $1 (bridge|analyzer|portal)
  if [[ -n $data ]]; then echo "$data/$1"; else volume_dir "$1-data"; fi
}

images=0
mapfile -t ids < <({ for r in proton-bridge proton-analyzer bridgekeep-portal; do
  docker image ls --no-trunc --format '{{.ID}}' "$r" 2>/dev/null; done; } | sort -u)
for id in "${ids[@]}"; do
  s=$(docker image inspect -f '{{.Size}}' "$id" 2>/dev/null || echo 0)
  images=$((images + s))
done

disk=${data:-$(docker info -f '{{.DockerRootDir}}' 2>/dev/null || echo /var/lib/docker)}
read -r free total < <(df -B1 --output=avail,size -- "$disk" 2>/dev/null | tail -n1 || echo "0 0")
low=no
if (( total > 0 )) && (( free * 10 < total || free < 5 * 1024 * 1024 * 1024 )); then low=yes; fi

printf 'bridge_bytes=%s\n' "$(size_of "$(where bridge)")"
printf 'analyzer_bytes=%s\n' "$(size_of "$(where analyzer)")"
printf 'portal_bytes=%s\n' "$(size_of "$(where portal)")"
printf 'images_bytes=%s\n' "$images"
printf 'disk_path=%s\n' "$disk"
printf 'disk_free_bytes=%s\n' "${free:-0}"
printf 'disk_total_bytes=%s\n' "${total:-0}"
printf 'low=%s\n' "$low"
printf 'ts=%s\n' "$(date +%s)"

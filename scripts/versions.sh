#!/usr/bin/env bash
# The versions ./bridgekeep status and the portal show, as key=value lines
# (or, with `tree FOLDER`, only that folder's git tree; see tree_now):
#   bridgekeep_version  the VERSION file of this checkout
#   bridgekeep_commit   its git commit (7 characters), read from .git without running git
#   bridge_version      the running Bridge container's version (its image label);
#                       empty when Bridge isn't running
#   portal_built, portal_checkout, analyzer_built, analyzer_checkout
#                       the git tree setup last built each image from
#                       (.bridgekeep/tree-*), and the checkout's tree now. They
#                       differ after a git pull until ./bridgekeep setup runs.
#
# Root runs this every 5 minutes from health-watch. Root never runs git on
# this checkout: .git is not checked for being root-only, and a repository's
# config can run commands. When the checkout tree is needed, git runs as the
# owner of .git instead (as nobody when that's root), with nothing of root's
# environment, so it can do no more than that user already could.
set -uo pipefail
export MSYS_NO_PATHCONV=1
cd "$(dirname "$0")/.." || exit 1
clean() { LC_ALL=C tr -cd "$1" | cut -c1-"${2:-40}"; }
hex40() { [[ $1 =~ ^[0-9a-f]{40}$ ]] && printf '%s' "$1"; }

v=$(head -n1 VERSION 2>/dev/null | clean '0-9A-Za-z.+-')

# The commit, from .git/HEAD and the ref it names (loose or packed).
commit() {
  [[ -d .git && ! -L .git ]] || return 0          # not a worktree link or a gitdir file
  local head ref line r
  IFS= read -r head <.git/HEAD 2>/dev/null || return 0
  if hex40 "$head" >/dev/null; then hex40 "$head"; return 0; fi
  [[ $head =~ ^ref:\ (refs/heads/[A-Za-z0-9._/-]+)$ ]] || return 0
  ref=${BASH_REMATCH[1]}
  [[ $ref == *..* ]] && return 0
  if [[ -f .git/$ref && ! -L .git/$ref ]]; then
    IFS= read -r line <".git/$ref" && hex40 "$line"
  elif [[ -f .git/packed-refs && ! -L .git/packed-refs ]]; then
    while IFS=' ' read -r line r; do
      [[ $r == "$ref" ]] && { hex40 "$line"; return 0; }
    done <.git/packed-refs
  fi
}
c=$(commit); c=${c:0:7}

# The checkout's git tree of a folder (portal, analyzer), as the owner of .git.
tree_now() {
  command -v git >/dev/null 2>&1 && [[ -d .git && ! -L .git ]] || { files_hash "$1"; return; }
  local uid gid out
  if [[ $(id -u) != 0 ]]; then
    out=$(git rev-parse "HEAD:$1" 2>/dev/null)
  else
    # The owner of .git, or nobody when root owns it: never root itself.
    uid=$(stat -c %u .git) gid=$(stat -c %g .git)
    [[ $uid == 0 ]] && uid=65534 gid=65534
    command -v setpriv >/dev/null 2>&1 || { files_hash "$1"; return; }
    out=$(setpriv --reuid="$uid" --regid="$gid" --clear-groups \
          env -i PATH=/usr/bin:/bin HOME=/nonexistent GIT_CONFIG_NOSYSTEM=1 \
          git -c safe.directory="$PWD" rev-parse "HEAD:$1" 2>/dev/null)   # unprivileged: the checkout itself is root's
  fi
  if hex40 "$out" >/dev/null; then echo "$out"; else files_hash "$1"; fi
}
# When git can't answer (no git, or .git under /root where the unprivileged user
# can't read it), hash the folder's files instead. "none" would match the last
# "none" forever and setup would never rebuild. Build output and caches are left out.
files_hash() {
  [[ -d $1 ]] || { echo none; return; }
  local h
  h=$(LC_ALL=C find "$1" \( -name node_modules -o -name web_dist -o -name __pycache__ -o -name '*.egg-info' \
        -o -name .pytest_cache \) -prune -o -type f -print0 2>/dev/null | LC_ALL=C sort -z \
      | xargs -0 -r sha256sum 2>/dev/null | sha256sum | cut -c1-40)
  if hex40 "$h" >/dev/null; then echo "$h"; else echo none; fi
}
# `versions.sh tree FOLDER`: just that tree (for ./bridgekeep setup, which may run as root).
if [[ ${1:-} == tree ]]; then
  [[ ${2:-} =~ ^[a-z]+$ ]] || exit 2
  tree_now "$2"; exit 0
fi
built() { local t; t=$(head -n1 ".bridgekeep/tree-$1" 2>/dev/null); hex40 "$t" || echo none; }

b=""
if command -v docker >/dev/null 2>&1; then
  id=$(docker compose ps -q bridge 2>/dev/null | head -n1)
  if [[ -n $id ]]; then
    # shellcheck disable=SC2016  # a Go template, not shell
    b=$(docker inspect -f '{{index .Config.Labels "org.opencontainers.image.version"}}' "$id" 2>/dev/null | clean '0-9A-Za-z.+-')
  fi
fi
printf 'bridgekeep_version=%s\nbridgekeep_commit=%s\nbridge_version=%s\n' "$v" "$c" "$b"
for s in portal analyzer; do
  printf '%s_built=%s\n%s_checkout=%s\n' "$s" "$(built "$s")" "$s" "$(tree_now "$s")"
done

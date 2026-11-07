#!/usr/bin/env bash
# Deterministic submodule fork-delta extractor for 64Gram.
#
# Usage: scripts/subdelta.sh <repo> <ref> <output_dir> [base_ref]
#
# For each forked submodule (URL owner TDesktop-x64), fetches the submodule's
# fork pin and official tdesktop upstream pin by SHA into a scratch bare repo
# and writes <name>.diff = git diff <upstream pin> <fork pin>.

set -euo pipefail

if [ "$#" -lt 3 ] || [ "$#" -gt 4 ]; then
  echo "Usage: $0 <repo> <ref> <output_dir> [base_ref]" >&2
  exit 2
fi

REPO="$1"
REF="$2"
OUTDIR="$3"
BASE_REF="${4:-}"

mkdir -p "$OUTDIR"

# Validate base version if BASE_REF is omitted
if [ -z "$BASE_REF" ]; then
  # sed reads the whole stream, so git never gets SIGPIPE under pipefail
  first_line=$(git -C "$REPO" show "$REF:changelog.txt" 2>/dev/null | sed -n '1p' || true)
  base_ver=$(echo "$first_line" | awk '{print $1}')
  ver_regex='^[0-9]+\.[0-9]+(\.[0-9]+)?$'
  if [[ ! "$base_ver" =~ $ver_regex ]]; then
    echo "Error: invalid base version in changelog.txt: '$base_ver'" >&2
    exit 2
  fi
  BASE_REF="upstream-v$base_ver"
  if ! git -C "$REPO" rev-parse --verify --quiet "$BASE_REF^{commit}" >/dev/null; then
    BASE_REF="v$base_ver"
  fi
fi

if ! git -C "$REPO" rev-parse --verify --quiet "$BASE_REF^{commit}" >/dev/null; then
  echo "Error: base ref '$BASE_REF' not found in $REPO" >&2
  exit 2
fi

get_upstream_url() {
  local sub_path="$1"
  local u
  u=$(git -C "$REPO" config --blob "$BASE_REF:.gitmodules" --get "submodule.$sub_path.url" 2>/dev/null || true)
  local local_regex='^(/|\.)'
  if [ -n "$u" ] && [[ "$u" =~ $local_regex ]]; then
    echo "$u"
    return
  fi
  case "$sub_path" in
    "Telegram/lib_base")
      echo "https://github.com/desktop-app/lib_base.git"
      ;;
    "Telegram/lib_ui")
      echo "https://github.com/desktop-app/lib_ui.git"
      ;;
    "Telegram/lib_storage")
      echo "https://github.com/desktop-app/lib_storage.git"
      ;;
    "Telegram/ThirdParty/tgcalls")
      echo "https://github.com/TelegramMessenger/tgcalls.git"
      ;;
    "cmake")
      echo "https://github.com/desktop-app/cmake_helpers.git"
      ;;
    *)
      if [ -n "$u" ]; then
        echo "${u/#git:\/\/github.com\//https:\/\/github.com\/}"
      fi
      ;;
  esac
}

scratch=$(mktemp -d)
# Cleanup is best effort: a failed rm must never fail the scan.
trap 'rm -rf "$scratch" 2>/dev/null || true' EXIT
git init --bare -q "$scratch"
# git fetch can spawn detached auto-gc/maintenance that keeps writing into
# objects/ while the EXIT trap deletes it ("Directory not empty"); disable it.
git -C "$scratch" config gc.auto 0
git -C "$scratch" config maintenance.auto false
git -C "$scratch" config fetch.writeCommitGraph false

sha_regex='^[0-9a-f]{40}$'

modules_txt=$(git -C "$REPO" config --blob "$REF:.gitmodules" --get-regexp '^submodule\..*\.path$' 2>/dev/null || true)

while IFS= read -r line || [ -n "$line" ]; do
  [ -z "$line" ] && continue
  key=$(echo "$line" | awk '{print $1}')
  sub_path=$(echo "$line" | cut -d' ' -f2-)
  sub_name="${key#submodule.}"
  sub_name="${sub_name%.path}"

  fork_url=$(git -C "$REPO" config --blob "$REF:.gitmodules" --get "submodule.$sub_name.url" 2>/dev/null || true)
  if [[ "$fork_url" != *"TDesktop-x64"* ]]; then
    continue
  fi

  fork_pin=$(git -C "$REPO" ls-tree "$REF" "$sub_path" 2>/dev/null | awk '{print $3}')
  if [[ ! "$fork_pin" =~ $sha_regex ]]; then
    echo "Error: invalid fork pin '$fork_pin' for $sub_path at $REF" >&2
    exit 2
  fi

  upstream_pin=$(git -C "$REPO" ls-tree "$BASE_REF" "$sub_path" 2>/dev/null | awk '{print $3}')
  if [[ ! "$upstream_pin" =~ $sha_regex ]]; then
    echo "Error: invalid upstream pin '$upstream_pin' for $sub_path at $BASE_REF" >&2
    exit 2
  fi

  upstream_url=$(get_upstream_url "$sub_path")
  if [ -z "$upstream_url" ]; then
    echo "Error: cannot determine upstream url for $sub_path" >&2
    exit 2
  fi

  diff_name="$(echo "$sub_path" | tr '/' '_').diff"
  out_diff="$OUTDIR/$diff_name"

  if [ "$fork_pin" = "$upstream_pin" ]; then
    : > "$out_diff"
    continue
  fi

  git -C "$scratch" fetch --no-tags --depth=1 -q "$upstream_url" "$upstream_pin"
  git -C "$scratch" fetch --no-tags --depth=1 -q "$fork_url" "$fork_pin"

  git -C "$scratch" diff "$upstream_pin" "$fork_pin" > "$out_diff"
done <<< "$modules_txt"

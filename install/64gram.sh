#!/usr/bin/env bash
# shellcheck disable=SC2024  # sudo ... </dev/tty is intentional, see below
# Install or update the audited 64Gram build from github.com/AbdallahxAhmed/secure-builds.
#
#   curl -fsSL https://raw.githubusercontent.com/AbdallahxAhmed/secure-builds/main/install/64gram.sh | bash
#
# Arch-based systems (pacman found): adds the signed [secure-builds] pacman
#   repository once and installs 64gram-secure; later updates arrive with
#   your normal `sudo pacman -Syu`.
# Any other Linux (or --user): installs for your user only, no root, into
#   ~/.local; run the same command again to update.
#
# Options: --user  per-user install even on Arch
#          --uninstall  remove what this script installed (keeps your chats/data)
#          --help
set -euo pipefail
# The `sudo ... </dev/tty` redirects are intentional: under `curl | bash`,
# stdin is the script itself, so prompts must read from the terminal.

OWNER_REPO="AbdallahxAhmed/secure-builds"
REPO_SECTION="secure-builds"
PKG="64gram-secure"
SIGNING_FPR="5C83C78C96C437BDDD9784EA58C99BB0C15EBBA6"
APP_ID="io.github.tdesktop_x64.TDesktop"
RAW="https://raw.githubusercontent.com"
GH="https://github.com"

PREFIX="${HOME}/.local"
OPT_DIR="${PREFIX}/opt/64gram"
BIN_LINK="${PREFIX}/bin/64gram"
DATA="${XDG_DATA_HOME:-${PREFIX}/share}"
DESKTOP_FILE="${DATA}/applications/${APP_ID}.desktop"
SERVICE_FILE="${DATA}/dbus-1/services/${APP_ID}.service"
ICON_SIZES=(16 32 48 64 128 256 512)

say() { printf '\033[1m==> %s\033[0m\n' "$*"; }
die() { printf 'error: %s\n' "$*" >&2; exit 1; }
need() { command -v "$1" >/dev/null 2>&1 || die "'$1' is required but not installed"; }
fetch() { curl -fsSL --proto '=https' --tlsv1.2 --retry 3 -o "$2" "$1"; }

usage() {
  cat <<'USAGE'
Install or update the audited 64Gram build (github.com/AbdallahxAhmed/secure-builds).
  (no option)   Arch-based: signed pacman repo + package; other Linux: per-user install
  --user        per-user install into ~/.local, even on Arch
  --uninstall   remove what this script installed (keeps your chats/data)
USAGE
}

TMP=""
cleanup() { [ -z "$TMP" ] || rm -rf "$TMP"; }
trap cleanup EXIT
mktmp() { TMP=$(mktemp -d); }

latest_tag() {
  # The pipeline records the last released 64Gram version in its state file;
  # reading it avoids GitHub's API rate limit.
  local ref
  ref=$(curl -fsSL --proto '=https' "${RAW}/${OWNER_REPO}/main/state/64gram.json" \
    | grep -oE '"built_ref": *"v[0-9]+\.[0-9]+\.[0-9]+"' | grep -oE 'v[0-9.]+') || true
  [ -n "$ref" ] && printf '64gram-%s\n' "$ref"
}

install_arch() {
  need sudo; need pacman-key; need curl; need gpg
  mktmp; local tmp="$TMP"

  say "Fetching the repository signing key"
  fetch "${RAW}/${OWNER_REPO}/main/keys/arch-repo.asc" "$tmp/key.asc"
  local got
  got=$(gpg --batch --with-colons --import-options show-only --import "$tmp/key.asc" 2>/dev/null \
        | awk -F: '/^fpr/{print $10; exit}')
  [ "$got" = "$SIGNING_FPR" ] || die "signing key fingerprint mismatch (got '$got', expected $SIGNING_FPR)"

  say "Trusting key $SIGNING_FPR in pacman (sudo)"
  sudo pacman-key --add "$tmp/key.asc" </dev/tty
  sudo pacman-key --lsign-key "$SIGNING_FPR" </dev/tty

  if ! grep -q "^\[${REPO_SECTION}\]" /etc/pacman.conf; then
    say "Adding the [${REPO_SECTION}] repository to /etc/pacman.conf"
    printf '\n[%s]\nSigLevel = Required\nServer = %s/%s/releases/download/arch-repo\n' \
      "$REPO_SECTION" "$GH" "$OWNER_REPO" | sudo tee -a /etc/pacman.conf >/dev/null
  fi

  say "Installing ${PKG} (pacman -Syu: Arch only supports installing on an up-to-date system)"
  sudo pacman -Syu --needed "$PKG" </dev/tty
  say "Done. Start 64Gram from your app menu or run: 64gram"
  say "Updates now come with your normal: sudo pacman -Syu"
}

install_user() {
  need curl; need sha256sum; need tar
  local tag ref tmp
  tag=$(latest_tag); [ -n "$tag" ] || die "could not find a 64Gram release"
  ref="${tag#64gram-}"
  if [ -f "$OPT_DIR/VERSION" ] && [ "$(cat "$OPT_DIR/VERSION")" = "$ref" ]; then
    say "64Gram $ref is already installed and up to date"; return 0
  fi
  mktmp; tmp="$TMP"

  local tarball="64gram-${ref}-linux-x86_64.tar.gz"
  say "Downloading 64Gram $ref"
  fetch "${GH}/${OWNER_REPO}/releases/download/${tag}/${tarball}" "$tmp/$tarball"
  fetch "${GH}/${OWNER_REPO}/releases/download/${tag}/SHA256SUMS" "$tmp/SHA256SUMS"
  (cd "$tmp" && grep -F "  $tarball" SHA256SUMS | sha256sum -c --strict --quiet -) \
    || die "checksum mismatch for $tarball"
  say "Checksum OK"
  if command -v gh >/dev/null 2>&1 && gh auth status >/dev/null 2>&1; then
    gh attestation verify "$tmp/$tarball" --repo "$OWNER_REPO" \
      --signer-workflow "$OWNER_REPO/.github/workflows/64gram.yml" >/dev/null \
      || die "build provenance attestation did not verify"
    say "Build provenance attestation OK"
  else
    say "Skipping attestation check (needs the GitHub CLI 'gh', logged in)"
  fi

  mkdir -p "$tmp/x" "${PREFIX}/opt" "${PREFIX}/bin" "${DATA}/applications" "${DATA}/dbus-1/services"
  tar -xzf "$tmp/$tarball" -C "$tmp/x" Telegram
  printf '%s\n' "$ref" > "$tmp/x/VERSION"

  local base="${RAW}/TDesktop-x64/tdesktop/${ref}"
  fetch "$base/lib/xdg/${APP_ID}.desktop" "$tmp/app.desktop"
  fetch "$base/lib/xdg/${APP_ID}.service" "$tmp/app.service"
  local s
  for s in "${ICON_SIZES[@]}"; do
    fetch "$base/Telegram/Resources/art/icon$s.png" "$tmp/icon$s.png"
  done

  sed -E -e "s|^TryExec=.*|TryExec=$OPT_DIR/Telegram|" \
      -e "s|^Exec=[^ ]+|Exec=$OPT_DIR/Telegram|" \
      -e "s|^Icon=org\\.telegram\\.desktop\$|Icon=$APP_ID|" \
      "$tmp/app.desktop" > "$tmp/app.desktop.out"
  # These files come from upstream's tag rather than the verified tarball:
  # refuse anything that would run more than the 64Gram binary.
  if grep -E '^Exec=' "$tmp/app.desktop.out" \
      | grep -vqxF -e "Exec=$OPT_DIR/Telegram -- %U" -e "Exec=$OPT_DIR/Telegram -quit"; then
    die "unexpected Exec= line in the upstream desktop file; not installing it"
  fi
  sed -E "s|^Exec=.*|Exec=$OPT_DIR/Telegram|" "$tmp/app.service" > "$tmp/app.service.out"
  grep -qxF "Name=$APP_ID" "$tmp/app.service.out" || die "unexpected upstream D-Bus service file"
  # Swap the program directory in one step so a failed download or check never leaves
  # a half-installed app.
  rm -rf "${OPT_DIR}.new"; mv "$tmp/x" "${OPT_DIR}.new"
  rm -rf "$OPT_DIR"; mv "${OPT_DIR}.new" "$OPT_DIR"
  ln -sfn "$OPT_DIR/Telegram" "$BIN_LINK"

  cp "$tmp/app.desktop.out" "$DESKTOP_FILE"
  cp "$tmp/app.service.out" "$SERVICE_FILE"
  for s in "${ICON_SIZES[@]}"; do
    install -Dm644 "$tmp/icon$s.png" "${DATA}/icons/hicolor/${s}x${s}/apps/${APP_ID}.png"
  done
  if command -v update-desktop-database >/dev/null 2>&1; then
    update-desktop-database -q "${DATA}/applications" || true
  fi
  if command -v gtk-update-icon-cache >/dev/null 2>&1; then
    gtk-update-icon-cache -q -t "${DATA}/icons/hicolor" 2>/dev/null || true
  fi

  say "Installed 64Gram $ref to $OPT_DIR"
  say "Start it from your app menu or run: $BIN_LINK"
  case ":$PATH:" in *":${PREFIX}/bin:"*) ;; *) say "Note: ${PREFIX}/bin is not on your PATH";; esac
  say "To update later, run the same install command again"
}

uninstall() {
  if command -v pacman >/dev/null 2>&1 && pacman -Q "$PKG" >/dev/null 2>&1; then
    say "Removing the ${PKG} package (sudo)"
    sudo pacman -Rns "$PKG" </dev/tty
    say "The [${REPO_SECTION}] entry in /etc/pacman.conf and the key are left in place; remove them by hand if you like"
  fi
  rm -rf "$OPT_DIR" "${OPT_DIR}.new"
  [ -L "$BIN_LINK" ] && rm -f "$BIN_LINK"
  rm -f "$DESKTOP_FILE" "$SERVICE_FILE"
  local s
  for s in "${ICON_SIZES[@]}"; do rm -f "${DATA}/icons/hicolor/${s}x${s}/apps/${APP_ID}.png"; done
  say "64Gram removed (your chats and settings in its data folder were not touched)"
}

main() {
  [ "$(uname -s)" = Linux ] || die "this installer is for Linux; Windows users: download the setup .exe from the releases page"
  [ "$(uname -m)" = x86_64 ] || die "only x86_64 builds are published"
  local mode=auto
  case "${1:-}" in
    --user) mode=user ;;
    --uninstall) uninstall; return ;;
    -h|--help) usage; return ;;
    "") ;;
    *) die "unknown option '$1' (try --help)" ;;
  esac
  if [ "$mode" = auto ] && command -v pacman >/dev/null 2>&1; then
    install_arch
  else
    install_user
  fi
}

# Everything runs from here, so a truncated `curl | bash` download does nothing.
main "$@"

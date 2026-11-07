#!/usr/bin/env python3
"""Harden 64Gram source tree before building.

Applies two hardening modifications:
1. In Telegram/SourceFiles/storage/localstorage.cpp, the line
   `CustomLangPack::currentInstance()->fetchCustomLangPack(langPackId, langPackBaseId);`
   becomes a comment so the client stops downloading and applying the unsigned
   UI-string pack from tdesktop-x64.github.io at startup.
2. In Telegram/SourceFiles/core/enhanced_settings.cpp, every default
   `"http://localhost:2468"` for radio_controller becomes `""` (exactly two
   occurrences replaced), so group-call join/leave hashes are not POSTed
   anywhere by default.

Exit codes: 0 = success, 1 = replacement or file error, 2 = usage error.
Python 3.12+, standard library only.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

EXIT_SUCCESS = 0
EXIT_FAILURE = 1
EXIT_USAGE_ERROR = 2

TARGET_LANGPACK = (
    "CustomLangPack::currentInstance()->fetchCustomLangPack(langPackId, langPackBaseId);"
)
REPLACEMENT_LANGPACK = (
    "// CustomLangPack::currentInstance()->fetchCustomLangPack(langPackId, langPackBaseId);"
)

TARGET_RADIO = '"http://localhost:2468"'
REPLACEMENT_RADIO = '""'


def find_target_file(worktree_dir: Path, rel_path: str, filename: str) -> Path:
    direct = worktree_dir / rel_path
    if direct.is_file():
        return direct
    matches = [p for p in worktree_dir.rglob(filename) if p.is_file()]
    if not matches:
        raise ValueError(
            f"Error: found 0 files named {filename!r} under '{worktree_dir}' "
            "(expected exactly 1)"
        )
    if len(matches) > 1:
        found_paths = ", ".join(str(p) for p in matches)
        raise ValueError(
            f"Error: found {len(matches)} files named {filename!r} under "
            f"'{worktree_dir}' (expected exactly 1): {found_paths}"
        )
    return matches[0]


def harden_64gram(worktree_dir: Path) -> None:
    localstorage_file = find_target_file(
        worktree_dir,
        "Telegram/SourceFiles/storage/localstorage.cpp",
        "localstorage.cpp",
    )
    enhanced_settings_file = find_target_file(
        worktree_dir,
        "Telegram/SourceFiles/core/enhanced_settings.cpp",
        "enhanced_settings.cpp",
    )

    try:
        content_localstorage = localstorage_file.read_text(encoding="utf-8")
    except OSError as exc:
        raise ValueError(f"Error reading {localstorage_file}: {exc}") from exc

    try:
        content_enhanced = enhanced_settings_file.read_text(encoding="utf-8")
    except OSError as exc:
        raise ValueError(f"Error reading {enhanced_settings_file}: {exc}") from exc

    errors: list[str] = []

    count_langpack = content_localstorage.count(TARGET_LANGPACK)
    if count_langpack != 1:
        errors.append(
            f"Error: replacement {TARGET_LANGPACK!r} found {count_langpack} time(s) "
            f"in {localstorage_file} (expected exactly 1)"
        )

    count_radio = content_enhanced.count(TARGET_RADIO)
    if count_radio != 2:
        errors.append(
            f"Error: replacement {TARGET_RADIO!r} found {count_radio} time(s) "
            f"in {enhanced_settings_file} (expected exactly 2)"
        )

    if errors:
        raise ValueError("\n".join(errors))

    new_localstorage = content_localstorage.replace(
        TARGET_LANGPACK, REPLACEMENT_LANGPACK, 1
    )
    new_enhanced = content_enhanced.replace(
        TARGET_RADIO, REPLACEMENT_RADIO
    )

    try:
        localstorage_file.write_text(new_localstorage, encoding="utf-8")
    except OSError as exc:
        raise ValueError(f"Error writing {localstorage_file}: {exc}") from exc

    try:
        enhanced_settings_file.write_text(new_enhanced, encoding="utf-8")
    except OSError as exc:
        raise ValueError(f"Error writing {enhanced_settings_file}: {exc}") from exc

    print(f"Applied replacement in {localstorage_file.name}: {TARGET_LANGPACK} -> {REPLACEMENT_LANGPACK}")
    print(f"Applied 2 replacements in {enhanced_settings_file.name}: {TARGET_RADIO} -> {REPLACEMENT_RADIO}")


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Harden 64Gram source tree before building."
    )
    parser.add_argument(
        "worktree_dir",
        type=Path,
        help="path to 64Gram source tree",
    )
    return parser.parse_args(argv)


def main(argv: list[str]) -> int:
    try:
        args = parse_args(argv)
    except SystemExit as exc:
        return EXIT_USAGE_ERROR if exc.code != 0 else EXIT_SUCCESS

    if not args.worktree_dir.is_dir():
        print(
            f"Error: '{args.worktree_dir}' is not an existing directory",
            file=sys.stderr,
        )
        return EXIT_USAGE_ERROR

    try:
        harden_64gram(args.worktree_dir)
    except ValueError as exc:
        print(f"harden error: {exc}", file=sys.stderr)
        return EXIT_FAILURE
    except Exception as exc:
        print(f"harden error: unexpected {type(exc).__name__}: {exc}", file=sys.stderr)
        return EXIT_FAILURE

    return EXIT_SUCCESS


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))

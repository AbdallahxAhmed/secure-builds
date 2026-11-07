#!/usr/bin/env python3
"""Harden EntinyGram by modifying InuConfig.kt in the source worktree.

Finds InuConfig.kt under <worktree-dir>, validates that target replacement
strings appear exactly once, and applies the replacements.

Exit codes: 0 = success, 1 = replacement or file error, 2 = usage error.
Python 3.12+, standard library only.
"""

from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path

EXIT_SUCCESS = 0
EXIT_FAILURE = 1
EXIT_USAGE_ERROR = 2

TARGET_FILENAME = "InuConfig.kt"

REPLACEMENTS: list[tuple[str, str]] = [
    (
        'BoolItem("hide_dev_badges", false)',
        'BoolItem("hide_dev_badges", true)',
    ),
    (
        'BoolItem("updates_enabled", true, exportable = false)',
        'BoolItem("updates_enabled", false, exportable = false)',
    ),
]


def find_inu_config(worktree_dir: Path) -> Path:
    """Find exactly one InuConfig.kt file under worktree_dir.

    Raises ValueError with an explanatory message if zero or more than one are found.
    """
    matches: list[Path] = []
    for root, _, files in os.walk(worktree_dir):
        for filename in files:
            if filename == TARGET_FILENAME:
                matches.append(Path(root) / filename)

    matches.sort()
    if not matches:
        raise ValueError(
            f"Error: found 0 files named {TARGET_FILENAME!r} under '{worktree_dir}' "
            "(expected exactly 1)"
        )
    if len(matches) > 1:
        found_paths = ", ".join(str(p) for p in matches)
        raise ValueError(
            f"Error: found {len(matches)} files named {TARGET_FILENAME!r} under "
            f"'{worktree_dir}' (expected exactly 1): {found_paths}"
        )
    return matches[0]


def harden_file(target_file: Path) -> None:
    """Validate and apply exact-string replacements on target_file.

    Raises ValueError if any replacement does not occur exactly once.
    """
    try:
        content = target_file.read_text(encoding="utf-8")
    except OSError as exc:
        raise ValueError(f"Error reading {target_file}: {exc}") from exc

    errors: list[str] = []
    for old, _ in REPLACEMENTS:
        count = content.count(old)
        if count != 1:
            errors.append(
                f"Error: replacement {old!r} found {count} time(s) in {target_file} "
                "(expected exactly 1)"
            )

    if errors:
        raise ValueError("\n".join(errors))

    new_content = content
    for old, new in REPLACEMENTS:
        new_content = new_content.replace(old, new, 1)

    try:
        target_file.write_text(new_content, encoding="utf-8")
    except OSError as exc:
        raise ValueError(f"Error writing {target_file}: {exc}") from exc

    for old, new in REPLACEMENTS:
        print(f"Applied replacement: {old} -> {new}")


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Harden EntinyGram by modifying InuConfig.kt."
    )
    parser.add_argument(
        "worktree_dir",
        metavar="<worktree-dir>",
        help="Path to the EntinyGram worktree directory",
    )
    return parser.parse_args(argv)


def main(argv: list[str]) -> int:
    args = parse_args(argv)
    worktree_path = Path(args.worktree_dir)
    if not worktree_path.is_dir():
        print(
            f"Usage error: '{args.worktree_dir}' is not an existing directory",
            file=sys.stderr,
        )
        return EXIT_USAGE_ERROR

    try:
        target_file = find_inu_config(worktree_path)
        harden_file(target_file)
    except ValueError as exc:
        print(exc, file=sys.stderr)
        return EXIT_FAILURE

    return EXIT_SUCCESS


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))

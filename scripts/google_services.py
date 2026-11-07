#!/usr/bin/env python3
"""Inject custom package name into Telegram's google-services.json.

Reads Telegram's public google-services.json, finds the client for
org.telegram.messenger, deep-copies it with the new package name,
and appends it to the client list (if not already present).
Writes the resulting JSON (indent=2, trailing newline) to all output paths.

Exit codes: 0 = success, 1 = input/content error, 2 = usage error.
Python 3.12+, standard library only.
"""

from __future__ import annotations

import argparse
import copy
import json
import os
import re
import sys
from pathlib import Path

EXIT_SUCCESS = 0
EXIT_FAILURE = 1
EXIT_USAGE_ERROR = 2

TARGET_BASE_PACKAGE = "org.telegram.messenger"
PACKAGE_RE = re.compile(r"^[a-zA-Z][a-zA-Z0-9_]*(\.[a-zA-Z][a-zA-Z0-9_]*)+$")


def validate_package_name(package: str) -> bool:
    """Validate Android package name format according to the specification."""
    return bool(PACKAGE_RE.match(package))


def update_google_services(data: dict, new_package: str) -> dict:
    """Find org.telegram.messenger client, clone it for new_package if needed."""
    if not isinstance(data, dict):
        raise ValueError("Invalid google-services.json: root must be a JSON object")

    clients = data.get("client")
    if not isinstance(clients, list):
        raise ValueError("Invalid google-services.json: 'client' must be a list")

    tg_client = None
    already_exists = False

    for client in clients:
        if not isinstance(client, dict):
            continue
        client_info = client.get("client_info")
        if not isinstance(client_info, dict):
            continue
        android_info = client_info.get("android_client_info")
        if not isinstance(android_info, dict):
            continue
        pkg = android_info.get("package_name")
        if pkg == TARGET_BASE_PACKAGE:
            tg_client = client
        if pkg == new_package:
            already_exists = True

    if tg_client is None:
        raise ValueError(
            f"Base client with package_name {TARGET_BASE_PACKAGE!r} not found in client list"
        )

    if not already_exists:
        cloned = copy.deepcopy(tg_client)
        cloned["client_info"]["android_client_info"]["package_name"] = new_package
        data["client"].append(cloned)

    return data


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Inject custom package into Telegram's google-services.json."
    )
    parser.add_argument(
        "--input",
        required=True,
        help="Path to Telegram google-services.json input file",
    )
    parser.add_argument(
        "--package",
        required=True,
        help="Target Android package name",
    )
    parser.add_argument(
        "--output",
        dest="outputs",
        action="extend",
        nargs="+",
        required=True,
        help="One or more destination file paths",
    )
    return parser.parse_args(argv)


def main(argv: list[str]) -> int:
    args = parse_args(argv)

    if not validate_package_name(args.package):
        print(
            f"Usage error: invalid package name: {args.package!r}",
            file=sys.stderr,
        )
        return EXIT_USAGE_ERROR

    input_path = Path(args.input)
    if not input_path.is_file():
        print(f"Error: input file not found: {args.input}", file=sys.stderr)
        return EXIT_FAILURE

    try:
        raw = input_path.read_text(encoding="utf-8")
        data = json.loads(raw)
    except (json.JSONDecodeError, OSError) as exc:
        print(f"Error reading {args.input}: {exc}", file=sys.stderr)
        return EXIT_FAILURE

    try:
        updated_data = update_google_services(data, args.package)
    except ValueError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return EXIT_FAILURE

    out_text = json.dumps(updated_data, indent=2, ensure_ascii=False) + "\n"

    for out_str in args.outputs:
        out_path = Path(out_str)
        try:
            out_path.parent.mkdir(parents=True, exist_ok=True)
            out_path.write_text(out_text, encoding="utf-8")
        except OSError as exc:
            print(f"Error writing to {out_str}: {exc}", file=sys.stderr)
            return EXIT_FAILURE

    return EXIT_SUCCESS


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))

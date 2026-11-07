#!/usr/bin/env python3
"""Unit tests for scripts/google_services.py.

Tests the CLI via subprocess against temporary directories.
Python 3.12+, standard library only, no network.
"""

from __future__ import annotations

import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
SCRIPT = REPO_ROOT / "scripts" / "google_services.py"

FIXTURE_GOOGLE_SERVICES = {
    "project_info": {
        "project_number": "123456789012",
        "project_id": "telegram-android-project",
    },
    "client": [
        {
            "client_info": {
                "mobilesdk_app_id": "1:123456789012:android:111aaa",
                "android_client_info": {
                    "package_name": "org.telegram.messenger",
                },
            },
            "oauth_client": [],
            "api_key": [{"current_key": "fake_key_messenger"}],
            "services": {"analytics_service": {"status": 1}},
        },
        {
            "client_info": {
                "mobilesdk_app_id": "1:123456789012:android:222bbb",
                "android_client_info": {
                    "package_name": "org.telegram.messenger.beta",
                },
            },
            "oauth_client": [],
            "api_key": [{"current_key": "fake_key_beta"}],
            "services": {"analytics_service": {"status": 1}},
        },
        {
            "client_info": {
                "mobilesdk_app_id": "1:123456789012:android:333ccc",
                "android_client_info": {
                    "package_name": "org.telegram.messenger.web",
                },
            },
            "oauth_client": [],
            "api_key": [{"current_key": "fake_key_web"}],
            "services": {"analytics_service": {"status": 1}},
        },
    ],
    "configuration_version": "1",
}


class GoogleServicesTest(unittest.TestCase):
    def run_script(self, *args: str) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            [sys.executable, str(SCRIPT), *args],
            capture_output=True,
            text=True,
        )

    def test_adds_new_client_while_keeping_original_three(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            input_file = tmp_path / "google-services.json"
            input_file.write_text(json.dumps(FIXTURE_GOOGLE_SERVICES, indent=2) + "\n")
            output_file = tmp_path / "out" / "google-services.json"

            proc = self.run_script(
                "--input", str(input_file),
                "--package", "org.fork.entinygram",
                "--output", str(output_file),
            )
            self.assertEqual(proc.returncode, 0, f"stderr: {proc.stderr}")

            raw_out = output_file.read_text(encoding="utf-8")
            self.assertTrue(raw_out.endswith("\n"))
            self.assertEqual(raw_out, json.dumps(json.loads(raw_out), indent=2) + "\n")

            data = json.loads(raw_out)
            clients = data.get("client", [])
            self.assertEqual(len(clients), 4)

            # First three clients preserved in order
            pkg_names = [
                c["client_info"]["android_client_info"]["package_name"]
                for c in clients
            ]
            self.assertEqual(
                pkg_names,
                [
                    "org.telegram.messenger",
                    "org.telegram.messenger.beta",
                    "org.telegram.messenger.web",
                    "org.fork.entinygram",
                ],
            )

            # New client has deep-copied data from org.telegram.messenger
            base_client = clients[0]
            new_client = clients[3]
            self.assertEqual(
                new_client["client_info"]["mobilesdk_app_id"],
                base_client["client_info"]["mobilesdk_app_id"],
            )
            self.assertEqual(new_client["api_key"], base_client["api_key"])
            self.assertEqual(new_client["services"], base_client["services"])

    def test_idempotent_when_package_already_exists(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            input_file = tmp_path / "input.json"
            input_file.write_text(json.dumps(FIXTURE_GOOGLE_SERVICES, indent=2) + "\n")

            # Case A: package already in fixture (beta)
            out_a = tmp_path / "out_a.json"
            proc_a = self.run_script(
                "--input", str(input_file),
                "--package", "org.telegram.messenger.beta",
                "--output", str(out_a),
            )
            self.assertEqual(proc_a.returncode, 0)
            data_a = json.loads(out_a.read_text(encoding="utf-8"))
            self.assertEqual(len(data_a["client"]), 3)

            # Case B: run once with new package, then run again with that output as input
            out_b1 = tmp_path / "out_b1.json"
            proc_b1 = self.run_script(
                "--input", str(input_file),
                "--package", "org.fork.entinygram",
                "--output", str(out_b1),
            )
            self.assertEqual(proc_b1.returncode, 0)
            content_b1 = out_b1.read_text(encoding="utf-8")

            out_b2 = tmp_path / "out_b2.json"
            proc_b2 = self.run_script(
                "--input", str(out_b1),
                "--package", "org.fork.entinygram",
                "--output", str(out_b2),
            )
            self.assertEqual(proc_b2.returncode, 0)
            content_b2 = out_b2.read_text(encoding="utf-8")

            self.assertEqual(content_b1, content_b2)
            data_b2 = json.loads(content_b2)
            self.assertEqual(len(data_b2["client"]), 4)

    def test_writes_same_content_to_two_outputs(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            input_file = tmp_path / "input.json"
            input_file.write_text(json.dumps(FIXTURE_GOOGLE_SERVICES, indent=2) + "\n")

            out1 = tmp_path / "nested" / "path1" / "google-services.json"
            out2 = tmp_path / "other" / "path2" / "google-services.json"

            proc = self.run_script(
                "--input", str(input_file),
                "--package", "org.fork.entinygram",
                "--output", str(out1),
                "--output", str(out2),
            )
            self.assertEqual(proc.returncode, 0, f"stderr: {proc.stderr}")

            self.assertTrue(out1.is_file())
            self.assertTrue(out2.is_file())
            self.assertEqual(
                out1.read_text(encoding="utf-8"),
                out2.read_text(encoding="utf-8"),
            )

    def test_missing_org_telegram_messenger_client_exits_one(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            bad_fixture = {
                "project_info": {"project_id": "test"},
                "client": [
                    {
                        "client_info": {
                            "android_client_info": {
                                "package_name": "org.telegram.messenger.beta",
                            },
                        },
                    },
                ],
                "configuration_version": "1",
            }
            input_file = tmp_path / "bad_input.json"
            input_file.write_text(json.dumps(bad_fixture))
            output_file = tmp_path / "out.json"

            proc = self.run_script(
                "--input", str(input_file),
                "--package", "org.fork.entinygram",
                "--output", str(output_file),
            )
            self.assertEqual(proc.returncode, 1)
            self.assertIn("org.telegram.messenger", proc.stderr)
            self.assertFalse(output_file.exists())

    def test_invalid_package_name_exits_two(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            input_file = tmp_path / "input.json"
            input_file.write_text(json.dumps(FIXTURE_GOOGLE_SERVICES))
            output_file = tmp_path / "out.json"

            invalid_packages = [
                "nodots",
                "123.starts.with.digit",
                "has-hyphen.pkg",
                ".leading.dot",
                "trailing.dot.",
                "double..dot",
                "",
            ]
            for bad_pkg in invalid_packages:
                with self.subTest(package=bad_pkg):
                    proc = self.run_script(
                        "--input", str(input_file),
                        "--package", bad_pkg,
                        "--output", str(output_file),
                    )
                    self.assertEqual(
                        proc.returncode, 2,
                        f"Expected exit 2 for package {bad_pkg!r}, got {proc.returncode}",
                    )
                    self.assertFalse(output_file.exists())

    def test_missing_required_arguments_exits_two(self) -> None:
        # Missing --package and --output
        proc = self.run_script("--input", "some.json")
        self.assertEqual(proc.returncode, 2)

    def test_missing_input_file_exits_one(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            non_existent = tmp_path / "not_there.json"
            output_file = tmp_path / "out.json"

            proc = self.run_script(
                "--input", str(non_existent),
                "--package", "org.fork.entinygram",
                "--output", str(output_file),
            )
            self.assertEqual(proc.returncode, 1)
            self.assertFalse(output_file.exists())


if __name__ == "__main__":
    unittest.main()

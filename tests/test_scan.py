#!/usr/bin/env python3
"""Unit tests for scripts/scan.py.

Each test builds a throwaway git repository (two commits: OLD and NEW) in a
TemporaryDirectory, runs the scanner as a subprocess, and asserts on exit
code plus report contents.  No network access happens anywhere here.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
SCAN = REPO_ROOT / "scripts" / "scan.py"

MANIFEST_INTERNET = (
    '<?xml version="1.0" encoding="utf-8"?>\n'
    "<manifest>\n"
    '  <uses-permission android:name="android.permission.INTERNET"/>\n'
    "</manifest>\n"
)

TRACKERS_FIXTURE = {
    "trackers": {
        "1": {
            "id": 1,
            "name": "ExampleAds",
            "code_signature": "com.example.chatter.|com.example.malware.",
            "network_signature": r"ads\.example\.com",
        },
        "2": {
            "id": 2,
            "name": "EmptyEntries",
            "code_signature": "",
            "network_signature": "",
        },
    }
}


class ScanTest(unittest.TestCase):
    def setUp(self) -> None:
        self._root = tempfile.TemporaryDirectory()
        self.addCleanup(self._root.cleanup)
        self.repo_path = Path(self._root.name) / "repo"
        self.repo_path.mkdir()
        self._git("init", "-q", "-b", "main")
        self._git("config", "user.email", "test@example.invalid")
        self._git("config", "user.name", "scanner test")

    # -- repo helpers ---------------------------------------------------------

    def _git(self, *args: str) -> str:
        proc = subprocess.run(
            ["git", "-C", str(self.repo_path), *args],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        self.assertEqual(proc.returncode, 0,
                         f"git {args} failed: {proc.stderr}")
        return proc.stdout.strip()

    def commit(self, message: str, **files) -> str:
        for name, content in files.items():
            target = self.repo_path / name
            target.parent.mkdir(parents=True, exist_ok=True)
            if isinstance(content, bytes):
                target.write_bytes(content)
            else:
                target.write_text(content, encoding="utf-8")
        self._git("add", "-A")
        self._git("commit", "-qm", message)
        return self._git("rev-parse", "HEAD")

    # -- scan helpers ---------------------------------------------------------

    def run_scan(self, old: str, new: str, profile: str,
                 trackers: dict | None = None):
        trackers = trackers if trackers is not None else TRACKERS_FIXTURE
        with tempfile.TemporaryDirectory() as tmp:
            trackers_path = Path(tmp) / "trackers.json"
            trackers_path.write_text(json.dumps(trackers), encoding="utf-8")
            report = Path(tmp) / "report.md"
            as_json = Path(tmp) / "report.json"
            proc = subprocess.run(
                [sys.executable, str(SCAN),
                 "--repo", str(self.repo_path),
                 "--old", old, "--new", new,
                 "--profile", profile,
                 "--trackers", str(trackers_path),
                 "--report", str(report),
                 "--json", str(as_json)],
                capture_output=True, text=True, timeout=180)
            report_text = report.read_text(encoding="utf-8") \
                if report.exists() else ""
            json_data = None
            if as_json.exists():
                json_data = json.loads(as_json.read_text(encoding="utf-8"))
            return proc, report_text, json_data

    # -- fixtures ---------------------------------------------------------------

    def baseline_commits(self, profile: str = "android-patchset") -> tuple[str, str]:
        """OLD = plain audited state; NEW = a boring clean change."""
        old = self.commit(
            "old release",
            **{
                "AndroidManifest.xml": MANIFEST_INTERNET,
                "lib/net.kt": 'val URL = "https://api.acme.dev/v1"\n',
                "lib/counted.kt": "class Analytics: com.example.chatter.Sdk()\n",
                "lib/build.gradle": "implementation 'com.example:old:1.0.0'\n",
                "lib/notes.md": "docs about https://api.acme.dev\n",
            })
        new = self.commit(
            "clean update",
            **{
                "lib/counted.kt":
                    "class Analytics: com.example.chatter.Sdk()\n"
                    "// minor docs only\n",
            })
        return old, new

    def expected_clean(self, report: str, json_data: dict | None) -> None:
        self.assertIn("Verdict: CLEAN", report)
        self.assertIsNotNone(json_data)
        self.assertFalse(json_data["flagged"])
        self.assertEqual(json_data["verdict"], "CLEAN")

    # -- individual checks ------------------------------------------------------

    def test_clean_update_exits_zero(self):
        old, new = self.baseline_commits()
        proc, report, data = self.run_scan(old, new, "android-patchset")
        self.assertEqual(proc.returncode, 0, report)
        self.expected_clean(report, data)

    def test_new_host_flags(self):
        old, new = self.baseline_commits()
        flagged = self.commit(
            "add telemetry",
            **{"lib/new.kt": 'val T = "https://newhost.examplex.dev/v1"\n'})
        proc, report, _ = self.run_scan(old, flagged, "android-patchset")
        self.assertEqual(proc.returncode, 10)
        self.assertIn("newhost.examplex.dev", report)
        self.assertIn("1. NEW NETWORK HOSTS", report)

    def test_preexisting_host_not_reflagged(self):
        old, new = self.baseline_commits()
        # NEW only reuses the already-audited host
        self.assertEqual(old != new, True)
        proc, report, _ = self.run_scan(old, new, "android-patchset")
        self.assertEqual(proc.returncode, 0, report)
        self.assertNotIn("api.acme.dev", report)

    def test_smali_const_string_host_is_flagged(self):
        old = self.commit(
            "old",
            **{
                "AndroidManifest.xml": MANIFEST_INTERNET,
                "smali/com/app/Main.smali":
                    "# baseline\nconst-string v0, \"something.old\"\n",
            })
        new = self.commit(
            "new",
            **{
                "smali/com/app/Main.smali":
                    '# baseline\nconst-string v0, "https://swing.delight.dev/v2"\n',
            })
        proc, report, _ = self.run_scan(old, new, "apktool")
        self.assertEqual(proc.returncode, 10)
        self.assertIn("swing.delight.dev", report)
        self.assertIn("smali", report)

    def test_new_permission_in_manifest(self):
        old, _ = self.baseline_commits()
        new = self.commit(
            "extra permission",
            **{"AndroidManifest.xml":
               MANIFEST_INTERNET.replace(
                   "</manifest>",
                   '  <uses-permission '
                   'android:name="android.permission.RECORD_AUDIO"/>\n'
                   "</manifest>\n")})
        proc, report, _ = self.run_scan(old, new, "android-patchset")
        self.assertEqual(proc.returncode, 10)
        self.assertIn("android.permission.RECORD_AUDIO", report)
        self.assertIn("2. ANDROID PERMISSIONS", report)

    def test_new_permission_inside_patch_file(self):
        old, _ = self.baseline_commits()
        patch = (
            "Subject: [PATCH] add camera\n"
            "---\n"
            "+ <uses-permission android:name=\"android.permission.CAMERA\" />\n"
            "+ <context\n"
        )
        new = self.commit("patch commit", **{"patches/0002-camera.patch": patch})
        proc, report, _ = self.run_scan(old, new, "android-patchset")
        self.assertEqual(proc.returncode, 10)
        self.assertIn("android.permission.CAMERA", report)
        self.assertIn("patches/0002-camera.patch", report)

    def test_permission_already_in_old_patch_not_reflagged(self):
        old_patch = (
            "Subject: [PATCH] add camera\n"
            "---\n"
            "+ <uses-permission android:name=\"android.permission.CAMERA\" />\n"
        )
        self.commit("old release",
                    **{
                        "AndroidManifest.xml": MANIFEST_INTERNET,
                        "patches/0002-camera.patch": old_patch,
                    })
        mid = self._git("rev-parse", "HEAD")
        new = self.commit(
            "clean changes on top",
            **{"README.md": "nothing interesting\n"})
        proc, report, _ = self.run_scan(mid, new, "android-patchset")
        self.assertEqual(proc.returncode, 0, report)

    def test_internet_permission_is_critical_in_apktool_profile(self):
        old, new = self.baseline_commits()
        proc, report, data = self.run_scan(old, new, "apktool")
        self.assertEqual(proc.returncode, 10)
        self.assertIn("CRITICAL", report)
        self.assertIn("android.permission.INTERNET", report)
        critical = [s for s in data["sections"] if s["critical"]]
        self.assertTrue(any("ANDROID PERMISSIONS" in s["title"]
                            for s in critical))

    def test_missing_manifest_is_critical_in_apktool_profile(self):
        base = self.commit(
            "old",
            **{
                "AndroidManifest.xml": MANIFEST_INTERNET,
                "apktool.yml": "apktool: 2.6.1\n",
                "res/values/strings.xml": "<resources/>\n",
                "lib/net/lib.so": b"\x7fELF\x02\x01\x01" + b"\x00" * 40,
            })
        self._git("rm", "-q", "AndroidManifest.xml", "apktool.yml")
        self._git("commit", "-qm", "delete build files")
        new = self._git("rev-parse", "HEAD")
        proc, report, _ = self.run_scan(base, new, "apktool")
        self.assertEqual(proc.returncode, 10)
        self.assertIn("7. BUILDABILITY", report)
        self.assertIn("missing", report)

    def test_tracker_signature_increase(self):
        old, _ = self.baseline_commits()
        new = self.commit(
            "add more tracker",
            **{"lib/more.kt":
               "class Extra: com.example.chatter.Sdk()\n"
               "class Also: com.example.malware.Nasty()\n"})
        proc, report, _ = self.run_scan(old, new, "android-patchset")
        self.assertEqual(proc.returncode, 10)
        self.assertIn("ExampleAds", report)
        self.assertIn("3. TRACKERS", report)
        self.assertIn("1 -> 3", report)  # 1 base + 2 added matches

    def test_tracker_decrease_is_not_flagged(self):
        old = self.commit(
            "old",
            **{
                "AndroidManifest.xml": MANIFEST_INTERNET,
                "lib/counted.kt":
                    "class A: com.example.chatter.Sdk()\n"
                    "class B: com.example.chatter.Sdk()\n",
            })
        new = self.commit(
            "cleanup",
            **{"lib/counted.kt": "class A: com.example.chatter.Sdk()\n"})
        proc, report, _ = self.run_scan(old, new, "android-patchset")
        self.assertEqual(proc.returncode, 0, report)

    def test_new_so_binary(self):
        old, _ = self.baseline_commits()
        new = self.commit(
            "embed native",
            **{"lib/native/bin.so": b"\x7fELF\x02\x01\x01" + b"\x00" * 16})
        proc, report, _ = self.run_scan(old, new, "android-patchset")
        self.assertEqual(proc.returncode, 10)
        self.assertIn("bin.so", report)
        self.assertIn("5. BINARIES", report)

    def test_zip_binary_detected_by_git(self):
        old, _ = self.baseline_commits()
        new = self.commit(
            "weird binary",
            **{"lib/data.weird": b"\x00\x01\x02\x03" * 400})
        proc, report, _ = self.run_scan(old, new, "android-patchset")
        self.assertEqual(proc.returncode, 10)
        self.assertIn("data.weird", report)

    def test_dependency_change_in_build_gradle(self):
        old, _ = self.baseline_commits()
        new = self.commit(
            "bump dep",
            **{"lib/build.gradle":
               "implementation 'com.example:old:1.0.0'\n"
               "implementation 'com.example:extra:9.9.9'\n"})
        proc, report, _ = self.run_scan(old, new, "android-patchset")
        self.assertEqual(proc.returncode, 10)
        self.assertIn("4. DEPENDENCIES", report)
        self.assertIn("com.example:extra", report)

    def test_apktool_res_change_is_info_only(self):
        base = self.commit(
            "old",
            **{
                "AndroidManifest.xml": MANIFEST_INTERNET,
                "apktool.yml": "apktool: 2.6.1\n",
                "res/values/strings.xml": "<resources><x/></resources>\n",
            })
        self.commit(
            "res tweak",
            **{"res/values/strings.xml": "<resources><y/></resources>\n"})
        new = self._git("rev-parse", "HEAD")
        proc, report, _ = self.run_scan(base, new, "apktool")
        self.assertEqual(proc.returncode, 10)  # INTERNET stays critical
        self.assertIn("res/values/strings.xml", report)
        self.assertIn("under res/ or assets/", report)

    def test_sensitive_path_in_android_patchset(self):
        old, _ = self.baseline_commits()
        new = self.commit(
            "sneak",
            **{"src/fork/helpers/network/Client.kt":
               "object Sneaky { val u = \"https://quiet.quiet.dev\" }\n"})
        proc, report, _ = self.run_scan(old, new, "android-patchset")
        self.assertEqual(proc.returncode, 10)
        self.assertIn("src/fork/helpers/network/Client.kt", report)

    def test_sensitive_upstream_commit_move(self):
        old = self.commit(
            "old",
            **{
                "AndroidManifest.xml": MANIFEST_INTERNET,
                "upstream-commit": "0" * 40 + "\n",
            })
        new = self.commit(
            "bump base",
            **{"upstream-commit": "1" * 40 + "\n"})
        proc, report, _ = self.run_scan(old, new, "android-patchset")
        self.assertEqual(proc.returncode, 10)
        self.assertIn("upstream-commit: " + "0" * 40 + " -> " + "1" * 40,
                      report)
        self.assertIn("-> " + "1" * 40, report)

    def test_informational_lines_present(self):
        old, _ = self.baseline_commits()
        new = self.commit("clean update again",
                          **{"README.md": "x\n"})
        proc, report, _ = self.run_scan(old, new, "android-patchset")
        self.assertEqual(proc.returncode, 0, report)
        self.assertIn("Files changed between", report)
        self.assertIn("clean update again", report)

    def test_missing_refs_are_internal_error(self):
        old, new = self.baseline_commits()
        proc, _report, _ = self.run_scan("deadbeef" * 4, new, "android-patchset")
        self.assertEqual(proc.returncode, 2)

    def test_usage_error_hits_exit_two(self):
        proc = subprocess.run(
            [sys.executable, str(SCAN), "--nope"], capture_output=True,
            text=True)
        self.assertEqual(proc.returncode, 2)


if __name__ == "__main__":
    unittest.main()

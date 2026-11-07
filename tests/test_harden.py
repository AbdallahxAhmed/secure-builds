#!/usr/bin/env python3
"""Unit tests for scripts/harden_entinygram.py.

Tests the CLI via subprocess against temporary directories.
Python 3.12+, standard library only, no network.
"""

from __future__ import annotations

import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
SCRIPT = REPO_ROOT / "scripts" / "harden_entinygram.py"

ORIGINAL_INU_CONFIG = """\
package org.fork

object InuConfig {
    val hideDevBadges = BoolItem("hide_dev_badges", false)
    val updatesEnabled = BoolItem("updates_enabled", true, exportable = false)
    val keepSetting = BoolItem("keep_setting", true)
}
"""


class HardenEntinygramTest(unittest.TestCase):
    def run_harden(self, *args: str) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            [sys.executable, str(SCRIPT), *args],
            capture_output=True,
            text=True,
        )

    def test_success_applies_both_replacements(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            worktree = Path(tmp)
            target = worktree / "src" / "fork" / "InuConfig.kt"
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text(ORIGINAL_INU_CONFIG, encoding="utf-8")

            proc = self.run_harden(str(worktree))
            self.assertEqual(proc.returncode, 0, f"stderr: {proc.stderr}")

            # Verify applied messages printed (one per applied replacement)
            self.assertIn(
                'Applied replacement: BoolItem("hide_dev_badges", false) -> '
                'BoolItem("hide_dev_badges", true)',
                proc.stdout,
            )
            self.assertIn(
                'Applied replacement: BoolItem("updates_enabled", true, exportable = false) -> '
                'BoolItem("updates_enabled", false, exportable = false)',
                proc.stdout,
            )

            # Verify file content updated
            updated = target.read_text(encoding="utf-8")
            self.assertIn('BoolItem("hide_dev_badges", true)', updated)
            self.assertIn(
                'BoolItem("updates_enabled", false, exportable = false)', updated
            )
            self.assertNotIn('BoolItem("hide_dev_badges", false)', updated)
            self.assertNotIn(
                'BoolItem("updates_enabled", true, exportable = false)', updated
            )
            self.assertIn('BoolItem("keep_setting", true)', updated)

    def test_second_run_fails_and_leaves_file_untouched(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            worktree = Path(tmp)
            target = worktree / "src" / "fork" / "InuConfig.kt"
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text(ORIGINAL_INU_CONFIG, encoding="utf-8")

            # First run: should succeed
            proc1 = self.run_harden(str(worktree))
            self.assertEqual(proc1.returncode, 0)
            hardened_content = target.read_text(encoding="utf-8")

            # Second run: must fail with exit 1
            proc2 = self.run_harden(str(worktree))
            self.assertEqual(proc2.returncode, 1)
            self.assertIn('BoolItem("hide_dev_badges", false)', proc2.stderr)
            self.assertIn("0 time(s)", proc2.stderr)

            # Ensure file is completely untouched after the failed second run
            self.assertEqual(target.read_text(encoding="utf-8"), hardened_content)

    def test_missing_inuconfig_exits_one(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            worktree = Path(tmp)
            other = worktree / "src" / "fork" / "OtherConfig.kt"
            other.parent.mkdir(parents=True, exist_ok=True)
            other.write_text("// no inu config here\n", encoding="utf-8")

            proc = self.run_harden(str(worktree))
            self.assertEqual(proc.returncode, 1)
            self.assertIn("InuConfig.kt", proc.stderr)
            self.assertIn("0 files", proc.stderr)

    def test_two_inuconfig_files_exits_one(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            worktree = Path(tmp)
            target1 = worktree / "pkg1" / "InuConfig.kt"
            target1.parent.mkdir(parents=True, exist_ok=True)
            target1.write_text(ORIGINAL_INU_CONFIG, encoding="utf-8")

            target2 = worktree / "pkg2" / "InuConfig.kt"
            target2.parent.mkdir(parents=True, exist_ok=True)
            target2.write_text(ORIGINAL_INU_CONFIG, encoding="utf-8")

            proc = self.run_harden(str(worktree))
            self.assertEqual(proc.returncode, 1)
            self.assertIn("InuConfig.kt", proc.stderr)
            self.assertIn("2 files", proc.stderr)

            # Ensure neither file was modified
            self.assertEqual(target1.read_text(encoding="utf-8"), ORIGINAL_INU_CONFIG)
            self.assertEqual(target2.read_text(encoding="utf-8"), ORIGINAL_INU_CONFIG)

    def test_one_target_string_missing_fails_and_leaves_file_unchanged(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            worktree = Path(tmp)
            target = worktree / "src" / "InuConfig.kt"
            target.parent.mkdir(parents=True, exist_ok=True)
            # Only hide_dev_badges is present; updates_enabled is missing
            partial_content = (
                'package org.fork\n'
                'val hideDevBadges = BoolItem("hide_dev_badges", false)\n'
            )
            target.write_text(partial_content, encoding="utf-8")

            proc = self.run_harden(str(worktree))
            self.assertEqual(proc.returncode, 1)
            self.assertIn('BoolItem("updates_enabled", true, exportable = false)', proc.stderr)
            self.assertIn("0 time(s)", proc.stderr)

            # File must remain completely unchanged (first replacement was not applied)
            self.assertEqual(target.read_text(encoding="utf-8"), partial_content)

    def test_target_string_duplicate_fails_and_leaves_file_unchanged(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            worktree = Path(tmp)
            target = worktree / "src" / "InuConfig.kt"
            target.parent.mkdir(parents=True, exist_ok=True)
            # hide_dev_badges occurs twice
            duplicate_content = (
                'package org.fork\n'
                'val hideDevBadges1 = BoolItem("hide_dev_badges", false)\n'
                'val hideDevBadges2 = BoolItem("hide_dev_badges", false)\n'
                'val updatesEnabled = BoolItem("updates_enabled", true, exportable = false)\n'
            )
            target.write_text(duplicate_content, encoding="utf-8")

            proc = self.run_harden(str(worktree))
            self.assertEqual(proc.returncode, 1)
            self.assertIn('BoolItem("hide_dev_badges", false)', proc.stderr)
            self.assertIn("2 time(s)", proc.stderr)
            self.assertEqual(target.read_text(encoding="utf-8"), duplicate_content)

    def test_usage_error_missing_arguments_exits_two(self) -> None:
        proc = self.run_harden()
        self.assertEqual(proc.returncode, 2)

    def test_usage_error_not_a_directory_exits_two(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            fake_dir = Path(tmp) / "does_not_exist"
            proc = self.run_harden(str(fake_dir))
            self.assertEqual(proc.returncode, 2)


if __name__ == "__main__":
    unittest.main()

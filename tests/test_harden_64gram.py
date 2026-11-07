#!/usr/bin/env python3
"""Unit tests for scripts/harden_64gram.py.

Tests the CLI via subprocess against temporary fixture worktrees.
Python 3.12+, standard library only, no network.
"""

from __future__ import annotations

import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
SCRIPT = REPO_ROOT / "scripts" / "harden_64gram.py"

FIXTURE_LOCALSTORAGE = """\
#include "storage/localstorage.h"

void LocalStorage::init() {
    CustomLangPack::currentInstance()->fetchCustomLangPack(langPackId, langPackBaseId);
    readSettings();
}
"""

FIXTURE_ENHANCED_SETTINGS = """\
#include "core/enhanced_settings.h"

void EnhancedSettings::load() {
    radio_controller_url = "http://localhost:2468";
    default_radio_controller = "http://localhost:2468";
    other_setting = 1;
}
"""


class Harden64gramTest(unittest.TestCase):
    def run_harden(self, *args: str) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            [sys.executable, str(SCRIPT), *args],
            capture_output=True,
            text=True,
        )

    def _setup_worktree(self, root: Path) -> tuple[Path, Path]:
        f1 = root / "Telegram" / "SourceFiles" / "storage" / "localstorage.cpp"
        f2 = root / "Telegram" / "SourceFiles" / "core" / "enhanced_settings.cpp"
        f1.parent.mkdir(parents=True, exist_ok=True)
        f2.parent.mkdir(parents=True, exist_ok=True)
        f1.write_text(FIXTURE_LOCALSTORAGE, encoding="utf-8")
        f2.write_text(FIXTURE_ENHANCED_SETTINGS, encoding="utf-8")
        return f1, f2

    def test_success_applies_all_replacements(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            worktree = Path(tmp)
            f1, f2 = self._setup_worktree(worktree)

            proc = self.run_harden(str(worktree))
            self.assertEqual(proc.returncode, 0, f"stderr: {proc.stderr}")

            # Verify stdout messages
            self.assertIn("Applied replacement in localstorage.cpp:", proc.stdout)
            self.assertIn("Applied 2 replacements in enhanced_settings.cpp:", proc.stdout)

            # Verify f1 modified
            c1 = f1.read_text(encoding="utf-8")
            self.assertIn(
                "// CustomLangPack::currentInstance()->fetchCustomLangPack(langPackId, langPackBaseId);",
                c1,
            )
            self.assertNotIn(
                "\n    CustomLangPack::currentInstance()->fetchCustomLangPack(langPackId, langPackBaseId);",
                c1,
            )

            # Verify f2 modified
            c2 = f2.read_text(encoding="utf-8")
            self.assertNotIn('"http://localhost:2468"', c2)
            self.assertIn('radio_controller_url = "";', c2)
            self.assertIn('default_radio_controller = "";', c2)
            self.assertIn("other_setting = 1;", c2)

    def test_second_run_fails_and_leaves_files_untouched(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            worktree = Path(tmp)
            f1, f2 = self._setup_worktree(worktree)

            proc1 = self.run_harden(str(worktree))
            self.assertEqual(proc1.returncode, 0)
            c1_after_1 = f1.read_text(encoding="utf-8")
            c2_after_1 = f2.read_text(encoding="utf-8")

            # Second run must fail with exit 1
            proc2 = self.run_harden(str(worktree))
            self.assertEqual(proc2.returncode, 1)
            self.assertIn("0 time(s)", proc2.stderr)

            # Verify contents are untouched
            self.assertEqual(f1.read_text(encoding="utf-8"), c1_after_1)
            self.assertEqual(f2.read_text(encoding="utf-8"), c2_after_1)

    def test_missing_file_exits_one(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            worktree = Path(tmp)
            # Only create localstorage.cpp, enhanced_settings.cpp is missing
            f1 = worktree / "Telegram" / "SourceFiles" / "storage" / "localstorage.cpp"
            f1.parent.mkdir(parents=True, exist_ok=True)
            f1.write_text(FIXTURE_LOCALSTORAGE, encoding="utf-8")

            proc = self.run_harden(str(worktree))
            self.assertEqual(proc.returncode, 1)
            self.assertIn("enhanced_settings.cpp", proc.stderr)
            self.assertIn("0 files", proc.stderr)

    def test_localstorage_target_missing_fails(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            worktree = Path(tmp)
            f1, f2 = self._setup_worktree(worktree)
            # localstorage without the target line
            f1.write_text("// clean localstorage\n", encoding="utf-8")

            proc = self.run_harden(str(worktree))
            self.assertEqual(proc.returncode, 1)
            self.assertIn("CustomLangPack", proc.stderr)
            self.assertIn("0 time(s)", proc.stderr)
            # Ensure f2 was NOT modified
            self.assertEqual(f2.read_text(encoding="utf-8"), FIXTURE_ENHANCED_SETTINGS)

    def test_enhanced_settings_wrong_count_fails(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            worktree = Path(tmp)
            f1, f2 = self._setup_worktree(worktree)
            # enhanced_settings with only 1 occurrence instead of 2
            f2.write_text('radio = "http://localhost:2468";\n', encoding="utf-8")

            proc = self.run_harden(str(worktree))
            self.assertEqual(proc.returncode, 1)
            self.assertIn("1 time(s)", proc.stderr)
            self.assertIn("expected exactly 2", proc.stderr)
            # Ensure f1 was NOT modified
            self.assertEqual(f1.read_text(encoding="utf-8"), FIXTURE_LOCALSTORAGE)

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

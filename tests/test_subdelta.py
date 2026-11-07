#!/usr/bin/env python3
"""Unit tests for scripts/subdelta.sh.

Tests subdelta.sh using local throwaway git repositories without network.
Python 3.12+, standard library only.
"""

from __future__ import annotations

import subprocess
import tempfile
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
SUBDELTA = REPO_ROOT / "scripts" / "subdelta.sh"


class SubdeltaTest(unittest.TestCase):
    def _git(self, repo: Path, *args: str) -> str:
        proc = subprocess.run(
            ["git", "-C", str(repo), *args],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        self.assertEqual(proc.returncode, 0, f"git {args} failed: {proc.stderr}")
        return proc.stdout.strip()

    def test_usage_error_fewer_arguments_exits_two(self) -> None:
        proc = subprocess.run(
            ["bash", str(SUBDELTA)],
            capture_output=True,
            text=True,
        )
        self.assertEqual(proc.returncode, 2)

    def test_subdelta_extracts_fork_diff_locally(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            sub_repo = tmp_path / "TDesktop-x64_lib_base"
            sub_repo.mkdir()
            self._git(sub_repo, "init", "-q", "-b", "main")
            self._git(sub_repo, "config", "user.email", "test@example.invalid")
            self._git(sub_repo, "config", "user.name", "test")

            # Upstream pin commit
            (sub_repo / "base.txt").write_text("upstream line\n", encoding="utf-8")
            self._git(sub_repo, "add", "-A")
            self._git(sub_repo, "commit", "-qm", "upstream commit")
            upstream_pin = self._git(sub_repo, "rev-parse", "HEAD")

            # Fork pin commit
            (sub_repo / "base.txt").write_text(
                "upstream line\nfork addition\n", encoding="utf-8"
            )
            self._git(sub_repo, "add", "-A")
            self._git(sub_repo, "commit", "-qm", "fork commit")
            fork_pin = self._git(sub_repo, "rev-parse", "HEAD")

            # Main repo
            main_repo = tmp_path / "64gram"
            main_repo.mkdir()
            self._git(main_repo, "init", "-q", "-b", "main")
            self._git(main_repo, "config", "user.email", "test@example.invalid")
            self._git(main_repo, "config", "user.name", "test")

            gitmodules = (
                '[submodule "Telegram/lib_base"]\n'
                "\tpath = Telegram/lib_base\n"
                f"\turl = {sub_repo}\n"
            )

            # Base commit (official tdesktop base tag)
            (main_repo / ".gitmodules").write_text(gitmodules, encoding="utf-8")
            (main_repo / "changelog.txt").write_text("7.3.5 (03.11.26)\n", encoding="utf-8")
            sub_dir = main_repo / "Telegram" / "lib_base"
            sub_dir.parent.mkdir(parents=True, exist_ok=True)
            self._git(main_repo, "add", ".gitmodules", "changelog.txt")
            # Add gitlink
            self._git(
                main_repo,
                "update-index",
                "--add",
                "--cacheinfo",
                "160000",
                upstream_pin,
                "Telegram/lib_base",
            )
            self._git(main_repo, "commit", "-qm", "base release")
            self._git(main_repo, "tag", "upstream-v7.3.5")

            # Fork commit (64Gram release tag)
            self._git(
                main_repo,
                "update-index",
                "--add",
                "--cacheinfo",
                "160000",
                fork_pin,
                "Telegram/lib_base",
            )
            self._git(main_repo, "commit", "-qm", "fork release")
            self._git(main_repo, "tag", "v1.2.11")

            out_dir = tmp_path / "subs_out"
            proc = subprocess.run(
                ["bash", str(SUBDELTA), str(main_repo), "v1.2.11", str(out_dir)],
                capture_output=True,
                text=True,
            )
            self.assertEqual(proc.returncode, 0, f"stderr: {proc.stderr}")

            diff_file = out_dir / "Telegram_lib_base.diff"
            self.assertTrue(diff_file.is_file(), f"Expected {diff_file} to exist")
            diff_content = diff_file.read_text(encoding="utf-8")
            self.assertIn("+fork addition", diff_content)


if __name__ == "__main__":
    unittest.main()

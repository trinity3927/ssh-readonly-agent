#!/usr/bin/env python3
"""Behavior tests for agent_ro dispatcher policy enforcement."""

import json
import os
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]
DISPATCHER = REPO_ROOT / "scripts" / "agent_ro_dispatch.py"


class DispatcherBehaviorTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp_dir = tempfile.TemporaryDirectory()
        self.tmp = Path(self.temp_dir.name)
        self.allowed_root = self.tmp / "allowed"
        self.allowed_root.mkdir(parents=True, exist_ok=True)
        self.sample_file = self.allowed_root / "sample.txt"
        self.sample_file.write_text("hello\n", encoding="utf-8")
        self.policy_file = self.tmp / "policy.json"

    def tearDown(self) -> None:
        self.temp_dir.cleanup()

    def write_policy(self, *, commands=None, allowed_roots=None) -> None:
        policy = {
            "allowed_commands": commands or ["find", "rg", "cat", "ls", "stat", "git", "grep"],
            "allowed_roots": [str(p) for p in (allowed_roots or [self.allowed_root])],
            "max_cmd_seconds": 5,
            "max_output_bytes": 1024 * 1024,
            "logging": False,
        }
        self.policy_file.write_text(json.dumps(policy), encoding="utf-8")

    def run_dispatch(self, command: str, *, commands=None, allowed_roots=None) -> subprocess.CompletedProcess:
        self.write_policy(commands=commands, allowed_roots=allowed_roots)
        env = os.environ.copy()
        env["AGENT_RO_POLICY_FILE"] = str(self.policy_file)
        env["SSH_ORIGINAL_COMMAND"] = command
        env["USER"] = "agent_ro"
        return subprocess.run(
            ["python3", str(DISPATCHER)],
            cwd=str(REPO_ROOT),
            capture_output=True,
            text=True,
            env=env,
            check=False,
        )

    def test_cat_allowed_path(self) -> None:
        result = self.run_dispatch(f"cat {self.sample_file}")
        self.assertEqual(result.returncode, 0)
        self.assertIn("hello", result.stdout)

    def test_cat_denied_outside_allowed_root(self) -> None:
        result = self.run_dispatch("cat /etc/passwd")
        self.assertEqual(result.returncode, 126)
        self.assertIn("DENY: path outside allowed roots", result.stderr)

    def test_ls_without_path_defaults_to_first_allowed_root(self) -> None:
        marker = self.allowed_root / "ls-default-marker.txt"
        marker.write_text("marker\n", encoding="utf-8")
        result = self.run_dispatch("ls")
        self.assertEqual(result.returncode, 0)
        self.assertIn("ls-default-marker.txt", result.stdout)

    def test_grep_non_recursive_is_denied(self) -> None:
        result = self.run_dispatch(f"grep hello {self.allowed_root}")
        self.assertEqual(result.returncode, 126)
        self.assertIn("DENY: grep allowed only with recursive options", result.stderr)

    def test_grep_short_recursive_is_allowed(self) -> None:
        result = self.run_dispatch(f"grep -R hello {self.allowed_root}")
        self.assertEqual(result.returncode, 0)
        self.assertIn("sample.txt:hello", result.stdout)

    def test_grep_long_recursive_is_allowed(self) -> None:
        result = self.run_dispatch(f"grep --recursive hello {self.allowed_root}")
        self.assertEqual(result.returncode, 0)
        self.assertIn("sample.txt:hello", result.stdout)

    def test_grep_directories_recurse_is_allowed(self) -> None:
        result = self.run_dispatch(f"grep --directories recurse hello {self.allowed_root}")
        self.assertEqual(result.returncode, 0)
        self.assertIn("sample.txt:hello", result.stdout)

    @unittest.skipIf(shutil.which("git") is None, "git not available")
    def test_git_status_is_denied_but_log_is_allowed(self) -> None:
        repo = self.allowed_root / "repo"
        repo.mkdir()

        git_env = os.environ.copy()
        git_env["GIT_CONFIG_GLOBAL"] = "/dev/null"
        subprocess.run(["git", "-C", str(repo), "init", "-q"], check=True, env=git_env)
        (repo / "README").write_text("x\n", encoding="utf-8")
        subprocess.run(["git", "-C", str(repo), "add", "README"], check=True, env=git_env)
        subprocess.run(
            [
                "git",
                "-C",
                str(repo),
                "-c",
                "user.name=Test",
                "-c",
                "user.email=test@example.com",
                "commit",
                "--no-gpg-sign",
                "-q",
                "-m",
                "init",
            ],
            check=True,
            env=git_env,
        )

        allowed = self.run_dispatch(f"git -C {repo} log --oneline -n 1", commands=["git"])
        denied = self.run_dispatch(f"git -C {repo} status", commands=["git"])

        self.assertEqual(allowed.returncode, 0)
        self.assertEqual(denied.returncode, 126)
        self.assertIn("DENY: only 'git log' and 'git show' are allowed", denied.stderr)


if __name__ == "__main__":
    unittest.main()

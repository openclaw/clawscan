#!/usr/bin/env python3
from __future__ import annotations

import argparse
import os
import runpy
import subprocess
import tempfile
import unittest
from pathlib import Path


SCRIPT = Path(__file__).resolve().parents[1] / "scripts" / "autoreview"


def load_helper() -> dict[str, object]:
    return runpy.run_path(str(SCRIPT), run_name="autoreview_under_test")


def git(repo: Path, *args: str) -> str:
    env = os.environ.copy()
    env.update(
        {
            "GIT_AUTHOR_NAME": "Autoreview Test",
            "GIT_AUTHOR_EMAIL": "autoreview@example.invalid",
            "GIT_COMMITTER_NAME": "Autoreview Test",
            "GIT_COMMITTER_EMAIL": "autoreview@example.invalid",
        }
    )
    result = subprocess.run(
        ["git", *args],
        cwd=repo,
        env=env,
        check=True,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    return result.stdout


def init_repo(tempdir: Path) -> Path:
    repo = tempdir / "repo"
    repo.mkdir()
    git(repo, "init", "-q")
    git(repo, "config", "user.name", "Autoreview Test")
    git(repo, "config", "user.email", "autoreview@example.invalid")
    return repo


class AutoreviewHardeningTests(unittest.TestCase):
    def setUp(self) -> None:
        self.helper = load_helper()

    def test_local_bundle_blocks_sensitive_untracked_file(self) -> None:
        with tempfile.TemporaryDirectory() as tempdir:
            repo = init_repo(Path(tempdir))
            (repo / ".env").write_text("placeholder=true\n", encoding="utf-8")

            with self.assertRaisesRegex(SystemExit, "untracked sensitive files"):
                self.helper["local_bundle"](repo)

    def test_local_bundle_omits_safe_untracked_binary_content(self) -> None:
        with tempfile.TemporaryDirectory() as tempdir:
            repo = init_repo(Path(tempdir))
            (repo / "image.bin").write_bytes(b"\x89PNG\r\n\0binary-content")

            bundle = self.helper["local_bundle"](repo)

            self.assertIn("## image.bin\n[binary file omitted]", bundle)

    def test_local_bundle_blocks_secret_like_staged_diff(self) -> None:
        with tempfile.TemporaryDirectory() as tempdir:
            repo = init_repo(Path(tempdir))
            path = repo / "tracked.txt"
            path.write_text("safe\n", encoding="utf-8")
            git(repo, "add", "tracked.txt")
            git(repo, "commit", "-q", "-m", "base")
            path.write_text("api_key=" + "x" * 24 + "\n", encoding="utf-8")
            git(repo, "add", "tracked.txt")

            with self.assertRaisesRegex(SystemExit, "secret-like content"):
                self.helper["local_bundle"](repo)

    def test_branch_bundle_rejects_unsafe_or_unknown_base_before_diff(self) -> None:
        with tempfile.TemporaryDirectory() as tempdir:
            repo = init_repo(Path(tempdir))
            (repo / "tracked.txt").write_text("base\n", encoding="utf-8")
            git(repo, "add", "tracked.txt")
            git(repo, "commit", "-q", "-m", "base")

            with self.assertRaisesRegex(SystemExit, "unsafe base ref"):
                self.helper["branch_bundle"](repo, "--help")
            with self.assertRaisesRegex(SystemExit, "unknown base ref"):
                self.helper["branch_bundle"](repo, "origin/main")

    def test_branch_bundle_blocks_sensitive_tracked_filename(self) -> None:
        with tempfile.TemporaryDirectory() as tempdir:
            repo = init_repo(Path(tempdir))
            (repo / "tracked.txt").write_text("base\n", encoding="utf-8")
            git(repo, "add", "tracked.txt")
            git(repo, "commit", "-q", "-m", "base")
            (repo / ".env").write_text("placeholder=true\n", encoding="utf-8")
            git(repo, "add", ".env")
            git(repo, "commit", "-q", "-m", "sensitive")

            with self.assertRaisesRegex(SystemExit, "sensitive tracked files"):
                self.helper["branch_bundle"](repo, "HEAD~1")

    def test_commit_bundle_blocks_secret_like_diff(self) -> None:
        with tempfile.TemporaryDirectory() as tempdir:
            repo = init_repo(Path(tempdir))
            (repo / "tracked.txt").write_text("token=" + "x" * 24 + "\n", encoding="utf-8")
            git(repo, "add", "tracked.txt")
            git(repo, "commit", "-q", "-m", "secret")

            with self.assertRaisesRegex(SystemExit, "secret-like content"):
                self.helper["commit_bundle"](repo, "HEAD")

    def test_git_path_list_preserves_newline_filenames(self) -> None:
        with tempfile.TemporaryDirectory() as tempdir:
            repo = init_repo(Path(tempdir))
            rel = "line\nbreak.txt"
            (repo / rel).write_text("content\n", encoding="utf-8")
            git(repo, "add", rel)

            paths = self.helper["git_path_list"](repo, "ls-files", "-z")

            self.assertIn(rel, paths)

    def test_bounded_rejects_large_bundle_component(self) -> None:
        with self.assertRaisesRegex(SystemExit, "review input exceeds 10 characters"):
            self.helper["bounded"]("x" * 25, 10)

    def test_build_prompt_hides_repo_path_and_bounds_the_final_prompt(self) -> None:
        with tempfile.TemporaryDirectory() as tempdir:
            repo = init_repo(Path(tempdir))

            prompt = self.helper["build_prompt"](repo, "local", None, "diff", "", "")

            self.assertNotIn(str(repo), prompt)
            self.assertIn("Repository: <repository-under-review>", prompt)
            with self.assertRaisesRegex(SystemExit, "review input exceeds 500000 characters"):
                self.helper["build_prompt"](repo, "local", None, "x" * 500_000, "", "")

    def test_read_text_rejects_oversized_input(self) -> None:
        with tempfile.TemporaryDirectory() as tempdir:
            path = Path(tempdir) / "large.txt"
            path.write_bytes(b"x" * 500_001)

            with self.assertRaisesRegex(SystemExit, "review input file exceeds 500000 bytes"):
                self.helper["read_text"](path)

    def test_evidence_file_must_be_repo_relative_and_not_symlinked(self) -> None:
        with tempfile.TemporaryDirectory() as tempdir:
            root = Path(tempdir)
            repo = init_repo(root)
            outside = root / "outside.md"
            outside.write_text("outside\n", encoding="utf-8")

            with self.assertRaisesRegex(SystemExit, "repo-relative"):
                self.helper["validate_evidence_file"](repo, str(outside), "--prompt-file")

            target = repo / "notes.md"
            target.write_text("notes\n", encoding="utf-8")
            link = repo / "link.md"
            link.symlink_to(target)
            with self.assertRaisesRegex(SystemExit, "symlinked"):
                self.helper["validate_evidence_file"](repo, "link.md", "--dataset")

    def test_safe_engine_env_strips_process_injection_variables(self) -> None:
        old = os.environ.copy()
        with tempfile.TemporaryDirectory() as tempdir:
            repo = init_repo(Path(tempdir))
            try:
                os.environ["GIT_DIR"] = "/tmp/unsafe-git-dir"
                os.environ["GIT_CONFIG_COUNT"] = "99"
                os.environ["DYLD_INSERT_LIBRARIES"] = "/tmp/unsafe.dylib"
                os.environ["NODE_OPTIONS"] = "--require=/tmp/unsafe.js"

                env = self.helper["safe_engine_env"](repo)

                self.assertNotEqual(env.get("GIT_DIR"), "/tmp/unsafe-git-dir")
                self.assertEqual(
                    env["GIT_CONFIG_COUNT"],
                    str(len(self.helper["ENGINE_GIT_CONFIG_OVERRIDES"])),
                )
                self.assertNotIn("DYLD_INSERT_LIBRARIES", env)
                self.assertNotIn("NODE_OPTIONS", env)
            finally:
                os.environ.clear()
                os.environ.update(old)

    def test_safe_engine_env_excludes_repo_local_path_entries(self) -> None:
        old_path = os.environ.get("PATH", "")
        with tempfile.TemporaryDirectory() as tempdir:
            repo = init_repo(Path(tempdir))
            os.environ["PATH"] = f"{repo}{os.pathsep}{old_path}"
            try:
                env = self.helper["safe_engine_env"](repo)
            finally:
                os.environ["PATH"] = old_path

            self.assertNotIn(str(repo.resolve()), env["PATH"].split(os.pathsep))

    def test_safe_engine_env_strips_ambient_credentials(self) -> None:
        old = os.environ.copy()
        with tempfile.TemporaryDirectory() as tempdir:
            repo = init_repo(Path(tempdir))
            try:
                os.environ.update(
                    {
                        "AWS_SHARED_CREDENTIALS_FILE": "/tmp/credentials",
                        "GH_TOKEN": "placeholder",
                        "NPM_CONFIG_USERCONFIG": "/tmp/npmrc",
                        "OPENAI_API_KEY": "placeholder",
                        "SSH_AUTH_SOCK": "/tmp/agent.sock",
                        "SUPERMEMORY_CC_API_KEY": "placeholder",
                        "AUTOREVIEW_SAFE_SETTING": "kept",
                    }
                )

                env = self.helper["safe_engine_env"](repo)

                for key in [
                    "AWS_SHARED_CREDENTIALS_FILE",
                    "GH_TOKEN",
                    "NPM_CONFIG_USERCONFIG",
                    "OPENAI_API_KEY",
                    "SSH_AUTH_SOCK",
                    "SUPERMEMORY_CC_API_KEY",
                ]:
                    self.assertNotIn(key, env)
                self.assertEqual(env["AUTOREVIEW_SAFE_SETTING"], "kept")
            finally:
                os.environ.clear()
                os.environ.update(old)

    def test_large_repo_relative_evidence_file_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as tempdir:
            repo = init_repo(Path(tempdir))
            evidence = repo / "evidence.txt"
            evidence.write_text("x" * 600_000, encoding="utf-8")

            with self.assertRaisesRegex(SystemExit, "file exceeds 500000 bytes"):
                self.helper["validate_evidence_file"](repo, "evidence.txt", "--dataset")

    def test_powershell_harness_invokes_python_implementation(self) -> None:
        wrapper = SCRIPT.with_name("test-review-harness.ps1").read_text(encoding="utf-8")
        self.assertIn("test-review-harness.py", wrapper)
        self.assertNotIn("Join-Path $PSScriptRoot 'test-review-harness'", wrapper)

    def test_parallel_tests_use_sanitized_path(self) -> None:
        captured: dict[str, object] = {}

        class FakeProcess:
            pass

        def fake_popen(command: object, **kwargs: object) -> FakeProcess:
            captured["command"] = command
            captured.update(kwargs)
            return FakeProcess()

        old_path = os.environ.get("PATH")
        old_popen = subprocess.Popen
        try:
            repo = Path("/tmp/reviewed-repo")
            os.environ["PATH"] = f"{repo}/node_modules/.bin{os.pathsep}/usr/bin"
            self.helper["start_parallel_tests"].__globals__["subprocess"].Popen = fake_popen

            proc, _started = self.helper["start_parallel_tests"]("pnpm test", repo, "default")

            self.assertIsInstance(proc, FakeProcess)
            env = captured["env"]
            assert isinstance(env, dict)
            self.assertNotIn(f"{repo}/node_modules/.bin", env["PATH"])
            self.assertIn("/usr/bin", env["PATH"])
            self.assertTrue(captured["shell"])
        finally:
            self.helper["start_parallel_tests"].__globals__["subprocess"].Popen = old_popen
            if old_path is None:
                os.environ.pop("PATH", None)
            else:
                os.environ["PATH"] = old_path

    def test_codex_disables_tools_and_uses_a_neutral_directory(self) -> None:
        captured: dict[str, object] = {}

        def fake_run_with_heartbeat(
            cmd: list[str],
            cwd: Path,
            **kwargs: object,
        ) -> subprocess.CompletedProcess[str]:
            captured["cmd"] = cmd
            captured["cwd"] = cwd
            captured["resolve_root"] = kwargs.get("resolve_root")
            captured["input_text"] = kwargs.get("input_text")
            output = (
                '{"findings":[],"overall_correctness":"patch is correct",'
                '"overall_explanation":"No issues found.","overall_confidence":0.9}'
            )
            output_path = Path(cmd[cmd.index("--output-last-message") + 1])
            output_path.write_text(output, encoding="utf-8")
            return subprocess.CompletedProcess(cmd, 0, output, "")

        self.helper["run_codex"].__globals__["run_with_heartbeat"] = fake_run_with_heartbeat
        self.helper["run_codex"].__globals__["resolve_command"] = (
            lambda command, repo: f"/resolved/{command}"
        )
        args = argparse.Namespace(
            codex_bin="codex",
            thinking="high",
            tools=True,
            model="gpt-5.5",
            web_search=True,
            stream_engine_output=False,
        )
        repo = Path("/repo")

        self.helper["run_codex"](args, repo, "prompt")

        cmd = captured["cmd"]
        cwd = captured["cwd"]
        assert isinstance(cmd, list)
        assert isinstance(cwd, Path)
        disabled = {cmd[index + 1] for index, value in enumerate(cmd) if value == "--disable"}
        self.assertEqual(disabled, set(self.helper["CODEX_DISABLED_TOOL_FEATURES"]))
        self.assertNotEqual(cwd, repo)
        self.assertEqual(cmd[cmd.index("-C") + 1], str(cwd))
        self.assertIn("--strict-config", cmd)
        self.assertIn("--skip-git-repo-check", cmd)
        self.assertNotIn("--search", cmd)
        self.assertEqual(captured["resolve_root"], repo)
        self.assertEqual(captured["input_text"], "prompt")

    def test_claude_disables_tools_and_uses_a_neutral_directory(self) -> None:
        captured: dict[str, object] = {}

        def fake_run_with_heartbeat(
            cmd: list[str],
            cwd: Path,
            **kwargs: object,
        ) -> subprocess.CompletedProcess[str]:
            captured["cmd"] = cmd
            captured["cwd"] = cwd
            captured["resolve_root"] = kwargs.get("resolve_root")
            return subprocess.CompletedProcess(cmd, 0, '{"findings":[]}', "")

        self.helper["run_claude"].__globals__["run_with_heartbeat"] = fake_run_with_heartbeat
        self.helper["run_claude"].__globals__["resolve_command"] = (
            lambda command, repo: f"/resolved/{command}"
        )
        self.helper["run_claude"].__globals__["ensure_claude_isolation_supported"] = (
            lambda args, repo: None
        )
        args = argparse.Namespace(
            claude_bin="claude",
            fallback_model=None,
            thinking="high",
            tools=True,
            model="claude-fable-5",
            web_search=True,
            stream_engine_output=False,
        )
        repo = Path("/repo")

        self.helper["run_claude"](args, repo, "prompt")

        cmd = captured["cmd"]
        cwd = captured["cwd"]
        assert isinstance(cmd, list)
        assert isinstance(cwd, Path)
        self.assertNotEqual(cwd, repo)
        self.assertEqual(cmd[cmd.index("--tools") + 1], "")
        self.assertNotIn("--allowedTools", cmd)
        self.assertEqual(captured["resolve_root"], repo)

    def test_engines_without_no_tool_mode_fail_closed(self) -> None:
        args = argparse.Namespace()
        for engine in ["run_copilot", "run_opencode"]:
            with self.assertRaisesRegex(SystemExit, "cannot enforce a no-tools read jail"):
                self.helper[engine](args, Path("/repo"), "prompt")

    def test_droid_runs_without_tools_from_a_neutral_directory(self) -> None:
        captured: dict[str, object] = {}

        def fake_run_with_heartbeat(
            cmd: list[str],
            cwd: Path,
            **kwargs: object,
        ) -> subprocess.CompletedProcess[str]:
            captured["cmd"] = cmd
            captured["cwd"] = cwd
            captured["resolve_root"] = kwargs.get("resolve_root")
            prompt_path = Path(cmd[cmd.index("-f") + 1])
            captured["prompt_path"] = prompt_path
            self.assertEqual(prompt_path.read_text(encoding="utf-8"), "prompt")
            return subprocess.CompletedProcess(cmd, 0, '{"findings":[]}', "")

        self.helper["run_droid"].__globals__["run_with_heartbeat"] = fake_run_with_heartbeat
        self.helper["run_droid"].__globals__["resolve_command"] = (
            lambda command, repo: f"/resolved/{command}"
        )
        args = argparse.Namespace(
            droid_bin="droid",
            thinking="high",
            tools=True,
            model="gpt-5.5",
            stream_engine_output=False,
        )
        repo = Path("/repo")

        self.helper["run_droid"](args, repo, "prompt")

        cmd = captured["cmd"]
        cwd = captured["cwd"]
        self.assertIsInstance(cmd, list)
        self.assertIsInstance(cwd, Path)
        assert isinstance(cmd, list)
        assert isinstance(cwd, Path)
        self.assertNotEqual(cwd, repo)
        self.assertEqual(cmd[cmd.index("--cwd") + 1], str(cwd))
        self.assertEqual(cmd[cmd.index("--disabled-tools") + 1], "*")
        self.assertEqual(captured["resolve_root"], repo)
        self.assertFalse(Path(captured["prompt_path"]).exists())


if __name__ == "__main__":
    unittest.main()

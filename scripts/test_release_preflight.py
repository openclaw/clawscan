import importlib.util
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

spec = importlib.util.spec_from_file_location("release", Path(__file__).with_name("release-preflight.py"))
release = importlib.util.module_from_spec(spec)
spec.loader.exec_module(release)


class ReleasePreflightTests(unittest.TestCase):
    def test_notes_require_unique_dated_nonempty_section(self):
        for text in [
            "## 1.2.3 - Unreleased\n- Fix",
            "## 1.2.3 - 2026-10-12\n",
            "## 1.2.3 - 2026-10-12\n- Fix\n## 1.2.3 - 2026-10-12\n- Duplicate",
        ]:
            with self.subTest(text=text), self.assertRaises(ValueError):
                release.notes_for(text, "1.2.3")

    def test_dry_run_writes_dated_notes_only_after_green_push_ci(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.addCleanup(os.chdir, os.getcwd())
        os.chdir(directory.name)
        Path("CHANGELOG.md").write_text(
            "## Unreleased\n\n- Upcoming\n\n## [1.2.3] - 2026-10-12\n\n- Fix\n\n## 1.2.2 - 2026-10-11\n- Old\n"
        )
        env = {key: os.environ[key] for key in ("PATH", "HOME", "SYSTEMROOT", "USERPROFILE") if key in os.environ}
        env.update({
            "GIT_CONFIG_NOSYSTEM": "1",
            "GIT_CONFIG_GLOBAL": os.devnull,
            "DRY_RUN": "true",
            "GITHUB_REPOSITORY": "owner/repo",
            "GITHUB_REF": "refs/heads/main",
            "CI_WORKFLOWS": "ci.yml",
            "GITHUB_OUTPUT": "outputs",
        })
        with patch.dict(os.environ, env, clear=True):
            release.git("init", "--quiet", "--template=", "-b", "main")
            release.git("add", "CHANGELOG.md")
            release.git(
                "-c", "user.name=Fixture", "-c", "user.email=fixture@example.test",
                "commit", "--quiet", "-m", "Add changelog",
            )
            head = release.git("rev-parse", "HEAD")
            release.git("update-ref", "refs/remotes/origin/main", head)

            run = {"head_sha": head, "event": "pull_request", "conclusion": "success"}
            responses = {
                "repos/owner/repo/branches/main": {"protected": True},
                "repos/owner/repo/actions/workflows/ci.yml/runs": {"workflow_runs": [run]},
            }
            with patch.object(release, "api", side_effect=lambda path: responses[path.partition("?")[0]]):
                with self.assertRaisesRegex(ValueError, "no green push"):
                    release.main()
                self.assertFalse(Path("release-notes.md").exists())
                self.assertFalse(Path("outputs").exists())

                run["event"] = "push"
                release.main()

        self.assertEqual(Path("release-notes.md").read_text(), "- Fix\n")
        self.assertEqual(
            Path("outputs").read_text().splitlines(),
            ["version=1.2.3", "tag=v1.2.3", f"sha={head}", "tag_object="],
        )


if __name__ == "__main__":
    unittest.main()

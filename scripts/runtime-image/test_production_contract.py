import json
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

import production_contract as contract


class ProductionContractTests(unittest.TestCase):
    def test_native_route_and_wrong_event_architecture_or_python(self):
        env = {
            "GITHUB_EVENT_NAME": "pull_request",
            "GITHUB_ACTIONS": "true",
            "RUNNER_OS": "Linux",
            "RUNNER_ARCH": "X64",
        }
        contract.native_route(env, "Linux", "x86_64", "3.12.16", "3.12.16")
        for name, value in [
            ("GITHUB_EVENT_NAME", "push"),
            ("GITHUB_EVENT_NAME", "workflow_dispatch"),
            ("RUNNER_ARCH", "ARM64"),
            ("GITHUB_ACTIONS", "false"),
        ]:
            with self.subTest(name=name, value=value), self.assertRaises(RuntimeError):
                contract.native_route(
                    {**env, name: value}, "Linux", "x86_64", "3.12.16", "3.12.16"
                )
        with self.assertRaises(RuntimeError):
            contract.native_route(env, "Linux", "aarch64", "3.12.16", "3.12.16")
        with self.assertRaises(RuntimeError):
            contract.native_route(env, "Linux", "x86_64", "3.12.14", "3.12.16")

    def test_clean_reviewed_source_and_changed_runtime_or_worktree(self):
        with tempfile.TemporaryDirectory() as directory:
            repo = Path(directory)

            def git(*args):
                return subprocess.check_output(
                    ["git", *args], cwd=repo, stderr=subprocess.DEVNULL
                )

            git("init", "-q")
            target = repo / "docker/clawscan-runtime/test.txt"
            target.parent.mkdir(parents=True)
            target.write_text("before\n")
            git("add", ".")
            commit = [
                "-c",
                "user.name=Fixture",
                "-c",
                "user.email=fixture@example.invalid",
                "commit",
                "-q",
                "-m",
                "fixture",
            ]
            git(*commit)
            parent = git("rev-parse", "HEAD").decode().strip()
            target.write_text("after\n")
            git("add", ".")
            git(*commit)
            expected = {
                "commit": git("rev-parse", "HEAD").decode().strip(),
                "parent": parent,
                "tree": git("rev-parse", "HEAD^{tree}").decode().strip(),
                "runtime_tree": git("rev-parse", "HEAD:docker/clawscan-runtime")
                .decode()
                .strip(),
                "diff_sha256": contract.digest(git("diff", "--binary", parent, "HEAD")),
                "files": {
                    "docker/clawscan-runtime/test.txt": contract.digest(
                        target.read_bytes()
                    )
                },
            }
            contract.source_binding(repo, repo, expected)
            for name in ["commit", "parent", "tree", "runtime_tree", "diff_sha256"]:
                with self.subTest(field=name), self.assertRaises(RuntimeError):
                    contract.source_binding(repo, repo, {**expected, name: "0" * 40})
            with tempfile.TemporaryDirectory() as other:
                current = Path(other) / "current"
                subprocess.run(
                    ["git", "clone", "-q", str(repo), str(current)], check=True
                )
                (current / "docker/clawscan-runtime/test.txt").write_text(
                    "future runtime\n"
                )
                subprocess.run(["git", "add", "."], cwd=current, check=True)
                subprocess.run(["git", *commit], cwd=current, check=True)
                with self.assertRaisesRegex(RuntimeError, "current runtime changed"):
                    contract.source_binding(repo, current, expected)
            target.write_text("modified after review\n")
            with self.assertRaises(RuntimeError):
                contract.source_binding(repo, repo, expected)

    def test_inventory_rejects_version_drift_extra_and_missing_packages(self):
        expected = {"example": "1.0"}
        contract.inventory_binding(dict(expected), expected)
        for actual in [{}, {"example": "2.0"}, {**expected, "extra": "1.0"}]:
            with self.subTest(actual=actual), self.assertRaises(RuntimeError):
                contract.inventory_binding(actual, expected)

    def test_aig_inventory_accounts_for_original_venv_seed(self):
        manifest = json.loads(
            Path(contract.__file__).with_name("production-contract.json").read_text()
        )
        expected = manifest["expected_packages"]["aig"]
        # Python 3.12.16 seeds this pip version before the original installer's
        # uv pip install commands add the locked scanner dependencies.
        actual = {**expected, "pip": "25.0.1"}
        contract.inventory_binding(actual, expected)
        missing_pip = {name: value for name, value in actual.items() if name != "pip"}
        for invalid in [
            missing_pip,
            {**actual, "pip": "25.0.2"},
            {**actual, "unreviewed-bootstrap-tool": "1.0"},
        ]:
            with self.subTest(actual=invalid), self.assertRaises(RuntimeError):
                contract.inventory_binding(invalid, expected)

    def test_offline_child_has_no_credentials_and_source_is_read_only(self):
        with patch.dict(
            "os.environ",
            {
                "OPENAI_API_KEY": "fixture-placeholder",
                "GITHUB_TOKEN": "fixture-placeholder",
            },
        ):
            env = contract.child_environment(Path("/fresh"))
        self.assertNotIn("OPENAI_API_KEY", env)
        self.assertNotIn("GITHUB_TOKEN", env)
        command = contract.offline_command(
            Path("/candidate"), Path("/fresh"), Path("/python")
        )
        self.assertIn("--unshare-all", command)
        self.assertNotIn("--share-net", command)
        index = command.index("/candidate")
        self.assertEqual(command[index - 1], "--ro-bind")
        self.assertNotIn(
            "/candidate",
            [command[i + 1] for i, value in enumerate(command) if value == "--bind"],
        )

    def test_production_snapshot_preserves_original_tests_and_package_counts(self):
        manifest = json.loads(
            Path(contract.__file__).with_name("production-contract.json").read_text()
        )
        self.assertEqual(len(manifest["expected_packages"]["skillspector"]), 77)
        self.assertEqual(len(manifest["expected_packages"]["aig"]), 26)
        self.assertEqual(manifest["expected_packages"]["aig"]["pip"], "25.0.1")
        self.assertEqual(len(manifest["tests"]), 7)
        self.assertEqual(
            manifest["tests"]["test_skillspector_javascript_ownership.py"],
            "3cd38754c6a7e76a5aefc8368eec8b4b0bbad2d97f433de3a9c2681b7f46583a",
        )
        self.assertEqual(
            manifest["tests"]["test_skillspector_javascript_validator_type_budget.py"],
            "dbb47fa8afb2b7d890d5b0558422b12ceb2d46b013080c167120ad1c5aea960a",
        )


if __name__ == "__main__":
    unittest.main()

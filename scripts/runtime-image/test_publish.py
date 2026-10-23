"""Offline command/registry stubs, not hosted image or publication proof."""

import copy
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch


SPEC = importlib.util.spec_from_file_location("runtime_publish", Path(__file__).with_name("publish.py"))
publish = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(publish)
SOURCE = "a" * 40
IMAGE = "ghcr.io/fixture/clawscan-runtime"


def encoded(value):
    return json.dumps(value, separators=(",", ":")).encode()


def content_digest(value):
    return "sha256:" + hashlib.sha256(encoded(value)).hexdigest()


class RegistryStub:
    def __init__(self):
        self.calls = []
        self.blobs = {}
        self.configs = {}
        self.proofs = []
        self.provenance = {"SLSA": {"buildType": "stub-only"}}
        self.live_source = SOURCE
        self.smoke_failure = False
        self.corrupt_raw = False
        self.drop_candidate = False
        self.after_push_corruption = False
        for arch in ("amd64", "arm64"):
            config = {"architecture": arch, "os": "linux", "config": {"Labels": {publish.REVISION: SOURCE}}}
            config_id = content_digest(config)
            manifest = {"schemaVersion": 2, "config": {"digest": config_id}, "layers": []}
            manifest_id = self.blob(manifest)
            attestation = {"schemaVersion": 2, "layers": [{"annotations": {"in-toto.io/predicate-type": "https://slsa.dev/provenance/v0.2"}}]}
            attestation_id = self.blob({**attestation, "fixture_arch": arch})
            index = {"schemaVersion": 2, "mediaType": "application/vnd.oci.image.index.v1+json", "manifests": [
                {"digest": manifest_id, "platform": {"os": "linux", "architecture": arch}},
                {"digest": attestation_id, "platform": {"os": "unknown", "architecture": "unknown"},
                 "annotations": {"vnd.docker.reference.type": "attestation-manifest", "vnd.docker.reference.digest": manifest_id}},
            ]}
            index_id = self.blob(index)
            self.configs[IMAGE + "@" + index_id] = config
            self.proofs.append({"source": SOURCE, "tree": "b" * 40, "runtime_tree": "c" * 40,
                                "run_id": "123", "run_attempt": "1", "arch": arch,
                                "hardware": {"amd64": "x86_64", "arm64": "aarch64"}[arch],
                                "build_digest": "sha256:" + "d" * 64, "loaded_image_id": config_id,
                                "smoke": "passed", "published_digest": index_id})
        self.loaded = {"Id": self.proofs[0]["loaded_image_id"], "Architecture": "amd64", "Os": "linux",
                       "Config": {"Labels": {publish.REVISION: SOURCE}}}

    def blob(self, value):
        result = content_digest(value)
        self.blobs[IMAGE + "@" + result] = value
        return result

    def command(self, *args):
        self.calls.append(list(args))
        if args[:2] == ("git", "rev-parse"):
            return {"HEAD": SOURCE, "HEAD^{tree}": "b" * 40, "HEAD:docker/clawscan-runtime": "c" * 40}[args[2]].encode()
        if args[:2] == ("git", "status"):
            return b""
        if args[:2] == ("docker", "info"):
            return b"x86_64\n"
        if args[:3] == ("docker", "image", "inspect"):
            return encoded([self.loaded])
        if args[:2] == ("docker", "run"):
            if self.smoke_failure:
                raise subprocess.CalledProcessError(1, args)
            return b"stub-only CLI smoke\n"
        if args[:2] == ("gh", "api"):
            return self.live_source.encode()
        if args[:4] == ("docker", "buildx", "imagetools", "inspect"):
            if args[4] == "--raw":
                return encoded(self.blobs[args[5]]) + (b" " if self.corrupt_raw else b"")
            if args[6] == "{{json .Image}}":
                return encoded(self.configs[args[4]])
            if args[6] == "{{json .Provenance}}":
                return encoded(self.provenance)
        if args[:4] == ("docker", "buildx", "imagetools", "create"):
            references = [value for value in args if value.startswith(IMAGE + "@")]
            candidate = {"schemaVersion": 2, "mediaType": "application/vnd.oci.image.index.v1+json",
                         "annotations": {publish.REVISION: SOURCE},
                         "manifests": [item for reference in references for item in self.blobs[reference]["manifests"]]}
            if self.drop_candidate:
                candidate["manifests"].pop()
            if "--dry-run" in args:
                return encoded(candidate)
            final_id = self.blob(candidate)
            Path(args[args.index("--metadata-file") + 1]).write_bytes(encoded({"containerimage.descriptor": {"digest": final_id}}))
            for index, value in enumerate(args):
                if value == "--tag":
                    self.blobs[args[index + 1]] = candidate if not self.after_push_corruption else {}
            return b""
        raise AssertionError(f"unexpected command in offline stub: {args}")

    def tag_writes(self):
        return [call for call in self.calls if "--tag" in call]


class PublicationTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.previous = Path.cwd()
        os.chdir(self.directory.name)
        self.addCleanup(os.chdir, self.previous)
        self.registry = RegistryStub()
        environment = {"GITHUB_SHA": SOURCE, "GITHUB_RUN_ID": "123", "GITHUB_RUN_ATTEMPT": "1",
                       "GITHUB_EVENT_NAME": "push", "GITHUB_REPOSITORY_OWNER": "fixture", "GITHUB_REPOSITORY": "fixture/repo",
                       "GITHUB_REF": "refs/heads/main", "GITHUB_STEP_SUMMARY": str(Path.cwd() / "summary"),
                       "BUILD_RESULT": "success", "EXPECTED_ARCH": "amd64", "BUILD_DIGEST": "sha256:" + "d" * 64,
                       "IMAGE_TAGS": IMAGE + ":main\n" + IMAGE + ":latest"}
        self.addCleanup(patch.stopall)
        patch.dict(os.environ, environment, clear=True).start()
        patch.object(publish, "command", side_effect=self.registry.command).start()
        patch.object(publish.platform, "system", return_value="Linux").start()
        patch.object(publish.platform, "machine", return_value="x86_64").start()
        self.write_proofs()

    def write_proofs(self):
        for proof in self.registry.proofs:
            publish.save(publish.ROOT / ("runtime-image-proof-linux-" + proof["arch"]) / "identity.json", proof)

    def assert_no_publication(self, expected=ValueError):
        with self.assertRaises(expected):
            publish.merge()
        self.assertEqual(self.registry.tag_writes(), [])

    def test_success_merges_exact_digests_and_retains_all_provenance(self):
        publish.merge()
        self.assertEqual(len(self.registry.tag_writes()), 1)
        call = self.registry.tag_writes()[0]
        references = [value for value in call if value.startswith(IMAGE + "@")]
        self.assertEqual(references, [IMAGE + "@" + proof["published_digest"] for proof in self.registry.proofs])
        self.assertEqual([call[index + 1] for index, value in enumerate(call) if value == "--tag"], [IMAGE + ":main", IMAGE + ":latest"])
        result = json.loads((publish.ROOT / "manifest.json").read_text())
        self.assertEqual(len(result["manifest"]["manifests"]), 4)
        self.assertEqual(result["source"], SOURCE)

    def test_failed_cancelled_skipped_or_unknown_platform_blocks_tags(self):
        for result in ("failure", "cancelled", "skipped", "", "unknown"):
            with self.subTest(result=result), patch.dict(os.environ, {"BUILD_RESULT": result}):
                self.assert_no_publication()

    def test_pr_and_untrusted_events_never_publish(self):
        for event in ("pull_request", "pull_request_target", "workflow_run"):
            with self.subTest(event=event), patch.dict(os.environ, {"GITHUB_EVENT_NAME": event}):
                self.assert_no_publication()
                with self.assertRaises(ValueError):
                    publish.published()
        self.assertEqual(self.registry.calls, [])

    def test_missing_malformed_and_duplicate_platform_proofs_block_tags(self):
        path = publish.ROOT / "runtime-image-proof-linux-arm64" / "identity.json"
        for contents in (None, "not-json", json.dumps(self.registry.proofs[0])):
            with self.subTest(contents=contents):
                self.write_proofs()
                if contents is None:
                    path.unlink()
                else:
                    path.write_text(contents)
                self.assert_no_publication()

    def test_wrong_source_tree_context_run_attempt_smoke_or_digest_blocks_tags(self):
        original = copy.deepcopy(self.registry.proofs)
        for key, value in (("source", "f" * 40), ("tree", "f" * 40), ("runtime_tree", "f" * 40),
                           ("run_id", "124"), ("run_attempt", "2"), ("smoke", "failed"), ("hardware", "emulated"),
                           ("published_digest", "sha256:bad"), ("loaded_image_id", "latest"),
                           ("build_digest", "")):
            with self.subTest(key=key):
                self.registry.proofs = copy.deepcopy(original)
                self.registry.proofs[1][key] = value
                self.write_proofs()
                self.assert_no_publication()

    def test_wrong_registry_platform_source_or_config_blocks_tags(self):
        reference = IMAGE + "@" + self.registry.proofs[0]["published_digest"]
        for change in ("arch", "source", "config"):
            with self.subTest(change=change):
                original = copy.deepcopy(self.registry.configs[reference])
                if change == "arch":
                    self.registry.configs[reference]["architecture"] = "arm64"
                elif change == "source":
                    self.registry.configs[reference]["config"]["Labels"][publish.REVISION] = "f" * 40
                else:
                    self.registry.proofs[0]["loaded_image_id"] = "sha256:" + "f" * 64
                    self.write_proofs()
                self.assert_no_publication()
                self.registry.configs[reference] = original

    def test_missing_or_wrong_architecture_descriptor_and_attestation_fail_closed(self):
        original = copy.deepcopy(self.registry.proofs)
        for change in ("arch", "missing", "subject"):
            with self.subTest(change=change):
                self.registry.proofs = copy.deepcopy(original)
                index = copy.deepcopy(self.registry.blobs[IMAGE + "@" + original[0]["published_digest"]])
                if change == "arch":
                    index["manifests"][0]["platform"]["architecture"] = "arm64"
                elif change == "missing":
                    index["manifests"].pop()
                else:
                    index["manifests"][1]["annotations"]["vnd.docker.reference.digest"] = "sha256:" + "f" * 64
                self.registry.proofs[0]["published_digest"] = self.registry.blob(index)
                self.write_proofs()
                self.assert_no_publication()

    def test_provenance_payload_required_not_just_descriptor(self):
        self.registry.provenance = None
        self.assert_no_publication()

    def test_digest_content_candidate_loss_and_stale_run_block_tags(self):
        self.registry.corrupt_raw = True
        self.assert_no_publication()
        self.registry.corrupt_raw = False
        self.registry.drop_candidate = True
        self.assert_no_publication()
        self.registry.drop_candidate = False
        self.registry.live_source = "f" * 40
        self.assert_no_publication()

    def test_foreign_or_missing_tags_block_publication(self):
        for tags in ("", "elsewhere/image:latest", IMAGE + ":main\n" + IMAGE + ":main", IMAGE + ":latest;oops"):
            with self.subTest(tags=tags), patch.dict(os.environ, {"IMAGE_TAGS": tags}):
                self.assert_no_publication()

    def test_postpublication_tag_readback_failure_is_not_success(self):
        self.registry.after_push_corruption = True
        with self.assertRaises(ValueError):
            publish.merge()
        self.assertFalse((publish.ROOT / "manifest.json").exists())

    def test_network_denied_smoke_uses_actual_installed_commands_and_config_id(self):
        publish.verify()
        call = next(call for call in self.registry.calls if call[:2] == ["docker", "run"])
        self.assertEqual(call, ["docker", "run", "--rm", "--network", "none", self.registry.loaded["Id"],
                                "/bin/sh", "-ec", "skillspector --help\naig-skill-scan --help\ncodex --version\n"])
        self.assertEqual(json.loads(publish.proof_path().read_text())["smoke"], "passed")

    def test_failed_smoke_or_wrong_loaded_identity_never_emits_proof(self):
        for change in ("smoke", "arch", "source", "digest"):
            with self.subTest(change=change):
                if change == "smoke":
                    self.registry.smoke_failure = True
                elif change == "arch":
                    self.registry.loaded["Architecture"] = "arm64"
                elif change == "source":
                    self.registry.loaded["Config"]["Labels"][publish.REVISION] = "f" * 40
                else:
                    self.registry.loaded["Id"] = "malformed"
                with self.assertRaises((ValueError, subprocess.CalledProcessError)):
                    publish.verify()
                self.assertFalse(publish.proof_path().exists())
                self.registry = RegistryStub()
                publish.command.side_effect = self.registry.command

    def test_native_hardware_is_not_inferred_from_image_architecture(self):
        with patch.object(publish.platform, "machine", return_value="aarch64"):
            with self.assertRaisesRegex(ValueError, "non-native runner"):
                publish.native()
        with patch.object(publish, "text", side_effect=lambda *args: "aarch64" if args[0] == "docker" else SOURCE), patch.object(publish, "identity"):
            with self.assertRaisesRegex(ValueError, "non-native Docker"):
                publish.native()

    def test_manual_and_semver_events_use_same_complete_manifest_gate(self):
        with patch.dict(os.environ, {"GITHUB_EVENT_NAME": "workflow_dispatch"}):
            publish.merge()
        with patch.dict(os.environ, {"GITHUB_REF": "refs/tags/v1.2.3", "IMAGE_TAGS": IMAGE + ":1.2.3\n" + IMAGE + ":1.2\n" + IMAGE + ":latest"}):
            publish.merge()
        self.assertEqual(len(self.registry.tag_writes()), 2)

    def test_real_script_entrypoint_executes_fail_closed_with_executable_stubs(self):
        patch.stopall()
        fixture = Path.cwd() / "bin"
        fixture.mkdir()
        responses = {}
        environment = {"GITHUB_SHA": SOURCE, "GITHUB_RUN_ID": "123", "GITHUB_RUN_ATTEMPT": "1",
                       "GITHUB_EVENT_NAME": "push", "GITHUB_REPOSITORY_OWNER": "fixture", "BUILD_RESULT": "success",
                       "GITHUB_REPOSITORY": "fixture/repo", "GITHUB_REF": "refs/heads/main",
                       "GITHUB_STEP_SUMMARY": str(Path.cwd() / "summary"), "IMAGE_TAGS": IMAGE + ":main\n" + IMAGE + ":latest"}
        self.registry.calls.clear()
        with patch.dict(os.environ, environment, clear=True), patch.object(publish, "command", side_effect=self.registry.command):
            publish.merge()
        for call in list(self.registry.calls):
            if call[:4] == ["docker", "buildx", "imagetools", "create"] and "--dry-run" not in call:
                continue
            responses[json.dumps(call)] = self.registry.command(*call).decode()
        metadata = (publish.ROOT / "create-metadata.json").read_text()
        (publish.ROOT / "manifest.json").unlink()
        (Path.cwd() / "responses.json").write_text(json.dumps(responses))
        stub = f'''#!{sys.executable}
import json, pathlib, sys
args = [pathlib.Path(sys.argv[0]).name, *sys.argv[1:]]
with open("stub-calls.jsonl", "a") as log:
    log.write(json.dumps(args) + "\\n")
if "--metadata-file" in args:
    pathlib.Path(args[args.index("--metadata-file") + 1]).write_text({metadata!r})
else:
    sys.stdout.write(json.loads(pathlib.Path("responses.json").read_text())[json.dumps(args)])
'''
        for name in ("docker", "git", "gh"):
            path = fixture / name
            path.write_text(stub)
            path.chmod(0o755)
        environment["PATH"] = str(fixture)
        script = str(Path(__file__).with_name("publish.py").resolve())
        result = subprocess.run([sys.executable, script, "merge"], env=environment, capture_output=True, text=True, timeout=30)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertTrue((publish.ROOT / "manifest.json").exists())
        calls = [json.loads(line) for line in Path("stub-calls.jsonl").read_text().splitlines()]
        self.assertEqual(sum("--tag" in call for call in calls), 1)
        (publish.ROOT / "manifest.json").unlink()
        Path("stub-calls.jsonl").unlink()
        environment["BUILD_RESULT"] = "failure"
        failed = subprocess.run([sys.executable, script, "merge"], env=environment, capture_output=True, text=True, timeout=30)
        self.assertNotEqual(failed.returncode, 0)
        self.assertFalse(Path("stub-calls.jsonl").exists())


if __name__ == "__main__":
    unittest.main()

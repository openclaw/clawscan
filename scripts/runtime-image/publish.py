"""Bind native runtime smoke evidence to digest-only exports and a complete index."""

import hashlib
import json
import os
from pathlib import Path
import platform
import re
import subprocess
import sys


ROOT = Path("runtime-image-proof")
REVISION = "org.opencontainers.image.revision"
SMOKE = "skillspector --help\naig-skill-scan --help\ncodex --version\n"


def require(condition, message):
    if not condition:
        raise ValueError(message)


def command(*args):
    return subprocess.check_output(args, timeout=120)


def text(*args):
    return command(*args).decode().strip()


def digest(value):
    require(isinstance(value, str) and re.fullmatch(r"sha256:[0-9a-f]{64}", value), "invalid digest")
    return value


def identity():
    source = text("git", "rev-parse", "HEAD")
    require(re.fullmatch(r"[0-9a-f]{40}", source) and source == os.environ["GITHUB_SHA"], "wrong source")
    require(not text("git", "status", "--porcelain", "--untracked-files=no"), "modified tracked source")
    return {
        "source": source,
        "tree": text("git", "rev-parse", "HEAD^{tree}"),
        "runtime_tree": text("git", "rev-parse", "HEAD:docker/clawscan-runtime"),
        "run_id": os.environ["GITHUB_RUN_ID"],
        "run_attempt": os.environ["GITHUB_RUN_ATTEMPT"],
    }


def image_name():
    return "ghcr.io/" + os.environ["GITHUB_REPOSITORY_OWNER"].lower() + "/clawscan-runtime"


def publication_allowed():
    require(os.environ["GITHUB_EVENT_NAME"] in {"push", "workflow_dispatch"}, "publication event forbidden")


def native():
    identity()
    arch = os.environ["EXPECTED_ARCH"]
    expected = {"amd64": "x86_64", "arm64": "aarch64"}[arch]
    require(platform.system() == "Linux" and platform.machine() == expected, "non-native runner")
    require(text("docker", "info", "--format", "{{.Architecture}}") == expected, "non-native Docker daemon")


def save(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2) + "\n")


def proof_path():
    return ROOT / "identity.json"


def checked_proof(path, current):
    proof = json.loads(path.read_text())
    require(all(proof.get(key) == value for key, value in current.items()), "proof source/run mismatch")
    require(proof.get("smoke") == "passed" and proof.get("arch") in {"amd64", "arm64"}, "unverified platform")
    require(proof.get("hardware") == {"amd64": "x86_64", "arm64": "aarch64"}[proof["arch"]], "wrong proof hardware")
    digest(proof["build_digest"])
    digest(proof["loaded_image_id"])
    return proof


def verify():
    native()
    current = identity()
    arch = os.environ["EXPECTED_ARCH"]
    loaded = json.loads(command("docker", "image", "inspect", "clawscan-runtime:ci"))[0]
    loaded_id = digest(loaded["Id"])
    require(loaded["Architecture"] == arch and loaded["Os"] == "linux", "wrong loaded architecture")
    require(loaded["Config"]["Labels"].get(REVISION) == current["source"], "wrong loaded revision")
    build_digest = digest(os.environ["BUILD_DIGEST"])
    smoke = command("docker", "run", "--rm", "--network", "none", loaded_id, "/bin/sh", "-ec", SMOKE)
    ROOT.mkdir(exist_ok=True)
    (ROOT / "cli-smoke.txt").write_bytes(smoke)
    print(smoke.decode(), end="")
    save(proof_path(), {**current, "arch": arch, "hardware": platform.machine(), "build_digest": build_digest,
                        "loaded_image_id": loaded_id, "smoke": "passed"})


def inspect_raw(reference, expected_digest=None):
    raw = command("docker", "buildx", "imagetools", "inspect", "--raw", reference)
    if expected_digest:
        require("sha256:" + hashlib.sha256(raw).hexdigest() == expected_digest, "registry digest mismatch")
    return json.loads(raw)


def platform_descriptors(index, arches):
    manifests = index["manifests"]
    images = [item for item in manifests if item.get("platform", {}).get("os") == "linux"]
    require(sorted(item["platform"]["architecture"] for item in images) == sorted(arches), "wrong manifest platforms")
    attestations = [item for item in manifests if item not in images]
    require(len(attestations) == len(images), "missing provenance descriptors")
    for item in manifests:
        digest(item["digest"])
    for image in images:
        matching = [item for item in attestations if item.get("annotations", {}).get("vnd.docker.reference.digest") == image["digest"]
                    and item.get("annotations", {}).get("vnd.docker.reference.type") == "attestation-manifest"
                    and item.get("platform") == {"architecture": "unknown", "os": "unknown"}]
        require(len(matching) == 1, "wrong attestation subject")
    return images


def registry_proof(proof):
    reference = image_name() + "@" + digest(proof["published_digest"])
    index = inspect_raw(reference, proof["published_digest"])
    image = platform_descriptors(index, [proof["arch"]])[0]
    manifest = inspect_raw(image_name() + "@" + image["digest"], image["digest"])
    require(manifest["config"]["digest"] == proof["loaded_image_id"], "published config differs from tested config")
    config = json.loads(command("docker", "buildx", "imagetools", "inspect", reference, "--format", "{{json .Image}}"))
    require(config["architecture"] == proof["arch"] and config["os"] == "linux", "wrong registry architecture")
    require(config["config"]["Labels"].get(REVISION) == proof["source"], "wrong registry revision")
    provenance = json.loads(command("docker", "buildx", "imagetools", "inspect", reference, "--format", "{{json .Provenance}}"))
    require(bool(provenance and provenance.get("SLSA")), "missing SLSA provenance")
    return index


def published():
    publication_allowed()
    proof = checked_proof(proof_path(), identity())
    require(proof["arch"] == os.environ["EXPECTED_ARCH"], "wrong proof architecture")
    proof["published_digest"] = digest(os.environ["PUBLISHED_DIGEST"])
    registry_proof(proof)
    save(proof_path(), proof)


def current_ref(source):
    reference = os.environ["GITHUB_REF"]
    require(reference.startswith(("refs/heads/", "refs/tags/v")), "unsupported publication ref")
    repo = os.environ["GITHUB_REPOSITORY"]
    resolved = text("gh", "api", f"repos/{repo}/commits/{reference}", "--jq", ".sha")
    require(resolved == source, "stale publication ref")


def merge():
    publication_allowed()
    require(os.environ.get("BUILD_RESULT") == "success", "native build fan-in failed")
    current = identity()
    paths = sorted(ROOT.glob("runtime-image-proof-linux-*/identity.json"))
    require(len(paths) == 2, "both platform proofs required")
    proofs = [checked_proof(path, current) for path in paths]
    require(sorted(proof["arch"] for proof in proofs) == ["amd64", "arm64"], "duplicate or missing architecture")
    indexes = [registry_proof(proof) for proof in proofs]
    tags = os.environ["IMAGE_TAGS"].splitlines()
    require(tags and len(tags) == len(set(tags)), "missing or duplicate tags")
    require(all(re.fullmatch(re.escape(image_name()) + r":[\w][\w.-]{0,127}", tag, re.ASCII) for tag in tags), "invalid image tags")
    references = [image_name() + "@" + proof["published_digest"] for proof in proofs]
    annotation = "index:" + REVISION + "=" + current["source"]
    base = ["docker", "buildx", "imagetools", "create", "--annotation", annotation]
    candidate = json.loads(command(*base, "--dry-run", *references))
    platform_descriptors(candidate, ["amd64", "arm64"])
    expected = sorted(item["digest"] for index in indexes for item in index["manifests"])
    require(sorted(item["digest"] for item in candidate["manifests"]) == expected, "merge lost image or provenance")
    current_ref(current["source"])
    metadata = ROOT / "create-metadata.json"
    tag_args = [value for tag in tags for value in ("--tag", tag)]
    command(*base, "--metadata-file", str(metadata), *tag_args, *references)
    final_digest = digest(json.loads(metadata.read_text())["containerimage.descriptor"]["digest"])
    final = inspect_raw(image_name() + "@" + final_digest, final_digest)
    require(final == candidate, "published index differs from validated index")
    for tag in tags:
        require(inspect_raw(tag, final_digest) == final, "tag does not resolve to complete index")
    result = {**current, "image": image_name(), "digest": final_digest, "tags": tags, "platforms": proofs,
              "manifest": final}
    save(ROOT / "manifest.json", result)
    with open(os.environ["GITHUB_STEP_SUMMARY"], "a") as summary:
        summary.write(f"Runtime `{image_name()}@{final_digest}`\n\nRevision `{current['source']}`\n")


if __name__ == "__main__":
    {"native": native, "verify": verify, "published": published, "merge": merge}[sys.argv[1]]()

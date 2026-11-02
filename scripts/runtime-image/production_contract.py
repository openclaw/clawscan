#!/usr/bin/env python3
"""Qualify an explicit scanner source snapshot with the host worker's locked SDKs."""

import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import shutil
import subprocess
import sys
import time
import urllib.request


def require(condition, message):
    if not condition:
        raise RuntimeError(message)


def digest(data):
    return hashlib.sha256(data).hexdigest()


def native_route(env, system, machine, version, expected_version):
    require(env.get("GITHUB_EVENT_NAME") == "pull_request", "PR-only qualification")
    require(env.get("GITHUB_ACTIONS") == "true", "native CI route required")
    require(env.get("RUNNER_OS") == "Linux" and system == "Linux", "Linux required")
    require(
        env.get("RUNNER_ARCH") == "X64" and machine == "x86_64", "native AMD64 required"
    )
    require(version == expected_version, "production Python version mismatch")


def git(repo, *args):
    env = {
        "PATH": "/usr/bin:/bin",
        "GIT_CONFIG_GLOBAL": "/dev/null",
        "GIT_CONFIG_NOSYSTEM": "1",
    }
    return subprocess.check_output(["/usr/bin/git", *args], cwd=repo, env=env)


def source_binding(candidate, current, expected):
    commit = expected["commit"]
    require(
        git(candidate, "rev-parse", "HEAD").decode().strip() == commit,
        "wrong candidate commit",
    )
    require(
        git(candidate, "show", "-s", "--format=%P", commit).decode().strip()
        == expected["parent"],
        "wrong candidate parent",
    )
    require(
        git(candidate, "rev-parse", "HEAD^{tree}").decode().strip() == expected["tree"],
        "wrong candidate tree",
    )
    require(
        git(candidate, "rev-parse", "HEAD:docker/clawscan-runtime").decode().strip()
        == expected["runtime_tree"],
        "wrong candidate runtime tree",
    )
    require(
        not git(candidate, "status", "--porcelain=v1", "--untracked-files=all"),
        "dirty candidate",
    )
    patch = git(
        candidate,
        "diff",
        "--binary",
        "--no-ext-diff",
        "--no-color",
        expected["parent"],
        commit,
    )
    require(digest(patch) == expected["diff_sha256"], "reviewed source diff mismatch")
    # CI helper changes may differ; the actual runtime inputs must be identical.
    require(
        git(current, "rev-parse", "HEAD:docker/clawscan-runtime").decode().strip()
        == expected["runtime_tree"],
        "current runtime changed; refresh reviewed source qualification",
    )
    require(
        not git(
            current,
            "status",
            "--porcelain=v1",
            "--untracked-files=all",
            "--",
            "docker/clawscan-runtime",
        ),
        "current runtime has uncommitted inputs",
    )
    for name, sha in expected["files"].items():
        require(
            digest((candidate / name).read_bytes()) == sha,
            "candidate file mismatch: " + name,
        )


def inventory_binding(actual, expected):
    require(
        actual == expected,
        "installed distributions differ from the observed production contract",
    )


def child_environment(output):
    paths = [str(Path(sys.executable).parent)]
    go = shutil.which("go")
    if go:
        paths.append(str(Path(go).parent))
    return {
        "PATH": ":".join(paths + ["/usr/bin", "/bin"]),
        "HOME": str(output / "home"),
        "RUNNER_TEMP": str(output / "runtime"),
        "GITHUB_PATH": str(output / "runtime/github-path"),
        "LANG": "C.UTF-8",
        "PYTHONDONTWRITEBYTECODE": "1",
        "PYTEST_DISABLE_PLUGIN_AUTOLOAD": "1",
        "LANGSMITH_TRACING": "false",
    }


def offline_command(candidate, output, interpreter_root):
    command = ["/usr/bin/bwrap", "--unshare-all", "--die-with-parent", "--new-session"]
    for path in [
        "/usr",
        "/lib",
        "/lib64",
        "/etc/ld.so.cache",
        str(interpreter_root),
        str(candidate),
        str(output),
    ]:
        command += ["--ro-bind", path, path]
    command += [
        "--symlink",
        "usr/bin",
        "/bin",
        "--proc",
        "/proc",
        "--dev",
        "/dev",
        "--tmpfs",
        "/tmp",
    ]
    for name in ["home", "tmp", "work", "outputs"]:
        path = str(output / name)
        command += ["--bind", path, path]
    return command + ["--chdir", str(output / "work"), "--"]


def fetch_worker(worker, output):
    names = {
        "install-clawscan-scanners.sh",
        "clawscan-source-commit.txt",
        "skillspector-pydantic-requirements.txt",
        "aig-worker-requirements.txt",
        "test_skillspector_serialization.py",
    }
    require(
        set(worker["files"]) == {"scripts/security/" + name for name in names},
        "unexpected worker source scope",
    )
    require(
        worker["repository"] == "openclaw/clawhub"
        and re.fullmatch("[0-9a-f]{40}", worker["commit"]),
        "unbound worker repository",
    )
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    original = output / "worker-original"
    for path, sha in worker["files"].items():
        url = f"https://raw.githubusercontent.com/openclaw/clawhub/{worker['commit']}/{path}"
        with opener.open(url, timeout=30) as response:
            body = response.read()
        require(digest(body) == sha, "original worker source hash mismatch: " + path)
        target = original / path
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(body)
    return original


def qualify(candidate, current, output, manifest):
    native_route(
        os.environ,
        platform.system(),
        platform.machine(),
        platform.python_version(),
        manifest["python"],
    )
    source_binding(candidate, current, manifest["source"])
    require(Path("/usr/bin/bwrap").is_file(), "bubblewrap required; no offline bypass")
    output.mkdir(mode=0o700, parents=True, exist_ok=False)
    for name in ["runtime", "home", "outputs", "tmp", "work"]:
        (output / name).mkdir()
    (output / "inputs.json").write_text(json.dumps(manifest, indent=2) + "\n")
    receipts = []

    def run(name, command, env, timeout=None):
        start = time.monotonic()
        try:
            result = subprocess.run(
                command, env=env, text=True, capture_output=True, timeout=timeout
            )
            row = {
                "name": name,
                "exit": result.returncode,
                "stdout": result.stdout,
                "stderr": result.stderr,
            }
        except subprocess.TimeoutExpired as error:

            def decode(value):
                return (
                    value.decode(errors="replace")
                    if isinstance(value, bytes)
                    else (value or "")
                )

            row = {
                "name": name,
                "exit": None,
                "timed_out": True,
                "stdout": decode(error.stdout),
                "stderr": decode(error.stderr),
            }
        row["seconds"] = time.monotonic() - start
        (output / "outputs" / (name + ".json")).write_text(
            json.dumps(row, indent=2) + "\n"
        )
        receipts.append({key: row[key] for key in ["name", "exit", "seconds"]})
        require(
            row["exit"] == 0,
            name + " failed; preserve failures and unchanged deadlines",
        )
        return row["stdout"]

    original = fetch_worker(manifest["worker"], output)
    worker = output / "worker-config"
    shutil.copytree(original, worker)
    pin = worker / "scripts/security/clawscan-source-commit.txt"
    require(
        pin.read_text().strip() == manifest["worker"]["original_clawscan_pin"],
        "original worker pin mismatch",
    )
    # Only this fresh prospective copy changes; retained original files stay exact.
    pin.write_text(manifest["source"]["commit"] + "\n")
    env = child_environment(output)
    env["CLAWSCAN_SOURCE_DIR"] = str(candidate)
    installer = str(worker / "scripts/security/install-clawscan-scanners.sh")
    for scanner in ["skillspector", "aig"]:
        run("install-" + scanner, ["/bin/sh", installer, scanner], env)
    interpreters = {
        "skillspector": (output / "runtime/clawscan-scanner-bin/skillspector")
        .resolve()
        .parent
        / "python",
        "aig": output / "runtime/aig-venv/bin/python",
    }
    for scanner, python in interpreters.items():
        code = "import importlib.metadata as m,json,re;print(json.dumps({re.sub(r'[-_.]+','-',d.metadata['Name']).lower():d.version for d in m.distributions()}))"
        actual = json.loads(
            run("inventory-" + scanner, [str(python), "-B", "-c", code], env)
        )
        inventory_binding(actual, manifest["expected_packages"][scanner])
    prefix = offline_command(candidate, output, Path(sys.base_prefix).resolve())
    python = str(interpreters["skillspector"])
    env["PATH"] = (
        str(output / "runtime/clawscan-scanner-bin")
        + ":"
        + str(Path(python).parent)
        + ":/usr/bin:/bin"
    )
    env["TMPDIR"] = str(output / "tmp")
    parent_network = os.readlink("/proc/self/ns/net")
    control = (
        "import os,socket; assert os.readlink('/proc/self/ns/net') != "
        + repr(parent_network)
        + "; s=socket.socket(); s.settimeout(1); assert s.connect_ex(('198.51.100.1',443)) != 0; print('isolated network namespace; connection denied')"
    )
    run("offline-routing-control", prefix + [python, "-B", "-c", control], env, 10)
    tests = candidate / "docker/clawscan-runtime/tests"
    for name, sha in manifest["tests"].items():
        require(
            digest((tests / name).read_bytes()) == sha, "original test bytes changed"
        )
        deadline = 35 if "type_budget" in name else 150
        run(
            name.removesuffix(".py"),
            prefix
            + [
                python,
                "-B",
                "-m",
                "pytest",
                "-q",
                "-p",
                "no:cacheprovider",
                "--durations=0",
                str(tests / name),
            ],
            env,
            deadline,
        )
    source_binding(candidate, current, manifest["source"])
    result = {
        "status": "inert-production-contract-passed",
        "tested_source": manifest["source"],
        "worker_source": manifest["worker"],
        "current_runtime_inputs_equal_tested_source": True,
        "runtime_ready": False,
        "original_package_acceptance": False,
        "model_calls": 0,
        "offline_tests": True,
        "receipts": receipts,
    }
    (output / "result.json").write_text(json.dumps(result, indent=2) + "\n")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--candidate", type=Path, required=True)
    parser.add_argument("--current", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    manifest = json.loads(
        Path(__file__).with_name("production-contract.json").read_text()
    )
    qualify(
        args.candidate.resolve(),
        args.current.resolve(),
        args.output.resolve(),
        manifest,
    )


if __name__ == "__main__":
    main()

#!/usr/bin/env python3
"""Execute two ClawScan binaries against secretless subprocess probes.

This verifies CLI/profile/environment upgrade behavior, not provider inference
or scanner verdict quality. No caller credentials or provider CLIs are inherited.
Build the previous binary from v0.2.0 and the candidate from the worktree, then:
  python3 scripts/verify-model-policy-upgrade.py --previous /path/old \
    --candidate /path/new --output /outside/repo/upgrade.json
"""

import argparse
import hashlib
import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path

CONTROLS = (
    "SKILLSPECTOR_PROVIDER",
    "SKILLSPECTOR_MODEL",
    "SKILLSPECTOR_REASONING_EFFORT",
    "DEFAULT_MODEL",
    "REASONING_EFFORT",
    "DEFAULT_BASE_URL",
)
PROBE = r"""
import hashlib, json, os, sys
from pathlib import Path
name = Path(sys.argv[0]).name
args = sys.argv[1:]
controls = {key: os.environ[key] for key in CONTROLS if key in os.environ}
record = {"probe": name, "controls": controls}
if name == "codex":
    # Record only model/config controls, never arbitrary command arguments.
    record["model"] = args[args.index("--model") + 1]
    record["config"] = [args[i+1] for i, v in enumerate(args) if v == "-c"]
    record["ignoreUserConfig"] = "--ignore-user-config" in args
    result = {"verdict":"benign", "probe":True}
    challenge = Path("artifact-inspection.json")
    if challenge.exists():
        data = json.loads(challenge.read_text())
        file = Path(data["required_file"])
        result["artifact_inspection"] = {
            "status":"completed", "challenge":data["challenge"],
            "required_file_sha256":hashlib.sha256(file.read_bytes()).hexdigest(),
            "files_inspected":[str(file)],
        }
    if "--output-last-message" in args:
        Path(args[args.index("--output-last-message")+1]).write_text(json.dumps(result))
    else:
        print(json.dumps(result))
elif name == "skillspector":
    Path(args[args.index("--output")+1]).write_text(json.dumps({"probe":True, "controls":controls}))
else:
    Path(args[args.index("-o")+1]).write_text(json.dumps({"version":"2.1.0", "runs":[]}))
with open(os.environ["PROBE_TRACE"], "a") as stream:
    stream.write(json.dumps(record)+"\n")
"""


def require(condition, message):
    if not condition:
        raise RuntimeError(message)


def binary_info(path):
    path = Path(path).resolve(strict=True)
    require(path.is_file() and os.access(path, os.X_OK), "binary must be executable")
    return path, {"sha256": hashlib.sha256(path.read_bytes()).hexdigest()}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--previous", required=True)
    parser.add_argument("--candidate", required=True)
    parser.add_argument("--output", required=True)
    options = parser.parse_args()
    previous, previous_info = binary_info(options.previous)
    candidate, candidate_info = binary_info(options.candidate)
    report = {
        "kind": "clawscan-model-policy-upgrade-v1",
        "previous": previous_info,
        "candidate": candidate_info,
        "execution": "real CLI binaries with synthetic subprocess probes; no provider calls",
        "cases": [],
    }
    with tempfile.TemporaryDirectory(prefix="clawscan-model-upgrade-") as directory:
        root = Path(directory)
        probes = root / "bin"
        probes.mkdir()
        code = "#!" + sys.executable + "\nCONTROLS=" + repr(CONTROLS) + "\n" + PROBE
        for name in ("skillspector", "aig-skill-scan", "codex"):
            path = probes / name
            path.write_text(code)
            path.chmod(0o700)
        target = root / "skill"
        target.mkdir()
        (target / "SKILL.md").write_text("# Harmless synthetic upgrade fixture\n")
        home = root / "home"
        home.mkdir()
        base_env = {
            "PATH": str(probes),
            "HOME": str(home),
            "OPENAI_API_KEY": "synthetic-not-a-credential",
            "TMPDIR": str(root),
        }

        def run(binary, label, args, controls=None, config=None):
            work = root / label
            work.mkdir()
            if config:
                (work / ".clawscan.yml").write_text(config)
            trace = work / "trace.jsonl"
            env = dict(base_env, PROBE_TRACE=str(trace))
            env.update(controls or {})
            result = subprocess.run(
                [str(binary), str(target), "--sandbox", "off", "--json", *args],
                cwd=work,
                env=env,
                text=True,
                capture_output=True,
                timeout=60,
                check=False,
            )
            require(result.returncode == 0, label + ": CLI failed: " + result.stderr)
            artifact = json.loads(result.stdout)
            for scanner, value in artifact["scanners"].items():
                require(
                    value["status"] == "completed",
                    label + ": scanner failed: " + scanner,
                )
            if artifact.get("judge") is not None:
                require(
                    artifact["judge"]["status"] == "completed", label + ": judge failed"
                )
            observed = [json.loads(line) for line in trace.read_text().splitlines()]
            report["cases"].append(
                {
                    "case": label,
                    "observed": observed,
                    "scanners": sorted(artifact["scanners"]),
                    "judgeConfiguredModel": (artifact.get("judge") or {}).get(
                        "configuredModel"
                    ),
                }
            )
            return {row["probe"]: row for row in observed}

        old = run(previous, "previous-bundled", ["--profile", "clawhub"])
        new = run(candidate, "candidate-bundled", ["--profile", "clawhub"])
        require(
            old["codex"]["model"] == "gpt-5.5"
            and "service_tier=fast" in old["codex"]["config"],
            "unexpected v0.2.0 baseline judge",
        )
        require(
            "SKILLSPECTOR_MODEL" not in old["skillspector"]["controls"],
            "unexpected v0.2.0 scanner default",
        )
        require(
            old["aig-skill-scan"]["controls"]["DEFAULT_MODEL"] == "gpt-5.5",
            "unexpected v0.2.0 AIG default",
        )
        require(
            new["codex"]["model"] == "gpt-6.1-sol"
            and 'service_tier="default"' in new["codex"]["config"],
            "candidate judge must explicitly request Standard Sol",
        )
        require(new["codex"]["ignoreUserConfig"], "candidate must ignore user config")
        require(
            new["skillspector"]["controls"]["SKILLSPECTOR_MODEL"] == "gpt-6.1-sol",
            "candidate scanner default missing",
        )
        require(
            new["skillspector"]["controls"]["SKILLSPECTOR_REASONING_EFFORT"]
            == "medium",
            "candidate effort missing",
        )
        require(
            new["aig-skill-scan"]["controls"]["DEFAULT_MODEL"] == "gpt-6.1-sol",
            "candidate AIG default missing",
        )

        aig_profile = run(
            candidate, "candidate-clawhub-aig", ["--profile", "clawhub-aig"]
        )
        require(aig_profile["codex"] == new["codex"], "bundled judges differ")

        override = {
            "SKILLSPECTOR_PROVIDER": "anthropic",
            "SKILLSPECTOR_MODEL": "operator-model",
            "SKILLSPECTOR_REASONING_EFFORT": "high",
            "DEFAULT_MODEL": "operator-aig",
            "REASONING_EFFORT": "low",
            "DEFAULT_BASE_URL": "https://provider.example/v1",
        }
        judge = "codex exec --model gpt-6-luna -c model_reasoning_effort=low -c 'service_tier=\"priority\"'"
        for binary, label in ((previous, "previous"), (candidate, "candidate")):
            observed = run(
                binary,
                label + "-overrides",
                ["--profile", "clawhub", "--judge", judge],
                override,
            )
            require(
                observed["skillspector"]["controls"] == override,
                label + ": operator controls changed",
            )
            require(
                observed["codex"]["model"] == "gpt-6-luna"
                and observed["codex"]["config"]
                == ["model_reasoning_effort=low", 'service_tier="priority"'],
                label + ": explicit judge changed",
            )
            shadow = "version: 1\nprofiles:\n  clawhub:\n    scanners: [skillspector]\n"
            observed = run(
                binary,
                label + "-project-shadow",
                ["--profile", "clawhub", "--discover-config"],
                config=shadow,
            )
            require(
                set(observed) == {"skillspector"}
                and "SKILLSPECTOR_MODEL" not in observed["skillspector"]["controls"],
                label + ": project shadow was merged with bundled defaults",
            )

        custom = "version: 1\nprofiles:\n  review:\n    scanners: [skillspector]\n    scannerEnvDefaults:\n      SKILLSPECTOR_MODEL: gpt-6.1-sol\n      SKILLSPECTOR_REASONING_EFFORT: medium\n"
        observed = run(
            candidate,
            "candidate-inferred-provider",
            ["--profile", "review", "--config", ".clawscan.yml"],
            config=custom,
        )
        require(
            observed["skillspector"]["controls"]
            == {
                "SKILLSPECTOR_PROVIDER": "openai",
                "SKILLSPECTOR_MODEL": "gpt-6.1-sol",
                "SKILLSPECTOR_REASONING_EFFORT": "medium",
            },
            "inferred provider skipped profile defaults",
        )
        observed = run(
            candidate,
            "candidate-custom-other-provider",
            ["--profile", "review", "--config", ".clawscan.yml"],
            {"SKILLSPECTOR_PROVIDER": "anthropic"},
            config=custom,
        )
        require(
            observed["skillspector"]["controls"]
            == {"SKILLSPECTOR_PROVIDER": "anthropic"},
            "other provider inherited OpenAI defaults",
        )
    output = Path(options.output)
    output.write_text(json.dumps(report, indent=2) + "\n")
    print(
        "PASS: "
        + str(len(report["cases"]))
        + " executed upgrade cases; secretless trace: "
        + str(output)
    )


if __name__ == "__main__":
    main()

"""Offline tests for clawscan-decisions-judge with a local Decisions API stub."""

import importlib.util
import io
import json
import os
from pathlib import Path
import tempfile
import threading
import unittest
from contextlib import redirect_stderr
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

JUDGE_PATH = Path(
    os.environ.get(
        "CLAWSCAN_DECISIONS_JUDGE",
        Path(__file__).resolve().parents[1] / "judges" / "clawscan_decisions_judge.py",
    )
)
spec = importlib.util.spec_from_file_location("clawscan_decisions_judge", JUDGE_PATH)
judge = importlib.util.module_from_spec(spec)
spec.loader.exec_module(judge)

# The ClawHub output schema lives with the profile; the runtime image build only
# has this directory, so schema checks run where the repository is available.
_parents = Path(__file__).resolve().parents
SCHEMA_PATH = _parents[3] / "internal" / "profiles" / "clawhub" / "output.schema.json" if len(_parents) > 3 else None
if SCHEMA_PATH is not None and not SCHEMA_PATH.is_file():
    SCHEMA_PATH = None


class DecisionsStub:
    def __init__(self):
        self.requests = []
        self.headers = []
        self.responses = []
        self.verdict = "benign"
        self.refuse = None
        stub = self

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *args):
                pass

            def do_POST(self):
                body = self.rfile.read(int(self.headers["Content-Length"]))
                request = json.loads(body)
                stub.requests.append({"path": self.path, "body": request})
                stub.headers.append({"Authorization": self.headers.get("Authorization")})
                if stub.responses:
                    status, payload, headers = stub.responses.pop(0)
                    self.send_response(status)
                    for key, value in headers.items():
                        self.send_header(key, value)
                    self.end_headers()
                    self.wfile.write(payload.encode())
                    return
                answers = []
                for question in request["questions"]:
                    if question["name"] == stub.refuse:
                        answers.append({"type": "refusal", "name": question["name"]})
                    elif question["type"] == "choice":
                        value = stub.verdict if question["name"] == "verdict" else question["choices"][0]["value"]
                        answers.append(
                            {
                                "type": "choice",
                                "name": question["name"],
                                "choice": value,
                                "probabilities": [
                                    {"value": choice["value"], "probability": 1.0 if choice["value"] == value else 0.0}
                                    for choice in question["choices"]
                                ],
                                "confidence": 0.9,
                            }
                        )
                    else:
                        answers.append({"type": "predicate", "name": question["name"], "probability": 0.75})
                payload = json.dumps({"model": "gpt-6-luna", "answers": answers, "usage": {"input_tokens": 10}})
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.end_headers()
                self.wfile.write(payload.encode())

        self.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        self.url = f"http://127.0.0.1:{self.server.server_address[1]}"

    def close(self):
        self.server.shutdown()
        self.server.server_close()


def make_workspace(root, skill="# Notes\nWrite notes locally.\n", scanners=None, extra_files=None):
    workspace = Path(root) / "workspace"
    (workspace / "artifact").mkdir(parents=True)
    (workspace / "scanners").mkdir()
    (workspace / "artifact" / "SKILL.md").write_text(skill)
    for name, content in (extra_files or {}).items():
        path = workspace / "artifact" / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(content if isinstance(content, bytes) else content.encode())
    scanners = scanners or {
        "skillspector": {
            "execution_successful": True,
            "risk_assessment": {"severity": "LOW", "recommendation": "SAFE"},
            "issues": [{"id": "SSD-1", "severity": "LOW", "file": "SKILL.md", "explanation": "Writes a local file"}],
        },
        "aig": {
            "version": "2.1.0",
            "runs": [
                {
                    "tool": {"driver": {"name": "A.I.G"}},
                    "results": [
                        {
                            "ruleId": "aig.network",
                            "level": "error",
                            "message": {"text": "Sends data to a remote host"},
                            "locations": [{"physicalLocation": {"artifactLocation": {"uri": "run.sh"}, "region": {"startLine": 3}}}],
                        }
                    ],
                }
            ],
        },
    }
    for name, raw in scanners.items():
        (workspace / "scanners" / f"{name}.json").write_text(json.dumps(raw))
    (workspace / "metadata.json").write_text(
        json.dumps(
            {
                "schemaVersion": "clawscan-v1",
                "target": {"kind": "skill", "input": "./skill", "resolvedPath": "/private/host/path"},
                "scanners": {name: {"status": "completed"} for name in scanners},
                "context": {"source": "publish", "injectionSignals": ["ignore-previous"]},
            }
        )
    )
    return workspace


class DecisionsJudgeTest(unittest.TestCase):
    def setUp(self):
        self.stub = DecisionsStub()
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.addCleanup(self.stub.close)
        self.env = {"DECISIONS_API_KEY": "fixture-key", "DECISIONS_BASE_URL": self.stub.url}

    def run_judge(self, workspace, *extra, env=None):
        output = Path(self.temp.name) / "out.json"
        stderr = io.StringIO()
        with redirect_stderr(stderr):
            schema = ["--output-schema", str(SCHEMA_PATH)] if SCHEMA_PATH else []
            code = judge.main(
                ["--workspace", str(workspace), "--output", str(output), *schema, *extra],
                env if env is not None else self.env,
            )
        result = json.loads(output.read_text()) if output.exists() else None
        return code, result, stderr.getvalue()

    def test_request_shape_and_verdict_mapping(self):
        workspace = make_workspace(self.temp.name, extra_files={"run.sh": "#!/bin/sh\ncurl https://example.com\n", "logo.png": b"\x89PNG\x00\x00"})
        instructions = Path(self.temp.name) / "policy.md"
        instructions.write_text("Policy text.")
        for verdict in ("benign", "suspicious", "malicious"):
            with self.subTest(verdict=verdict):
                self.stub.verdict = verdict
                code, result, stderr = self.run_judge(workspace, "--instructions", str(instructions))
                self.assertEqual(code, 0, stderr)
                self.assertEqual(result["verdict"], verdict)
                self.assertEqual(result["confidence"], "high")
                self.assertEqual(result["decision"]["model"], "gpt-6-luna")
                self.assertEqual(result["decision"]["usage"], {"input_tokens": 10})
                self.assertIsInstance(result["decision"]["latencyMs"], int)
                self.assertEqual(result["decision"]["signals"]["exfiltration"], 0.75)
                self.assertEqual(
                    [item["ruleId"] for item in result["scan_findings_in_context"]],
                    ["aig.network at run.sh:3", "SSD-1 at SKILL.md"],
                )
        request = self.stub.requests[-1]
        self.assertEqual(request["path"], "/v1/decisions")
        self.assertEqual(self.stub.headers[-1]["Authorization"], "Bearer fixture-key")
        body = request["body"]
        self.assertEqual(body["model"], "gpt-6-luna")
        self.assertEqual(body["input"][0], {"role": "developer", "content": "Policy text."})
        parts = body["input"][1]["content"]
        self.assertEqual([part["type"] for part in parts], ["input_text", "input_text", "input_json"])
        self.assertIn("curl https://example.com", parts[0]["text"])
        self.assertNotIn("PNG", parts[0]["text"])
        evidence = parts[2]["data"]
        self.assertNotIn("/private/host/path", json.dumps(evidence))
        self.assertEqual(evidence["metadata"]["runContext"]["injectionSignals"], ["ignore-previous"])
        manifest = {entry["path"]: entry for entry in evidence["artifactManifest"]}
        self.assertEqual(manifest["logo.png"]["status"], "omitted")
        self.assertEqual(evidence["findings"][0]["severity"], "error")
        verdict_question = body["questions"][0]
        self.assertEqual(verdict_question["name"], "verdict")
        self.assertEqual(verdict_question["type"], "choice")
        self.assertEqual([choice["value"] for choice in verdict_question["choices"]], ["benign", "suspicious", "malicious"])
        self.assertTrue(all(isinstance(choice, dict) and choice["description"] for choice in verdict_question["choices"]))
        names = [question["name"] for question in body["questions"]]
        self.assertIn("dimension.instruction_scope", names)
        self.assertIn("signal.remote_code_execution", names)
        self.assertIn("finding.1", names)

    def test_sarif_coverage_gaps_and_scanner_failures_are_preserved(self):
        sarif = {
            "version": "2.1.0",
            "runs": [
                {
                    "tool": {"driver": {"name": "aig-mcp"}},
                    "invocations": [
                        {
                            "executionSuccessful": False,
                            "toolExecutionNotifications": [{"level": "error", "message": {"text": "timeout scanning dist/bundle.js"}}],
                        }
                    ],
                    "results": [{"ruleId": "mcp.tool_poisoning", "level": "error", "message": {"text": "Suspicious tool description"}}],
                }
            ],
        }
        workspace = make_workspace(self.temp.name, scanners={"aig-mcp": sarif})
        metadata = json.loads((workspace / "metadata.json").read_text())
        metadata["scanners"]["aig-mcp"] = {"status": "partial", "error": "scanner reported incomplete coverage"}
        (workspace / "metadata.json").write_text(json.dumps(metadata))
        code, result, stderr = self.run_judge(workspace)
        self.assertEqual(code, 0, stderr)
        evidence = self.stub.requests[-1]["body"]["input"][0]["content"][2]["data"]
        summary = evidence["scanners"][0]
        self.assertEqual(summary["scanner"], "aig-mcp")
        self.assertFalse(summary["invocations"][0]["executionSuccessful"])
        self.assertIn("timeout scanning dist/bundle.js", summary["invocations"][0]["notifications"][0]["message"])
        self.assertEqual(evidence["metadata"]["scannerStatus"]["aig-mcp"]["status"], "partial")
        self.assertEqual(evidence["findings"][0]["ruleId"], "mcp.tool_poisoning")
        self.assertIn("not evidence of malice", self.stub.requests[-1]["body"]["questions"][0]["instructions"])

    def test_refusal_is_an_operational_failure(self):
        self.stub.refuse = "dimension.install_mechanism"
        code, result, stderr = self.run_judge(make_workspace(self.temp.name))
        self.assertEqual(code, 1)
        self.assertIsNone(result)
        self.assertIn("Decisions API refused question(s): dimension.install_mechanism", stderr)

    def test_http_error_preserves_api_message(self):
        self.stub.responses.append(
            (400, json.dumps({"error": {"message": "choices must be objects", "type": "invalid_request_error", "param": "questions"}}), {})
        )
        code, result, stderr = self.run_judge(make_workspace(self.temp.name))
        self.assertEqual(code, 1)
        self.assertIsNone(result)
        self.assertIn("Decisions API HTTP 400: choices must be objects (type=invalid_request_error, param=questions)", stderr)
        self.assertNotIn("fixture-key", stderr)
        self.assertEqual(len(self.stub.requests), 1)

    def test_rate_limit_is_retried_with_retry_after(self):
        self.stub.responses.append((429, json.dumps({"error": {"message": "slow down"}}), {"Retry-After": "0"}))
        code, result, stderr = self.run_judge(make_workspace(self.temp.name))
        self.assertEqual(code, 0, stderr)
        self.assertEqual(result["decision"]["httpAttempts"], 2)
        self.assertEqual(len(self.stub.requests), 2)

    def test_oversized_input_fails_before_any_request(self):
        workspace = make_workspace(self.temp.name, skill="# Big\n" + "x" * 5000)
        code, result, stderr = self.run_judge(workspace, "--max-input-chars", "3000")
        self.assertEqual(code, 2)
        self.assertIsNone(result)
        self.assertIn("decisions judge input too large", stderr)
        self.assertIn("exceeds the 3000-char limit", stderr)
        self.assertEqual(self.stub.requests, [])
        env = dict(self.env, DECISIONS_MAX_INPUT_CHARS="3000")
        code, _, stderr = self.run_judge(workspace, env=env)
        self.assertEqual(code, 2)
        self.assertIn("exceeds the 3000-char limit", stderr)

    def test_large_files_are_excerpted_within_budget(self):
        workspace = make_workspace(self.temp.name, extra_files={"data/big.txt": "y" * 50_000})
        code, result, stderr = self.run_judge(workspace, "--max-file-chars", "1000")
        self.assertEqual(code, 0, stderr)
        artifact = result["decision"]["input"]["artifact"]
        self.assertEqual(artifact["excerpted"], 1)
        text = self.stub.requests[-1]["body"]["input"][0]["content"][0]["text"]
        self.assertIn("chars of this file not shown", text)
        self.assertLess(len(text), 5000)

    def test_findings_are_bounded_for_input_json(self):
        issues = [
            {"id": f"SSD-{index}", "severity": "LOW", "file": f"f{index}.md", "explanation": "z" * 2000}
            for index in range(600)
        ]
        workspace = make_workspace(self.temp.name, scanners={"skillspector": {"issues": issues}})
        code, result, stderr = self.run_judge(workspace, "--max-findings", "600")
        self.assertEqual(code, 0, stderr)
        counts = result["decision"]["input"]["findings"]
        self.assertEqual(counts["total"], 600)
        self.assertGreater(counts["omitted"], 0)
        evidence = self.stub.requests[-1]["body"]["input"][0]["content"][2]["data"]
        self.assertLessEqual(len(json.dumps(evidence, separators=(",", ":")).encode()), judge.EVIDENCE_JSON_BUDGET_BYTES)
        self.assertEqual(len(result["scan_findings_in_context"]), judge.DEFAULT_MAX_FINDING_QUESTIONS)

    def test_missing_key_and_base_url_normalization(self):
        code, _, stderr = self.run_judge(make_workspace(self.temp.name), env={"DECISIONS_BASE_URL": self.stub.url})
        self.assertEqual(code, 2)
        self.assertIn("DECISIONS_API_KEY or OPENAI_API_KEY is required", stderr)
        self.assertEqual(judge.decisions_endpoint("https://api.openai.com/v1/"), "https://api.openai.com/v1/decisions")
        self.assertEqual(judge.decisions_endpoint("https://clawrouter.openclaw.ai"), "https://clawrouter.openclaw.ai/v1/decisions")

    @unittest.skipIf(SCHEMA_PATH is None, "ClawHub output schema is not available")
    def test_schema_validator_rejects_unexpected_shapes(self):
        schema = json.loads(SCHEMA_PATH.read_text())
        self.assertTrue(judge.schema_errors({"verdict": "benign"}, schema))
        self.assertTrue(judge.schema_errors({"verdict": "unknown"}, {"properties": {"verdict": {"enum": ["benign"]}}}))


if __name__ == "__main__":
    unittest.main()

import assert from "node:assert/strict";
import { describe, it } from "node:test";
import { gateResultFromArtifact } from "../src/artifact.ts";

const skillSpectorCompleted = {
  status: "completed",
  error: "",
  raw: { status: "clean", findings: [] },
};
const staticCompleted = {
  status: "completed",
  error: "",
  raw: { schemaVersion: "clawscan-static-v1", findings: [] },
};

describe("gateResultFromArtifact", () => {
  it("continues silently for a valid pass artifact", () => {
    const result = gateResultFromArtifact(
      JSON.stringify({
        schemaVersion: "clawscan-run-v1",
        gate: "pass",
        gateRules: [],
        scanners: {
          skillspector: skillSpectorCompleted,
          "clawscan-static": staticCompleted,
        },
      }),
      ["skillspector", "clawscan-static"],
    );

    assert.equal(result, undefined);
  });

  it("maps every fired warning to a structured non-blocking finding", () => {
    const result = gateResultFromArtifact(
      JSON.stringify({
        schemaVersion: "clawscan-run-v1",
        gate: "warn",
        gateRules: [
          {
            scanner: "skillspector",
            rule: "high-finding",
            path: "filtered_findings[].severity",
            value: "HIGH",
            action: "warn",
          },
          {
            scanner: "clawscan-static",
            rule: "any-finding",
            path: "findings[]",
            action: "warn",
          },
        ],
        scanners: {
          skillspector: {
            status: "completed",
            error: "",
            raw: {
              filtered_findings: [
                {
                  rule_id: "SS-101",
                  severity: "HIGH",
                  file_path: "package.json",
                  start_line: 12,
                  description: "Suspicious package script",
                },
              ],
            },
          },
          "clawscan-static": {
            status: "completed",
            error: "",
            raw: {
              schemaVersion: "clawscan-static-v1",
              findings: [
                {
                  id: "prompt-injection",
                  severity: "high",
                  path: "SKILL.md",
                  line: 4,
                  title: "Prompt injection language",
                },
              ],
            },
          },
        },
      }),
      ["skillspector", "clawscan-static"],
    );

    assert.deepEqual(result, {
      findings: [
        {
          ruleId: "clawscan/skillspector/SS-101",
          severity: "warn",
          file: "package.json",
          line: 12,
          message: "HIGH: Suspicious package script",
        },
        {
          ruleId: "clawscan/clawscan-static/prompt-injection",
          severity: "warn",
          file: "SKILL.md",
          line: 4,
          message: "high: Prompt injection language",
        },
      ],
    });
  });

  it("evaluates valid evidence from a completed scanner with a nonzero-exit error", () => {
    const result = gateResultFromArtifact(
      JSON.stringify({
        schemaVersion: "clawscan-run-v1",
        gate: "warn",
        gateRules: [
          {
            scanner: "skillspector",
            rule: "high-finding",
            path: "issues[].severity",
            value: "HIGH",
            action: "warn",
          },
        ],
        scanners: {
          skillspector: {
            status: "completed",
            error: "scanner exited with code 1",
            exitCode: 1,
            raw: {
              risk_assessment: { severity: "HIGH" },
              issues: [
                {
                  id: "SS-101",
                  severity: "HIGH",
                  path: "package.json",
                  line: 12,
                  description: "Suspicious package script",
                },
              ],
            },
          },
        },
      }),
      ["skillspector"],
    );

    assert.deepEqual(result, {
      findings: [
        {
          ruleId: "clawscan/skillspector/SS-101",
          severity: "warn",
          file: "package.json",
          line: 12,
          message: "HIGH: Suspicious package script",
        },
      ],
    });
  });

  it("maps a block artifact to an explicit block with its fired findings", () => {
    const result = gateResultFromArtifact(
      JSON.stringify({
        schemaVersion: "clawscan-run-v1",
        gate: "block",
        gateRules: [
          {
            scanner: "skillspector",
            rule: "critical-finding",
            path: "filtered_findings[].severity",
            value: "CRITICAL",
            action: "block",
          },
        ],
        scanners: {
          skillspector: {
            status: "completed",
            error: "",
            raw: {
              filtered_findings: [
                {
                  rule_id: "SS-900",
                  severity: "CRITICAL",
                  file_path: "SKILL.md",
                  start_line: 9,
                  description: "Credential theft behavior",
                },
              ],
            },
          },
          "clawscan-static": staticCompleted,
        },
      }),
      ["skillspector", "clawscan-static"],
    );

    assert.deepEqual(result, {
      block: true,
      blockReason: "ClawScan gate blocked installation: CRITICAL: Credential theft behavior",
      findings: [
        {
          ruleId: "clawscan/skillspector/SS-900",
          severity: "critical",
          file: "SKILL.md",
          line: 9,
          message: "CRITICAL: Credential theft behavior",
        },
      ],
    });
  });

  it("bounds and sanitizes untrusted fired-rule text, file paths, and line numbers", () => {
    const result = gateResultFromArtifact(
      JSON.stringify({
        schemaVersion: "clawscan-run-v1",
        gate: "warn",
        gateRules: [
          {
            scanner: "demo scanner\u0000",
            rule: "any-finding",
            path: "findings[]",
            action: "warn",
          },
        ],
        scanners: {
          "demo scanner\u0000": {
            status: "completed",
            raw: {
              findings: [
                {
                  id: "odd rule/id",
                  title: `unsafe\u0000 title ${"x".repeat(400)}`,
                  severity: "HIGH",
                  path: "/../../private/\u0000token.ts",
                  line: 9_999_999,
                },
              ],
            },
          },
        },
      }),
      ["demo scanner\u0000"],
    );

    assert.ok(result?.findings);
    assert.equal(result.findings[0]?.ruleId, "clawscan/demo-scanner/odd-rule-id");
    assert.equal(result.findings[0]?.file, "private/token.ts");
    assert.equal(result.findings[0]?.line, 1_000_000);
    assert.ok((result.findings[0]?.message.length ?? 0) <= 282);
    assert.doesNotMatch(result.findings[0]?.message ?? "", /[\u0000-\u001f\u007f]/);
  });

  for (const fixture of [
    {
      name: "malformed JSON",
      stdout: "{",
      requiredScanners: ["skillspector"],
    },
    {
      name: "an unknown gate verdict",
      stdout: JSON.stringify({
        schemaVersion: "clawscan-run-v1",
        gate: "maybe",
        gateRules: [],
        scanners: { skillspector: skillSpectorCompleted },
      }),
      requiredScanners: ["skillspector"],
    },
    {
      name: "a missing required scanner",
      stdout: JSON.stringify({
        schemaVersion: "clawscan-run-v1",
        gate: "pass",
        gateRules: [],
        scanners: {},
      }),
      requiredScanners: ["skillspector"],
    },
    ...["skipped", "completed"].map((status) => ({
      name: `a ${status} required scanner`,
      stdout: JSON.stringify({
        schemaVersion: "clawscan-run-v1",
        gate: "pass",
        gateRules: [],
        scanners: { skillspector: { status, error: "untrusted scanner error" } },
      }),
      requiredScanners: ["skillspector"],
    })),
  ]) {
    it(`fails closed for ${fixture.name}`, () => {
      const result = gateResultFromArtifact(fixture.stdout, fixture.requiredScanners);

      assert.equal(result?.block, true);
      assert.match(result?.blockReason ?? "", /^ClawScan blocked installation:/);
      assert.equal(result?.findings?.[0]?.severity, "critical");
      assert.doesNotMatch(result?.blockReason ?? "", /untrusted scanner error/);
    });
  }

  it("fails closed when any additional profile scanner does not complete", () => {
    const result = gateResultFromArtifact(
      JSON.stringify({
        schemaVersion: "clawscan-run-v1",
        gate: "pass",
        gateRules: [],
        scanners: {
          skillspector: skillSpectorCompleted,
          "clawscan-static": staticCompleted,
          "team-scanner": { status: "failed" },
        },
      }),
      ["skillspector", "clawscan-static"],
    );

    assert.equal(result?.block, true);
    assert.equal(
      result?.blockReason,
      "ClawScan blocked installation: scanner team-scanner did not complete",
    );
  });

  for (const [name, scanner, raw] of [
    ["completion-only SkillSpector", "skillspector", { status: "completed" }],
    [
      "failed SkillSpector execution",
      "skillspector",
      { status: "clean", execution_successful: false },
    ],
    ["invalid static scanner", "clawscan-static", { schemaVersion: "wrong", findings: [] }],
  ] as const) {
    it(`fails closed for ${name} evidence`, () => {
      const result = gateResultFromArtifact(
        JSON.stringify({
          schemaVersion: "clawscan-run-v1",
          gate: "pass",
          gateRules: [],
          scanners: { [scanner]: { status: "completed", error: "", raw } },
        }),
        [scanner],
      );

      assert.equal(result?.block, true);
      assert.equal(
        result?.blockReason,
        `ClawScan blocked installation: required scanner ${scanner} returned unusable evidence`,
      );
    });
  }

  it("fails closed when an artifact contains no scanner results", () => {
    const result = gateResultFromArtifact(
      JSON.stringify({
        schemaVersion: "clawscan-run-v1",
        gate: "pass",
        gateRules: [],
        scanners: {},
      }),
      [],
    );

    assert.equal(
      result?.blockReason,
      "ClawScan blocked installation: scanner artifact did not contain any scanner results",
    );
  });

  it("fails closed when a fired rule names a scanner outside the artifact", () => {
    const result = gateResultFromArtifact(
      JSON.stringify({
        schemaVersion: "clawscan-run-v1",
        gate: "warn",
        gateRules: [
          {
            scanner: "invented-scanner",
            rule: "nativeFinding",
            action: "warn",
          },
        ],
        scanners: {
          skillspector: skillSpectorCompleted,
          "clawscan-static": staticCompleted,
        },
      }),
      ["skillspector", "clawscan-static"],
    );

    assert.equal(result?.block, true);
    assert.equal(
      result?.blockReason,
      "ClawScan blocked installation: fired gate rule referenced an unavailable scanner",
    );
  });

  it("fails closed instead of returning an unbounded finding list", () => {
    const result = gateResultFromArtifact(
      JSON.stringify({
        schemaVersion: "clawscan-run-v1",
        gate: "warn",
        gateRules: Array.from({ length: 101 }, (_, index) => ({
          scanner: "clawscan-static",
          rule: "nativeFinding",
          findingCode: `finding-${index}`,
          action: "warn",
        })),
        scanners: {
          "clawscan-static": staticCompleted,
        },
      }),
      ["clawscan-static"],
    );

    assert.equal(result?.block, true);
    assert.equal(
      result?.blockReason,
      "ClawScan blocked installation: scanner artifact contained too many fired gate rules",
    );
    assert.equal(result?.findings?.length, 1);
  });
});

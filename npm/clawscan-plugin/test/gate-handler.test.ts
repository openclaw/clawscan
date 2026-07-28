import assert from "node:assert/strict";
import { describe, it } from "node:test";
import {
  createBeforeInstallHandler,
  type CommandOptions,
  type CommandResult,
} from "../src/gate-handler.ts";

type CommandCall = {
  argv: string[];
  options: CommandOptions;
};

const passArtifact = JSON.stringify({
  schemaVersion: "clawscan-run-v1",
  gate: "pass",
  gateRules: [],
  scanners: {
    skillspector: { status: "completed" },
    "clawscan-static": { status: "completed" },
  },
});

function commandResult(overrides: Partial<CommandResult> = {}): CommandResult {
  return {
    code: 0,
    stdout: "",
    stderr: "",
    signal: null,
    termination: "exit",
    ...overrides,
  };
}

describe("createBeforeInstallHandler", () => {
  it("runs the full shipped profile and continues silently for a pass artifact", async () => {
    const calls: CommandCall[] = [];
    const outputs = [commandResult(), commandResult({ stdout: passArtifact })];
    const handler = createBeforeInstallHandler({
      resolveBinaryPath: () => "/plugin/node_modules/@openclaw/clawscan/binaries/clawscan",
      resolveConfigPath: () => "/plugin/profiles/clawhub.yml",
      profile: "clawhub",
      runCommand: async (argv, options) => {
        calls.push({ argv, options });
        return outputs.shift() ?? commandResult();
      },
    });

    const result = await handler({ sourcePath: "/candidate/demo-skill" });

    assert.equal(result, undefined);
    assert.deepEqual(calls, [
      {
        argv: ["docker", "info"],
        options: { timeoutMs: 5_000 },
      },
      {
        argv: [
          "/plugin/node_modules/@openclaw/clawscan/binaries/clawscan",
          "/candidate/demo-skill",
          "--config",
          "/plugin/profiles/clawhub.yml",
          "--profile",
          "clawhub",
          "--sandbox",
          "docker",
          "--json",
        ],
        options: {
          timeoutMs: 600_000,
          env: { CLAWSCAN_SKILLSPECTOR_LLM: "0" },
          maxOutputBytes: { stdout: 8_388_608, stderr: 65_536 },
          outputCapture: "head",
          terminateOnOutputLimit: true,
        },
      },
    ]);
  });

  it("degrades visibly to the static scanner with exact safe arguments when Docker is unavailable", async () => {
    const calls: CommandCall[] = [];
    const staticPassArtifact = JSON.stringify({
      schemaVersion: "clawscan-run-v1",
      gate: "pass",
      gateRules: [],
      scanners: {
        "clawscan-static": { status: "completed" },
      },
    });
    const outputs = [
      commandResult({ code: 1, stderr: "daemon unavailable" }),
      commandResult({ stdout: staticPassArtifact }),
    ];
    const handler = createBeforeInstallHandler({
      resolveBinaryPath: () => "/plugin/bin/clawscan",
      resolveConfigPath: () => "/plugin/profiles/clawhub.yml",
      profile: "clawhub",
      runCommand: async (argv, options) => {
        calls.push({ argv, options });
        return outputs.shift() ?? commandResult();
      },
    });

    const result = await handler({ sourcePath: "/candidate/demo-skill" });

    assert.deepEqual(result, {
      findings: [
        {
          ruleId: "clawscan/docker-unavailable",
          severity: "warn",
          file: ".",
          line: 1,
          message: "Gate degraded: Docker unavailable; clawscan-static only.",
        },
      ],
    });
    assert.deepEqual(calls[1], {
      argv: [
        "/plugin/bin/clawscan",
        "/candidate/demo-skill",
        "--config",
        "/plugin/profiles/clawhub.yml",
        "--profile",
        "clawhub-static",
        "--scanner",
        "clawscan-static",
        "--sandbox",
        "off",
        "--json",
      ],
      options: {
        timeoutMs: 600_000,
        env: { CLAWSCAN_SKILLSPECTOR_LLM: "0" },
        maxOutputBytes: { stdout: 8_388_608, stderr: 65_536 },
        outputCapture: "head",
        terminateOnOutputLimit: true,
      },
    });
  });

  it("validates the scanners selected by a shipped non-default profile", async () => {
    const calls: CommandCall[] = [];
    const outputs = [
      commandResult(),
      commandResult({
        stdout: JSON.stringify({
          schemaVersion: "clawscan-run-v1",
          gate: "pass",
          gateRules: [],
          scanners: {
            "clawscan-static": { status: "completed" },
          },
        }),
      }),
    ];
    const handler = createBeforeInstallHandler({
      resolveBinaryPath: () => "/plugin/bin/clawscan",
      resolveConfigPath: () => "/plugin/profiles/clawhub.yml",
      profile: "clawhub-static",
      runCommand: async (argv, options) => {
        calls.push({ argv, options });
        return outputs.shift() ?? commandResult();
      },
    });

    const result = await handler({ sourcePath: "/candidate/demo-skill" });

    assert.equal(result, undefined);
    assert.ok(calls[1]?.argv.includes("clawhub-static"));
  });

  it("treats a missing Docker command as degraded mode instead of skipping the scan", async () => {
    let invocation = 0;
    const handler = createBeforeInstallHandler({
      resolveBinaryPath: () => "/plugin/bin/clawscan",
      resolveConfigPath: () => "/plugin/profiles/clawhub.yml",
      profile: "clawhub",
      runCommand: async () => {
        invocation += 1;
        if (invocation === 1) {
          throw Object.assign(new Error("spawn docker ENOENT"), { code: "ENOENT" });
        }
        return commandResult({
          stdout: JSON.stringify({
            schemaVersion: "clawscan-run-v1",
            gate: "pass",
            gateRules: [],
            scanners: { "clawscan-static": { status: "completed" } },
          }),
        });
      },
    });

    const result = await handler({ sourcePath: "/candidate/demo-skill" });

    assert.equal(invocation, 2);
    assert.equal(result?.block, undefined);
    assert.equal(result?.findings?.[0]?.ruleId, "clawscan/docker-unavailable");
  });

  it("blocks with bounded sanitized stderr when the ClawScan process exits nonzero", async () => {
    const outputs = [
      commandResult(),
      commandResult({
        code: 17,
        stderr: `bad\u0000 output ${"x".repeat(1_000)}`,
      }),
    ];
    const handler = createBeforeInstallHandler({
      resolveBinaryPath: () => "/plugin/bin/clawscan",
      resolveConfigPath: () => "/plugin/profiles/clawhub.yml",
      profile: "clawhub",
      runCommand: async () => outputs.shift() ?? commandResult(),
    });

    const result = await handler({ sourcePath: "/candidate/demo-skill" });

    assert.equal(result?.block, true);
    assert.match(
      result?.blockReason ?? "",
      /^ClawScan blocked installation: ClawScan process exited with code 17: bad output/,
    );
    assert.ok((result?.blockReason?.length ?? 0) <= 631);
    assert.doesNotMatch(result?.blockReason ?? "", /[\u0000-\u001f\u007f]/);
  });

  it("blocks explicitly when the resolved ClawScan binary is missing", async () => {
    let invocation = 0;
    const handler = createBeforeInstallHandler({
      resolveBinaryPath: () => "/plugin/bin/clawscan",
      resolveConfigPath: () => "/plugin/profiles/clawhub.yml",
      profile: "clawhub",
      runCommand: async () => {
        invocation += 1;
        if (invocation === 1) {
          return commandResult();
        }
        throw Object.assign(new Error("spawn /private/plugin/bin/clawscan ENOENT"), {
          code: "ENOENT",
        });
      },
    });

    const result = await handler({ sourcePath: "/candidate/demo-skill" });

    assert.equal(result?.block, true);
    assert.equal(
      result?.blockReason,
      "ClawScan blocked installation: ClawScan binary was not found",
    );
    assert.doesNotMatch(result?.blockReason ?? "", /\/private\/plugin/);
  });

  for (const fixture of [
    {
      name: "timeout",
      result: commandResult({ code: null, termination: "timeout" }),
      reason: "ClawScan blocked installation: ClawScan process timed out",
    },
    {
      name: "signal",
      result: commandResult({ code: null, signal: "SIGTERM", termination: "signal" }),
      reason: "ClawScan blocked installation: ClawScan process was terminated by SIGTERM",
    },
  ]) {
    it(`blocks explicitly on process ${fixture.name}`, async () => {
      const outputs = [commandResult(), fixture.result];
      const handler = createBeforeInstallHandler({
        resolveBinaryPath: () => "/plugin/bin/clawscan",
        resolveConfigPath: () => "/plugin/profiles/clawhub.yml",
        profile: "clawhub",
        runCommand: async () => outputs.shift() ?? commandResult(),
      });

      const result = await handler({ sourcePath: "/candidate/demo-skill" });

      assert.equal(result?.block, true);
      assert.equal(result?.blockReason, fixture.reason);
    });
  }

  it("blocks when the static fallback fails and keeps degraded mode visible", async () => {
    const outputs = [
      commandResult({ code: 1 }),
      commandResult({ code: 23, stderr: "static scan failed" }),
    ];
    const handler = createBeforeInstallHandler({
      resolveBinaryPath: () => "/plugin/bin/clawscan",
      resolveConfigPath: () => "/plugin/profiles/clawhub.yml",
      profile: "clawhub",
      runCommand: async () => outputs.shift() ?? commandResult(),
    });

    const result = await handler({ sourcePath: "/candidate/demo-skill" });

    assert.equal(result?.block, true);
    assert.equal(
      result?.blockReason,
      "ClawScan blocked installation: ClawScan static fallback exited with code 23: static scan failed",
    );
    assert.deepEqual(
      result?.findings?.map((finding) => finding.ruleId),
      ["clawscan/docker-unavailable", "clawscan/gate-failure"],
    );
  });

  it("blocks explicitly when scanner output exceeds the host capture limit", async () => {
    const outputs = [
      commandResult(),
      commandResult({
        code: null,
        signal: "SIGTERM",
        termination: "signal",
        outputLimitExceeded: true,
      }),
    ];
    const handler = createBeforeInstallHandler({
      resolveBinaryPath: () => "/plugin/bin/clawscan",
      resolveConfigPath: () => "/plugin/profiles/clawhub.yml",
      profile: "clawhub",
      runCommand: async () => outputs.shift() ?? commandResult(),
    });

    const result = await handler({ sourcePath: "/candidate/demo-skill" });

    assert.equal(
      result?.blockReason,
      "ClawScan blocked installation: ClawScan process exceeded its output limit",
    );
  });
});

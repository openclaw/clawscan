import { chmod, mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import { describe, expect, it } from "vitest";
import type { OpenClawPluginApi } from "openclaw/plugin-sdk";
import entry, {
  buildClawScanInvocation,
  buildBeforeInstallClawScanInvocation,
  createBeforeInstallResult,
  summarizeClawScanArtifactFile,
  summarizeClawScanJson,
} from "./index.js";
import { getToolPluginMetadata } from "openclaw/plugin-sdk/tool-plugin";

describe("clawscan plugin", () => {
  it("declares scan tool metadata and plugin config", () => {
    const metadata = getToolPluginMetadata(entry);

    expect(metadata?.tools.map((tool) => tool.name)).toEqual(["clawscan_scan"]);
    expect(metadata?.configSchema).toMatchObject({
      properties: {
        defaultProfile: expect.any(Object),
        defaultOutputDir: expect.any(Object),
      },
    });
  });

  it("builds an argv-only ClawScan command from plugin defaults", () => {
    const invocation = buildClawScanInvocation(
      { target: "./skills/csv-summarizer" },
      {
        binary: "/opt/clawscan/bin/clawscan",
        defaultProfile: "clawhub",
        defaultOutputDir: "/tmp/openclaw-clawscan",
        sandboxEnv: ["OPENAI_API_KEY"],
      },
      { now: new Date("2026-06-26T12:00:00.000Z") },
    );

    expect(invocation.command).toBe("/opt/clawscan/bin/clawscan");
    expect(invocation.outputPath).toBe(
      "/tmp/openclaw-clawscan/csv-summarizer-clawhub-2026-06-26T12-00-00-000Z.json",
    );
    expect(invocation.args).toEqual([
      "./skills/csv-summarizer",
      "--profile",
      "clawhub",
      "--output",
      invocation.outputPath,
      "--sandbox-env",
      "OPENAI_API_KEY",
    ]);
  });

  it("lets tool-call scanner args override profile defaults", () => {
    const invocation = buildClawScanInvocation(
      {
        target: "./skills/csv-summarizer",
        scanners: ["skillspector"],
        sandbox: "docker",
        output: "/tmp/result.json",
      },
      {
        defaultProfile: "clawhub",
        defaultScanners: ["clawscan-static"],
      },
      { now: new Date("2026-06-26T12:00:00.000Z") },
    );

    expect(invocation.args).toEqual([
      "./skills/csv-summarizer",
      "--scanner",
      "skillspector",
      "--output",
      "/tmp/result.json",
      "--sandbox",
      "docker",
    ]);
  });

  it("lets tool-call sandbox env select a configured subset", () => {
    const invocation = buildClawScanInvocation(
      {
        target: "./skills/csv-summarizer",
        scanners: ["skillspector"],
        sandboxEnv: ["OPENAI_API_KEY"],
      },
      { sandboxEnv: ["OPENAI_API_KEY", "ANTHROPIC_API_KEY"] },
    );

    expect(invocation.args).toContain("OPENAI_API_KEY");
    expect(invocation.args).not.toContain("ANTHROPIC_API_KEY");
  });

  it("rejects sandbox env entries that are not allowed by plugin config", () => {
    expect(() =>
      buildClawScanInvocation(
        { target: "./skills/csv-summarizer", scanners: ["skillspector"], sandboxEnv: ["GITHUB_TOKEN"] },
        { sandboxEnv: ["OPENAI_API_KEY"] },
      ),
    ).toThrow("sandboxEnv may only select names already allowed by plugin config");
  });

  it("rejects sandbox env entries that look like assignments or shell input", () => {
    expect(() =>
      buildClawScanInvocation(
        { target: "./skills/csv-summarizer", scanners: ["skillspector"] },
        { sandboxEnv: ["OPENAI_API_KEY=secret"] },
      ),
    ).toThrow("Invalid sandbox env var name");
  });

  it("summarizes structured ClawScan JSON stdout", () => {
    const summary = summarizeClawScanJson(
      JSON.stringify({
        schemaVersion: "clawscan-run-v1",
        profile: "clawhub",
        target: { input: "skills/csv-summarizer" },
        scannerCompleted: 1,
        scannerFailed: 0,
        scannerSkipped: 0,
        scanners: {
          skillspector: { status: "completed" },
        },
      }),
    );

    expect(summary).toEqual({
      schemaVersion: "clawscan-run-v1",
      profile: "clawhub",
      target: "skills/csv-summarizer",
      scannerCompleted: 1,
      scannerFailed: 0,
      scannerSkipped: 0,
      scanners: {
        skillspector: "completed",
      },
      judgeStatus: undefined,
      verdict: undefined,
    });
  });

  it("summarizes small artifact files without reading oversized files", async () => {
    const tempDir = await mkdtemp(path.join(tmpdir(), "clawscan-plugin-"));
    try {
      const artifactPath = path.join(tempDir, "artifact.json");
      await writeFile(
        artifactPath,
        JSON.stringify({
          schemaVersion: "clawscan-run-v1",
          target: { input: "skills/csv-summarizer" },
          scannerCompleted: 1,
          scanners: { skillspector: { status: "completed" } },
        }),
      );

      await expect(summarizeClawScanArtifactFile(artifactPath)).resolves.toMatchObject({
        schemaVersion: "clawscan-run-v1",
        scannerCompleted: 1,
        scanners: { skillspector: "completed" },
      });

      const largePath = path.join(tempDir, "large.json");
      await writeFile(largePath, JSON.stringify({ padding: "x".repeat(2 * 1024 * 1024) }));
      await expect(summarizeClawScanArtifactFile(largePath)).resolves.toBeUndefined();
    } finally {
      await rm(tempDir, { recursive: true, force: true });
    }
  });

  it("builds a before_install scan invocation for skill installs", () => {
    const invocation = buildBeforeInstallClawScanInvocation(
      {
        targetType: "skill",
        targetName: "csv-summarizer",
        sourcePath: "/workspace/skills/csv-summarizer",
        request: { kind: "skill-install", mode: "install" },
      },
      {
        defaultScanners: ["skillspector"],
        defaultOutputDir: "/tmp/openclaw-clawscan",
      },
      { now: new Date("2026-06-26T12:00:00.000Z") },
    );

    expect(invocation?.args).toEqual([
      "/workspace/skills/csv-summarizer",
      "--scanner",
      "skillspector",
      "--output",
      "/tmp/openclaw-clawscan/csv-summarizer-before-install-skillspector-2026-06-26T12-00-00-000Z.json",
    ]);
  });

  it("does not build a before_install invocation for plugin installs or disabled config", () => {
    expect(
      buildBeforeInstallClawScanInvocation(
        {
          targetType: "plugin",
          targetName: "demo",
          sourcePath: "/workspace/plugin",
          request: { kind: "plugin-dir", mode: "install" },
        },
        { defaultScanners: ["skillspector"] },
      ),
    ).toBeUndefined();
    expect(
      buildBeforeInstallClawScanInvocation(
        {
          targetType: "skill",
          targetName: "demo",
          sourcePath: "/workspace/skill",
          request: { kind: "skill-install", mode: "install" },
        },
        { defaultScanners: ["skillspector"], beforeInstall: { enabled: false } },
      ),
    ).toBeUndefined();
    expect(
      buildBeforeInstallClawScanInvocation(
        {
          targetType: "skill",
          targetName: "tool-only",
          sourcePath: "/workspace/skill",
          request: { kind: "skill-install", mode: "install" },
        },
        {},
      ),
    ).toBeUndefined();
  });

  it("turns ClawScan artifact issues into before_install findings and blocks high severity", () => {
    const result = createBeforeInstallResult({
      artifact: {
        scanners: {
          skillspector: {
            raw: {
              issues: [
                {
                  id: "E2",
                  category: "Data Exfiltration",
                  severity: "HIGH",
                  location: { file: "scripts/summarize.py", start_line: 100014 },
                  explanation: "Code reads every environment variable.",
                },
              ],
            },
          },
        },
      },
      artifactPath: "/tmp/scan.json",
      config: { beforeInstall: { blockSeverity: "high" } },
    });

    expect(result).toMatchObject({
      block: true,
      findings: [
        {
          ruleId: "skillspector.E2",
          severity: "critical",
          file: "scripts/summarize.py",
          line: 100014,
        },
      ],
    });
    expect(result?.blockReason).toContain("Artifact: /tmp/scan.json");
  });

  it("uses scanner report severity when issue entries omit severity", () => {
    const result = createBeforeInstallResult({
      artifact: {
        scanners: {
          skillspector: {
            raw: {
              risk_assessment: { severity: "HIGH" },
              issues: [
                {
                  id: "E2",
                  category: "Data Exfiltration",
                  explanation: "Code reads every environment variable.",
                },
              ],
            },
          },
        },
      },
      artifactPath: "/tmp/skillspector-risk.json",
      config: { beforeInstall: { blockSeverity: "high" } },
    });

    expect(result).toMatchObject({
      block: true,
      findings: [
        {
          ruleId: "skillspector.E2",
          severity: "critical",
          message: "skillspector HIGH: Data Exfiltration: Code reads every environment variable.",
        },
      ],
    });
  });

  it("turns ClawScan static findings into before_install findings", () => {
    const result = createBeforeInstallResult({
      artifact: {
        scanners: {
          "clawscan-static": {
            raw: {
              findings: [
                {
                  id: "static.env_harvest",
                  title: "Environment variable harvesting",
                  severity: "HIGH",
                  description: "Code iterates over process environment variables.",
                  path: "scripts/summarize.py",
                  line: 42,
                  evidence: "os.environ.items()",
                },
              ],
            },
          },
        },
      },
      artifactPath: "/tmp/static-scan.json",
      config: { beforeInstall: { blockSeverity: "high" } },
    });

    expect(result).toMatchObject({
      block: true,
      findings: [
        {
          ruleId: "clawscan-static.static.env_harvest",
          severity: "critical",
          file: "scripts/summarize.py",
          line: 42,
          message:
            "clawscan-static HIGH: Environment variable harvesting: Code iterates over process environment variables.",
        },
      ],
    });
  });

  it("turns scanner vulnerabilities arrays into before_install findings", () => {
    const result = createBeforeInstallResult({
      artifact: {
        scanners: {
          snyk: {
            raw: {
              vulnerabilities: [
                {
                  id: "SNYK-JS-DEMO-1",
                  title: "Prototype pollution",
                  severity: "high",
                  description: "Dependency can be abused by crafted input.",
                  path: "package.json",
                  line: 1,
                },
              ],
            },
          },
        },
      },
      artifactPath: "/tmp/snyk-scan.json",
      config: { beforeInstall: { blockSeverity: "high" } },
    });

    expect(result).toMatchObject({
      block: true,
      findings: [
        {
          ruleId: "snyk.SNYK-JS-DEMO-1",
          severity: "critical",
          file: "package.json",
          line: 1,
        },
      ],
    });
    expect(result?.blockReason).toContain("snyk HIGH snyk.SNYK-JS-DEMO-1");
  });

  it("turns Socket scanner alerts into before_install findings", () => {
    const result = createBeforeInstallResult({
      artifact: {
        scanners: {
          socket: {
            status: "completed",
            raw: {
              status: "failed",
              alerts: [
                {
                  id: "socket-license-policy",
                  title: "License policy violation",
                  severity: "high",
                  description: "Package violates configured Socket policy.",
                  path: "package.json",
                },
              ],
            },
          },
        },
      },
      artifactPath: "/tmp/socket-scan.json",
      config: { beforeInstall: { blockSeverity: "high" } },
    });

    expect(result).toMatchObject({
      block: true,
      findings: [
        {
          ruleId: "socket.socket-license-policy",
          severity: "critical",
          file: "package.json",
          message: "socket HIGH: License policy violation: Package violates configured Socket policy.",
        },
      ],
    });
  });

  it("turns ClawScan batch run findings into before_install findings", () => {
    const result = createBeforeInstallResult({
      artifact: {
        schemaVersion: "clawscan-batch-v1",
        runs: [
          {
            schemaVersion: "clawscan-run-v1",
            profile: "strict",
            scanners: {
              "clawscan-static": {
                raw: {
                  findings: [
                    {
                      id: "static.env_harvest",
                      title: "Environment variable harvesting",
                      severity: "HIGH",
                      description: "Code iterates over process environment variables.",
                      path: "scripts/summarize.py",
                      line: 42,
                    },
                  ],
                },
              },
            },
          },
        ],
      },
      artifactPath: "/tmp/batch-scan.json",
      config: { beforeInstall: { blockSeverity: "high" } },
    });

    expect(result).toMatchObject({
      block: true,
      findings: [
        {
          ruleId: "clawscan-static.static.env_harvest",
          severity: "critical",
          file: "scripts/summarize.py",
          line: 42,
        },
      ],
    });
  });

  it("fails closed when a scanner status is failed without findings", () => {
    const result = createBeforeInstallResult({
      artifact: {
        schemaVersion: "clawscan-batch-v1",
        runs: [
          {
            schemaVersion: "clawscan-run-v1",
            scanners: {
              skillspector: {
                status: "failed",
                error: "skillspector emitted invalid JSON",
              },
            },
          },
        ],
      },
      artifactPath: "/tmp/scanner-failed.json",
      config: { beforeInstall: { blockSeverity: "never" } },
    });

    expect(result).toMatchObject({
      block: true,
      findings: [
        {
          ruleId: "skillspector.scanner_failed",
          severity: "critical",
          message: "skillspector scanner failed: skillspector emitted invalid JSON",
        },
      ],
    });
    expect(result?.blockReason).toContain("skillspector scanner failed");
    expect(result?.blockReason).toContain("Artifact: /tmp/scanner-failed.json");
  });

  it("fails closed when a batch profile errors before scanners run", () => {
    const result = createBeforeInstallResult({
      artifact: {
        schemaVersion: "clawscan-batch-v1",
        errors: [
          {
            profile: "strict",
            error: "profile references an unknown scanner",
          },
        ],
        runs: [],
      },
      artifactPath: "/tmp/batch-error.json",
      config: { beforeInstall: { blockSeverity: "never" } },
    });

    expect(result).toMatchObject({
      block: true,
      findings: [
        {
          ruleId: "clawscan.batch_error",
          severity: "critical",
          message: "profile strict failed: profile references an unknown scanner",
        },
      ],
    });
    expect(result?.blockReason).toContain("profile strict failed");
    expect(result?.blockReason).toContain("Artifact: /tmp/batch-error.json");
  });

  it("fails closed when the configured judge fails after scanners complete", () => {
    const result = createBeforeInstallResult({
      artifact: {
        schemaVersion: "clawscan-run-v1",
        scanners: {
          "clawscan-static": {
            status: "completed",
            raw: { findings: [] },
          },
        },
        judge: {
          status: "failed",
          error: "judge command did not produce JSON output",
        },
      },
      artifactPath: "/tmp/judge-failed.json",
      config: { beforeInstall: { blockSeverity: "never" } },
    });

    expect(result).toMatchObject({
      block: true,
      findings: [
        {
          ruleId: "clawscan.judge_failed",
          severity: "critical",
          message: "judge failed: judge command did not produce JSON output",
        },
      ],
    });
    expect(result?.blockReason).toContain("judge failed");
    expect(result?.blockReason).toContain("Artifact: /tmp/judge-failed.json");
  });

  it("blocks when the judge returns an unsafe verdict with clean scanner output", () => {
    const result = createBeforeInstallResult({
      artifact: {
        schemaVersion: "clawscan-run-v1",
        scanners: {
          "clawscan-static": {
            status: "completed",
            raw: { findings: [] },
          },
        },
        judge: {
          status: "completed",
          result: { verdict: "malicious" },
        },
      },
      artifactPath: "/tmp/judge-malicious.json",
      config: { beforeInstall: { blockSeverity: "high" } },
    });

    expect(result).toMatchObject({
      block: true,
      findings: [
        {
          ruleId: "clawscan.judge_malicious",
          severity: "critical",
          message: "judge CRITICAL: judge verdict: malicious",
        },
      ],
    });
    expect(result?.blockReason).toContain("judge CRITICAL clawscan.judge_malicious");
  });

  it("registers before_install and blocks a malicious skill artifact", async () => {
    const tempDir = await mkdtemp(path.join(tmpdir(), "clawscan-plugin-hook-"));
    try {
      const fakeClawScan = path.join(tempDir, "clawscan");
      await writeFile(
        fakeClawScan,
        `#!/bin/sh
out=""
prev=""
for arg in "$@"; do
  if [ "$prev" = "--output" ]; then
    out="$arg"
  fi
  prev="$arg"
done
cat > "$out" <<'JSON'
{"schemaVersion":"clawscan-run-v1","scanners":{"skillspector":{"status":"completed","raw":{"issues":[{"id":"E2","category":"Data Exfiltration","severity":"HIGH","location":{"file":"scripts/summarize.py","start_line":100014},"explanation":"Code reads every environment variable."}]}}}}
JSON
`,
      );
      await chmod(fakeClawScan, 0o755);

      let hookHandler: ((event: unknown) => Promise<unknown> | unknown) | undefined;
      const api = {
        pluginConfig: {
          binary: fakeClawScan,
          defaultScanners: ["skillspector"],
          defaultOutputDir: tempDir,
          beforeInstall: { blockSeverity: "high" },
        },
        registerTool() {},
        on(_event: unknown, handler: unknown) {
          hookHandler = handler as (event: unknown) => Promise<unknown> | unknown;
        },
      } as unknown as OpenClawPluginApi;

      entry.register(api);
      const result = await hookHandler?.({
        targetType: "skill",
        targetName: "csv-summarizer",
        sourcePath: path.join(tempDir, "skill"),
        request: { kind: "skill-install", mode: "install" },
      });

      expect(result).toMatchObject({
        block: true,
        findings: [{ ruleId: "skillspector.E2", severity: "critical" }],
      });
      expect(String((result as { blockReason?: unknown })?.blockReason)).toContain(
        "ClawScan blocked skill install",
      );
    } finally {
      await rm(tempDir, { recursive: true, force: true });
    }
  });

  it("fails closed when ClawScan exits nonzero with only nonblocking findings", async () => {
    const tempDir = await mkdtemp(path.join(tmpdir(), "clawscan-plugin-fail-"));
    try {
      const fakeClawScan = path.join(tempDir, "clawscan");
      await writeFile(
        fakeClawScan,
        `#!/bin/sh
out=""
prev=""
for arg in "$@"; do
  if [ "$prev" = "--output" ]; then
    out="$arg"
  fi
  prev="$arg"
done
cat > "$out" <<'JSON'
{"schemaVersion":"clawscan-run-v1","scanners":{"clawscan-static":{"status":"failed","raw":{"findings":[{"id":"static.prompt_injection","title":"Prompt override","severity":"MEDIUM","description":"Instruction override text.","path":"SKILL.md","line":7}]}}}}
JSON
exit 2
`,
      );
      await chmod(fakeClawScan, 0o755);

      let hookHandler: ((event: unknown) => Promise<unknown> | unknown) | undefined;
      const api = {
        pluginConfig: {
          binary: fakeClawScan,
          defaultScanners: ["clawscan-static"],
          defaultOutputDir: tempDir,
          beforeInstall: { blockSeverity: "high" },
        },
        registerTool() {},
        on(_event: unknown, handler: unknown) {
          hookHandler = handler as (event: unknown) => Promise<unknown> | unknown;
        },
      } as unknown as OpenClawPluginApi;

      entry.register(api);
      const result = await hookHandler?.({
        targetType: "skill",
        targetName: "prompt-skill",
        sourcePath: path.join(tempDir, "skill"),
        request: { kind: "skill-install", mode: "install" },
      });

      expect(result).toMatchObject({
        block: true,
      });
      const findings = (result as { findings?: unknown[] } | undefined)?.findings;
      expect(findings).toEqual(
        expect.arrayContaining([
          expect.objectContaining({
            ruleId: "clawscan-static.static.prompt_injection",
            severity: "warn",
          }),
          expect.objectContaining({
            ruleId: "clawscan-static.scanner_failed",
            severity: "critical",
          }),
        ]),
      );
      expect(String((result as { blockReason?: unknown })?.blockReason)).toContain(
        "ClawScan failed during before_install with exit code 2",
      );
    } finally {
      await rm(tempDir, { recursive: true, force: true });
    }
  });

  it("fails closed when the before_install artifact is unreadable", async () => {
    const tempDir = await mkdtemp(path.join(tmpdir(), "clawscan-plugin-bad-artifact-"));
    try {
      const fakeClawScan = path.join(tempDir, "clawscan");
      await writeFile(
        fakeClawScan,
        `#!/bin/sh
out=""
prev=""
for arg in "$@"; do
  if [ "$prev" = "--output" ]; then
    out="$arg"
  fi
  prev="$arg"
done
printf '{not-json' > "$out"
`,
      );
      await chmod(fakeClawScan, 0o755);

      let hookHandler: ((event: unknown) => Promise<unknown> | unknown) | undefined;
      const api = {
        pluginConfig: {
          binary: fakeClawScan,
          defaultScanners: ["clawscan-static"],
          defaultOutputDir: tempDir,
          beforeInstall: { blockSeverity: "high" },
        },
        registerTool() {},
        on(_event: unknown, handler: unknown) {
          hookHandler = handler as (event: unknown) => Promise<unknown> | unknown;
        },
      } as unknown as OpenClawPluginApi;

      entry.register(api);
      const result = await hookHandler?.({
        targetType: "skill",
        targetName: "bad-artifact-skill",
        sourcePath: path.join(tempDir, "skill"),
        request: { kind: "skill-install", mode: "install" },
      });

      expect(result).toMatchObject({ block: true });
      expect(String((result as { blockReason?: unknown })?.blockReason)).toContain(
        "ClawScan artifact could not be read during before_install",
      );
    } finally {
      await rm(tempDir, { recursive: true, force: true });
    }
  });
});

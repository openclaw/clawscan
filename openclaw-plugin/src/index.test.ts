import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import { describe, expect, it } from "vitest";
import entry, {
  buildClawScanInvocation,
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
});

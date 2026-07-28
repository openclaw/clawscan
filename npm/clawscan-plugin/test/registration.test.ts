import assert from "node:assert/strict";
import { describe, it } from "node:test";
import type { BeforeInstallEvent } from "../src/gate-handler.ts";
import { registerInstallGate, type RegisteredHandler } from "../src/register.ts";

describe("registerInstallGate", () => {
  it("registers a high-priority before_install hook with an explicit resolved config", async () => {
    let registeredHandler: RegisteredHandler | undefined;
    let resolvedPath = "";
    const commandCalls: string[][] = [];
    registerInstallGate(
      {
        pluginConfig: {
          configPath: "/trusted/custom.yml",
          profile: "clawhub",
        },
        resolvePath: (input) => {
          resolvedPath = input;
          return input;
        },
        runtime: {
          system: {
            runCommandWithTimeout: async (argv) => {
              commandCalls.push(argv);
              if (argv[0] === "docker") {
                return {
                  code: 0,
                  stdout: "",
                  stderr: "",
                  signal: null,
                  killed: false,
                  termination: "exit",
                };
              }
              return {
                code: 0,
                stdout: JSON.stringify({
                  schemaVersion: "clawscan-run-v1",
                  gate: "pass",
                  gateRules: [],
                  scanners: {
                    "team-scanner": { status: "completed" },
                  },
                }),
                stderr: "",
                signal: null,
                killed: false,
                termination: "exit",
              };
            },
          },
        },
        on: (name, handler, options) => {
          assert.equal(name, "before_install");
          assert.deepEqual(options, { priority: 100, timeoutMs: 615_000 });
          registeredHandler = handler;
        },
      },
      () => "/plugin/bin/clawscan",
    );

    assert.ok(registeredHandler);
    const result = await registeredHandler({
      sourcePath: "/untrusted/candidate",
    } satisfies BeforeInstallEvent);

    assert.equal(result, undefined);
    assert.equal(resolvedPath, "/trusted/custom.yml");
    assert.deepEqual(commandCalls[1], [
      "/plugin/bin/clawscan",
      "/untrusted/candidate",
      "--config",
      "/trusted/custom.yml",
      "--profile",
      "clawhub",
      "--sandbox",
      "docker",
      "--json",
    ]);
  });
});

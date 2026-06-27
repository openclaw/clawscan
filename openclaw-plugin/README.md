# ClawScan OpenClaw Plugin

OpenClaw tool plugin for running ClawScan from an agent and checking skill installs.

The plugin exposes one tool and one install hook:

- `clawscan_scan`: runs the `clawscan` CLI with a safe argv array and writes the artifact JSON to disk.
- `before_install`: scans skill install sources before OpenClaw runs the skill installer.

## Install

From a local ClawScan checkout:

```bash
cd openclaw-plugin
npm install
npm run build
openclaw plugins install --link "$PWD"
```

## Configure

OpenClaw passes `plugins.entries.clawscan.config` to the plugin at runtime.

Example:

```json
{
  "plugins": {
    "entries": {
      "clawscan": {
        "enabled": true,
        "config": {
          "binary": "clawscan",
          "defaultProfile": "clawhub",
          "defaultOutputDir": "~/.openclaw/clawscan",
          "sandbox": "docker",
          "sandboxEnv": ["OPENAI_API_KEY"],
          "beforeInstall": {
            "enabled": true,
            "blockSeverity": "high"
          }
        }
      }
    }
  }
}
```

Config fields:

- `binary`: ClawScan executable path or command name. Defaults to `clawscan`.
- `defaultProfile`: profile used when a tool call does not specify `profile` or `scanners`.
- `defaultConfig`: default `.clawscan.yml` path.
- `defaultScanners`: scanner ids used when a tool call does not specify `profile` or `scanners`.
- `defaultOutputDir`: artifact directory. Defaults to `~/.openclaw/clawscan`.
- `json`: pass `--json` when you also want ClawScan to print the full artifact to stdout. Defaults to `false`; the plugin reads summaries from the artifact file.
- `sandbox`: `docker` or `off`.
- `sandboxImage`: Docker runtime image for ClawScan sandboxed execution.
- `sandboxEnv`: environment variable names to allow through ClawScan's sandbox. This is names only, never secret values.
- `timeoutMs`: maximum scan runtime in milliseconds. Defaults to 10 minutes.
- `beforeInstall.enabled`: set `false` to disable the plugin-owned skill install hook. Defaults to enabled.
- `beforeInstall.blockSeverity`: minimum ClawScan issue severity that blocks a skill install. Defaults to `high`; use `never` to report findings without blocking.

Secrets stay outside plugin config. Set scanner credentials in the OpenClaw process environment, such as `SNYK_TOKEN`, `SOCKET_CLI_API_TOKEN`, or model provider keys. If ClawScan runs scanner commands in Docker, list only the required env var names in `sandboxEnv`. Tool calls may select a subset of those configured names, but cannot add new env vars.

## Skill Install Hook

OpenClaw runs install checks in this order:

1. `security.installPolicy`, when configured by the operator.
2. Plugin `before_install` hooks from already-loaded plugins.
3. The actual skill install command.

This plugin registers `before_install` for skill installs only. When `defaultScanners`, `defaultProfile`, or `defaultConfig` is configured, it scans the install source path with ClawScan, writes the artifact under `defaultOutputDir`, returns findings to OpenClaw, and blocks when any finding meets `beforeInstall.blockSeverity`. Without a configured default scanner, profile, or config file, the hook is inactive so the plugin can be used only as the `clawscan_scan` tool.

Example using SkillSpector for skill installs:

```json
{
  "plugins": {
    "entries": {
      "clawscan": {
        "enabled": true,
        "config": {
          "defaultScanners": ["skillspector"],
          "defaultOutputDir": "~/.openclaw/clawscan",
          "beforeInstall": {
            "enabled": true,
            "blockSeverity": "high"
          }
        }
      }
    }
  }
}
```

Use `security.installPolicy` instead when you need an admin/operator-owned policy that runs before plugin code is loaded. This plugin hook is user/plugin-level policy and only runs after the ClawScan plugin is installed and enabled.

## Tool Input

Minimal call using configured defaults:

```json
{
  "target": "./skills/my-skill"
}
```

Run a specific scanner:

```json
{
  "target": "./skills/my-skill",
  "scanners": ["skillspector"]
}
```

Run a baked-in profile:

```json
{
  "target": "./skills/my-skill",
  "profile": "skills-sh"
}
```

Use a project config:

```json
{
  "target": "./skills/my-skill",
  "config": "./.clawscan.yml",
  "profile": "candidate"
}
```

The tool returns the exit code, artifact path, argv used, and a concise summary parsed from ClawScan JSON stdout when available.

## Build And Validate

```bash
npm run build
npm test
npm run plugin:validate
```

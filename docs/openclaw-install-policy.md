# OpenClaw install policy

ClawScan can run as OpenClaw's external `security.installPolicy.exec` command.
This is an operator-owned boundary. It does not require a ClawScan plugin,
plugin activation, or a new install hook.

> [!IMPORTANT]
> Deploy this adapter only with an OpenClaw release whose protocol-v1 install
> policy parser supports `decision: "warn"` and pauses for explicit user
> confirmation. Older allow/block-only hosts intentionally reject `warn` and
> fail closed. No compatible release floor exists until the coordinated
> OpenClaw host change lands.

OpenClaw writes a protocol v1 request to the command's stdin before a supported
third-party skill or plugin install/update stage is committed. One install can
produce more than one policy call. ClawScan evaluates each staged
`sourcePath` and writes one protocol v1 allow/warn/block response to stdout.

## Resolve the trusted executable

Install the binary package:

```sh
npm install -g @openclaw/clawscan
```

OpenClaw requires the policy command to be an absolute, non-symlink path. The
package exports a resolver for its native executable:

```sh
node --input-type=module -e '
  import { pathToFileURL } from "node:url";
  const module = await import(pathToFileURL(process.argv[1]).href);
  console.log(module.resolveBundledBinaryPath());
' "$(npm root -g)/@openclaw/clawscan/lib/resolve-binary.mjs"
```

Use the printed path as `command`, and its containing directory in
`trustedDirs`.

## Configure OpenClaw

```json5
{
  security: {
    installPolicy: {
      enabled: true,
      targets: ["skill", "plugin"],
      exec: {
        source: "exec",
        command: "/absolute/path/to/clawscan",
        args: ["openclaw-install-policy"],
        trustedDirs: ["/absolute/path/to"],
        passEnv: ["PATH", "DOCKER_HOST"],
        timeoutMs: 1200000,
        noOutputTimeoutMs: 1200000,
        maxOutputBytes: 1048576,
      },
    },
  },
}
```

The default `openclaw-install-policy` profile composes SkillSpector and
`clawscan-static` deterministically and has no judge. ClawScan runs
command-backed scanners in Docker by default. `PATH` lets it locate Docker;
`DOCKER_HOST` is only needed when the local Docker setup uses it.

For npm plugin installs, OpenClaw calls the policy before mutation with an
`npm-package-metadata.json` file, then calls it again for the resolved package
and installed dependency tree. ClawScan narrowly recognizes the metadata call
from its complete host tuple: plugin/npm request and origin, immutable network
npm source, package content role, file path kind, matching package names, and
the exact metadata filename. It validates that provenance and uses the built-in
static scanner without Docker for this lightweight phase. It does not present
that result as a scan of plugin code. The later package and dependency-tree
calls keep the full profile. Dependency packages are exposed in a dedicated
scan view so normal `node_modules` exclusions cannot hide their code. Local
`plugin-file` requests never match the metadata shortcut. A dependency-tree
phase with no installed runtime dependencies returns an explicit allow/info
response because the package itself was already scanned in the package phase.
For managed npm roots, the dependency view omits only OpenClaw's exact
host-validated `node_modules/openclaw` peer symlink; other links escaping the
staged root fail closed.

On native Windows, the default profile visibly degrades to
`clawscan-static` with the sandbox disabled because the Linux Docker runtime
cannot consume native Windows staging paths. The response is `warn`, requiring
OpenClaw to obtain explicit confirmation, and includes a finding for this
reduced coverage. Explicit `--scanner` or
`--sandbox` arguments remain operator-owned and disable this automatic fallback.

To use an operator-owned profile, add explicit arguments:

```json5
args: [
  "openclaw-install-policy",
  "--config",
  "/absolute/path/to/.clawscan.yml",
  "--profile",
  "install-policy",
]
```

The configured command is the composition point for multiple checks. ClawScan
does not claim an active-scanner singleton and does not replace other policy
engines. Operators can select several scanner adapters in one profile or wrap
several policy checks behind their configured executable and combine their
responses deterministically.

## Request and response contract

The command accepts OpenClaw's complete policy payload, including:

- `targetType`: `skill` or `plugin`
- staged `sourcePath` and `sourcePathKind`
- `source` and `origin` metadata
- request kind, install/update mode, and requested specifier
- target-specific skill or plugin metadata

ClawScan uses the host-declared target type, so staged plugin files and
dependency trees are scanned as plugins even when they do not contain a
top-level plugin manifest.

Successful scans return:

```json
{"protocolVersion":1,"decision":"allow"}
```

Warning gate rules return `decision: "warn"` with a required reason and
optional bounded findings. OpenClaw owns the confirmation prompt and resumes
the install only after explicit user confirmation. Blocking gate rules return
`decision: "block"` with a required reason and optional critical findings;
blocks are not overridable. Invalid requests, scanner errors, skipped required
scanners, empty results, and unknown gate verdicts return a valid block response
with a fail-closed reason. OpenClaw also fails closed if the executable cannot
start, times out, exits nonzero, emits malformed output, or does not support a
returned protocol decision.

The policy process never prompts. It does not issue approval tokens, negotiate
capabilities, or maintain install phase IDs. Its only approval signal is the
top-level protocol-v1 decision; OpenClaw owns all acknowledgement state and UI.

## Scope

OpenClaw routes supported third-party skill install/update paths and supported
plugin install/update sources through `security.installPolicy`. Skill Workshop
authoring and manual filesystem copies are outside this supply-chain install
scope.

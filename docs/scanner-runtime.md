# Scanner runtime compatibility

## Interrupted-run diagnostics

Set `CLAWSCAN_PROGRESS=1` to emit `[clawscan-progress] ` followed by one JSON event
per line to stderr. Normal CLI output stays unchanged without this opt-in.
`schemaVersion: "clawscan-progress-v1"` events contain only a fixed phase
identifier, event type, monotonic elapsed milliseconds within that target run,
process ID and, when available, duration, exit code and a failure boolean. No
arguments, paths, environment values, prompts, raw output or error text are logged.
Custom scanner names are replaced with `scanner:custom`.

`phase_start` / `phase_end` bracket preparation, each scanner and the judge.
`command_start` / `command_end` bracket default-runner subprocess execution. The
PID is the direct child (the Docker client or judge shell when applicable), not
necessarily its nested tool/model process. Injected command runners need their
own subprocess instrumentation. The built-in static scanner has phase events,
not command events. A judge receipt retry produces another command pair in the
same judge phase. Multiple targets restart the elapsed clock at preparation.

For opt-in inner judge diagnostics, also set `CLAWSCAN_CHILD_PROGRESS=1`. The
default command runner then observes judge stdout as it arrives, projecting
recognized Codex `exec --json` JSONL lifecycle records into `child_event` events
under the same prefix/schema. Only `childEvent` (thread/turn/item lifecycle or
error), `childItem` (a fixed item-type enum), `childState` (in_progress,
completed, failed or declined), and a bounded per-command `sequence` are added.
No child IDs, commands, output, text, usage, paths, or errors are copied. The
existing PID still identifies the direct shell/Docker client, not an inner tool.
Stdout/stderr capture, command exit semantics, artifacts and sandbox policy are
unchanged. Both opt-ins are required; other scanner phases are not observed.

Observation accepts at most 64 KiB per JSONL record and 512 diagnostic records
per direct command. Oversized records are discarded through their newline and
produce `child_event_dropped`; exceeding the event budget produces a single
`child_event_limit` and stops observation, not execution. Malformed JSON and
unknown event/item types are ignored. Complete newline-terminated records are
emitted immediately; a final unterminated record is considered only at normal
command return. Custom/Docker commands must forward JSONL stdout to be observed.
Progress sinks must return promptly, as with existing phase diagnostics.

These records are untrusted child-reported activity, not provider telemetry or
proof of a native invocation, tool success, sandbox failure, or valid verdict.
An unfinished command item suggests a tool wait; repeated completed items suggest
ongoing activity. Silence cannot distinguish provider waiting from model
reasoning, local startup, ignored/oversized records, or non-JSONL output. Consumers
that strictly validate the phase schema must explicitly admit the new allowlisted
fields/events before counting them as diagnostics. Never use them as verdict
evidence or infer zero operational failures from them.

Retain stderr on worker timeout to identify the last started unfinished phase,
including when an outer process-group kill prevents ClawScan from writing its
final artifact. These are best-effort diagnostics, **never a completed scan or a
security verdict**: an end event means control returned, not that evidence was
valid. Require the unchanged final artifact, scanner evidence and judge schema
validation. An absent final artifact or a deadline at any stage remains an
operational failure. This instrumentation neither changes deadlines nor repairs
an underlying scanner/provider stall.

The bundled ClawHub profiles use GPT-6.1 Sol: medium reasoning for the OpenAI
SkillSpector and A.I.G scanner lanes; high reasoning and default Standard service
for the final Codex judge. The profile contains explicit non-secret
`scannerEnvDefaults`. Environment overrides take precedence. A project-local
profile shadows the bundled profile completely, including these defaults.

## Pinned integrations

The runtime builds NVIDIA SkillSpector from
`95a52d89fa16f608f0b18ccee76b0918ea4b7eef` and Tencent Zhuque Lab's
[AI-Infra-Guard](https://github.com/Tencent/AI-Infra-Guard) skill scanner from
`a5c5a72c2e5b88fc6e5b27e0c86110943c4d350b`. Latest upstream was inspected before
selecting these revisions. Both still use Chat Completions by default. The PyPI
A.I.G 0.2.2 release also lacks upstream's reasoning-effort support.

The small patches under `docker/clawscan-runtime/patches/` are owned integration
fixes, not a new ClawScan model-provider framework:

- SkillSpector selects LangChain's maintained `use_responses_api=True` path for
  exact `gpt-6.1-sol`, including tool calls, tool results and structured output.
  Unsupported Sol sampling controls fail before network access.
- A.I.G reuses the official OpenAI SDK's Responses streaming API for that exact
  model. A.I.G tools are XML in text, so complete text history is replayed, not
  converted to synthetic OpenAI tools. Reasoning effort and usage are mapped;
  failed, incomplete, refused, truncated and timed-out streams fail closed.
- Other model names retain upstream's Chat Completions paths and provider URL
  overrides. A custom endpoint must itself support Responses when selecting Sol.
- Scanner JSON/SARIF stays upstream raw evidence. SkillSpector's upstream
  provenance records requested and observed model/control data. Do not treat
  configured model names or this source pin as proof of an observed response.

Docker builds apply patches with `git apply --check` and execute offline tests
against the actual installed scanner packages and OpenAI SDK serializers.
Upstream pin changes must keep these gates green; remove a patch when upstream
provides the equivalent tested behavior. The runtime updater follows A.I.G's Git
HEAD rather than PyPI until a compatible release is available.

## Consume without a public release

Check out the exact reviewed ClawScan commit, then build both binary and image:

```sh
go build -trimpath -o /tmp/clawscan-sol ./cmd/clawscan
docker build -t clawscan-runtime:reviewed-sol docker/clawscan-runtime
/tmp/clawscan-sol ./my-skill --profile clawhub \
  --sandbox-image clawscan-runtime:reviewed-sol
```

A consumer workflow can pin the ClawScan source commit and run these same builds;
no tag or npm publication is required. If it needs the npm binary resolver,
`node scripts/build-npm-package.mjs --version v0.0.0-sol.1 --pack --smoke` creates
a local tarball under `dist/npm` for installation into the consumer's build.
The ordinary source npm directory is a wrapper, not a prebuilt binary package.

An old npm 0.2.0 binary can instead use a fully supplied project profile for
judge/model settings, but cannot interpret the new `scannerEnvDefaults` field;
it would need explicit environment settings and still needs the rebuilt runtime.
Prefer pinning/building the reviewed source. Pin the consumer's runtime image to
the corresponding built digest; do not assume mutable `latest` is updated.

For unsandboxed execution, install the same patched scanner sources yourself.
A stock `pip install aig-skill-scan` or unpatched SkillSpector is not equivalent.
Live provider tests are optional and must use existing authorized credentials;
never put keys in profiles, command-line flags, fixtures or evidence files.

## Judge model provenance

Run artifacts expose `judge.configuredModel` only when ClawScan can conservatively
recognize a literal model flag on a single direct final POSIX `codex exec`
invocation. This is the **configured request**, not a provider-observed model or
proof that inference completed. The complete command stays omitted because it
can contain credentials. Never infer execution provenance from model-authored
`judge.result.model` or other response text. Dynamic/ambiguous commands,
unsupported options, non-GPT IDs, other harnesses and Windows remain unknown
(the field is absent), rather than guessed. Consumers should preserve unknown.

## Standard tier and explicit overrides

Both exact Sol adapter paths send `service_tier: "default"` explicitly, independent
of provider project defaults. Optional `SKILLSPECTOR_SERVICE_TIER` and
`AIG_SERVICE_TIER` override only these Sol paths; supported values are `default`,
`flex`, `priority` and `auto`. Unset/blank means Standard; invalid values fail
before network access without echoing their values. These controls are passed
through the scanner sandbox allowlist. Other models retain upstream behavior.
An explicit `auto` override deliberately opts back into provider project defaults.

### AIG transient Responses failures

The exact Sol AIG adapter permits at most **three provider attempts per chat**,
with SDK automatic retries disabled. Only structured `server_is_overloaded`,
`slow_down`, or `server_error` errors with compatible types/statuses qualify.
HTTP overload requires 503, slow-down requires 429, and server errors require
500/503; streaming error envelopes have no HTTP error status. Unknown codes,
quota/billing/spend/usage limits, authentication/invalid requests, refusals,
policy blocks, incomplete responses, and missing/empty completion remain errors.

OpenAI SDK 2.8.1 raises `APIError` for nested SSE error envelopes before the
typed event consumer sees them. For that streaming exception only, a missing
code can qualify when its **error-envelope message exactly equals** the retained
service message `Our servers are currently overloaded. Please try again later.`
and its type is absent or a compatible server/API error type. This is not a
substring match and never examines model-output text. A present unknown or
contradictory code/type cannot be overridden by the message. Production evidence
retains the message, not its original wire body; the synthetic missing-code
fixture demonstrates compatibility, not the actual incident's unknown code.

Every attempt, connection/header wait, stream, backoff and cancellation shares
the original complete-response deadline (300 seconds by default). The Sol path
uses the same SDK's cancellable async HTTP Responses client in a
call-local event-loop thread: upstream callers already run inside an async
CLI, and a synchronous stream watchdog cannot cancel opening/trickling headers.
Caller interruption cancels the call-local task once. Repeated interruptions
preserve the original abort while waiting for response/client closure and event-loop
finalization. A call-local completion event and actual thread deregistration, not
`Thread.join()`/`is_alive()` after an interrupted join, establish worker completion.
Worker startup is inside this barrier too. On the main thread only, callable
SIGINT handlers are briefly deferred across `Thread.start()`, restored exactly,
and replayed through the original handler before releasing deferred provider work.
This prevents SIGINT from leaving CPython 3.12's pre-native-launch registration
stranded without a real worker. Async Runner and custom-handler semantics are
preserved; ignored/default OS handlers and non-main threads are not changed.
A genuine launch failure propagates without waiting for a nonexistent worker.
As with `asyncio.wait_for`, the deadline initiates cancellation; cooperative
cleanup can finish after it. Cleanup is shielded from subsequent cancellation,
not detached or given a fresh request deadline. Python cannot forcibly terminate
an uncooperative thread/finalizer. Process budgets belong to the caller: ClawHub's
external consumer supplies a 900-second process budget plus a 60-second cleanup
allowance. The public CLI instead uses the external-command runner's configured
timeout (20 minutes by default), cancelling the direct command via Go's
`exec.CommandContext` without a separate 60-second cleanup phase. That cancellation
does not guarantee process-tree termination or a strict wall-clock bound on pipe
cleanup.
Process termination (`SIG_DFL`, SIGKILL, interpreter/native failure) cannot promise
in-process cleanup. Deferral changes no persistent signal policy or signal mask.
The synchronous wait observes pending caller-task cancellation, including the
async CLI's first SIGINT, without waiting for its blocked caller loop to resume.
No endpoint, HTTP transport protocol, model, reasoning, tier or process budget
changes. Other models retain their upstream synchronous behavior. Each failed
stream closes before another attempt; failed partial XML/text is discarded and
no local tools execute inside retries. Empty output raises instead of entering
upstream's separate empty-response retry/fallback loop.

Backoff is 1 then 2 seconds plus up to 250 ms jitter. Valid `Retry-After` seconds
or HTTP dates are minimum delays. A delay above 10 seconds or the remaining
deadline stops retries rather than retrying early. Terminal API errors are
sanitized before reaching the CLI traceback; provider bodies are not logged.

Bounded `aig_provider_attempt v=1` stderr/log records contain only a random
call ID, attempt ordinal, started/failed/completed outcome and allowlisted error
category. These are **scanner-provider attempts**, not native judge invocations
or worker retries. The current Go adapter does not retain successful scanner
stderr, and failure stderr may be truncated: these logs are debugging evidence,
not authoritative population counts. Missing telemetry stays unknown; a parent-
owned consumer companion is needed before exposing complete production counts.

The bundled final Codex judges also pass `-c 'service_tier="default"'`
explicitly, alongside `--ignore-user-config` and high reasoning. A complete
operator `--judge` command override remains authoritative, including a different
model, effort, or service tier.

## Executed upgrade proof

`scripts/verify-model-policy-upgrade.py` compares an actual binary built from
`v0.2.0` with a candidate binary. Run it with `--previous <old-binary>`,
`--candidate <candidate-binary>` and `--output <outside-repository.json>`.
It executes real ClawScan CLI/profile resolution and scanner/judge subprocess
paths with synthetic probes, an isolated environment and no provider credentials
or calls. The trace records binary SHA-256 identities and non-secret model
controls. Assertions cover bundled model/tier changes, retained explicit
provider/model/effort/judge overrides, whole-profile project shadows, and
provider-inferred custom model defaults. This is upgrade-routing proof, not a
live provider wire test, scanner verdict evaluation or runtime-image proof.

## Minimum CI image proof

Build the runtime directory context for both production platforms (Linux amd64
and arm64). Build logs must show exact-pin patch application and all installed
SkillSpector/AIG SDK wire-contract tests passing. Export the resulting image or
OCI layout successfully and retain its immutable digest; a cache-only build or
host-side Python tests are not final-image export proof. From the exported image,
smoke `skillspector --help`, `aig-skill-scan --help`, and `codex --version`.
No credentials or live paid calls are needed for these CI checks.

A consumer deliberately running `--sandbox off` may instead install these same
pinned, patched scanner sources into its host environment and execute the SDK
contract tests there. In that mode it does not depend on a runtime-image rollout;
it must not silently fall back to stock pip/uvx scanner packages.

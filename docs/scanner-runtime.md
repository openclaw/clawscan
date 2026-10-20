# Scanner runtime compatibility

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

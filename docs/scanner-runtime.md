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

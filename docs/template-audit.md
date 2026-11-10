# Template artifact audit contract

Use the separate built-in `clawhub-template` profile for an already validated,
extracted OpenClaw Template package. It runs **only `aig-mcp` as a scanner**.
The existing `clawhub` skill/plugin and `clawhub-aig` profiles are unchanged.
There are no Template-specific CLI flags or profile-name branches in the runner.

```sh
clawscan ./extracted-package --profile clawhub-template \
  --context ./trusted-job-context.json \
  --sandbox docker --sandbox-image <reviewed-runtime-image@sha256:digest> \
  --output ./audit/artifact.json
```

The image argument is an operator-selected immutable reference, not a literal
placeholder to run. Do not use a mutable `latest` tag for production qualification.
Credentials use the supported `LLM_API_KEY`/`OPENAI_API_KEY` setup; the existing
Codex evidence judge also requires its supported OpenAI/Codex credential setup.
Never source a package's environment or pass keys in arguments. Model defaults
remain `gpt-6.1-sol` / medium for AIG and the existing Sol/high verdict judge.

## Identity and exact scope

Directory dispatch recognizes the bounded, regular `package.json` selector
`openclaw.template`. It must name a safe package-relative file whose basename is
`CLAW.md`; a nested path such as `manifests/CLAW.md` is valid. The selector and
its parents must not be symlinks. A root `CLAW.md` alone does not select this lane.
The retired `openclaw.claw` selector is rejected, including when both exist.
Canonical Template directory identity takes precedence over root skill/plugin
markers because their content belongs to the composed Template. Pass the
**package directory**, not a manifest or a nested bundled skill/plugin path.
Classification is not Template admission, publisher verification or a grant of
privileges. The registry must independently validate the full Template schema,
frontmatter, archive entries and exact artifact digest before invoking ClawScan.

The adapter stages all shipped files in a private `template/` directory,
including `node_modules`, compiled code, hidden files, `.git/` and
`clawscan-results/`. The plugin adapter still excludes `node_modules`; that
exclusion does **not** apply to Templates. Existing bounds fail closed rather
than truncate: 20,000 files, 256 MiB total and 64 MiB per regular file, plus
existing non-regular-entry and escaping-symlink protections. The scanner runs
outside the target working directory, so shipped `.env` is not its startup
configuration. The original package is never installed or executed. Each
Template scanner command has the same 30-minute budget as a whole plugin.

The Template-specific AIG prompt covers:

- `CLAW.md` as agent instructions as well as configuration;
- `BOOTSTRAP.md`, profiles, automations/scheduled tasks, workspace instruction
  files and their interactions (capabilities, persistence, exfiltration);
- every bundled skill, plugin, hook, script and compiled/vendored code;
- shipped external-source/download/execution instructions as findings to assess,
  **without executing them**.

ClawScan does not resolve, download, install or recursively scan external
references, and does not fetch ClawHub dependency audit results. A reference alone
is neither evidence of malice nor proof of safety. Only the contents actually
shipped, including any instruction to retrieve or execute other code, are audited.
The scanner prompt instructs static inspection only; security depends on the
reviewed patched runtime's read-only tool allowlist and confinement, not on that
instruction alone. See [scanner isolation](scanners.md#plugin-code-audit-with-aig-mcp).

## Native evidence versus publication verdict

Tencent Zhuque Lab’s AIG MCP 0.2.0 emits **SARIF 2.1.0, not a publication verdict**.
The upstream [CLI entry](https://github.com/Tencent/AI-Infra-Guard/blob/main/mcp-scan/mcp_scan/main.py)
and [SARIF formatter](https://github.com/Tencent/AI-Infra-Guard/blob/main/mcp-scan/mcp_scan/utils/sarif_formatter.py)
were inspected for the standalone final-result semantics. The pinned adapter
and real-CLI runtime tests (`docker/clawscan-runtime/tests/test_aig_mcp_entry_network.py`)
exercise its final-report conversion: explicit `<empty>` produces no results;
parsed `<vuln>` findings produce SARIF; refusal, malformed findings and unusable
final reports fail in the patched runtime.

Its native document has `version: "2.1.0"` and a run with
`tool.driver.name: "aig-mcp-scan"` / `version: "0.2.0"`,
`properties.scanNote: "complete"`, advisory `properties.securityScore`, and
`results[]` containing `ruleId` (MCP01–MCP10, supplemental or upstream dynamic IDs),
SARIF `level`, `message.text`,
`locations[].physicalLocation` and upstream finding properties such as
`description`, `severity` and optional `suggestion`. Reports also preserve upstream
`partialFingerprints` and run metadata (`primaryLanguage`, `llm`, `startTime`,
`endTime`). Do not restrict or rewrite upstream rule IDs. Preserve the raw JSON. Scores, finding severities
and successful execution are **not** a benign/suspicious/malicious decision.
ClawScan's existing severity-based prediction is benchmark-only; this profile
adds no severity-to-malicious rule.

For compatibility, this profile explicitly retains the **existing evidence-only
Codex verdict judge**, using the unchanged `clawhub/evidence-judge.md` and
`clawhub/evidence-judge.schema.json` (same resolved command as `clawhub`).
It receives raw scanner reports/status/error and host-path-free run context;
there is no artifact copy, file/shell/web/code tool access or external dependency
lookup. This is result-to-verdict adjudication, **not a second whole-artifact
review**. Its existing intent-aware policy and uncertainty handling remain the
publication authority; ordinary vulnerabilities are not automatically malice.
The unchanged evidence-only overview explains that verdict and is advisory;
its failure never changes verdict/gate/run completion. `--no-overview` skips it.

Consumers should require, in the normal `clawscan-run-v1` artifact:

1. The expected exact source/runtime qualification, successful process/run
   completion and existing cleanup/integrity protections. Verify the original
   archive/extracted artifact binding before and after the scan; do not treat
   package-authored identity or run context as a trusted publisher claim.
2. `profile: "clawhub-template"` and `target.kind: "template"`; select this
   expected lane from trusted registry family/admission state, not package text.
3. Exactly the `aig-mcp` scanner, `status: "completed"` and its unchanged
   `raw` SARIF with the expected driver, one run and `scanNote: "complete"`.
4. A completed judge with the expected shared prompt/schema hashes and a valid
   `judge.result`: `verdict` (`benign | suspicious | malicious`),
   `confidence` (`high | medium | low`), all five `dimensions` with status and
   numeric confidence, and `scan_findings_in_context` preserving rule/scanner IDs.
   Optional readable prose comes from `overview.result`, never the AIG score.

Use the registry's existing strict artifact validator and verdict-to-public-DTO
mapping. A missing/wrong profile, unsupported target, skipped/failed scanner,
malformed or incomplete SARIF, failed judge, cancellation or timeout is an
operational failure, not a clean verdict. Existing adapter stderr/iteration,
provider-error and imported-SARIF checks still apply. Imported fixture reports
cannot prove the originating scanner logs/coverage; use them for tests, not as
proof a live scan completed. No partial report is silently accepted as clean.

## Source and runtime rollout

The new profile, target classification and Template prompt are **embedded in the
ClawScan Go binary**. They are not present in source commit
`80d11a34a97a9181213c806fc3013123360f9012` or an image embedding that binary.
Passing `--profile clawhub-template` to that old binary cannot activate this
implementation. Supplying a new YAML profile alone also cannot add the target
classification, full staging or scanner prompt.

No scanner Python patch or runtime tool-version change is required by this
implementation. A candidate host Go binary can dispatch AIG/Codex commands into
an independently qualified existing patched immutable scanner runtime. However,
a worker that re-enters `clawscan` inside its immutable image needs a new,
reviewed source-to-image/binary binding before advancing its ClawScan source pin.
Do not merely relabel the old image or weaken qualification to admit a new pin.
Build/publication, image smoke, credentialed provider smoke and deployment are
separate authorized rollout gates; tests with recorded Docker commands are not
a substitute for actual container qualification.

Fixture-backed tests cover benign mixed content, malicious shipped bootstrap,
automation and download instructions, external ClawHub references without
recursive scanning, byte-exact staging and evidence-only profile dispatch. They
verify mechanics and policy wiring, not live-model detection quality.

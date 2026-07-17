package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/openclaw/clawscan/internal/profiles"
	"github.com/openclaw/clawscan/internal/runner"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, err.Error())
		os.Exit(1)
	}
}

func run() error {
	clawhubDir := flag.String("clawhub-dir", "", "Path to a ClawHub checkout")
	out := flag.String("out", "", "Optional JSON proof output path")
	outSystemPrompt := flag.String("out-system-prompt", "", "Optional exported system prompt path")
	outPrompt := flag.String("out-prompt", "", "Optional exported full judge prompt template path")
	outProductionPrompt := flag.String("out-production-prompt", "", "Optional exact ClawHub-rendered prompt path")
	outClawScanPrompt := flag.String("out-clawscan-prompt", "", "Optional exact ClawScan-rendered prompt path")
	outOutputSchema := flag.String("out-output-schema", "", "Optional exported output schema path")
	outSkillSpectorResult := flag.String("out-skillspector-result", "", "Optional exported SkillSpector fixture JSON path")
	fixturePath := flag.String("fixture", "", "Optional production context and scanner fixture JSON path")
	flag.Parse()
	if *clawhubDir == "" {
		return fmt.Errorf("missing required --clawhub-dir")
	}
	resolvedClawHubDir, err := resolveClawHubDir(*clawhubDir)
	if err != nil {
		return err
	}
	rendered, err := renderClawHubPrompt(resolvedClawHubDir)
	if err != nil {
		return err
	}
	clawScanPromptSource, clawScanOutputSchema, err := embeddedClawHubProfileFiles()
	if err != nil {
		return err
	}
	if !bytes.Equal(clawScanOutputSchema, rendered.OutputSchema) {
		return fmt.Errorf(
			"ClawHub output schema parity check failed: production sha256=%s clawscan sha256=%s",
			sha(string(rendered.OutputSchema)),
			sha(string(clawScanOutputSchema)),
		)
	}
	systemPrompt := rendered.SystemPrompt
	expected, actual, skillSpectorInput, fixtureLabel, err := renderParityInputs(
		resolvedClawHubDir,
		*fixturePath,
		rendered,
		clawScanPromptSource,
	)
	if err != nil {
		return err
	}
	if err := writeOptionalFile(*outProductionPrompt, []byte(expected)); err != nil {
		return err
	}
	if err := writeOptionalFile(*outClawScanPrompt, []byte(actual)); err != nil {
		return err
	}
	if actual != expected {
		return fmt.Errorf(
			"ClawHub prompt parity check failed: production sha256=%s clawscan sha256=%s; %s",
			sha(expected),
			sha(actual),
			firstPromptDifference(expected, actual),
		)
	}
	prompt, err := splitPrompt(systemPrompt, actual)
	if err != nil {
		return err
	}
	skillSpectorFixture, err := prettyJSON(skillSpectorInput)
	if err != nil {
		return err
	}
	promptTemplate, err := buildPromptTemplate(actual, skillSpectorFixture)
	if err != nil {
		promptTemplate, err = buildPromptTemplateFromRendered(actual)
		if err != nil {
			return err
		}
	}
	schema := rendered.OutputSchema
	proof := map[string]any{
		"ok":                        true,
		"clawhubDir":                filepath.Clean(resolvedClawHubDir),
		"combinedPromptSha256":      sha(actual),
		"combinedPromptLength":      len(actual),
		"systemPromptSha256":        sha(systemPrompt),
		"systemPromptLength":        len(systemPrompt),
		"promptSha256":              sha(prompt),
		"promptLength":              len(prompt),
		"promptTemplateSha256":      sha(promptTemplate),
		"promptTemplateLength":      len(promptTemplate),
		"outputSchemaSha256":        sha(string(schema)),
		"fixture":                   fixtureLabel,
		"explicitSkillSpectorInput": true,
		"skillSpectorMarkerPresent": bytes.Contains([]byte(actual), []byte("SkillSpector findings supplied to Codex")),
		"productionPromptSha256":    sha(expected),
		"clawscanPromptSha256":      sha(actual),
	}
	encoded, err := json.MarshalIndent(proof, "", "  ")
	if err != nil {
		return err
	}
	if *out != "" {
		if err := os.MkdirAll(filepath.Dir(*out), 0o755); err != nil {
			return err
		}
		if err := os.WriteFile(*out, append(encoded, '\n'), 0o644); err != nil {
			return err
		}
	}
	if err := writeOptionalFile(*outSystemPrompt, []byte(systemPrompt)); err != nil {
		return err
	}
	if err := writeOptionalFile(*outPrompt, []byte(promptTemplate)); err != nil {
		return err
	}
	if err := writeOptionalFile(*outSkillSpectorResult, []byte(skillSpectorFixture)); err != nil {
		return err
	}
	if err := writeOptionalFile(*outOutputSchema, schema); err != nil {
		return err
	}
	fmt.Println(string(encoded))
	return nil
}

func firstPromptDifference(expected string, actual string) string {
	limit := min(len(expected), len(actual))
	index := 0
	for index < limit && expected[index] == actual[index] {
		index++
	}
	if index == limit && len(expected) == len(actual) {
		return "no differing byte found"
	}
	start := max(0, index-80)
	expectedEnd := min(len(expected), index+160)
	actualEnd := min(len(actual), index+160)
	return fmt.Sprintf(
		"first differing byte=%d production=%q clawscan=%q",
		index,
		expected[start:expectedEnd],
		actual[start:actualEnd],
	)
}

type parityFixture struct {
	Context      json.RawMessage `json:"context"`
	SkillSpector json.RawMessage `json:"skillspector"`
}

func renderParityInputs(
	clawhubDir string,
	fixturePath string,
	rendered clawHubPromptRender,
	clawScanPromptSource string,
) (expected string, actual string, skillSpectorInput any, fixtureLabel string, err error) {
	if fixturePath == "" {
		skillSpectorAnalysis := proofSkillSpectorAnalysis()
		actual, err := runner.RenderClawHubPrompt(clawScanPromptSource, runner.Artifact{
			Profile: "clawhub",
			Context: json.RawMessage(`{
				"targetKind":"skillVersion",
				"source":"publish",
				"hasMaliciousSignal":true,
				"trustedOpenClawPlugin":true,
				"injectionSignals":["html-comment-injection"],
				"skillSpectorCheckedAt":123
			}`),
			Scanners: map[string]runner.ScannerResult{
				"skillspector": {
					Status: "completed",
					Raw:    mustJSON(skillSpectorAnalysis),
				},
			},
		})
		if err != nil {
			return "", "", nil, "", err
		}
		return rendered.Prompt, actual, skillSpectorAnalysis, "synthetic", nil
	}

	resolvedFixturePath, err := filepath.Abs(fixturePath)
	if err != nil {
		return "", "", nil, "", err
	}
	raw, err := os.ReadFile(resolvedFixturePath)
	if err != nil {
		return "", "", nil, "", err
	}
	var fixture parityFixture
	if err := json.Unmarshal(raw, &fixture); err != nil {
		return "", "", nil, "", fmt.Errorf("parse parity fixture: %w", err)
	}
	if !json.Valid(fixture.Context) {
		return "", "", nil, "", fmt.Errorf("parity fixture context is not valid JSON")
	}
	context, err := parityFixtureContext(fixture)
	if err != nil {
		return "", "", nil, "", err
	}
	expected, err = renderClawHubFixturePrompt(clawhubDir, resolvedFixturePath)
	if err != nil {
		return "", "", nil, "", err
	}
	artifact := runner.Artifact{
		Profile: "clawhub",
		Context: context,
		Scanners: map[string]runner.ScannerResult{
			"skillspector": {Status: "completed", Raw: fixture.SkillSpector},
		},
	}
	actual, err = runner.RenderClawHubPrompt(clawScanPromptSource, artifact)
	if err != nil {
		return "", "", nil, "", err
	}
	if err := json.Unmarshal(fixture.SkillSpector, &skillSpectorInput); err != nil {
		return "", "", nil, "", fmt.Errorf("parse SkillSpector fixture: %w", err)
	}
	return expected, actual, skillSpectorInput, resolvedFixturePath, nil
}

func parityFixtureContext(fixture parityFixture) (json.RawMessage, error) {
	var context map[string]any
	if err := json.Unmarshal(fixture.Context, &context); err != nil {
		return nil, fmt.Errorf("parse parity fixture context: %w", err)
	}
	if _, ok := context["skillSpectorCheckedAt"]; !ok {
		var skillSpector map[string]any
		if err := json.Unmarshal(fixture.SkillSpector, &skillSpector); err != nil {
			return nil, fmt.Errorf("parse parity fixture SkillSpector result: %w", err)
		}
		if checkedAt, ok := skillSpector["checkedAt"]; ok {
			context["skillSpectorCheckedAt"] = checkedAt
		}
	}
	raw, err := json.Marshal(context)
	if err != nil {
		return nil, fmt.Errorf("encode parity fixture context: %w", err)
	}
	return raw, nil
}

func embeddedClawHubProfileFiles() (string, []byte, error) {
	dir, err := os.MkdirTemp("", "clawscan-profile-parity-*")
	if err != nil {
		return "", nil, err
	}
	defer os.RemoveAll(dir)
	opts, err := profiles.ResolveArgs([]string{"./skill", "--profile", "clawhub"}, dir)
	if err != nil {
		return "", nil, err
	}
	if opts.Judge == nil {
		return "", nil, fmt.Errorf("embedded clawhub profile has no judge")
	}
	prompt := opts.Judge.Files["clawhub/prompt.md"]
	schema := opts.Judge.Files["clawhub/output.schema.json"]
	if len(prompt) == 0 || len(schema) == 0 {
		return "", nil, fmt.Errorf("embedded clawhub profile is missing prompt or output schema")
	}
	return string(prompt), schema, nil
}

func mustJSON(value any) json.RawMessage {
	raw, err := json.Marshal(value)
	if err != nil {
		panic(err)
	}
	return raw
}

func renderClawHubFixturePrompt(clawhubDir string, fixturePath string) (string, error) {
	script := `
const clawhubDir = process.argv[1];
const fixturePath = process.argv[2];
const worker = await import(clawhubDir + "/scripts/security/run-codex-scan-worker.ts");
const fixture = JSON.parse(await Bun.file(fixturePath).text());
const context = fixture.context ?? {};
const skillSpector = fixture.skillspector == null
  ? undefined
  : worker.normalizeSkillSpectorAnalysis(
      JSON.stringify(fixture.skillspector),
      fixture.skillspector.checkedAt,
    );
const job = {
  job: {
    targetKind: context.targetKind ?? "skillVersion",
    source: context.source ?? "publish",
    hasMaliciousSignal: Boolean(context.hasMaliciousSignal),
  },
  target: {
    trustedOpenClawPlugin: Boolean(context.trustedOpenClawPlugin),
    version: {
      vtAnalysis: fixture.virustotal ?? null,
      skillSpectorAnalysis: skillSpector ?? null,
    },
  },
};
process.stdout.write(worker.buildPrompt(
  job,
  context.injectionSignals ?? [],
  skillSpector,
));
`
	cmd := exec.Command("bun", "-e", script, "--", clawhubDir, fixturePath)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	if err != nil {
		return "", fmt.Errorf("render ClawHub fixture prompt with bun: %w: %s", err, stderr.String())
	}
	return string(out), nil
}

func splitPrompt(systemPrompt string, fullPrompt string) (string, error) {
	prefix := systemPrompt + "\n\n"
	if !strings.HasPrefix(fullPrompt, prefix) {
		return "", fmt.Errorf("ClawHub prompt does not start with system prompt plus blank line")
	}
	return strings.TrimPrefix(fullPrompt, prefix), nil
}

func writeOptionalFile(path string, content []byte) error {
	if path == "" {
		return nil
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	return os.WriteFile(path, content, 0o644)
}

func buildPromptTemplate(prompt string, skillSpectorFixture string) (string, error) {
	const placeholder = "{{ scanners.skillspector }}"
	prompt = strings.Replace(prompt, skillSpectorFixture, placeholder, 1)
	if !strings.Contains(prompt, placeholder) {
		return "", fmt.Errorf("failed to build exported prompt template with scanner placeholder %s", placeholder)
	}
	return prompt, nil
}

func buildPromptTemplateFromRendered(prompt string) (string, error) {
	const (
		label       = "SkillSpector findings supplied to Codex:"
		placeholder = "{{ scanners.skillspector }}"
	)
	prefix := label + "\n```json\n"
	start := strings.Index(prompt, prefix)
	if start == -1 {
		return "", fmt.Errorf("rendered prompt missing %s block", label)
	}
	contentStart := start + len(prefix)
	contentEndOffset := strings.Index(prompt[contentStart:], "\n```")
	if contentEndOffset == -1 {
		return "", fmt.Errorf("rendered prompt has unterminated %s block", label)
	}
	contentEnd := contentStart + contentEndOffset
	return prompt[:contentStart] + placeholder + prompt[contentEnd:], nil
}

func prettyJSON(value any) (string, error) {
	raw, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		return "", err
	}
	return string(raw), nil
}

func resolveClawHubDir(path string) (string, error) {
	return filepath.Abs(path)
}

type clawHubPromptRender struct {
	SystemPrompt string
	Prompt       string
	OutputSchema []byte
}

var (
	workerSchemaPathPattern      = regexp.MustCompile(`(?m)^\s*const\s+schemaPath\s*=\s*join\(\s*root\s*,\s*"([^"]+)"\s*\)`)
	workerOutputSchemaArgPattern = regexp.MustCompile(`(?s)"--output-schema"\s*,\s*schemaPath`)
)

func renderClawHubPrompt(clawhubDir string) (clawHubPromptRender, error) {
	outputSchema, err := readClawHubWorkerOutputSchema(clawhubDir)
	if err != nil {
		return clawHubPromptRender{}, err
	}
	script := `
const clawhubDir = process.argv[1];
const worker = await import(clawhubDir + "/scripts/security/run-codex-scan-worker.ts");
const securityPrompt = await import(clawhubDir + "/convex/lib/securityPrompt.ts");
const skillSpectorAnalysis = worker.normalizeSkillSpectorAnalysis(JSON.stringify({
  status: "suspicious",
  score: 55,
  recommendation: "DO_NOT_INSTALL",
  issueCount: 1,
  issues: [{ issueId: "SDI-1", severity: "HIGH", explanation: "Mismatch" }],
}), 123);
const job = {
  job: {
    _id: "job123",
    hasMaliciousSignal: true,
    leaseToken: "lease-secret",
    source: "publish",
    targetKind: "skillVersion",
    waitForVtUntil: 0,
  },
  target: {
    trustedOpenClawPlugin: true,
    version: {
      vtAnalysis: {
        status: "suspicious",
        source: "engines",
        metadata: { stats: { malicious: 1, suspicious: 0, harmless: 12 } },
      },
    },
  },
};
console.log(JSON.stringify({
  systemPrompt: securityPrompt.SKILL_SECURITY_EVALUATOR_SYSTEM_PROMPT,
  prompt: worker.buildPrompt(job, ["html-comment-injection"], skillSpectorAnalysis),
}));
`
	cmd := exec.Command("bun", "-e", script, "--", clawhubDir)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	if err != nil {
		return clawHubPromptRender{}, fmt.Errorf("render ClawHub prompt with bun: %w: %s", err, stderr.String())
	}
	var payload struct {
		SystemPrompt string `json:"systemPrompt"`
		Prompt       string `json:"prompt"`
	}
	if err := json.Unmarshal(out, &payload); err != nil {
		return clawHubPromptRender{}, err
	}
	return clawHubPromptRender{SystemPrompt: payload.SystemPrompt, Prompt: payload.Prompt, OutputSchema: outputSchema}, nil
}

func readClawHubWorkerOutputSchema(clawhubDir string) ([]byte, error) {
	workerPath := filepath.Join(clawhubDir, "scripts/security/run-codex-scan-worker.ts")
	workerSource, err := os.ReadFile(workerPath)
	if err != nil {
		return nil, err
	}
	schemaRelPath, err := clawHubWorkerOutputSchemaRelPath(string(workerSource))
	if err != nil {
		return nil, fmt.Errorf("resolve ClawHub worker output schema: %w", err)
	}
	return os.ReadFile(filepath.Join(clawhubDir, filepath.FromSlash(schemaRelPath)))
}

func clawHubWorkerOutputSchemaRelPath(workerSource string) (string, error) {
	if !workerOutputSchemaArgPattern.MatchString(workerSource) {
		return "", fmt.Errorf("worker no longer passes schemaPath to --output-schema")
	}
	matches := workerSchemaPathPattern.FindStringSubmatch(workerSource)
	if matches == nil {
		return "", fmt.Errorf("worker schemaPath declaration not found")
	}
	return matches[1], nil
}

func proofSkillSpectorAnalysis() skillSpectorAnalysis {
	return skillSpectorAnalysis{
		Status:         "suspicious",
		Score:          55,
		Recommendation: "DO_NOT_INSTALL",
		IssueCount:     1,
		CheckedAt:      123,
		Issues: []skillSpectorIssue{{
			IssueID:     "SDI-1",
			Severity:    "HIGH",
			Explanation: "Mismatch",
		}},
	}
}

type skillSpectorAnalysis struct {
	Status         string              `json:"status"`
	Score          int                 `json:"score"`
	Recommendation string              `json:"recommendation"`
	IssueCount     int                 `json:"issueCount"`
	CheckedAt      int                 `json:"checkedAt"`
	Issues         []skillSpectorIssue `json:"issues"`
}

type skillSpectorIssue struct {
	IssueID     string `json:"issueId"`
	Severity    string `json:"severity"`
	Explanation string `json:"explanation"`
}

func sha(value string) string {
	sum := sha256.Sum256([]byte(value))
	return hex.EncodeToString(sum[:])
}

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

	"github.com/openclaw/clawscan/internal/clawhubprompt"
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
	outOutputSchema := flag.String("out-output-schema", "", "Optional exported output schema path")
	outRequest := flag.String("out-request", "", "Optional exported canonical request JSON path")
	outSkillSpectorResult := flag.String("out-skillspector-result", "", "Optional exported SkillSpector fixture JSON path")
	outVirusTotalResult := flag.String("out-virustotal-result", "", "Optional exported VirusTotal fixture JSON path")
	model := flag.String("model", "openai/gpt-5.5", "Model id for canonical request hashing")
	reasoning := flag.String("reasoning", "high", "Reasoning effort for canonical request hashing")
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
	systemPrompt := rendered.SystemPrompt
	expected := rendered.Prompt
	job := proofJob()
	skillSpectorAnalysis := proofSkillSpectorAnalysis()
	actual, err := clawhubprompt.Build(systemPrompt, job, []string{"html-comment-injection"}, skillSpectorAnalysis)
	if err != nil {
		return err
	}
	if actual != expected {
		return fmt.Errorf("ClawHub prompt parity check failed")
	}
	prompt, err := splitPrompt(systemPrompt, actual)
	if err != nil {
		return err
	}
	vtFixture, err := prettyJSON(job.Target.Version.VTAnalysis)
	if err != nil {
		return err
	}
	skillSpectorFixture, err := prettyJSON(skillSpectorAnalysis)
	if err != nil {
		return err
	}
	promptTemplate, err := buildPromptTemplate(actual, vtFixture, skillSpectorFixture)
	if err != nil {
		return err
	}
	schema := rendered.OutputSchema
	requestBody, err := runner.OpenAIRequestBody(runner.OpenAIRequestOptions{Model: *model, Reasoning: *reasoning}, systemPrompt, prompt, schema)
	if err != nil {
		return err
	}
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
		"requestSha256":             sha(string(requestBody)),
		"model":                     *model,
		"reasoning":                 *reasoning,
		"explicitSkillSpectorInput": true,
		"skillSpectorMarkerPresent": bytes.Contains([]byte(actual), []byte("SkillSpector findings supplied to Codex")),
		"skillSpectorIssuePresent":  bytes.Contains([]byte(actual), []byte("SDI-1")),
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
	if err := writeOptionalFile(*outVirusTotalResult, []byte(vtFixture)); err != nil {
		return err
	}
	if err := writeOptionalFile(*outOutputSchema, schema); err != nil {
		return err
	}
	if err := writeOptionalFile(*outRequest, append(requestBody, '\n')); err != nil {
		return err
	}
	fmt.Println(string(encoded))
	return nil
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

func buildPromptTemplate(prompt string, vtFixture string, skillSpectorFixture string) (string, error) {
	replacements := []struct {
		fixture     string
		placeholder string
	}{
		{fixture: vtFixture, placeholder: "{{ scanners.virustotal }}"},
		{fixture: skillSpectorFixture, placeholder: "{{ scanners.skillspector }}"},
	}
	for _, replacement := range replacements {
		prompt = strings.Replace(prompt, replacement.fixture, replacement.placeholder, 1)
		if !strings.Contains(prompt, replacement.placeholder) {
			return "", fmt.Errorf("failed to build exported prompt template with scanner placeholder %s", replacement.placeholder)
		}
	}
	return prompt, nil
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
const skillSpectorAnalysis = {
  status: "suspicious",
  score: 55,
  recommendation: "DO_NOT_INSTALL",
  issueCount: 1,
  checkedAt: 123,
  issues: [{ issueId: "SDI-1", severity: "HIGH", explanation: "Mismatch" }],
};
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

func proofJob() clawhubprompt.Job {
	return clawhubprompt.Job{
		Job: clawhubprompt.JobMetadata{
			TargetKind:         "skillVersion",
			Source:             "publish",
			HasMaliciousSignal: true,
		},
		Target: clawhubprompt.Target{
			TrustedOpenClawPlugin: true,
			Version: &clawhubprompt.Version{
				VTAnalysis: vtAnalysis{
					Status: "suspicious",
					Source: "engines",
					Metadata: vtMetadata{
						Stats: vtStats{Malicious: 1, Suspicious: 0, Harmless: 12},
					},
				},
			},
		},
	}
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

type vtAnalysis struct {
	Status   string     `json:"status"`
	Source   string     `json:"source"`
	Metadata vtMetadata `json:"metadata"`
}

type vtMetadata struct {
	Stats vtStats `json:"stats"`
}

type vtStats struct {
	Malicious  int `json:"malicious"`
	Suspicious int `json:"suspicious"`
	Harmless   int `json:"harmless"`
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

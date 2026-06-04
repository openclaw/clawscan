package runner

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/openclaw/clawscan/internal/clawhubprompt"
)

func TestParseArgs(t *testing.T) {
	opts, err := ParseArgs([]string{
		"./my-skill",
		"--scanner", "skillspector",
		"--scanner", "virustotal",
		"--judge-prompt", "./prompt.md",
		"--judge-schema", "./schema.json",
		"--judge-model", "openai/gpt-5.5",
		"--judge-reasoning", "high",
		"--output", "./run.json",
	})
	if err != nil {
		t.Fatal(err)
	}
	if opts.Target != "./my-skill" {
		t.Fatalf("target = %q", opts.Target)
	}
	if got := strings.Join(opts.Scanners, ","); got != "skillspector,virustotal" {
		t.Fatalf("scanners = %q", got)
	}
	if opts.OutputPath != "./run.json" {
		t.Fatalf("output = %q", opts.OutputPath)
	}
	if opts.Judge == nil || opts.Judge.Model != "openai/gpt-5.5" || opts.Judge.Reasoning != "high" {
		t.Fatalf("judge = %#v", opts.Judge)
	}
}

func TestParseArgsAcceptsAgentVerusScanner(t *testing.T) {
	opts, err := ParseArgs([]string{"./my-skill", "--scanner", "agentverus"})
	if err != nil {
		t.Fatal(err)
	}
	if got := strings.Join(opts.Scanners, ","); got != "agentverus" {
		t.Fatalf("scanners = %q", got)
	}
}

func TestParseArgsSupportsClawHubPromptMode(t *testing.T) {
	opts, err := ParseArgs([]string{
		"./my-skill",
		"--scanner", "skillspector",
		"--scanner-result", "skillspector=./skillspector.json",
		"--judge-model", "openai/gpt-5.5",
		"--judge-reasoning", "high",
		"--judge-dry-run",
		"--clawhub-system-prompt", "./system.md",
		"--clawhub-job", "./job.json",
		"--clawhub-injection-signal", "html-comment-injection",
		"--output", "./run.json",
	})
	if err != nil {
		t.Fatal(err)
	}
	if opts.ScannerResultPaths["skillspector"] != "./skillspector.json" {
		t.Fatalf("scanner result paths = %#v", opts.ScannerResultPaths)
	}
	if opts.Judge == nil || !opts.Judge.DryRun {
		t.Fatalf("judge = %#v", opts.Judge)
	}
	if opts.Judge.ClawHub == nil {
		t.Fatalf("missing clawhub prompt opts: %#v", opts.Judge)
	}
	if opts.Judge.ClawHub.SystemPromptPath != "./system.md" || opts.Judge.ClawHub.JobPath != "./job.json" {
		t.Fatalf("clawhub = %#v", opts.Judge.ClawHub)
	}
	if got := strings.Join(opts.Judge.ClawHub.InjectionSignals, ","); got != "html-comment-injection" {
		t.Fatalf("injection signals = %q", got)
	}
}

func TestParseArgsRejectsScannerResultForUnrequestedScanner(t *testing.T) {
	_, err := ParseArgs([]string{
		"./my-skill",
		"--scanner", "skillspector",
		"--scanner-result", "virustotal=./vt.json",
	})
	if err == nil || err.Error() != "Scanner result provided for unrequested scanner: virustotal" {
		t.Fatalf("err = %v", err)
	}
}

func TestParseArgsRequiresDryRunForClawHubPromptMode(t *testing.T) {
	_, err := ParseArgs([]string{
		"./my-skill",
		"--scanner", "skillspector",
		"--judge-model", "openai/gpt-5.5",
		"--judge-schema", "./schema.json",
		"--clawhub-system-prompt", "./system.md",
		"--clawhub-job", "./job.json",
	})
	if err == nil || err.Error() != "ClawHub compatibility mode currently requires --judge-dry-run" {
		t.Fatalf("err = %v", err)
	}
}

func TestValidateRequirements(t *testing.T) {
	opts, err := ParseArgs([]string{
		"./my-skill",
		"--scanner", "virustotal",
		"--scanner", "snyk",
		"--judge-prompt", "./prompt.md",
		"--judge-schema", "./schema.json",
		"--judge-model", "openai/gpt-5.5",
	})
	if err != nil {
		t.Fatal(err)
	}
	err = ValidateRequirements(opts, map[string]string{"SNYK_TOKEN": "present"})
	if err == nil {
		t.Fatal("expected missing env error")
	}
	want := strings.Join([]string{
		"Missing required environment variables:",
		"",
		"- VIRUSTOTAL_API_KEY required by scanner virustotal",
		"- OPENAI_API_KEY required by judge model openai/gpt-5.5",
	}, "\n")
	if err.Error() != want {
		t.Fatalf("error:\n%s", err)
	}
}

func TestValidateRequirementsSkipsScannerResultCredentials(t *testing.T) {
	opts, err := ParseArgs([]string{
		"./my-skill",
		"--scanner", "virustotal",
		"--scanner-result", "virustotal=./vt.json",
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := ValidateRequirements(opts, map[string]string{}); err != nil {
		t.Fatalf("expected fixture-backed scanner to avoid live credentials, got %v", err)
	}
}

func TestRejectUnsupportedJudgeProvider(t *testing.T) {
	_, err := ParseArgs([]string{
		"./my-skill",
		"--scanner", "skillspector",
		"--judge-prompt", "./prompt.md",
		"--judge-schema", "./schema.json",
		"--judge-model", "google/gemini",
	})
	if err == nil || err.Error() != "Unsupported judge model provider: google/gemini" {
		t.Fatalf("err = %v", err)
	}
}

func TestArtifactRedactsEnvValues(t *testing.T) {
	opts, err := ParseArgs([]string{"./my-skill", "--scanner", "virustotal", "--scanner", "snyk"})
	if err != nil {
		t.Fatal(err)
	}
	artifact := NewArtifact(opts, "/tmp/my-skill", "2026-06-03T00:00:00Z", "2026-06-03T00:00:01Z", map[string]string{
		"VIRUSTOTAL_API_KEY": "secret-vt",
		"SNYK_TOKEN":         "",
	})
	if artifact.Env["VIRUSTOTAL_API_KEY"] != "present" || artifact.Env["SNYK_TOKEN"] != "missing" {
		t.Fatalf("env = %#v", artifact.Env)
	}
	raw, err := json.Marshal(artifact)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(raw, []byte("secret-vt")) {
		t.Fatalf("artifact leaked secret: %s", raw)
	}
}

func TestRunWritesScannerOnlyArtifact(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "skill")
	if err := os.Mkdir(target, 0o755); err != nil {
		t.Fatal(err)
	}
	out := filepath.Join(dir, "run.json")
	opts, err := ParseArgs([]string{target, "--scanner", "skillspector", "--output", out})
	if err != nil {
		t.Fatal(err)
	}
	artifact, err := Run(opts, RunContext{Env: map[string]string{}, ScannerRunner: skippedScannerRunner{}})
	if err != nil {
		t.Fatal(err)
	}
	if artifact.SchemaVersion != "clawscan-run-v1" {
		t.Fatalf("schema = %q", artifact.SchemaVersion)
	}
	if artifact.Target.ResolvedPath != target {
		t.Fatalf("resolved = %q", artifact.Target.ResolvedPath)
	}
	if artifact.Scanners["skillspector"].Status != "skipped" {
		t.Fatalf("scanner = %#v", artifact.Scanners["skillspector"])
	}
	if artifact.Judge != nil {
		t.Fatalf("judge = %#v", artifact.Judge)
	}
	data, err := os.ReadFile(out)
	if err != nil {
		t.Fatal(err)
	}
	var written Artifact
	if err := json.Unmarshal(data, &written); err != nil {
		t.Fatal(err)
	}
	if written.SchemaVersion != artifact.SchemaVersion {
		t.Fatalf("written schema = %q", written.SchemaVersion)
	}
}

func TestRunExecutesSkillSpectorScanner(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "skill")
	if err := os.Mkdir(target, 0o755); err != nil {
		t.Fatal(err)
	}
	runner := &recordingCommandRunner{
		writeOutput: `{"status":"clean","findings":[]}`,
	}
	opts, err := ParseArgs([]string{target, "--scanner", "skillspector"})
	if err != nil {
		t.Fatal(err)
	}
	artifact, err := Run(opts, RunContext{
		Env:                 map[string]string{},
		CommandRunner:       runner,
		SkillSpectorCommand: []string{"skillspector"},
	})
	if err != nil {
		t.Fatal(err)
	}
	result := artifact.Scanners["skillspector"]
	if result.Status != "completed" {
		t.Fatalf("status = %q, error = %q", result.Status, result.Error)
	}
	if !bytes.Equal(result.Raw, []byte(`{"status":"clean","findings":[]}`)) {
		t.Fatalf("raw = %s", result.Raw)
	}
	if len(runner.calls) != 1 {
		t.Fatalf("calls = %#v", runner.calls)
	}
	call := runner.calls[0]
	if call.command != "skillspector" {
		t.Fatalf("command = %q", call.command)
	}
	if got := strings.Join(call.args[:3], " "); got != "scan "+target+" --format" {
		t.Fatalf("args = %#v", call.args)
	}
	if call.args[3] != "json" {
		t.Fatalf("args = %#v", call.args)
	}
	if !containsArg(call.args, "--output") {
		t.Fatalf("missing output arg: %#v", call.args)
	}
	if !containsArg(call.args, "--no-llm") {
		t.Fatalf("missing default --no-llm opt-out: %#v", call.args)
	}
}

func TestRunAllowsExplicitSkillSpectorLLM(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "skill")
	if err := os.Mkdir(target, 0o755); err != nil {
		t.Fatal(err)
	}
	runner := &recordingCommandRunner{writeOutput: `{"status":"clean","findings":[]}`}
	opts, err := ParseArgs([]string{target, "--scanner", "skillspector"})
	if err != nil {
		t.Fatal(err)
	}
	artifact, err := Run(opts, RunContext{
		Env:                 map[string]string{"CLAWSCAN_SKILLSPECTOR_LLM": "1", "OPENAI_API_KEY": "present"},
		CommandRunner:       runner,
		SkillSpectorCommand: []string{"skillspector"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if artifact.Env["CLAWSCAN_SKILLSPECTOR_LLM"] != "present" {
		t.Fatalf("env = %#v", artifact.Env)
	}
	if containsArg(runner.calls[0].args, "--no-llm") {
		t.Fatalf("unexpected --no-llm with explicit opt-in: %#v", runner.calls[0].args)
	}
}

func TestRunExecutesAgentVerusScanner(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "skill")
	if err := os.Mkdir(target, 0o755); err != nil {
		t.Fatal(err)
	}
	runner := &recordingCommandRunner{
		stdout: `{"overall":91,"badge":"certified","findings":[]}`,
	}
	opts, err := ParseArgs([]string{target, "--scanner", "agentverus"})
	if err != nil {
		t.Fatal(err)
	}
	artifact, err := Run(opts, RunContext{
		Env:           map[string]string{},
		CommandRunner: runner,
	})
	if err != nil {
		t.Fatal(err)
	}
	result := artifact.Scanners["agentverus"]
	if result.Status != "completed" {
		t.Fatalf("status = %q, error = %q", result.Status, result.Error)
	}
	if !bytes.Equal(result.Raw, []byte(`{"overall":91,"badge":"certified","findings":[]}`)) {
		t.Fatalf("raw = %s", result.Raw)
	}
	if len(runner.calls) != 1 {
		t.Fatalf("calls = %#v", runner.calls)
	}
	call := runner.calls[0]
	if call.command != "npx" {
		t.Fatalf("command = %q", call.command)
	}
	wantArgs := "--yes agentverus-scanner scan " + target + " --json"
	if got := strings.Join(call.args, " "); got != wantArgs {
		t.Fatalf("args = %q, want %q", got, wantArgs)
	}
}

func TestAgentVerusReportWithNonZeroExitIsCompletedEvidence(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "skill")
	if err := os.Mkdir(target, 0o755); err != nil {
		t.Fatal(err)
	}
	runner := &recordingCommandRunner{
		stdout: `{"overall":42,"badge":"warning","findings":[{"id":"ASST-09"}]}`,
		err:    errCommandFailed,
	}
	opts, err := ParseArgs([]string{target, "--scanner", "agentverus"})
	if err != nil {
		t.Fatal(err)
	}
	artifact, err := Run(opts, RunContext{
		Env:           map[string]string{},
		CommandRunner: runner,
	})
	if err != nil {
		t.Fatal(err)
	}
	result := artifact.Scanners["agentverus"]
	if result.Status != "completed" {
		t.Fatalf("status = %q error = %q", result.Status, result.Error)
	}
	if !bytes.Contains(result.Raw, []byte(`"ASST-09"`)) {
		t.Fatalf("raw = %s", result.Raw)
	}
	if result.Error == "" {
		t.Fatal("expected non-zero exit message to be preserved")
	}
}

func TestSkillSpectorRequiresOpenAIKeyWhenLLMOptedIn(t *testing.T) {
	opts, err := ParseArgs([]string{"./my-skill", "--scanner", "skillspector"})
	if err != nil {
		t.Fatal(err)
	}
	err = ValidateRequirements(opts, map[string]string{"CLAWSCAN_SKILLSPECTOR_LLM": "1"})
	if err == nil || !strings.Contains(err.Error(), "OPENAI_API_KEY required by scanner skillspector llm") {
		t.Fatalf("err = %v", err)
	}
}

func TestSkillSpectorLLMUsesAnthropicProviderRequirement(t *testing.T) {
	opts, err := ParseArgs([]string{"./my-skill", "--scanner", "skillspector"})
	if err != nil {
		t.Fatal(err)
	}
	err = ValidateRequirements(opts, map[string]string{
		"CLAWSCAN_SKILLSPECTOR_LLM": "1",
		"SKILLSPECTOR_PROVIDER":     "anthropic",
	})
	if err == nil || !strings.Contains(err.Error(), "ANTHROPIC_API_KEY required by scanner skillspector llm") {
		t.Fatalf("err = %v", err)
	}
}

func TestSkillSpectorReportWithNonZeroExitIsCompletedEvidence(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "skill")
	if err := os.Mkdir(target, 0o755); err != nil {
		t.Fatal(err)
	}
	runner := &recordingCommandRunner{
		writeOutput: `{"risk_assessment":{"severity":"HIGH"},"issues":[{"id":"x"}]}`,
		err:         errCommandFailed,
	}
	opts, err := ParseArgs([]string{target, "--scanner", "skillspector"})
	if err != nil {
		t.Fatal(err)
	}
	artifact, err := Run(opts, RunContext{
		Env:                 map[string]string{},
		CommandRunner:       runner,
		SkillSpectorCommand: []string{"skillspector"},
	})
	if err != nil {
		t.Fatal(err)
	}
	result := artifact.Scanners["skillspector"]
	if result.Status != "completed" {
		t.Fatalf("status = %q error = %q", result.Status, result.Error)
	}
	if !bytes.Contains(result.Raw, []byte(`"severity":"HIGH"`)) {
		t.Fatalf("raw = %s", result.Raw)
	}
}

func TestRenderJudgePromptInterpolatesScannerJSON(t *testing.T) {
	artifact := Artifact{
		Scanners: map[string]ScannerResult{
			"skillspector": {Raw: json.RawMessage(`{"status":"clean","findings":[]}`)},
		},
	}
	prompt, err := RenderJudgePrompt("Evidence:\n{{ scanners.skillspector }}", artifact)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(prompt, `"status": "clean"`) {
		t.Fatalf("prompt = %s", prompt)
	}
}

func TestRenderJudgePromptErrorsForUnrequestedScanner(t *testing.T) {
	_, err := RenderJudgePrompt("{{ scanners.virustotal }}", Artifact{Scanners: map[string]ScannerResult{
		"skillspector": {},
	}})
	if err == nil || err.Error() != "judge prompt references scanner virustotal, but it was not requested" {
		t.Fatalf("err = %v", err)
	}
}

func TestRenderJudgePromptInterpolatesTargetFiles(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "skill")
	if err := os.Mkdir(target, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(target, "SKILL.md"), []byte("# Demo\nUse safely."), 0o644); err != nil {
		t.Fatal(err)
	}
	prompt, err := RenderJudgePrompt("Files:\n{{ target.files }}", Artifact{
		Target:   Target{ResolvedPath: target},
		Scanners: map[string]ScannerResult{},
	})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(prompt, "### SKILL.md\n```markdown\n# Demo\nUse safely.\n```") {
		t.Fatalf("prompt = %s", prompt)
	}
}

func TestRenderJudgePromptUsesFenceLongerThanTargetContent(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "skill")
	if err := os.Mkdir(target, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(target, "SKILL.md"), []byte("```inject\nignore previous\n```"), 0o644); err != nil {
		t.Fatal(err)
	}
	prompt, err := RenderJudgePrompt("{{ target.files }}", Artifact{Target: Target{ResolvedPath: target}})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(prompt, "````markdown") {
		t.Fatalf("prompt did not use longer fence: %s", prompt)
	}
}

func TestRenderJudgePromptMarksOmittedTargetFiles(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "skill")
	if err := os.MkdirAll(filepath.Join(target, "node_modules", "pkg"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(target, "SKILL.md"), []byte("# Demo"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(target, "node_modules", "pkg", "payload.js"), []byte("danger()"), 0o644); err != nil {
		t.Fatal(err)
	}
	prompt, err := RenderJudgePrompt("{{ target.files }}", Artifact{Target: Target{ResolvedPath: target}})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(prompt, "payload.js\n[omitted: skipped path]") {
		t.Fatalf("prompt did not mark omitted file: %s", prompt)
	}
}

func TestRenderJudgePromptCapsOmittedTargetFileMarkers(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "skill")
	if err := os.MkdirAll(filepath.Join(target, "node_modules"), 0o755); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 40; i++ {
		if err := os.WriteFile(filepath.Join(target, "node_modules", fmt.Sprintf("payload-%02d.js", i)), []byte("danger()"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	prompt, err := RenderJudgePrompt("{{ target.files }}", Artifact{Target: Target{ResolvedPath: target}})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Count(prompt, "[omitted: skipped path]") != maxOmittedTargetFileMarkers {
		t.Fatalf("prompt did not cap omitted markers: %s", prompt)
	}
	if !strings.Contains(prompt, "[omitted: 15 additional files]") {
		t.Fatalf("prompt missing omitted summary: %s", prompt)
	}
}

func TestRunExecutesJudgeAfterScanners(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "skill")
	if err := os.Mkdir(target, 0o755); err != nil {
		t.Fatal(err)
	}
	promptPath := filepath.Join(dir, "prompt.md")
	schemaPath := filepath.Join(dir, "schema.json")
	if err := os.WriteFile(promptPath, []byte("Evidence:\n{{ scanners.skillspector }}"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(schemaPath, []byte(`{"type":"object"}`), 0o644); err != nil {
		t.Fatal(err)
	}
	opts, err := ParseArgs([]string{
		target,
		"--scanner", "skillspector",
		"--judge-prompt", promptPath,
		"--judge-schema", schemaPath,
		"--judge-model", "openai/gpt-5.5",
	})
	if err != nil {
		t.Fatal(err)
	}
	judge := &recordingJudgeRunner{result: map[string]any{"verdict": "benign"}}
	artifact, err := Run(opts, RunContext{
		Env: map[string]string{"OPENAI_API_KEY": "present"},
		ScannerRunner: staticScannerRunner{results: map[string]ScannerResult{
			"skillspector": {Status: "completed", Raw: json.RawMessage(`{"status":"clean"}`)},
		}},
		JudgeRunner: judge,
	})
	if err != nil {
		t.Fatal(err)
	}
	if artifact.Judge == nil || artifact.Judge.Status != "completed" {
		t.Fatalf("judge = %#v", artifact.Judge)
	}
	if !strings.Contains(judge.prompt, `"status": "clean"`) {
		t.Fatalf("prompt = %s", judge.prompt)
	}
}

func TestRunDryRunsClawHubPromptWithScannerResultFixture(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "skill")
	if err := os.Mkdir(target, 0o755); err != nil {
		t.Fatal(err)
	}
	systemPromptPath := filepath.Join(dir, "system.md")
	jobPath := filepath.Join(dir, "job.json")
	skillSpectorPath := filepath.Join(dir, "skillspector.json")
	if err := os.WriteFile(systemPromptPath, []byte("SYSTEM"), 0o644); err != nil {
		t.Fatal(err)
	}
	jobJSON := `{"job":{"targetKind":"skillVersion","source":"publish","hasMaliciousSignal":true},"target":{"trustedOpenClawPlugin":true,"version":{"vtAnalysis":{"status":"suspicious","source":"engines","metadata":{"stats":{"malicious":1,"suspicious":0,"harmless":12}}}}}}`
	if err := os.WriteFile(jobPath, []byte(jobJSON), 0o644); err != nil {
		t.Fatal(err)
	}
	skillSpectorJSON := `{"status":"suspicious","score":55,"recommendation":"DO_NOT_INSTALL","issueCount":1,"checkedAt":123,"issues":[{"issueId":"SDI-1","severity":"HIGH","explanation":"Mismatch"}]}`
	if err := os.WriteFile(skillSpectorPath, []byte(skillSpectorJSON), 0o644); err != nil {
		t.Fatal(err)
	}
	opts, err := ParseArgs([]string{
		target,
		"--scanner", "skillspector",
		"--scanner-result", "skillspector=" + skillSpectorPath,
		"--judge-model", "openai/gpt-5.5",
		"--judge-dry-run",
		"--clawhub-system-prompt", systemPromptPath,
		"--clawhub-job", jobPath,
		"--clawhub-injection-signal", "html-comment-injection",
	})
	if err != nil {
		t.Fatal(err)
	}
	expectedPrompt, err := clawhubprompt.Build(
		"SYSTEM",
		clawhubprompt.Job{
			Job: clawhubprompt.JobMetadata{
				TargetKind:         "skillVersion",
				Source:             "publish",
				HasMaliciousSignal: true,
			},
			Target: clawhubprompt.Target{
				TrustedOpenClawPlugin: true,
				Version: &clawhubprompt.Version{
					VTAnalysis: clawhubprompt.RawJSON(`{"status":"suspicious","source":"engines","metadata":{"stats":{"malicious":1,"suspicious":0,"harmless":12}}}`),
				},
			},
		},
		[]string{"html-comment-injection"},
		clawhubprompt.RawJSON(skillSpectorJSON),
	)
	if err != nil {
		t.Fatal(err)
	}
	judge := &recordingJudgeRunner{result: map[string]any{"verdict": "benign"}}
	artifact, err := Run(opts, RunContext{
		Env:           map[string]string{},
		ScannerRunner: errorScannerRunner{},
		JudgeRunner:   judge,
	})
	if err != nil {
		t.Fatal(err)
	}
	if artifact.Scanners["skillspector"].Status != "completed" {
		t.Fatalf("scanner = %#v", artifact.Scanners["skillspector"])
	}
	if !bytes.Equal(artifact.Scanners["skillspector"].Raw, []byte(skillSpectorJSON)) {
		t.Fatalf("raw = %s", artifact.Scanners["skillspector"].Raw)
	}
	if artifact.Judge == nil || artifact.Judge.Status != "dry_run" {
		t.Fatalf("judge = %#v", artifact.Judge)
	}
	if artifact.Judge.PromptSHA != sha256Hex(expectedPrompt) {
		t.Fatalf("prompt sha = %q, want %q", artifact.Judge.PromptSHA, sha256Hex(expectedPrompt))
	}
	if judge.prompt != "" {
		t.Fatalf("dry run called judge with prompt: %s", judge.prompt)
	}
}

type skippedScannerRunner struct{}

func (skippedScannerRunner) RunScanner(name string, target string, startedAt string) (ScannerResult, error) {
	return ScannerResult{
		Status:      "skipped",
		StartedAt:   startedAt,
		CompletedAt: startedAt,
		Error:       "Scanner adapter not implemented in foundation slice.",
	}, nil
}

type staticScannerRunner struct {
	results map[string]ScannerResult
}

func (runner staticScannerRunner) RunScanner(name string, target string, startedAt string) (ScannerResult, error) {
	result := runner.results[name]
	result.StartedAt = startedAt
	result.CompletedAt = startedAt
	return result, nil
}

type errorScannerRunner struct{}

func (errorScannerRunner) RunScanner(name string, target string, startedAt string) (ScannerResult, error) {
	return ScannerResult{}, fmt.Errorf("unexpected live scanner call for %s", name)
}

type recordingJudgeRunner struct {
	prompt string
	result any
}

func (runner *recordingJudgeRunner) RunJudge(opts JudgeOptions, artifact Artifact, prompt string, schema json.RawMessage) (*JudgeResult, error) {
	runner.prompt = prompt
	return &JudgeResult{
		Status:     "completed",
		Model:      opts.Model,
		PromptPath: opts.PromptPath,
		SchemaPath: opts.SchemaPath,
		Result:     runner.result,
	}, nil
}

type recordingCommandRunner struct {
	calls       []commandCall
	writeOutput string
	stdout      string
	err         error
}

type commandCall struct {
	command string
	args    []string
	cwd     string
}

func (r *recordingCommandRunner) Run(command string, args []string, cwd string, timeout time.Duration) (CommandOutput, error) {
	r.calls = append(r.calls, commandCall{command: command, args: append([]string(nil), args...), cwd: cwd})
	outputIndex := indexOfArg(args, "--output")
	if outputIndex >= 0 && outputIndex+1 < len(args) {
		if err := os.WriteFile(args[outputIndex+1], []byte(r.writeOutput), 0o644); err != nil {
			return CommandOutput{}, err
		}
	}
	stdout := r.stdout
	if stdout == "" {
		stdout = "ok"
	}
	return CommandOutput{Stdout: stdout}, r.err
}

var errCommandFailed = errors.New("exit status 1")

func containsArg(args []string, value string) bool {
	return indexOfArg(args, value) >= 0
}

func indexOfArg(args []string, value string) int {
	for index, arg := range args {
		if arg == value {
			return index
		}
	}
	return -1
}

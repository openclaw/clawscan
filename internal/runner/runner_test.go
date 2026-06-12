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
)

func TestParseArgs(t *testing.T) {
	opts, err := ParseArgs([]string{
		"./my-skill",
		"--scanner", "skillspector",
		"--scanner", "virustotal",
		"--judge", "codex exec --cd {{ workspace }} --output-schema {{ output_schema }} --output-last-message {{ output }} - < {{ prompt }}",
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
	if opts.Judge == nil || !strings.Contains(opts.Judge.Command, "codex exec") {
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

func TestParseArgsAcceptsStaticScanner(t *testing.T) {
	opts, err := ParseArgs([]string{"./my-skill", "--scanner", "static"})
	if err != nil {
		t.Fatal(err)
	}
	if got := strings.Join(opts.Scanners, ","); got != "static" {
		t.Fatalf("scanners = %q", got)
	}
}

func TestParseArgsSupportsJudgeCommand(t *testing.T) {
	opts, err := ParseArgs([]string{
		"./my-skill",
		"--scanner", "skillspector",
		"--scanner-result", "skillspector=./skillspector.json",
		"--judge", "judge --prompt {{ prompt:./custom-prompt.md }} --schema {{ output_schema:./custom.schema.json }} --output {{ output }}",
		"--output", "./run.json",
	})
	if err != nil {
		t.Fatal(err)
	}
	if opts.ScannerResultPaths["skillspector"] != "./skillspector.json" {
		t.Fatalf("scanner result paths = %#v", opts.ScannerResultPaths)
	}
	if opts.Judge == nil || !strings.Contains(opts.Judge.Command, "{{ prompt:./custom-prompt.md }}") {
		t.Fatalf("judge = %#v", opts.Judge)
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

func TestValidateRequirements(t *testing.T) {
	opts, err := ParseArgs([]string{
		"./my-skill",
		"--scanner", "virustotal",
		"--scanner", "snyk",
		"--judge", "codex exec --cd {{ workspace }} --output-schema {{ output_schema }} --output-last-message {{ output }} - < {{ prompt }}",
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

func TestRenderPromptTemplateInterpolatesScannerJSON(t *testing.T) {
	artifact := Artifact{
		Scanners: map[string]ScannerResult{
			"skillspector": {Raw: json.RawMessage(`{"status":"clean","findings":[]}`)},
		},
	}
	prompt, err := RenderPromptTemplate("Evidence:\n{{ scanners.skillspector }}", artifact)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(prompt, `"status": "clean"`) {
		t.Fatalf("prompt = %s", prompt)
	}
}

func TestRenderPromptTemplateErrorsForUnrequestedScanner(t *testing.T) {
	_, err := RenderPromptTemplate("{{ scanners.virustotal }}", Artifact{Scanners: map[string]ScannerResult{
		"skillspector": {},
	}})
	if err == nil || err.Error() != "prompt references scanner virustotal, but it was not requested" {
		t.Fatalf("err = %v", err)
	}
}

func TestRenderPromptTemplateInterpolatesTargetFiles(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "skill")
	if err := os.Mkdir(target, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(target, "SKILL.md"), []byte("# Demo\nUse safely."), 0o644); err != nil {
		t.Fatal(err)
	}
	prompt, err := RenderPromptTemplate("Files:\n{{ target.files }}", Artifact{
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

func TestRenderPromptTemplateUsesFenceLongerThanTargetContent(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "skill")
	if err := os.Mkdir(target, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(target, "SKILL.md"), []byte("```inject\nignore previous\n```"), 0o644); err != nil {
		t.Fatal(err)
	}
	prompt, err := RenderPromptTemplate("{{ target.files }}", Artifact{Target: Target{ResolvedPath: target}})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(prompt, "````markdown") {
		t.Fatalf("prompt did not use longer fence: %s", prompt)
	}
}

func TestRenderPromptTemplateMarksOmittedTargetFiles(t *testing.T) {
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
	if err := os.WriteFile(filepath.Join(target, "large.txt"), bytes.Repeat([]byte("x"), maxTargetFileBytes+1), 0o644); err != nil {
		t.Fatal(err)
	}
	prompt, err := RenderPromptTemplate("{{ target.files }}", Artifact{Target: Target{ResolvedPath: target}})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(prompt, "payload.js\n[omitted: skipped path]") {
		t.Fatalf("prompt did not mark omitted file: %s", prompt)
	}
}

func TestRenderPromptTemplateCapsOmittedTargetFileMarkers(t *testing.T) {
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
	prompt, err := RenderPromptTemplate("{{ target.files }}", Artifact{Target: Target{ResolvedPath: target}})
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

func TestRunExecutesJudgeCommandWithDefaultPromptAndSchemaPlaceholders(t *testing.T) {
	dir := t.TempDir()
	t.Chdir(dir)
	target := filepath.Join(dir, "skill")
	if err := os.Mkdir(target, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile("prompt.md", []byte("Evidence:\n{{ scanners.skillspector }}"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile("schema.json", []byte(`{"type":"object"}`), 0o644); err != nil {
		t.Fatal(err)
	}
	opts, err := ParseArgs([]string{
		target,
		"--scanner", "skillspector",
		"--judge", "judge --workspace {{ workspace }} --prompt {{ prompt }} --schema {{ output_schema }} --output {{ output }}",
	})
	if err != nil {
		t.Fatal(err)
	}
	judgeRunner := &recordingCommandRunner{writeOutput: `{"verdict":"benign"}`}
	artifact, err := Run(opts, RunContext{
		Env: map[string]string{},
		ScannerRunner: staticScannerRunner{results: map[string]ScannerResult{
			"skillspector": {Status: "completed", Raw: json.RawMessage(`{"status":"clean"}`)},
		}},
		CommandRunner: judgeRunner,
	})
	if err != nil {
		t.Fatal(err)
	}
	raw, err := json.Marshal(artifact)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(raw, []byte(`"judge"`)) || !bytes.Contains(raw, []byte(`"verdict":"benign"`)) {
		t.Fatalf("artifact = %s", raw)
	}
	if len(judgeRunner.calls) != 1 {
		t.Fatalf("calls = %#v", judgeRunner.calls)
	}
	renderedCommand := strings.Join(append([]string{judgeRunner.calls[0].command}, judgeRunner.calls[0].args...), " ")
	if strings.Contains(renderedCommand, "{{") {
		t.Fatalf("unrendered placeholder in command: %s", renderedCommand)
	}
	if !strings.Contains(renderedCommand, "--workspace ") || !strings.Contains(renderedCommand, "--prompt ") || !strings.Contains(renderedCommand, "--schema ") || !strings.Contains(renderedCommand, "--output ") {
		t.Fatalf("rendered command missing expected paths: %s", renderedCommand)
	}
}

func TestRunExecutesJudgeCommandWithExplicitPromptAndSchemaPlaceholders(t *testing.T) {
	dir := t.TempDir()
	t.Chdir(dir)
	target := filepath.Join(dir, "skill")
	if err := os.Mkdir(target, 0o755); err != nil {
		t.Fatal(err)
	}
	promptPath := filepath.Join(dir, "review.md")
	schemaPath := filepath.Join(dir, "verdict.schema.json")
	skillSpectorPath := filepath.Join(dir, "skillspector.json")
	if err := os.WriteFile(promptPath, []byte("Evidence:\n{{ scanners.skillspector }}"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(schemaPath, []byte(`{"type":"object"}`), 0o644); err != nil {
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
		"--judge", "judge --prompt {{ prompt:" + promptPath + " }} --schema {{ output_schema:" + schemaPath + " }} --output {{ output }}",
	})
	if err != nil {
		t.Fatal(err)
	}
	expectedPrompt, err := RenderPromptTemplate("Evidence:\n{{ scanners.skillspector }}", Artifact{
		Scanners: map[string]ScannerResult{
			"skillspector": {Raw: json.RawMessage(skillSpectorJSON)},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	judgeRunner := &recordingCommandRunner{writeOutput: `{"verdict":"benign"}`}
	artifact, err := Run(opts, RunContext{
		Env:           map[string]string{},
		ScannerRunner: errorScannerRunner{},
		CommandRunner: judgeRunner,
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
	raw, err := json.Marshal(artifact)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(raw, []byte(sha256Hex(expectedPrompt))) {
		t.Fatalf("artifact missing rendered prompt hash: %s", raw)
	}
	if !bytes.Contains(raw, []byte(sha256Hex(`{"type":"object"}`))) {
		t.Fatalf("artifact missing schema hash: %s", raw)
	}
}

func TestRunJudgeWorkspaceSkipsIgnoredAndLargeTargetFiles(t *testing.T) {
	dir := t.TempDir()
	t.Chdir(dir)
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
	if err := os.WriteFile("prompt.md", []byte("Evidence only"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile("schema.json", []byte(`{"type":"object"}`), 0o644); err != nil {
		t.Fatal(err)
	}
	opts, err := ParseArgs([]string{
		target,
		"--scanner", "skillspector",
		"--judge", "test ! -e {{ workspace }}/artifact/node_modules/pkg/payload.js && test ! -e {{ workspace }}/artifact/large.txt && printf '{\"ok\":true}\\n' > {{ output }} # {{ prompt }} {{ output_schema }}",
	})
	if err != nil {
		t.Fatal(err)
	}
	artifact, err := Run(opts, RunContext{
		Env: map[string]string{},
		ScannerRunner: staticScannerRunner{results: map[string]ScannerResult{
			"skillspector": {Status: "completed", Raw: json.RawMessage(`{"status":"clean"}`)},
		}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if artifact.Judge == nil || artifact.Judge.Status != "completed" {
		t.Fatalf("judge = %#v", artifact.Judge)
	}
}

func TestPrepareJudgeWorkspaceRecordsOmittedTargetFiles(t *testing.T) {
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
	if err := os.WriteFile(filepath.Join(target, "large.txt"), bytes.Repeat([]byte("x"), maxTargetFileBytes+1), 0o644); err != nil {
		t.Fatal(err)
	}
	workspace := filepath.Join(dir, "workspace")
	artifact := NewArtifact(Options{Target: target}, target, "2026-01-01T00:00:00Z", "2026-01-01T00:00:00Z", map[string]string{})
	if err := prepareJudgeWorkspace(workspace, artifact); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(workspace, "artifact", "node_modules", "pkg", "payload.js")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("node_modules payload copied, err=%v", err)
	}
	if _, err := os.Stat(filepath.Join(workspace, "artifact", "large.txt")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("large file copied, err=%v", err)
	}
	metadata, err := os.ReadFile(filepath.Join(workspace, "metadata.json"))
	if err != nil {
		t.Fatal(err)
	}
	for _, expected := range []string{"node_modules", "skipped path", "large.txt", "file exceeds size limit"} {
		if !bytes.Contains(metadata, []byte(expected)) {
			t.Fatalf("metadata missing %q: %s", expected, metadata)
		}
	}
}

func TestRunJudgeRejectsNonObjectJSON(t *testing.T) {
	dir := t.TempDir()
	t.Chdir(dir)
	target := filepath.Join(dir, "skill")
	if err := os.MkdirAll(target, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(target, "SKILL.md"), []byte("# Demo"), 0o644); err != nil {
		t.Fatal(err)
	}
	opts, err := ParseArgs([]string{
		target,
		"--scanner", "skillspector",
		"--judge", "printf '[true]\\n'",
	})
	if err != nil {
		t.Fatal(err)
	}
	artifact, err := Run(opts, RunContext{
		Env: map[string]string{},
		ScannerRunner: staticScannerRunner{results: map[string]ScannerResult{
			"skillspector": {Status: "completed", Raw: json.RawMessage(`{"status":"clean"}`)},
		}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if artifact.Judge == nil {
		t.Fatal("missing judge result")
	}
	if artifact.Judge.Status != "failed" {
		t.Fatalf("judge status = %q", artifact.Judge.Status)
	}
	if !strings.Contains(artifact.Judge.Error, "expected JSON object") {
		t.Fatalf("judge error = %q", artifact.Judge.Error)
	}
}

func TestRunJudgeDoesNotPersistRenderedCommand(t *testing.T) {
	dir := t.TempDir()
	t.Chdir(dir)
	target := filepath.Join(dir, "skill")
	if err := os.MkdirAll(target, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(target, "SKILL.md"), []byte("# Demo"), 0o644); err != nil {
		t.Fatal(err)
	}
	opts, err := ParseArgs([]string{
		target,
		"--scanner", "skillspector",
		"--judge", "SECRET_TOKEN=supersecret printf '{\"ok\":true}\\n' > {{ output }}",
	})
	if err != nil {
		t.Fatal(err)
	}
	artifact, err := Run(opts, RunContext{
		Env: map[string]string{},
		ScannerRunner: staticScannerRunner{results: map[string]ScannerResult{
			"skillspector": {Status: "completed", Raw: json.RawMessage(`{"status":"clean"}`)},
		}},
	})
	if err != nil {
		t.Fatal(err)
	}
	raw, err := json.Marshal(artifact)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(raw, []byte("supersecret")) {
		t.Fatalf("artifact leaked rendered judge command: %s", raw)
	}
	if artifact.Judge == nil || artifact.Judge.Command != "" {
		t.Fatalf("judge command persisted: %#v", artifact.Judge)
	}
}

func TestRunJudgeQuotesGeneratedPlaceholderPaths(t *testing.T) {
	dir := t.TempDir()
	t.Chdir(dir)
	tempRoot := filepath.Join(dir, "tmp with spaces")
	if err := os.MkdirAll(tempRoot, 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("TMPDIR", tempRoot)
	target := filepath.Join(dir, "skill")
	if err := os.MkdirAll(target, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(target, "SKILL.md"), []byte("# Demo"), 0o644); err != nil {
		t.Fatal(err)
	}
	opts, err := ParseArgs([]string{
		target,
		"--scanner", "skillspector",
		"--judge", "test -d {{ workspace }} && printf '{\"ok\":true}\\n' > {{ output }}",
	})
	if err != nil {
		t.Fatal(err)
	}
	artifact, err := Run(opts, RunContext{
		Env: map[string]string{},
		ScannerRunner: staticScannerRunner{results: map[string]ScannerResult{
			"skillspector": {Status: "completed", Raw: json.RawMessage(`{"status":"clean"}`)},
		}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if artifact.Judge == nil || artifact.Judge.Status != "completed" {
		t.Fatalf("judge = %#v", artifact.Judge)
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
	outputArgs := args
	if command == "/bin/sh" && len(args) == 2 && args[0] == "-c" {
		outputArgs = strings.Fields(args[1])
	}
	outputIndex := indexOfArg(outputArgs, "--output")
	if outputIndex < 0 {
		outputIndex = indexOfArg(outputArgs, "--output-last-message")
	}
	if outputIndex >= 0 && outputIndex+1 < len(outputArgs) {
		outputPath := strings.Trim(outputArgs[outputIndex+1], "'")
		if err := os.WriteFile(outputPath, []byte(r.writeOutput), 0o644); err != nil {
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

package runner

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"unicode/utf8"
)

var discordStaticAnalyzers = []any{
	"static_patterns_agent_snooping", "static_patterns_anti_refusal", "static_patterns_data_exfiltration",
	"static_patterns_deserialization", "static_patterns_excessive_agency", "static_patterns_harmful_content",
	"static_patterns_memory_poisoning", "static_patterns_output_handling", "static_patterns_privilege_escalation",
	"static_patterns_prompt_injection", "static_patterns_rogue_agent", "static_patterns_ssrf",
	"static_patterns_supply_chain", "static_patterns_system_prompt_leakage", "static_patterns_tool_misuse",
}

func completenessRow(outcome, phase, reason, message, path string, analyzers []any) map[string]any {
	row := map[string]any{
		"outcome": outcome, "phase": phase, "reason_code": reason, "message": message,
		"path": path, "start_line": nil, "end_line": nil, "fatal": false,
	}
	if analyzers != nil {
		row["analyzers"] = analyzers
	}
	return row
}

func nodeModulesPath(index int) string {
	return fmt.Sprintf("node_modules/@discord/embedded-app-sdk/node_modules/@types/lodash/generated-module-%05d.d.ts", index)
}

// largePartialReport starts from the usable partial fixture and replaces its
// accounting lists, so the report still qualifies for the judge-gaps path.
func largePartialReport(t *testing.T, ledger []any, scope []any, issues []any) []byte {
	t.Helper()
	raw, err := os.ReadFile("testdata/skillspector-usable-partial.json")
	if err != nil {
		t.Fatal(err)
	}
	var report map[string]any
	if err := json.Unmarshal(raw, &report); err != nil {
		t.Fatal(err)
	}
	accounting := report["analysis_completeness"].(map[string]any)
	accounting["ledger_exceptions"] = ledger
	accounting["scope_exclusions"] = scope
	if issues != nil {
		report["issues"] = issues
		report["risk_assessment"] = map[string]any{"score": 100, "severity": "CRITICAL", "recommendation": "DO_NOT_INSTALL"}
	}
	encoded, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if !skillSpectorUsablePartial(encoded) {
		t.Fatal("large fixture no longer qualifies as a usable partial report")
	}
	return encoded
}

func syntheticLedgerAndScope(ledgerCount, scopeCount int) ([]any, []any) {
	ledger := make([]any, 0, ledgerCount)
	reasons := []string{"excluded_executable_content", "opaque_content", "static_parse_limit", "obfuscated_instruction_text"}
	for index := range ledgerCount {
		reason := reasons[index%len(reasons)]
		ledger = append(ledger, completenessRow("partial", "static", reason, "Artifact contents could not be fully interpreted.", nodeModulesPath(index), discordStaticAnalyzers))
	}
	scope := make([]any, 0, scopeCount)
	for index := range scopeCount {
		reason := "excluded_directory"
		if index%10 == 0 {
			reason = "binary_content"
		}
		scope = append(scope, completenessRow("out_of_scope", "exclusion_audit", reason, "Directory tree is excluded from the configured scan scope.", nodeModulesPath(index), nil))
	}
	return ledger, scope
}

// discordSizedReport mirrors the @openclaw/discord 2026.10.10 SkillSpector
// report shape: 1,662 issues, 1,638 ledger exceptions, and 1,578 scope
// exclusions with the same reason-code mix and field shapes.
func discordSizedReport(t *testing.T) []byte {
	t.Helper()
	ledger := make([]any, 0, 1_638)
	for index := range 1_576 {
		ledger = append(ledger, completenessRow("partial", "exclusion_audit", "excluded_executable_content", "Executable content was inventoried but excluded from content analysis.", nodeModulesPath(index), nil))
	}
	for _, group := range []struct {
		reason string
		count  int
	}{{"opaque_content", 43}, {"static_parse_limit", 10}, {"obfuscated_instruction_text", 9}} {
		for index := range group.count {
			ledger = append(ledger, completenessRow("partial", "static", group.reason, "Artifact contents could not be fully interpreted.", fmt.Sprintf("dist/.setup/%s-chunk-%02d-C18HNgge.mjs", group.reason, index), []any{"static_patterns_tool_misuse"}))
		}
	}
	scope := []any{completenessRow("out_of_scope", "static", "binary_content", "Binary content is unsupported by this analyzer.", "assets/icon.png", discordStaticAnalyzers)}
	scope = append(scope, completenessRow("out_of_scope", "exclusion_audit", "excluded_directory", "Directory tree is excluded from the configured scan scope.", "node_modules", nil))
	for index := range 1_576 {
		scope = append(scope, completenessRow("out_of_scope", "exclusion_audit", "excluded_directory", "Directory tree is excluded from the configured scan scope.", nodeModulesPath(index), nil))
	}
	issues := make([]any, 0, 1_662)
	for index := range 1_662 {
		path := nodeModulesPath(index)
		issues = append(issues, map[string]any{
			"id": "SC9", "finding_id": fmt.Sprintf("finding-%032x", index), "category": "Supply Chain",
			"pattern": "Concealed Executable Artifact", "severity": "HIGH", "confidence": 1.0,
			"location":    map[string]any{"file": path, "start_line": 1, "end_line": nil},
			"finding":     path,
			"explanation": "An executable nested in a document or hidden/disguised artifact can evade ordinary extension-based review while still being available to the skill at runtime.",
			"remediation": "Review the artifact provenance and the reason executable content is packaged in this location; keep executable files explicit and directly reviewable.",
			"tags":        []any{"supply-chain", "concealed-executable", "local-only"},
			"evidence":    map[string]any{"outer_path": path, "nested_path": path, "concealment": "excluded_directory", "excluded_from_analysis": true},
		})
	}
	return largePartialReport(t, ledger, scope, issues)
}

func clawHubPromptSource(t *testing.T) []byte {
	t.Helper()
	source, err := os.ReadFile("../profiles/clawhub/prompt.md")
	if err != nil {
		t.Fatal(err)
	}
	return source
}

func partialSkillSpectorArtifact(raw []byte) Artifact {
	return Artifact{
		Scanners: map[string]ScannerResult{
			"skillspector": {Status: "partial", ReportPolicy: judgeGapsReportPolicy, Raw: raw},
		},
	}
}

func TestClawHubPromptSummarizesLargeAccountingLists(t *testing.T) {
	ledger, scope := syntheticLedgerAndScope(5_000, 5_000)
	raw := largePartialReport(t, ledger, scope, nil)
	if len(raw) <= historicalCodexInputLimitChars {
		t.Fatalf("fixture is too small to exercise summarization: %d chars", len(raw))
	}

	prompt, err := RenderClawHubPrompt(string(clawHubPromptSource(t)), partialSkillSpectorArtifact(raw))
	if err != nil {
		t.Fatal(err)
	}
	if chars := utf8.RuneCountInString(prompt); chars > 100_000 {
		t.Fatalf("summarized prompt is %d chars", chars)
	}
	for _, want := range []string{
		`"total": 5000`,
		`"excluded_executable_content": 1250`,
		`"obfuscated_instruction_text": 1250`,
		`"excluded_directory": 4500`,
		`"binary_content": 500`,
		"analysis_completeness.ledger_exceptions in scanners/skillspector.json",
		"analysis_completeness.scope_exclusions in scanners/skillspector.json",
	} {
		if !strings.Contains(prompt, want) {
			t.Fatalf("summarized prompt lost %q", want)
		}
	}
}

func TestClawHubPromptSummaryIsDeterministicAndSamplesEveryReason(t *testing.T) {
	ledger := []any{
		completenessRow("partial", "static", "excluded_executable_content", "m", "node_modules/a.js", nil),
		completenessRow("partial", "static", "excluded_executable_content", "m", "node_modules/b.js", nil),
		completenessRow("partial", "static", "excluded_executable_content", "m", "node_modules/c.js", nil),
		completenessRow("partial", "static", "excluded_executable_content", "m", "node_modules/d.js", nil),
		completenessRow("partial", "static", "opaque_content", "m", "dist/plugin.mjs", []any{"static_patterns_tool_misuse"}),
		map[string]any{"fatal": false, "path": "no-reason.js"},
	}
	summary := summarizeClawHubCompletenessRecords("ledger_exceptions", "reason_code", ledger)
	again := summarizeClawHubCompletenessRecords("ledger_exceptions", "reason_code", ledger)
	first, _ := json.Marshal(summary)
	second, _ := json.Marshal(again)
	if string(first) != string(second) {
		t.Fatal("summary is not deterministic")
	}
	counts := summary["counts_by_reason_code"].(map[string]int)
	if counts["excluded_executable_content"] != 4 || counts["opaque_content"] != 1 || counts["(none)"] != 1 {
		t.Fatalf("counts = %#v", counts)
	}
	sample := summary["sample"].([]any)
	var paths []string
	for _, entry := range sample {
		paths = append(paths, entry.(map[string]any)["path"].(string))
	}
	if got, want := strings.Join(paths, ","), "node_modules/a.js,node_modules/b.js,node_modules/c.js,no-reason.js,dist/plugin.mjs"; got != want {
		t.Fatalf("sample paths = %s, want %s", got, want)
	}
	if summary["total"] != 6 || summary["sample_omitted"] != 1 {
		t.Fatalf("summary totals = %v / %v", summary["total"], summary["sample_omitted"])
	}
}

func TestClawHubPromptSummaryBoundsGroupsAndEntries(t *testing.T) {
	rows := make([]any, 0, 200)
	long := strings.Repeat("x", 10_000)
	manyFields := map[string]any{}
	for index := range 40 {
		manyFields[fmt.Sprintf("field_%02d", index)] = long
	}
	for index := range 200 {
		row := map[string]any{"reason_code": fmt.Sprintf("reason_%03d", index), "path": long, "analyzers": make([]any, 100), "nested": map[string]any{"deep": long}}
		rows = append(rows, row)
	}
	rows = append(rows, manyFields)
	summary := summarizeClawHubCompletenessRecords("scope_exclusions", "reason_code", rows)
	encoded, err := json.Marshal(summary)
	if err != nil {
		t.Fatal(err)
	}
	if len(encoded) > 40_000 {
		t.Fatalf("bounded summary is %d bytes", len(encoded))
	}
	if counts := summary["counts_by_reason_code"].(map[string]int); len(counts) != maxClawHubCompletenessCountGroups {
		t.Fatalf("count groups = %d", len(counts))
	}
	if summary["other_reason_code_groups"] != 201-maxClawHubCompletenessCountGroups || summary["other_reason_code_entries"] != 201-maxClawHubCompletenessCountGroups {
		t.Fatalf("other groups = %v entries = %v", summary["other_reason_code_groups"], summary["other_reason_code_entries"])
	}
	if strings.Contains(string(encoded), strings.Repeat("x", maxClawHubSkillSpectorShortTextChars+1)) {
		t.Fatal("sample text was not truncated")
	}
	unexpected := summarizeClawHubCompletenessRecords("references", "status", map[string]any{"huge": long})
	if strings.Contains(fmt.Sprint(unexpected), long) || unexpected["unexpected_type"] == nil {
		t.Fatalf("non-array list was not omitted: %#v", unexpected)
	}
}

// historicalCodexInputLimitChars is the Codex CLI input limit that made the
// unsummarized Discord-sized report unusable. ClawScan no longer enforces it;
// the fixture only proves that the summary keeps the prompt compact.
const historicalCodexInputLimitChars = 1_048_576

func TestClawHubPromptDiscordSizedPartialReportStaysCompact(t *testing.T) {
	raw := discordSizedReport(t)
	var report map[string]any
	if err := json.Unmarshal(raw, &report); err != nil {
		t.Fatal(err)
	}
	accounting := report["analysis_completeness"].(map[string]any)
	if len(accounting["ledger_exceptions"].([]any)) != 1_638 || len(accounting["scope_exclusions"].([]any)) != 1_578 {
		t.Fatal("fixture does not match the Discord accounting counts")
	}
	// Before summarization the normalized accounting block alone was larger
	// than the historical Codex input limit for this report shape.
	uncapped, err := json.MarshalIndent(accounting, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if len(uncapped) <= historicalCodexInputLimitChars {
		t.Fatalf("fixture is not Discord-sized: uncapped accounting is %d chars", len(uncapped))
	}

	prompt, err := RenderClawHubPrompt(string(clawHubPromptSource(t)), partialSkillSpectorArtifact(raw))
	if err != nil {
		t.Fatal(err)
	}
	if chars := utf8.RuneCountInString(prompt); chars > 100_000 {
		t.Fatalf("Discord-sized prompt is %d chars", chars)
	}
	for _, want := range []string{
		`"total": 1638`, `"total": 1578`,
		`"excluded_executable_content": 1576`, `"opaque_content": 43`, `"static_parse_limit": 10`, `"obfuscated_instruction_text": 9`,
		`"excluded_directory": 1577`, `"binary_content": 1`,
		"dist/.setup/opaque_content-chunk-00-C18HNgge.mjs", "assets/icon.png",
		`"issueCount": 1662`, "scanners/skillspector.json",
	} {
		if !strings.Contains(prompt, want) {
			t.Fatalf("Discord-sized prompt lost %q", want)
		}
	}
}

func TestClawHubLargePartialReportReachesJudgeWithFullWorkspaceReport(t *testing.T) {
	ledger, scope := syntheticLedgerAndScope(5_000, 5_000)
	raw := largePartialReport(t, ledger, scope, nil)
	path := filepath.Join(t.TempDir(), "report.json")
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	target, err := filepath.Abs(filepath.Join("testdata", "partial-judge", "benign"))
	if err != nil {
		t.Fatal(err)
	}
	command := &recordingCommandRunner{}
	command.runHook = func(_ string, _ []string, workspace string) error {
		prompt, err := os.ReadFile(filepath.Join(workspace, "prompt.md"))
		if err != nil {
			return err
		}
		if !strings.Contains(string(prompt), `"summarized": true`) {
			t.Fatal("judge prompt did not summarize the accounting lists")
		}
		full, err := os.ReadFile(filepath.Join(workspace, "scanners", "skillspector.json"))
		if err != nil || string(full) != string(raw) {
			t.Fatalf("judge workspace lost the complete raw report: err=%v", err)
		}
		command.writeOutput = `{"verdict":"benign"}`
		return nil
	}
	artifact, err := Run(Options{
		Target: target, Profile: "clawhub", Scanners: []string{"skillspector"},
		OutputPath:         filepath.Join(t.TempDir(), "run.json"),
		ScannerResultPaths: map[string]string{"skillspector": path},
		Judge:              &JudgeOptions{Command: "judge --prompt {{ prompt:clawhub/prompt.md }} --output {{ output }}", Files: map[string][]byte{"clawhub/prompt.md": clawHubPromptSource(t)}},
	}, RunContext{Env: map[string]string{}, CommandRunner: command})
	if err != nil {
		t.Fatal(err)
	}
	if len(command.calls) != 1 || artifact.Judge == nil || artifact.Judge.Status != "completed" || !artifact.Complete {
		t.Fatalf("judge calls=%d judge=%+v complete=%v", len(command.calls), artifact.Judge, artifact.Complete)
	}
}

// ClawScan has no judge input budget: an oversized prompt reaches the judge
// command, and a judge that enforces its own input limit fails with its own
// error, which ClawScan preserves without retrying.
func TestOversizeJudgePromptReachesJudgeAndKeepsItsError(t *testing.T) {
	target, err := filepath.Abs(filepath.Join("testdata", "partial-judge", "benign"))
	if err != nil {
		t.Fatal(err)
	}
	oversizeSystemPrompt := strings.Repeat("é", historicalCodexInputLimitChars+1)
	for _, test := range []struct {
		name    string
		profile string
		source  string
	}{
		{name: "clawhub prompt", profile: "clawhub", source: "clawhub/prompt.md"},
		{name: "custom prompt", profile: "custom", source: "big.md"},
	} {
		t.Run(test.name, func(t *testing.T) {
			exitCode := 1
			command := &recordingCommandRunner{
				stdout:   `{"type":"thread.started","thread_id":"t"}`,
				stderr:   `Error: input_too_large: judge input limit exceeded`,
				err:      errCommandFailed,
				exitCode: &exitCode,
			}
			var promptChars int
			command.runHook = func(_ string, _ []string, workspace string) error {
				prompt, err := os.ReadFile(filepath.Join(workspace, "prompt.md"))
				if err != nil {
					return err
				}
				promptChars = utf8.RuneCount(prompt)
				return nil
			}
			artifact, err := Run(Options{
				Target: target, Profile: test.profile, Scanners: []string{fixtureScannerID}, ScannerRegistry: fixtureScannerRegistry(t),
				Judge: &JudgeOptions{
					Command: "judge --prompt {{ prompt:" + test.source + " }} --output {{ output }}",
					Files:   map[string][]byte{test.source: []byte(oversizeSystemPrompt)},
				},
			}, RunContext{Env: map[string]string{}, CommandRunner: command})
			if err != nil {
				t.Fatal(err)
			}
			if len(command.calls) != 1 || promptChars <= historicalCodexInputLimitChars {
				t.Fatalf("judge calls=%d prompt chars=%d", len(command.calls), promptChars)
			}
			judge := artifact.Judge
			if judge == nil || judge.Status != "failed" || !strings.Contains(judge.Error, "input_too_large") || strings.Contains(judge.Error, "too large:") {
				t.Fatalf("judge = %+v", judge)
			}
			if len(judge.Attempts) != 1 || judge.Attempts[0].Error != judge.Error {
				t.Fatalf("attempts = %+v", judge.Attempts)
			}
			if artifact.Status != "failed" || artifact.Complete || artifact.Gate != "error" {
				t.Fatalf("artifact status=%s complete=%v gate=%s", artifact.Status, artifact.Complete, artifact.Gate)
			}
		})
	}
}

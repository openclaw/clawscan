package runner

import (
	"strings"
	"testing"
	"time"
)

func TestDefaultBenchmarkRegistryResolvesBuiltInsAndAliases(t *testing.T) {
	registry := DefaultBenchmarkRegistry()
	if got := strings.Join(registry.IDs(), ","); got != "clawhub-security-signals,cuhk-zhuque/SkillTrustBench" {
		t.Fatalf("ids = %q", got)
	}
	for _, input := range []string{
		"clawhub-security-signals",
		"openclaw/clawhub-security-signals",
		"cuhk-zhuque/SkillTrustBench",
		"SkillTrustBench",
		"skilltrustbench",
	} {
		adapter, err := registry.Resolve(input)
		if err != nil {
			t.Fatalf("Resolve(%q): %v", input, err)
		}
		if adapter.ID() != canonicalBenchmarkIDForTest(input) {
			t.Fatalf("Resolve(%q) id = %q", input, adapter.ID())
		}
	}
}

func TestBenchmarkRegistryRejectsDuplicateIDsAndAliases(t *testing.T) {
	_, err := NewBenchmarkRegistry(
		stubBenchmarkAdapter{id: "demo"},
		stubBenchmarkAdapter{id: "Demo"},
	)
	if err == nil || err.Error() != "Duplicate benchmark adapter id or alias: Demo" {
		t.Fatalf("err = %v", err)
	}
	_, err = NewBenchmarkRegistry(
		stubBenchmarkAdapter{id: "demo", aliases: []string{"sample"}},
		stubBenchmarkAdapter{id: "sample"},
	)
	if err == nil || err.Error() != "Duplicate benchmark adapter id or alias: sample" {
		t.Fatalf("err = %v", err)
	}
}

func TestRunBenchmarkRejectsUnsupportedBenchmarkThroughRegistry(t *testing.T) {
	_, err := RunBenchmark(Options{
		Benchmark: &BenchmarkOptions{
			ID:    "skillscan-paper",
			Split: "benchmark",
		},
		Scanners: []string{"clawscan-static"},
	}, RunContext{Env: map[string]string{}})
	if err == nil || err.Error() != "Unsupported benchmark: skillscan-paper" {
		t.Fatalf("err = %v", err)
	}
}

func TestRunBenchmarkExecutesUserDefinedScannerFromRunRegistry(t *testing.T) {
	custom := NewUserDefinedScanner(UserDefinedScannerConfig{
		ID: "fixture-scanner", Command: "fixture-scan {{target}}", Targets: []string{targetKindSkill},
	})
	registry, err := DefaultScannerRegistry().WithAdapters(custom)
	if err != nil {
		t.Fatal(err)
	}
	opts := benchmarkTestOptions(t, "clawhub-security-signals", "eval_holdout", 0, 0, "")
	opts.Scanners = []string{"fixture-scanner"}
	opts.ScannerRegistry = registry
	opts.GateRules = map[string]ScannerGatePolicy{
		"fixture-scanner": {BlockOnExitCode: &ExitCodeRule{Codes: []int{3}}},
	}
	exitCode := 3
	commandRunner := &recordingCommandRunner{stdout: `{"verdict":"clean"}`, err: errCommandFailed, exitCode: &exitCode}
	artifact, err := RunBenchmark(opts, RunContext{
		Env: map[string]string{}, CommandRunner: commandRunner,
		BenchmarkClient: staticBenchmarkClient{rows: []OpenClawBenchmarkRow{{
			ID: "row-1", SkillSlug: "owner/demo", SkillVersion: "1.0.0",
			SkillMDContent: "# Demo\n", ClawScanVerdict: "clean",
		}}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(commandRunner.calls) != 1 || !strings.Contains(commandRunner.calls[0].args[1], "fixture-scan") {
		t.Fatalf("calls = %#v", commandRunner.calls)
	}
	result := artifact.Cases[0].Run.Scanners["fixture-scanner"]
	if result.Status != "completed" || string(result.Raw) != `{"verdict":"clean"}` {
		t.Fatalf("result = %#v", result)
	}
	if artifact.Cases[0].Run.Gate != "block" || len(artifact.Cases[0].Run.GateRules) != 1 {
		t.Fatalf("gate = %q, rules = %#v", artifact.Cases[0].Run.Gate, artifact.Cases[0].Run.GateRules)
	}
}

func TestRunBenchmarkRejectsUnrequestedGateScannerBeforeDatasetIO(t *testing.T) {
	opts := benchmarkTestOptions(t, "clawhub-security-signals", "eval_holdout", 0, 0, "")
	opts.GateRules = map[string]ScannerGatePolicy{
		"absent-scanner": {BlockOnExitCode: &ExitCodeRule{Nonzero: true}},
	}
	_, err := RunBenchmark(opts, RunContext{
		Env:             map[string]string{},
		BenchmarkClient: panicBenchmarkClient{},
	})
	if err == nil || err.Error() != "gate rule references scanner absent-scanner, but it was not requested" {
		t.Fatalf("err = %v", err)
	}
}

type panicBenchmarkClient struct{}

func (panicBenchmarkClient) FetchOpenClawRows(string, string, int, int) ([]OpenClawBenchmarkRow, error) {
	panic("benchmark client called before gate validation")
}

func (panicBenchmarkClient) FetchSkillTrustBenchRows(string, string, int, int) ([]SkillTrustBenchRow, error) {
	panic("benchmark client called before gate validation")
}

func (panicBenchmarkClient) MaterializeSkillTrustBenchRow(string, SkillTrustBenchRow) (string, error) {
	panic("benchmark client called before gate validation")
}

type stubBenchmarkAdapter struct {
	id      string
	aliases []string
	info    DatasetInfo
}

func (adapter stubBenchmarkAdapter) ID() string {
	return adapter.id
}

func (adapter stubBenchmarkAdapter) Aliases() []string {
	return append([]string(nil), adapter.aliases...)
}

func (adapter stubBenchmarkAdapter) Info() DatasetInfo {
	return adapter.info
}

func (adapter stubBenchmarkAdapter) Source() string {
	return "fixture"
}

func (adapter stubBenchmarkAdapter) Config() string {
	return "default"
}

func (adapter stubBenchmarkAdapter) DefaultSplit() string {
	return "benchmark"
}

func (adapter stubBenchmarkAdapter) Splits() []string {
	return []string{"benchmark"}
}

func (adapter stubBenchmarkAdapter) RunCases(Options, RunContext, map[string]string, func() time.Time, BenchmarkClient) ([]BenchmarkCase, error) {
	return nil, nil
}

func (adapter stubBenchmarkAdapter) SupportsPredictionsOutput() bool {
	return false
}

func TestDefaultBenchmarkRegistryProvidesDatasetCatalogInfo(t *testing.T) {
	registry := DefaultBenchmarkRegistry()
	for _, id := range registry.IDs() {
		info, ok := registry.Info(id)
		if !ok {
			t.Fatalf("missing dataset info for %s", id)
		}
		if info.ID != id {
			t.Fatalf("%s info id = %q", id, info.ID)
		}
		if strings.TrimSpace(info.DisplayName) == "" {
			t.Fatalf("%s info missing display name", id)
		}
		if strings.TrimSpace(info.SourceURL) == "" {
			t.Fatalf("%s info missing source URL", id)
		}
		if strings.TrimSpace(info.Description) == "" {
			t.Fatalf("%s info missing description", id)
		}
		if len(info.Splits) == 0 {
			t.Fatalf("%s info missing splits", id)
		}
		if info.DefaultSplit == "" {
			t.Fatalf("%s info missing default split", id)
		}
		if strings.TrimSpace(info.RequiredEnv) == "" {
			t.Fatalf("%s info missing required env summary", id)
		}
	}

	openClaw, _ := registry.Info("clawhub-security-signals")
	if got := strings.Join(openClaw.Splits, ","); got != "eval_holdout,test,train,validation" {
		t.Fatalf("OpenClaw splits = %q", got)
	}
	if openClaw.DefaultSplit != "eval_holdout" {
		t.Fatalf("OpenClaw default split = %q", openClaw.DefaultSplit)
	}

	skillTrustBench, _ := registry.Info("cuhk-zhuque/SkillTrustBench")
	if got := strings.Join(skillTrustBench.Aliases, ","); got != "SkillTrustBench" {
		t.Fatalf("SkillTrustBench aliases = %q", got)
	}
	if skillTrustBench.DefaultSplit != "benchmark" {
		t.Fatalf("SkillTrustBench default split = %q", skillTrustBench.DefaultSplit)
	}
}

func canonicalBenchmarkIDForTest(input string) string {
	switch strings.ToLower(strings.TrimSpace(input)) {
	case strings.ToLower(openClawBenchmarkID), strings.ToLower(openClawBenchmarkDataset):
		return openClawBenchmarkID
	default:
		return skillTrustBenchID
	}
}

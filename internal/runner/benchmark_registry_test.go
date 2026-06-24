package runner

import (
	"strings"
	"testing"
	"time"
)

func TestDefaultBenchmarkRegistryResolvesBuiltInsAndAliases(t *testing.T) {
	registry := DefaultBenchmarkRegistry()
	if got := strings.Join(registry.IDs(), ","); got != "OpenClaw/clawhub-security-signals,cuhk-zhuque/SkillTrustBench" {
		t.Fatalf("ids = %q", got)
	}
	for _, input := range []string{
		"OpenClaw/clawhub-security-signals",
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

type stubBenchmarkAdapter struct {
	id      string
	aliases []string
}

func (adapter stubBenchmarkAdapter) ID() string {
	return adapter.id
}

func (adapter stubBenchmarkAdapter) Aliases() []string {
	return append([]string(nil), adapter.aliases...)
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

func canonicalBenchmarkIDForTest(input string) string {
	switch strings.ToLower(strings.TrimSpace(input)) {
	case strings.ToLower(openClawBenchmarkID):
		return openClawBenchmarkID
	default:
		return skillTrustBenchID
	}
}

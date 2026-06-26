package main

import (
	"strings"
	"testing"
)

func TestRenderBenchmarkBlockUsesArtifactSummary(t *testing.T) {
	artifact := benchmarkArtifact{
		Benchmark: benchmarkMetadata{
			ID:     "cuhk-zhuque/SkillTrustBench",
			Split:  "benchmark",
			Rows:   2,
			Offset: 0,
			Limit:  2,
		},
		Summary: benchmarkSummary{
			CaseCount: 2,
			Evaluation: benchmarkEvaluationSummary{
				Scored:     2,
				Correct:    1,
				Incorrect:  1,
				Abstained:  0,
				Unscorable: 0,
				Errors:     0,
				Accuracy:   0.5,
			},
		},
	}

	block := renderBenchmarkBlock(artifact, benchmarkBlockOptions{
		Profile:     "clawhub",
		Artifact:    "artifacts/skilltrustbench-candidate.json",
		WorkflowURL: "https://github.com/openclaw/clawscan/actions/runs/123",
		Commit:      "abcdef1",
	})

	for _, want := range []string{
		"<!-- clawscan-benchmark:clawhub:start -->",
		"Profile: `clawhub`",
		"Benchmark: `cuhk-zhuque/SkillTrustBench` (`benchmark` split)",
		"Cases: `2`",
		"Accuracy: `0.5000`",
		"Scored: `2`, correct: `1`, incorrect: `1`, abstained: `0`, unscorable: `0`, errors: `0`",
		"Artifact: `artifacts/skilltrustbench-candidate.json`",
		"Workflow run: https://github.com/openclaw/clawscan/actions/runs/123",
		"Commit: `abcdef1`",
		"<!-- clawscan-benchmark:clawhub:end -->",
	} {
		if !strings.Contains(block, want) {
			t.Fatalf("block missing %q:\n%s", want, block)
		}
	}
}

func TestUpdateReadmeBenchmarkBlockReplacesMarkedRegion(t *testing.T) {
	readme := strings.Join([]string{
		"# ClawScan",
		"",
		"Before",
		"<!-- clawscan-benchmark:clawhub:start -->",
		"old",
		"<!-- clawscan-benchmark:clawhub:end -->",
		"After",
		"",
	}, "\n")

	updated, err := updateReadmeBenchmarkBlock(readme, "clawhub", "new block")
	if err != nil {
		t.Fatal(err)
	}

	want := strings.Join([]string{
		"# ClawScan",
		"",
		"Before",
		"<!-- clawscan-benchmark:clawhub:start -->",
		"new block",
		"<!-- clawscan-benchmark:clawhub:end -->",
		"After",
		"",
	}, "\n")
	if updated != want {
		t.Fatalf("updated README mismatch:\n--- got ---\n%s\n--- want ---\n%s", updated, want)
	}
}

func TestUpdateReadmeBenchmarkBlockRejectsMissingMarkers(t *testing.T) {
	_, err := updateReadmeBenchmarkBlock("# ClawScan\n", "clawhub", "new block")
	if err == nil || !strings.Contains(err.Error(), "missing benchmark marker") {
		t.Fatalf("err = %v", err)
	}
}

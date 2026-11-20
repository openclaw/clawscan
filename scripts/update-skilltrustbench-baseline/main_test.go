package main

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestRunWritesLegacyArtifactMetadataAndRegressionMetrics(t *testing.T) {
	dir := t.TempDir()
	artifactPath := filepath.Join(dir, "skilltrustbench-candidate.json")
	const subsetHash = "b2f66a93db7e7875aaff679cd9e30e110947ebac41459e03b8990222bd648575"
	raw := []byte(`{
  "benchmark": {
    "id": "cuhk-zhuque/SkillTrustBench",
    "split": "benchmark",
    "rows": 5,
    "idsSource": "https://example.test/subset.jsonl",
    "idsCount": 5,
    "idsSha256": "` + subsetHash + `"
  },
  "summary": {
    "caseCount": 5,
    "evaluation": {
      "scored": 5,
      "correct": 3,
      "incorrect": 2,
      "abstained": 0,
      "unscorable": 0,
      "errors": 0,
      "accuracy": 0.6
    }
  },
  "cases": [
    {"id":"case_1","expected":{"verdict":"malicious"},"evaluation":{"predictedVerdict":"clean","status":"incorrect"}},
    {"id":"case_2","expected":{"verdict":"malicious"},"evaluation":{"predictedVerdict":"malicious","status":"correct"}},
    {"id":"case_3","expected":{"verdict":"suspicious"},"evaluation":{"predictedVerdict":"suspicious","status":"correct"}},
    {"id":"case_4","expected":{"verdict":"clean"},"evaluation":{"predictedVerdict":"malicious","status":"incorrect"}},
    {"id":"case_5","expected":{"verdict":"clean"},"evaluation":{"predictedVerdict":"clean","status":"correct"}}
  ]
}`)
	if err := os.WriteFile(artifactPath, raw, 0o644); err != nil {
		t.Fatal(err)
	}

	output := filepath.Join(dir, "benchmarks", "baseline.json")
	profileSource := "proposals/GHSA-abcd-1234-5678/clawscan.yml"
	workflowURL := "https://github.com/openclaw/clawscan/actions/runs/123"
	var stdout strings.Builder
	err := run([]string{"--artifact", artifactPath, "--output", output, "--profile-source", profileSource,
		"--workflow-url", workflowURL, "--subset-case-ids-sha256", subsetHash}, &stdout)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(stdout.String(), "wrote "+output) {
		t.Fatalf("stdout = %q", stdout.String())
	}
	data, err := os.ReadFile(output)
	if err != nil {
		t.Fatal(err)
	}
	var baseline baseline
	if err := json.Unmarshal(data, &baseline); err != nil {
		t.Fatal(err)
	}

	sum := sha256.Sum256(raw)
	if baseline.Benchmark != "SkillTrustBench" || baseline.Subset != "leaderboard-10pct" {
		t.Fatalf("baseline identity = %#v", baseline)
	}
	if baseline.SubsetSource != defaultSubsetSource || baseline.SubsetCaseIDsSHA256 != subsetHash || baseline.NumCases != 5 {
		t.Fatalf("subset metadata = %#v", baseline)
	}
	if baseline.Profile != "clawhub" || baseline.ProfileSource != profileSource || baseline.WorkflowRun != workflowURL {
		t.Fatalf("profile metadata = %#v", baseline)
	}
	if baseline.ArtifactSHA256 != fmt.Sprintf("%x", sum[:]) {
		t.Fatalf("artifact sha = %q", baseline.ArtifactSHA256)
	}
	if baseline.Metrics.Accuracy != 0.6 || baseline.Metrics.AgreementRate != 0.6 {
		t.Fatalf("accuracy metrics = %#v", baseline.Metrics)
	}
	if baseline.Metrics.MaliciousRecall != 0.5 || baseline.Metrics.SuspiciousRecall != 1 {
		t.Fatalf("recall metrics = %#v", baseline.Metrics)
	}
	if baseline.Metrics.NormalFalsePositiveCount != 1 || baseline.Metrics.NormalFalsePositiveRate != 0.5 {
		t.Fatalf("normal false positives = %#v", baseline.Metrics)
	}
	if baseline.Metrics.FalseCleanCount != 1 {
		t.Fatalf("false clean count = %#v", baseline.Metrics)
	}
}

func TestDefaultBaselineOutputPathUsesUTCDateFilename(t *testing.T) {
	got := defaultBaselineOutputPath(time.Date(2026, 6, 29, 23, 59, 0, 0, time.UTC))
	want := "benchmarks/skilltrustbench-leaderboard-10pct/2026-06-29.json"
	if got != want {
		t.Fatalf("default output path = %q, want %q", got, want)
	}
}

func TestRunChecksSelectedCasesBeforeReplacingBaseline(t *testing.T) {
	const artifact = `{
		"status":"completed","complete":true,
		"benchmark":{"id":"cuhk-zhuque/SkillTrustBench","idsSource":"ids.jsonl","idsCount":1,"idsSha256":"HASH","rows":1},
		"summary":{"caseCount":1,"evaluation":{"scored":1,"correct":1,"accuracy":1}},
		"cases":[{"id":"case_1","expected":{"verdict":"clean"},"evaluation":{"predictedVerdict":"clean","status":"correct"}}]
	}`
	hash := fmt.Sprintf("%x", sha256.Sum256([]byte("case_1\n")))
	for _, tc := range []struct{ name, from, to, wantErr string }{
		{"completed run", "", "", ""},
		{"failed run", `"status":"completed","complete":true`, `"status":"failed","complete":false`, "incomplete"},
		{"inconsistent completion", `"complete":true`, `"complete":false`, "incomplete"},
		{"wrong dataset", "cuhk-zhuque/SkillTrustBench", "other/dataset", "SkillTrustBench"},
		{"missing selection", "ids.jsonl", "", "missing --ids"},
		{"different selection", "HASH", "other", "idsSha256"},
		{"missing selected case", `"idsCount":1`, `"idsCount":2`, "cases"},
		{"wrong summary count", `"caseCount":1`, `"caseCount":2`, "cases"},
		{"wrong row count", `"rows":1`, `"rows":2`, "rows"},
		{"different case", "case_1", "case_2", "case IDs"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			input, output := filepath.Join(dir, "run.json"), filepath.Join(dir, "baseline.json")
			raw := strings.Replace(artifact, tc.from, tc.to, 1)
			raw = strings.Replace(raw, "HASH", hash, 1)
			if err := os.WriteFile(input, []byte(raw), 0o600); err != nil {
				t.Fatal(err)
			}
			const previous = "previous baseline"
			if err := os.WriteFile(output, []byte(previous), 0o600); err != nil {
				t.Fatal(err)
			}
			err := run([]string{"--artifact", input, "--output", output, "--profile-source", "profile.yml", "--subset-case-ids-sha256", hash}, io.Discard)
			if tc.wantErr == "" {
				if err != nil {
					t.Fatal(err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("got %v, want %q", err, tc.wantErr)
			}
			if got, err := os.ReadFile(output); err != nil || string(got) != previous {
				t.Fatalf("previous baseline changed: %q, %v", got, err)
			}
		})
	}
}

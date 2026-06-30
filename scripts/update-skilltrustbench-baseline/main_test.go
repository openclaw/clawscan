package main

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestBuildBaselineUsesArtifactMetadataAndRegressionMetrics(t *testing.T) {
	dir := t.TempDir()
	artifactPath := filepath.Join(dir, "skilltrustbench-candidate.json")
	raw := []byte(`{
  "benchmark": {
    "id": "cuhk-zhuque/SkillTrustBench",
    "split": "benchmark",
    "rows": 5,
    "idsSource": "https://example.test/subset.jsonl",
    "idsCount": 5,
    "idsSha256": "subset-sha"
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
    {"expected":{"verdict":"malicious"},"evaluation":{"predictedVerdict":"clean","status":"incorrect"}},
    {"expected":{"verdict":"malicious"},"evaluation":{"predictedVerdict":"malicious","status":"correct"}},
    {"expected":{"verdict":"suspicious"},"evaluation":{"predictedVerdict":"suspicious","status":"correct"}},
    {"expected":{"verdict":"clean"},"evaluation":{"predictedVerdict":"malicious","status":"incorrect"}},
    {"expected":{"verdict":"clean"},"evaluation":{"predictedVerdict":"clean","status":"correct"}}
  ]
}`)
	if err := os.WriteFile(artifactPath, raw, 0o644); err != nil {
		t.Fatal(err)
	}

	baseline, err := buildBaseline(baselineOptions{
		ArtifactPath:  artifactPath,
		OutputPath:    filepath.Join(dir, "baseline.json"),
		Profile:       "clawhub",
		ProfileSource: "proposals/GHSA-abcd-1234-5678/clawscan.yml",
		WorkflowURL:   "https://github.com/openclaw/clawscan/actions/runs/123",
		Subset:        "leaderboard-10pct",
		SubsetSource:  defaultSubsetSource,
		SubsetSHA256:  "subset-sha",
	})
	if err != nil {
		t.Fatal(err)
	}

	sum := sha256.Sum256(raw)
	if baseline.Benchmark != "SkillTrustBench" || baseline.Subset != "leaderboard-10pct" {
		t.Fatalf("baseline identity = %#v", baseline)
	}
	if baseline.SubsetSource != defaultSubsetSource || baseline.SubsetCaseIDsSHA256 != "subset-sha" || baseline.NumCases != 5 {
		t.Fatalf("subset metadata = %#v", baseline)
	}
	if baseline.Profile != "clawhub" || baseline.ProfileSource != "proposals/GHSA-abcd-1234-5678/clawscan.yml" {
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

func TestRunWritesBaselineJSON(t *testing.T) {
	dir := t.TempDir()
	artifactPath := filepath.Join(dir, "artifact.json")
	outputPath := filepath.Join(dir, "benchmarks", "baseline.json")
	if err := os.WriteFile(artifactPath, []byte(`{
  "benchmark": {"id":"cuhk-zhuque/SkillTrustBench","idsSource":"subset.jsonl","idsCount":1,"idsSha256":"sha"},
  "summary": {"caseCount":1,"evaluation":{"scored":1,"correct":1,"accuracy":1}},
  "cases": [{"expected":{"verdict":"clean"},"evaluation":{"predictedVerdict":"clean","status":"correct"}}]
}`), 0o644); err != nil {
		t.Fatal(err)
	}

	var stdout strings.Builder
	err := run([]string{
		"--artifact", artifactPath,
		"--output", outputPath,
		"--profile", "clawhub",
		"--profile-source", "proposals/GHSA-abcd-1234-5678/clawscan.yml",
		"--subset-case-ids-sha256", "sha",
	}, &stdout)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(outputPath)
	if err != nil {
		t.Fatal(err)
	}
	var decoded baseline
	if err := json.Unmarshal(raw, &decoded); err != nil {
		t.Fatal(err)
	}
	if decoded.NumCases != 1 || decoded.Metrics.Accuracy != 1 {
		t.Fatalf("baseline = %#v", decoded)
	}
	if !strings.Contains(stdout.String(), "wrote "+outputPath) {
		t.Fatalf("stdout = %q", stdout.String())
	}
}

func TestBuildBaselineRequiresIDsMetadata(t *testing.T) {
	dir := t.TempDir()
	artifactPath := filepath.Join(dir, "artifact.json")
	if err := os.WriteFile(artifactPath, []byte(`{"benchmark":{"id":"cuhk-zhuque/SkillTrustBench"},"summary":{}}`), 0o644); err != nil {
		t.Fatal(err)
	}
	_, err := buildBaseline(baselineOptions{
		ArtifactPath:  artifactPath,
		Profile:       "clawhub",
		ProfileSource: "proposals/GHSA-abcd-1234-5678/clawscan.yml",
		Subset:        "leaderboard-10pct",
		SubsetSource:  defaultSubsetSource,
		SubsetSHA256:  defaultSubsetCaseIDsSHA256,
	})
	if err == nil || !strings.Contains(err.Error(), "missing --ids reproducibility metadata") {
		t.Fatalf("err = %v", err)
	}
}

func TestBuildBaselineRejectsUnexpectedSubsetHash(t *testing.T) {
	dir := t.TempDir()
	artifactPath := filepath.Join(dir, "artifact.json")
	if err := os.WriteFile(artifactPath, []byte(`{
  "benchmark": {"id":"cuhk-zhuque/SkillTrustBench","idsSource":"subset.jsonl","idsCount":1,"idsSha256":"actual"},
  "summary": {"caseCount":1,"evaluation":{"scored":1,"correct":1,"accuracy":1}},
  "cases": [{"expected":{"verdict":"clean"},"evaluation":{"predictedVerdict":"clean","status":"correct"}}]
}`), 0o644); err != nil {
		t.Fatal(err)
	}
	_, err := buildBaseline(baselineOptions{
		ArtifactPath:  artifactPath,
		Profile:       "clawhub",
		ProfileSource: "proposals/GHSA-abcd-1234-5678/clawscan.yml",
		Subset:        "leaderboard-10pct",
		SubsetSource:  defaultSubsetSource,
		SubsetSHA256:  "expected",
	})
	if err == nil || !strings.Contains(err.Error(), "has idsSha256 actual, expected expected") {
		t.Fatalf("err = %v", err)
	}
}

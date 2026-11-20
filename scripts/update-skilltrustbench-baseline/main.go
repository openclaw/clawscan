package main

import (
	"crypto/sha256"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/openclaw/clawscan/internal/runner"
)

const (
	defaultSubsetSource        = "https://huggingface.co/datasets/cuhk-zhuque/SkillTrustBench-results/resolve/main/data/evaluation_subset_10pct.jsonl"
	defaultSubsetCaseIDsSHA256 = "903a036e4b7b16ee28e22d5d9db57a00b3764cfe41e43144acad67921e5196c2"
)

type benchmarkArtifact struct {
	Status    string            `json:"status"`
	Complete  *bool             `json:"complete"`
	Benchmark benchmarkMetadata `json:"benchmark"`
	Summary   benchmarkSummary  `json:"summary"`
	Cases     []benchmarkCase   `json:"cases"`
}

type benchmarkMetadata struct {
	ID        string `json:"id"`
	Rows      *int   `json:"rows"`
	IDsSource string `json:"idsSource"`
	IDsCount  int    `json:"idsCount"`
	IDsSHA256 string `json:"idsSha256"`
}

type benchmarkSummary struct {
	CaseCount  *int                              `json:"caseCount"`
	Evaluation runner.BenchmarkEvaluationSummary `json:"evaluation"`
}

type benchmarkCase struct {
	ID         string               `json:"id"`
	Expected   benchmarkExpected    `json:"expected"`
	Evaluation *benchmarkEvaluation `json:"evaluation"`
}

type benchmarkExpected struct {
	Verdict string `json:"verdict"`
}

type benchmarkEvaluation struct {
	PredictedVerdict string `json:"predictedVerdict"`
}

type baseline struct {
	Benchmark           string          `json:"benchmark"`
	Subset              string          `json:"subset"`
	SubsetSource        string          `json:"subsetSource"`
	SubsetCaseIDsSHA256 string          `json:"subsetCaseIdsSha256"`
	NumCases            int             `json:"numCases"`
	Profile             string          `json:"profile"`
	ProfileSource       string          `json:"profileSource"`
	WorkflowRun         string          `json:"workflowRun,omitempty"`
	ArtifactSHA256      string          `json:"artifactSha256"`
	Metrics             baselineMetrics `json:"metrics"`
}

type baselineMetrics struct {
	Scored                   int     `json:"scored"`
	Correct                  int     `json:"correct"`
	Incorrect                int     `json:"incorrect"`
	Abstained                int     `json:"abstained"`
	Unscorable               int     `json:"unscorable"`
	Errors                   int     `json:"errors"`
	Accuracy                 float64 `json:"accuracy"`
	AgreementRate            float64 `json:"agreementRate"`
	MaliciousRecall          float64 `json:"maliciousRecall"`
	SuspiciousRecall         float64 `json:"suspiciousRecall"`
	NormalFalsePositiveCount int     `json:"normalFalsePositiveCount"`
	NormalFalsePositiveRate  float64 `json:"normalFalsePositiveRate"`
	FalseCleanCount          int     `json:"falseCleanCount"`
}

type baselineOptions struct {
	ArtifactPath  string
	OutputPath    string
	Profile       string
	ProfileSource string
	WorkflowURL   string
	Subset        string
	SubsetSource  string
	SubsetSHA256  string
}

func main() {
	if err := run(os.Args[1:], os.Stdout); err != nil {
		fmt.Fprintln(os.Stderr, err.Error())
		os.Exit(1)
	}
}

func run(args []string, stdout io.Writer) error {
	flags := flag.NewFlagSet("update-skilltrustbench-baseline", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	artifactPath := flags.String("artifact", "", "benchmark artifact JSON path")
	outputPath := flags.String("output", defaultBaselineOutputPath(time.Now().UTC()), "baseline JSON output path")
	profile := flags.String("profile", "clawhub", "profile name")
	profileSource := flags.String("profile-source", "", "profile config source path")
	workflowURL := flags.String("workflow-url", "", "workflow run URL")
	subset := flags.String("subset", "leaderboard-10pct", "subset label")
	subsetSource := flags.String("subset-source", defaultSubsetSource, "subset ID source URL")
	subsetSHA256 := flags.String("subset-case-ids-sha256", defaultSubsetCaseIDsSHA256, "expected SHA-256 for selected case IDs")
	if err := flags.Parse(args); err != nil {
		return err
	}
	opts := baselineOptions{
		ArtifactPath:  *artifactPath,
		OutputPath:    *outputPath,
		Profile:       *profile,
		ProfileSource: *profileSource,
		WorkflowURL:   *workflowURL,
		Subset:        *subset,
		SubsetSource:  *subsetSource,
		SubsetSHA256:  *subsetSHA256,
	}
	result, err := buildBaseline(opts)
	if err != nil {
		return err
	}
	data, err := json.MarshalIndent(result, "", "  ")
	if err != nil {
		return err
	}
	data = append(data, '\n')
	if err := os.MkdirAll(filepath.Dir(opts.OutputPath), 0o755); err != nil {
		return err
	}
	if err := os.WriteFile(opts.OutputPath, data, 0o644); err != nil {
		return fmt.Errorf("write baseline %s: %w", opts.OutputPath, err)
	}
	fmt.Fprintf(stdout, "wrote %s\n", opts.OutputPath)
	return nil
}

func defaultBaselineOutputPath(now time.Time) string {
	return filepath.ToSlash(filepath.Join(
		"benchmarks",
		"skilltrustbench-leaderboard-10pct",
		now.Format("2006-01-02")+".json",
	))
}

func buildBaseline(opts baselineOptions) (baseline, error) {
	if opts.ArtifactPath == "" {
		return baseline{}, errors.New("missing required --artifact")
	}
	if opts.Profile == "" {
		return baseline{}, errors.New("missing required --profile")
	}
	if opts.ProfileSource == "" {
		return baseline{}, errors.New("missing required --profile-source")
	}
	if opts.Subset == "" {
		return baseline{}, errors.New("missing required --subset")
	}
	if opts.SubsetSource == "" {
		return baseline{}, errors.New("missing required --subset-source")
	}
	if opts.SubsetSHA256 == "" {
		return baseline{}, errors.New("missing required --subset-case-ids-sha256")
	}
	raw, err := os.ReadFile(opts.ArtifactPath)
	if err != nil {
		return baseline{}, fmt.Errorf("read benchmark artifact %s: %w", opts.ArtifactPath, err)
	}
	var artifact benchmarkArtifact
	if err := json.Unmarshal(raw, &artifact); err != nil {
		return baseline{}, fmt.Errorf("parse benchmark artifact %s: %w", opts.ArtifactPath, err)
	}
	if err := artifact.validateSelection(opts.SubsetSHA256); err != nil {
		return baseline{}, fmt.Errorf("benchmark artifact %s: %w", opts.ArtifactPath, err)
	}
	sum := sha256.Sum256(raw)
	return baseline{
		Benchmark:           "SkillTrustBench",
		Subset:              opts.Subset,
		SubsetSource:        opts.SubsetSource,
		SubsetCaseIDsSHA256: artifact.Benchmark.IDsSHA256,
		NumCases:            len(artifact.Cases),
		Profile:             opts.Profile,
		ProfileSource:       opts.ProfileSource,
		WorkflowRun:         opts.WorkflowURL,
		ArtifactSHA256:      fmt.Sprintf("%x", sum[:]),
		Metrics:             baselineMetricsFromArtifact(artifact),
	}, nil
}

func (a benchmarkArtifact) validateSelection(expectedSHA string) error {
	if a.Benchmark.ID != "cuhk-zhuque/SkillTrustBench" {
		return fmt.Errorf("expected SkillTrustBench artifact, got benchmark.id %q", a.Benchmark.ID)
	}
	// Artifacts written before lifecycle tracking have neither field.
	if a.Status != "" || a.Complete != nil {
		if a.Status != "completed" || a.Complete == nil || !*a.Complete {
			return fmt.Errorf("benchmark incomplete (status %q)", a.Status)
		}
	}
	if a.Benchmark.IDsSource == "" || a.Benchmark.IDsSHA256 == "" || a.Benchmark.IDsCount <= 0 {
		return errors.New("missing --ids reproducibility metadata")
	}
	if a.Benchmark.IDsSHA256 != expectedSHA {
		return fmt.Errorf("has idsSha256 %s, expected %s", a.Benchmark.IDsSHA256, expectedSHA)
	}
	count := len(a.Cases)
	if count != a.Benchmark.IDsCount {
		return fmt.Errorf("found %d cases for %d selected IDs", count, a.Benchmark.IDsCount)
	}
	if a.Summary.CaseCount != nil && *a.Summary.CaseCount != count {
		return fmt.Errorf("summary reports %d cases, found %d", *a.Summary.CaseCount, count)
	}
	if a.Benchmark.Rows != nil && *a.Benchmark.Rows != count {
		return fmt.Errorf("benchmark reports %d rows, found %d cases", *a.Benchmark.Rows, count)
	}
	ids := make([]string, 0, count)
	for _, c := range a.Cases {
		ids = append(ids, c.ID)
	}
	if runner.BenchmarkIDsSHA256(ids) != expectedSHA {
		return errors.New("case IDs do not match the selected subset")
	}
	return nil
}

func baselineMetricsFromArtifact(artifact benchmarkArtifact) baselineMetrics {
	metrics := baselineMetrics{
		Scored:        artifact.Summary.Evaluation.Scored,
		Correct:       artifact.Summary.Evaluation.Correct,
		Incorrect:     artifact.Summary.Evaluation.Incorrect,
		Abstained:     artifact.Summary.Evaluation.Abstained,
		Unscorable:    artifact.Summary.Evaluation.Unscorable,
		Errors:        artifact.Summary.Evaluation.Errors,
		Accuracy:      artifact.Summary.Evaluation.Accuracy,
		AgreementRate: artifact.Summary.Evaluation.Accuracy,
	}
	var maliciousTotal, maliciousCorrect int
	var suspiciousTotal, suspiciousCorrect int
	var normalTotal int
	for _, benchmarkCase := range artifact.Cases {
		expected := strings.ToLower(strings.TrimSpace(benchmarkCase.Expected.Verdict))
		if expected == "normal" {
			expected = "clean"
		}
		predicted := ""
		if benchmarkCase.Evaluation != nil {
			predicted = strings.ToLower(strings.TrimSpace(benchmarkCase.Evaluation.PredictedVerdict))
			if predicted == "normal" {
				predicted = "clean"
			}
		}
		switch expected {
		case "malicious":
			maliciousTotal++
			if predicted == "malicious" {
				maliciousCorrect++
			}
			if predicted == "clean" {
				metrics.FalseCleanCount++
			}
		case "suspicious":
			suspiciousTotal++
			if predicted == "suspicious" {
				suspiciousCorrect++
			}
			if predicted == "clean" {
				metrics.FalseCleanCount++
			}
		case "clean":
			normalTotal++
			if predicted != "" && predicted != "clean" {
				metrics.NormalFalsePositiveCount++
			}
		}
	}
	metrics.MaliciousRecall = ratio(maliciousCorrect, maliciousTotal)
	metrics.SuspiciousRecall = ratio(suspiciousCorrect, suspiciousTotal)
	metrics.NormalFalsePositiveRate = ratio(metrics.NormalFalsePositiveCount, normalTotal)
	return metrics
}

func ratio(numerator int, denominator int) float64 {
	if denominator == 0 {
		return 0
	}
	return float64(numerator) / float64(denominator)
}

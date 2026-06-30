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
)

const (
	defaultSubsetSource        = "https://huggingface.co/datasets/cuhk-zhuque/SkillTrustBench-results/resolve/main/data/evaluation_subset_10pct.jsonl"
	defaultSubsetCaseIDsSHA256 = "903a036e4b7b16ee28e22d5d9db57a00b3764cfe41e43144acad67921e5196c2"
)

type benchmarkArtifact struct {
	Benchmark benchmarkMetadata `json:"benchmark"`
	Summary   benchmarkSummary  `json:"summary"`
	Cases     []benchmarkCase   `json:"cases"`
}

type benchmarkMetadata struct {
	ID        string `json:"id"`
	Split     string `json:"split"`
	Rows      int    `json:"rows"`
	IDsSource string `json:"idsSource"`
	IDsCount  int    `json:"idsCount"`
	IDsSHA256 string `json:"idsSha256"`
}

type benchmarkSummary struct {
	CaseCount  int                        `json:"caseCount"`
	Evaluation benchmarkEvaluationSummary `json:"evaluation"`
}

type benchmarkEvaluationSummary struct {
	Scored     int     `json:"scored"`
	Correct    int     `json:"correct"`
	Incorrect  int     `json:"incorrect"`
	Abstained  int     `json:"abstained"`
	Unscorable int     `json:"unscorable"`
	Errors     int     `json:"errors"`
	Accuracy   float64 `json:"accuracy"`
}

type benchmarkCase struct {
	Expected   benchmarkExpected    `json:"expected"`
	Evaluation *benchmarkEvaluation `json:"evaluation"`
}

type benchmarkExpected struct {
	Verdict string `json:"verdict"`
}

type benchmarkEvaluation struct {
	PredictedVerdict string `json:"predictedVerdict"`
	Status           string `json:"status"`
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
	if artifact.Benchmark.ID == "" {
		return baseline{}, fmt.Errorf("benchmark artifact %s missing benchmark.id", opts.ArtifactPath)
	}
	if artifact.Benchmark.IDsSource == "" || artifact.Benchmark.IDsSHA256 == "" || artifact.Benchmark.IDsCount == 0 {
		return baseline{}, fmt.Errorf("benchmark artifact %s missing --ids reproducibility metadata", opts.ArtifactPath)
	}
	if artifact.Benchmark.IDsSHA256 != opts.SubsetSHA256 {
		return baseline{}, fmt.Errorf("benchmark artifact %s has idsSha256 %s, expected %s", opts.ArtifactPath, artifact.Benchmark.IDsSHA256, opts.SubsetSHA256)
	}
	caseCount := artifact.Summary.CaseCount
	if caseCount == 0 {
		caseCount = len(artifact.Cases)
	}
	if caseCount == 0 {
		caseCount = artifact.Benchmark.Rows
	}
	sum := sha256.Sum256(raw)
	return baseline{
		Benchmark:           "SkillTrustBench",
		Subset:              opts.Subset,
		SubsetSource:        opts.SubsetSource,
		SubsetCaseIDsSHA256: artifact.Benchmark.IDsSHA256,
		NumCases:            caseCount,
		Profile:             opts.Profile,
		ProfileSource:       opts.ProfileSource,
		WorkflowRun:         opts.WorkflowURL,
		ArtifactSHA256:      fmt.Sprintf("%x", sum[:]),
		Metrics:             baselineMetricsFromArtifact(artifact),
	}, nil
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

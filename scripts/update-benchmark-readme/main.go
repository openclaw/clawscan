package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"
)

type benchmarkArtifact struct {
	Benchmark benchmarkMetadata `json:"benchmark"`
	Summary   benchmarkSummary  `json:"summary"`
}

type benchmarkMetadata struct {
	ID     string `json:"id"`
	Split  string `json:"split"`
	Offset int    `json:"offset"`
	Limit  int    `json:"limit"`
	Rows   int    `json:"rows"`
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

type benchmarkBlockOptions struct {
	Profile     string
	Artifact    string
	WorkflowURL string
	Commit      string
}

func main() {
	if err := run(os.Args[1:], os.Stdout); err != nil {
		fmt.Fprintln(os.Stderr, err.Error())
		os.Exit(1)
	}
}

func run(args []string, stdout io.Writer) error {
	flags := flag.NewFlagSet("update-benchmark-readme", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	artifactPath := flags.String("artifact", "", "benchmark artifact JSON path")
	readmePath := flags.String("readme", "README.md", "README path")
	profile := flags.String("profile", "clawhub", "profile marker id")
	workflowURL := flags.String("workflow-url", "", "workflow run URL")
	commit := flags.String("commit", "", "commit SHA or ref")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if *artifactPath == "" {
		return errors.New("missing required --artifact")
	}
	if *profile == "" {
		return errors.New("missing required --profile")
	}

	artifact, err := readBenchmarkArtifact(*artifactPath)
	if err != nil {
		return err
	}
	readme, err := os.ReadFile(*readmePath)
	if err != nil {
		return fmt.Errorf("read README %s: %w", *readmePath, err)
	}
	block := renderBenchmarkBlock(artifact, benchmarkBlockOptions{
		Profile:     *profile,
		Artifact:    *artifactPath,
		WorkflowURL: *workflowURL,
		Commit:      *commit,
	})
	updated, err := updateReadmeBenchmarkBlock(string(readme), *profile, block)
	if err != nil {
		return err
	}
	if err := os.WriteFile(*readmePath, []byte(updated), 0o644); err != nil {
		return fmt.Errorf("write README %s: %w", *readmePath, err)
	}
	fmt.Fprint(stdout, block)
	return nil
}

func readBenchmarkArtifact(path string) (benchmarkArtifact, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return benchmarkArtifact{}, fmt.Errorf("read benchmark artifact %s: %w", path, err)
	}
	var artifact benchmarkArtifact
	if err := json.Unmarshal(data, &artifact); err != nil {
		return benchmarkArtifact{}, fmt.Errorf("parse benchmark artifact %s: %w", path, err)
	}
	if artifact.Benchmark.ID == "" {
		return benchmarkArtifact{}, fmt.Errorf("benchmark artifact %s missing benchmark.id", path)
	}
	return artifact, nil
}

func renderBenchmarkBlock(artifact benchmarkArtifact, opts benchmarkBlockOptions) string {
	caseCount := artifact.Summary.CaseCount
	if caseCount == 0 {
		caseCount = artifact.Benchmark.Rows
	}
	lines := []string{
		benchmarkStartMarker(opts.Profile),
		fmt.Sprintf("Profile: `%s`", opts.Profile),
		fmt.Sprintf("Benchmark: `%s` (`%s` split)", artifact.Benchmark.ID, artifact.Benchmark.Split),
		fmt.Sprintf("Cases: `%d`", caseCount),
		fmt.Sprintf("Accuracy: `%.4f`", artifact.Summary.Evaluation.Accuracy),
		fmt.Sprintf(
			"Scored: `%d`, correct: `%d`, incorrect: `%d`, abstained: `%d`, unscorable: `%d`, errors: `%d`",
			artifact.Summary.Evaluation.Scored,
			artifact.Summary.Evaluation.Correct,
			artifact.Summary.Evaluation.Incorrect,
			artifact.Summary.Evaluation.Abstained,
			artifact.Summary.Evaluation.Unscorable,
			artifact.Summary.Evaluation.Errors,
		),
	}
	if opts.Artifact != "" {
		lines = append(lines, fmt.Sprintf("Artifact: `%s`", opts.Artifact))
	}
	if opts.WorkflowURL != "" {
		lines = append(lines, "Workflow run: "+opts.WorkflowURL)
	}
	if opts.Commit != "" {
		lines = append(lines, fmt.Sprintf("Commit: `%s`", opts.Commit))
	}
	lines = append(lines, benchmarkEndMarker(opts.Profile), "")
	return strings.Join(lines, "\n")
}

func updateReadmeBenchmarkBlock(readme string, profile string, replacement string) (string, error) {
	start := benchmarkStartMarker(profile)
	end := benchmarkEndMarker(profile)
	startIndex := strings.Index(readme, start)
	endIndex := strings.Index(readme, end)
	if startIndex == -1 || endIndex == -1 || endIndex < startIndex {
		return "", fmt.Errorf("missing benchmark marker pair for profile %s", profile)
	}
	endIndex += len(end)
	if strings.HasPrefix(readme[endIndex:], "\r\n") {
		endIndex += 2
	} else if strings.HasPrefix(readme[endIndex:], "\n") {
		endIndex++
	}

	if !strings.Contains(replacement, start) || !strings.Contains(replacement, end) {
		replacement = start + "\n" + strings.Trim(replacement, "\n") + "\n" + end
	}
	if !strings.HasSuffix(replacement, "\n") {
		replacement += "\n"
	}
	return readme[:startIndex] + replacement + readme[endIndex:], nil
}

func benchmarkStartMarker(profile string) string {
	return fmt.Sprintf("<!-- clawscan-benchmark:%s:start -->", profile)
}

func benchmarkEndMarker(profile string) string {
	return fmt.Sprintf("<!-- clawscan-benchmark:%s:end -->", profile)
}

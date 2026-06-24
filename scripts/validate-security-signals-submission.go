package main

import (
	"fmt"
	"io"
	"os"

	"github.com/openclaw/clawscan/internal/runner"
)

func main() {
	if err := run(os.Args[1:], os.Stdout); err != nil {
		fmt.Fprintln(os.Stderr, err.Error())
		os.Exit(1)
	}
}

func run(args []string, stdout io.Writer) error {
	var submissionDir string
	jsonOutput := false
	for _, arg := range args {
		switch arg {
		case "--help", "-h":
			fmt.Fprint(stdout, helpText())
			return nil
		case "--json":
			jsonOutput = true
		default:
			if len(arg) > 0 && arg[0] == '-' {
				return fmt.Errorf("Unknown argument: %s", arg)
			}
			if submissionDir != "" {
				return fmt.Errorf("Unexpected argument: %s", arg)
			}
			submissionDir = arg
		}
	}
	if submissionDir == "" {
		return fmt.Errorf("validate-security-signals-submission requires <submission-dir>")
	}

	result, err := runner.ValidateSecuritySignalsSubmission(submissionDir, runner.HuggingFaceBenchmarkClient{
		Endpoint: os.Getenv("CLAWSCAN_HUGGINGFACE_ROWS_ENDPOINT"),
	})
	if err != nil {
		return err
	}
	if jsonOutput {
		return runner.WriteJSON(stdout, result)
	}
	printSubmissionSummary(stdout, result)
	return nil
}

func printSubmissionSummary(w io.Writer, result runner.SecuritySignalsSubmissionResult) {
	metrics := result.Metrics
	fmt.Fprintf(w, "Security Signals submission valid: %d case(s)\n", metrics.CaseCount)
	fmt.Fprintf(w, "dataset=%s split=%s revision=%s\n", result.Benchmark.Dataset, result.Benchmark.Split, result.Benchmark.Revision)
	fmt.Fprintf(w, "F1=%.4f precision=%.4f recall=%.4f FPR=%.4f\n", metrics.F1, metrics.Precision, metrics.Recall, metrics.FalsePositiveRate)
	fmt.Fprintf(w, "TP=%d FP=%d TN=%d FN=%d\n", metrics.TruePositive, metrics.FalsePositive, metrics.TrueNegative, metrics.FalseNegative)
}

func helpText() string {
	return `Usage: go run ./scripts/validate-security-signals-submission.go <submission-dir> [--json]

Validates one Security Signals leaderboard submission directory for CI and
repository maintenance. The directory must contain metadata.json and
predictions.jsonl.
`
}

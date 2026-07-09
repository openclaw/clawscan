package runner

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"time"
)

var errInvalidAIGSARIF = errors.New("aig-skill-scan returned invalid SARIF 2.1.0 JSON")

type aigSARIFDocument struct {
	Version    string         `json:"version"`
	Properties map[string]any `json:"properties,omitempty"`
	Runs       []aigSARIFRun  `json:"runs"`
}

type aigSARIFRun struct {
	Properties map[string]any   `json:"properties,omitempty"`
	Results    []aigSARIFResult `json:"results,omitempty"`
}

type aigSARIFResult struct {
	Properties map[string]any `json:"properties,omitempty"`
}

func (runner ExternalScannerRunner) runAIG(target string, startedAt string) (ScannerResult, error) {
	command := "aig-skill-scan"
	completedAt := func() string {
		return time.Now().UTC().Format(time.RFC3339Nano)
	}
	skipped := func(message string) ScannerResult {
		return ScannerResult{
			Status:      "skipped",
			StartedAt:   startedAt,
			CompletedAt: completedAt(),
			Command:     []string{command, "--repo", target, "--language", "en"},
			Error:       message,
			Raw:         nil,
		}
	}

	if isURLTarget(target) {
		return skipped("aig-skill-scan supports local directory targets only; URL targets are unsupported."), nil
	}
	info, err := os.Stat(target)
	if err != nil {
		return ScannerResult{}, err
	}
	if !info.IsDir() {
		return skipped("aig-skill-scan supports local directory targets only; file targets are unsupported."), nil
	}

	resultDir, err := os.MkdirTemp("", "clawscan-aig-*")
	if err != nil {
		return ScannerResult{}, err
	}
	defer os.RemoveAll(resultDir)

	resultPath := filepath.Join(resultDir, "aig-skill-scan.sarif.json")
	args := []string{"--repo", target, "--language", "en", "-o", resultPath}
	fullCommand := append([]string{command}, args...)
	timeout := runner.Timeout
	if timeout == 0 {
		timeout = 20 * time.Minute
	}

	output, runErr := runner.CommandRunner.Run(command, args, resultDir, timeout)
	raw, readErr := os.ReadFile(resultPath)
	finishedAt := completedAt()
	if readErr != nil {
		message := "aig-skill-scan did not write SARIF output."
		if runErr != nil {
			message = scannerCommandError(runErr, output.Stderr, runner.Env) + ": " + message
		}
		return ScannerResult{
			Status:      "failed",
			StartedAt:   startedAt,
			CompletedAt: finishedAt,
			Command:     fullCommand,
			Error:       message,
			Raw:         nil,
		}, nil
	}
	if _, err := parseAIGSARIF(raw); err != nil {
		message := err.Error()
		if runErr != nil {
			message = scannerCommandError(runErr, output.Stderr, runner.Env) + ": " + message
		}
		return ScannerResult{
			Status:      "failed",
			StartedAt:   startedAt,
			CompletedAt: finishedAt,
			Command:     fullCommand,
			Error:       message,
			Raw:         nil,
		}, nil
	}

	result := ScannerResult{
		Status:      "completed",
		StartedAt:   startedAt,
		CompletedAt: finishedAt,
		Command:     fullCommand,
		Error:       "",
		Raw:         json.RawMessage(raw),
	}
	if runErr != nil {
		result.Error = scannerCommandError(runErr, output.Stderr, runner.Env)
	}
	return result, nil
}

func aigRequirements(env map[string]string) []EnvRequirement {
	reason := "scanner aig (set LLM_API_KEY or OPENAI_API_KEY)"
	if strings.TrimSpace(env["LLM_API_KEY"]) != "" {
		return []EnvRequirement{{EnvVar: "LLM_API_KEY", Reason: reason}}
	}
	if strings.TrimSpace(env["OPENAI_API_KEY"]) != "" {
		return []EnvRequirement{{EnvVar: "OPENAI_API_KEY", Reason: reason}}
	}
	return []EnvRequirement{{EnvVar: "LLM_API_KEY", Reason: reason}}
}

func parseAIGSARIF(raw []byte) (aigSARIFDocument, error) {
	var document aigSARIFDocument
	if err := json.Unmarshal(raw, &document); err != nil {
		return aigSARIFDocument{}, errInvalidAIGSARIF
	}
	if document.Version != "2.1.0" || document.Runs == nil {
		return aigSARIFDocument{}, errInvalidAIGSARIF
	}
	return document, nil
}

func aigSARIFPrediction(raw json.RawMessage) (string, bool) {
	document, err := parseAIGSARIF(raw)
	if err != nil {
		return "", false
	}
	if prediction, ok := predictionFromAIGProperties(document.Properties); ok {
		return prediction, true
	}
	for _, run := range document.Runs {
		if prediction, ok := predictionFromAIGProperties(run.Properties); ok {
			return prediction, true
		}
	}
	for _, run := range document.Runs {
		for _, result := range run.Results {
			if prediction, ok := predictionFromAIGProperties(result.Properties); ok {
				return prediction, true
			}
		}
	}
	return "", false
}

func predictionFromAIGProperties(properties map[string]any) (string, bool) {
	for _, key := range []string{"prediction", "verdict", "judgment", "status"} {
		if prediction, ok := normalizePredictionLabel(properties[key]); ok {
			return prediction, true
		}
	}
	return "", false
}

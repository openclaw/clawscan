package runner

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"time"
)

var errInvalidCiscoJSON = errors.New("Cisco skill-scanner returned invalid JSON")

func (runner ExternalScannerRunner) runCisco(target string, startedAt string) (ScannerResult, error) {
	resultDir, err := os.MkdirTemp("", "clawscan-cisco-*")
	if err != nil {
		return ScannerResult{}, err
	}
	defer os.RemoveAll(resultDir)

	command := "skill-scanner"
	resultPath := filepath.Join(resultDir, "cisco-skill-scanner.json")
	args := []string{"scan", target, "--format", "json", "--output", resultPath}
	fullCommand := append([]string{command}, args...)
	timeout := runner.Timeout
	if timeout == 0 {
		timeout = 20 * time.Minute
	}

	output, runErr := runner.CommandRunner.Run(command, args, "", timeout)
	raw, readErr := os.ReadFile(resultPath)
	completedAt := time.Now().UTC().Format(time.RFC3339Nano)
	if readErr != nil {
		message := "Cisco skill-scanner did not write JSON output."
		if runErr != nil {
			message = scannerCommandError(runErr, output.Stderr, runner.Env) + ": " + message
		}
		return ScannerResult{
			Status:      "failed",
			StartedAt:   startedAt,
			CompletedAt: completedAt,
			Command:     fullCommand,
			Error:       message,
			Raw:         nil,
		}, nil
	}
	if !json.Valid(raw) {
		message := errInvalidCiscoJSON.Error()
		if runErr != nil {
			message = scannerCommandError(runErr, output.Stderr, runner.Env) + ": " + message
		}
		return ScannerResult{
			Status:      "failed",
			StartedAt:   startedAt,
			CompletedAt: completedAt,
			Command:     fullCommand,
			Error:       message,
			Raw:         nil,
		}, nil
	}
	result := ScannerResult{
		Status:      "completed",
		StartedAt:   startedAt,
		CompletedAt: completedAt,
		Command:     fullCommand,
		Error:       "",
		Raw:         json.RawMessage(raw),
	}
	if runErr != nil {
		result.Error = scannerCommandError(runErr, output.Stderr, runner.Env)
	}
	return result, nil
}

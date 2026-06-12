package runner

import (
	"encoding/json"
	"errors"
	"strings"
	"time"
)

var errInvalidSnykJSON = errors.New("Snyk scanner returned invalid JSON")

func (runner ExternalScannerRunner) runSnyk(target string, startedAt string) (ScannerResult, error) {
	command := "uvx"
	args := []string{"snyk-agent-scan@latest", "--json", "--no-bootstrap", "--skills", target}
	fullCommand := append([]string{command}, args...)
	timeout := runner.Timeout
	if timeout == 0 {
		timeout = 20 * time.Minute
	}
	output, runErr := runner.CommandRunner.Run(command, args, "", timeout)
	completedAt := time.Now().UTC().Format(time.RFC3339Nano)
	raw := strings.TrimSpace(output.Stdout)
	if runErr != nil {
		message := scannerCommandError(runErr, output.Stderr)
		if json.Valid([]byte(raw)) {
			return ScannerResult{
				Status:      "completed",
				StartedAt:   startedAt,
				CompletedAt: completedAt,
				Command:     fullCommand,
				Error:       message,
				Raw:         json.RawMessage(raw),
			}, nil
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
	if raw == "" {
		return ScannerResult{
			Status:      "failed",
			StartedAt:   startedAt,
			CompletedAt: completedAt,
			Command:     fullCommand,
			Error:       "Snyk scanner did not return JSON on stdout.",
			Raw:         nil,
		}, nil
	}
	if !json.Valid([]byte(raw)) {
		return ScannerResult{}, errInvalidSnykJSON
	}
	return ScannerResult{
		Status:      "completed",
		StartedAt:   startedAt,
		CompletedAt: completedAt,
		Command:     fullCommand,
		Error:       "",
		Raw:         json.RawMessage(raw),
	}, nil
}

func scannerCommandError(runErr error, stderr string) string {
	message := runErr.Error()
	if strings.TrimSpace(stderr) != "" {
		message += ": " + strings.TrimSpace(stderr)
	}
	return message
}

package runner

import (
	"encoding/json"
	"errors"
	"strings"
	"time"
)

var errInvalidSocketJSON = errors.New("Socket scanner returned invalid JSON")

func (runner ExternalScannerRunner) runSocket(target string, startedAt string) (ScannerResult, error) {
	command := "npx"
	args := []string{"--yes", "socket", "scan", "create", "--no-banner", "--no-spinner", "--no-interactive", "--json", target}
	if runner.SandboxMode == SandboxModeDocker {
		command = "socket"
		args = []string{"scan", "create", "--no-banner", "--no-spinner", "--no-interactive", "--json", target}
	}
	fullCommand := append([]string{command}, args...)
	timeout := runner.Timeout
	if timeout == 0 {
		timeout = 20 * time.Minute
	}
	output, runErr := runner.CommandRunner.Run(command, args, "", timeout)
	completedAt := time.Now().UTC().Format(time.RFC3339Nano)
	raw := strings.TrimSpace(output.Stdout)
	if runErr != nil {
		message := scannerCommandError(runErr, output.Stderr, runner.Env)
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
			Error:       "Socket scanner did not return JSON on stdout.",
			Raw:         nil,
		}, nil
	}
	if !json.Valid([]byte(raw)) {
		return ScannerResult{
			Status:      "failed",
			StartedAt:   startedAt,
			CompletedAt: completedAt,
			Command:     fullCommand,
			Error:       errInvalidSocketJSON.Error(),
			Raw:         nil,
		}, nil
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

package runner

import (
	"os"
	"time"
)

// runReportFile records a command's exit code only when its report is usable.
func (runner ExternalScannerRunner) runReportFile(command string, args []string, cwd, startedAt, path, missingReport string, validate func([]byte) error) ScannerResult {
	timeout := runner.Timeout
	if timeout == 0 {
		timeout = defaultScannerTimeout
	}
	output, runErr := runner.CommandRunner.Run(command, args, cwd, timeout)
	raw, readErr := os.ReadFile(path)
	result := ScannerResult{
		Status:      commandScannerResultStatus(output, runErr),
		StartedAt:   startedAt,
		CompletedAt: time.Now().UTC().Format(time.RFC3339Nano),
		Command:     append([]string{command}, args...),
	}
	if runErr != nil {
		result.Error = commandError(runErr, output.Stderr, runner.Env)
	}
	var reportError string
	if readErr != nil {
		reportError = missingReport
	} else if err := validate(raw); err != nil {
		reportError = err.Error()
	}
	if reportError != "" {
		result.Status = "failed"
		if runErr != nil {
			result.Error += ": "
		}
		result.Error += reportError
		return result
	}
	result.Raw = raw
	result.ExitCode = gateEligibleExitCode(output.ExitCode)
	return result
}

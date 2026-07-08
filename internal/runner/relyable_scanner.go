package runner

import (
	"encoding/json"
	"strings"
	"time"
)

// runRelyable invokes relyable-scan, the functional re-derivation scanner.
// Relyable emits graded functional-conformance evidence (relyable-scan-v1):
// does the skill still do what its docs claim, recomputed? Strongest grade that
// applies: a declared rederive.json property manifest (exogenous), the author's
// own committed oracle (self_spec), or a code-blind inferred golden when an LLM
// key is set (cold_golden, abstains unless the docs pin behavior); else the
// honest non_rederivable floor. Functional axis only; complements the security
// scanners and does not detect malware or prompt injection.
//
// Executing skill code is fail-closed on relyable's side: without an explicit
// disposable-host acknowledgement it runs nothing (the self_spec lane reports
// UNJUDGEABLE_NO_SANDBOX per tool; the exogenous and cold lanes record a no-ack
// degrade reason). The Docker sandbox is that acknowledgement,
// so --allow-host-exec is passed only in sandbox mode; with the sandbox off,
// operators can opt in themselves via RELYABLE_SCAN_ALLOW_HOST_EXEC=1.
func (runner ExternalScannerRunner) runRelyable(target string, startedAt string) (ScannerResult, error) {
	command := "relyable-scan"
	args := []string{target, "--json"}
	if runner.SandboxMode == SandboxModeDocker {
		args = append(args, "--allow-host-exec")
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
		message := commandError(runErr, output.Stderr, runner.Env)
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
			Error:       "Relyable scanner did not return JSON on stdout.",
			Raw:         nil,
		}, nil
	}
	if !json.Valid([]byte(raw)) {
		return ScannerResult{
			Status:      "failed",
			StartedAt:   startedAt,
			CompletedAt: completedAt,
			Command:     fullCommand,
			Error:       "Relyable scanner returned invalid JSON.",
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

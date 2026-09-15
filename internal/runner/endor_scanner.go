package runner

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"
)

var (
	errInvalidEndorJSON   = errors.New("Endor scanner returned invalid findings JSON")
	endorAnalysisFailures = regexp.MustCompile(`\b[1-9][0-9]* (scan failure|call graph error)\(s\)`)
)

const endorScanScript = `set -eu
export NPM_CONFIG_IGNORE_SCRIPTS=true
git -c core.hooksPath=/dev/null -c user.name=ClawScan -c user.email=clawscan@example.invalid -C "$1" init -q -b main
git -C "$1" config core.hooksPath /dev/null
git -C "$1" config user.name ClawScan
git -C "$1" config user.email clawscan@example.invalid
git -c core.hooksPath=/dev/null -c user.name=ClawScan -c user.email=clawscan@example.invalid -C "$1" add --all --force
git -c core.hooksPath=/dev/null -c user.name=ClawScan -c user.email=clawscan@example.invalid -C "$1" commit -q --allow-empty -m "ClawScan scan snapshot"
git -c core.hooksPath=/dev/null -C "$1" remote add origin https://example.invalid/clawscan/scan-target.git
exec endorctl scan --dry-run --dependencies --languages=javascript,typescript --call-graph-languages=javascript,typescript --build=false --output-type=json --path "$1"`

type endorFindingsReport struct {
	AllFindings      []json.RawMessage `json:"all_findings"`
	BlockingFindings []json.RawMessage `json:"blocking_findings"`
	WarningFindings  []json.RawMessage `json:"warning_findings"`
}

func (runner ExternalScannerRunner) runEndor(target string, startedAt string) (ScannerResult, error) {
	completedAt := func() string {
		return time.Now().UTC().Format(time.RFC3339Nano)
	}
	failed := func(message string) ScannerResult {
		return ScannerResult{
			Status:      "failed",
			StartedAt:   startedAt,
			CompletedAt: completedAt(),
			Error:       message,
		}
	}
	skipped := func(message string) ScannerResult {
		return ScannerResult{
			Status:      "skipped",
			StartedAt:   startedAt,
			CompletedAt: completedAt(),
			Error:       message,
		}
	}

	if isURLTarget(target) {
		return skipped("Endor supports local directory targets only; URL targets are unsupported."), nil
	}
	scanRoot, supported, err := endorScanRoot(target)
	if err != nil {
		return ScannerResult{}, err
	}
	if !supported {
		return skipped("Endor requires a local directory or explicit manifest file target."), nil
	}
	if !regularFileExists(filepath.Join(scanRoot, "package.json")) {
		return skipped("Endor requires package.json at the target root."), nil
	}
	if runner.SandboxMode != SandboxModeDocker {
		return failed("Endor requires the Docker sandbox; --sandbox off is unsupported."), nil
	}

	workspace, err := os.MkdirTemp("", "clawscan-endor-*")
	if err != nil {
		return ScannerResult{}, err
	}
	defer os.RemoveAll(workspace)
	scratch := filepath.Join(workspace, "artifact")
	if _, err := copyTargetToWorkspace(scanRoot, scratch); err != nil {
		return ScannerResult{}, fmt.Errorf("prepare Endor workspace: %w", err)
	}

	command := "/bin/sh"
	args := []string{"-c", endorScanScript, "clawscan-endor", "."}
	fullCommand := append([]string{command}, args...)
	timeout := runner.Timeout
	if timeout == 0 {
		timeout = 20 * time.Minute
	}
	output, runErr := runner.CommandRunner.Run(command, args, scratch, timeout)
	exitCode := gateEligibleExitCode(output.ExitCode)
	raw := []byte(output.Stdout)
	reportErr := validateEndorFindingsReport(raw)
	result := ScannerResult{
		Status:      "completed",
		StartedAt:   startedAt,
		CompletedAt: completedAt(),
		Command:     fullCommand,
		ExitCode:    exitCode,
	}
	if reportErr == nil {
		result.Raw = json.RawMessage(raw)
	}
	if runErr != nil {
		result.Status = "failed"
		result.Error = scannerCommandError(runErr, output.Stderr, runner.Env)
		if reportErr != nil {
			result.Error += ": " + reportErr.Error()
		}
		return result, nil
	}
	if reportErr != nil {
		result.Status = "failed"
		result.Error = reportErr.Error()
		return result, nil
	}
	if message, ok := endorReportedAnalysisError(output.Stderr, runner.Env); ok {
		result.Status = "failed"
		result.Error = message
	}
	return result, nil
}

func endorRequirements(env map[string]string) []EnvRequirement {
	const credentialReason = "scanner endor (set ENDOR_TOKEN or both ENDOR_API_CREDENTIALS_KEY and ENDOR_API_CREDENTIALS_SECRET)"
	requirements := []EnvRequirement{{EnvVar: "ENDOR_NAMESPACE", Reason: "scanner endor"}}
	if strings.TrimSpace(env["ENDOR_TOKEN"]) != "" {
		return append(requirements, EnvRequirement{EnvVar: "ENDOR_TOKEN", Reason: credentialReason})
	}
	if strings.TrimSpace(env["ENDOR_API_CREDENTIALS_KEY"]) != "" || strings.TrimSpace(env["ENDOR_API_CREDENTIALS_SECRET"]) != "" {
		return append(requirements,
			EnvRequirement{EnvVar: "ENDOR_API_CREDENTIALS_KEY", Reason: credentialReason},
			EnvRequirement{EnvVar: "ENDOR_API_CREDENTIALS_SECRET", Reason: credentialReason},
		)
	}
	return append(requirements, EnvRequirement{EnvVar: "ENDOR_TOKEN", Reason: credentialReason})
}

func endorScanRoot(target string) (string, bool, error) {
	info, err := os.Stat(target)
	if err != nil {
		return "", false, err
	}
	if info.IsDir() {
		return target, true, nil
	}
	switch filepath.Base(target) {
	case skillManifestName, pluginManifestName, "package.json":
		return filepath.Dir(target), true, nil
	default:
		return "", false, nil
	}
}

func regularFileExists(path string) bool {
	info, err := os.Lstat(path)
	return err == nil && info.Mode().IsRegular()
}

func validateEndorFindingsReport(raw []byte) error {
	if strings.TrimSpace(string(raw)) == "" {
		return errInvalidEndorJSON
	}
	var report endorFindingsReport
	if err := json.Unmarshal(raw, &report); err != nil || report.AllFindings == nil || report.BlockingFindings == nil || report.WarningFindings == nil {
		return errInvalidEndorJSON
	}
	for _, findings := range [][]json.RawMessage{report.AllFindings, report.BlockingFindings, report.WarningFindings} {
		for _, finding := range findings {
			var object map[string]json.RawMessage
			if err := json.Unmarshal(finding, &object); err != nil || object == nil {
				return errInvalidEndorJSON
			}
		}
	}
	return nil
}

func endorReportedAnalysisError(stderr string, env map[string]string) (string, bool) {
	var evidence []string
	for _, line := range strings.Split(stderr, "\n") {
		trimmed := strings.TrimSpace(line)
		if strings.Contains(trimmed, "ERROR ") || endorAnalysisFailures.MatchString(trimmed) {
			evidence = append(evidence, trimmed)
		}
	}
	if len(evidence) == 0 {
		return "", false
	}
	message := "Endor reported one or more analysis errors"
	if details := strings.TrimSpace(redactEnvValues(strings.Join(evidence, "; "), env)); details != "" {
		message += ": " + details
	}
	return message, true
}

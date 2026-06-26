package runner

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
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
	args = append(args, ciscoAnalyzerArgs(runner.Env)...)
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

func ciscoAnalyzerArgs(env map[string]string) []string {
	var args []string
	if ciscoLLMConfigured(env) || ciscoMetaLLMConfigured(env) {
		args = append(args, "--use-llm")
	}
	if ciscoMetaLLMConfigured(env) {
		args = append(args, "--enable-meta")
	}
	if strings.TrimSpace(env["VIRUSTOTAL_API_KEY"]) != "" {
		args = append(args, "--use-virustotal")
	}
	if strings.TrimSpace(env["AI_DEFENSE_API_KEY"]) != "" || strings.TrimSpace(env["AI_DEFENSE_API_URL"]) != "" {
		args = append(args, "--use-aidefense")
	}
	return args
}

func ciscoLLMConfigured(env map[string]string) bool {
	for _, key := range []string{
		"SKILL_SCANNER_LLM_API_KEY",
		"SKILL_SCANNER_LLM_PROVIDER",
		"SKILL_SCANNER_LLM_MODEL",
		"SKILL_SCANNER_LLM_BASE_URL",
		"SKILL_SCANNER_LLM_USER",
		"SKILL_SCANNER_LLM_API_VERSION",
		"SKILL_SCANNER_LLM_FORCE_JSON_OBJECT",
		"AWS_PROFILE",
		"AWS_REGION",
		"GOOGLE_APPLICATION_CREDENTIALS",
	} {
		if strings.TrimSpace(env[key]) != "" {
			return true
		}
	}
	return false
}

func ciscoMetaLLMConfigured(env map[string]string) bool {
	for _, key := range []string{
		"SKILL_SCANNER_META_LLM_API_KEY",
		"SKILL_SCANNER_META_LLM_MODEL",
		"SKILL_SCANNER_META_LLM_BASE_URL",
		"SKILL_SCANNER_META_LLM_API_VERSION",
	} {
		if strings.TrimSpace(env[key]) != "" {
			return true
		}
	}
	return false
}

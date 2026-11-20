package runner

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
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
	cwd := ""
	if runner.SandboxMode == SandboxModeDocker {
		cwd = resultDir
	}
	return runner.runReportFile(command, args, cwd, startedAt, resultPath, "Cisco skill-scanner did not write JSON output.", func(raw []byte) error {
		if !json.Valid(raw) {
			return errInvalidCiscoJSON
		}
		return nil
	}), nil
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

package runner

import (
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strings"
	"time"
)

type UserDefinedScannerConfig struct {
	ID      string
	Command string
	Env     []string
	Targets []string
}

func NewUserDefinedScanner(config UserDefinedScannerConfig) ScannerAdapter {
	targets := make(map[string]bool, len(config.Targets))
	for _, target := range config.Targets {
		targets[target] = true
	}
	return userDefinedScannerAdapter{config: config, targets: targets}
}

type userDefinedScannerAdapter struct {
	config  UserDefinedScannerConfig
	targets map[string]bool
}

func (adapter userDefinedScannerAdapter) ID() string { return adapter.config.ID }

func (adapter userDefinedScannerAdapter) Requirements(_ map[string]string) []EnvRequirement {
	requirements := make([]EnvRequirement, 0, len(adapter.config.Env))
	for _, name := range adapter.config.Env {
		requirements = append(requirements, EnvRequirement{EnvVar: name, Reason: adapter.config.ID + " scanner"})
	}
	return requirements
}

func (adapter userDefinedScannerAdapter) Info() ScannerInfo {
	return ScannerInfo{ID: adapter.config.ID, DisplayName: adapter.config.ID, RequiredEnv: append([]string(nil), adapter.config.Env...)}
}

func (adapter userDefinedScannerAdapter) InstallPlan() InstallPlan {
	return InstallPlan{ScannerID: adapter.config.ID, InstallUnsupportedReason: "user-defined scanner"}
}

func (adapter userDefinedScannerAdapter) SupportsTargetKind(kind string) bool {
	return adapter.targets[kind]
}

func (adapter userDefinedScannerAdapter) CommandBacked() bool { return true }

func (adapter userDefinedScannerAdapter) Run(runner ExternalScannerRunner, target string, startedAt string) (ScannerResult, error) {
	shell := userDefinedScannerShell(runtime.GOOS, runner.SandboxMode)
	targetReplacement := shell.quote(target)
	usePositionalTarget := shell.command == "/bin/sh"
	if usePositionalTarget {
		targetReplacement = `"$1"`
	} else if strings.Contains(target, "%") {
		// cmd.exe expands %VAR% even inside double quotes, so a target path
		// containing % would be corrupted before the scanner sees it. Refuse
		// rather than scan the wrong path.
		return ScannerResult{
			Status: "failed", StartedAt: startedAt, CompletedAt: time.Now().UTC().Format(time.RFC3339Nano),
			Error: fmt.Sprintf("User-defined scanner %s cannot receive target paths containing %% on the Windows host shell; use the Docker sandbox or a %%-free path", adapter.config.ID),
		}, nil
	}
	rendered := targetPlaceholderPattern.ReplaceAllStringFunc(adapter.config.Command, func(string) string {
		return targetReplacement
	})
	args := append(append([]string(nil), shell.args...), rendered)
	if usePositionalTarget {
		args = append(args, "clawscan-target", target)
	}
	fullCommand := append([]string{shell.command}, args...)
	timeout := runner.Timeout
	if timeout == 0 {
		timeout = 20 * time.Minute
	}
	output, runErr := runner.CommandRunner.Run(shell.command, args, userDefinedScannerCWD(target), timeout)
	exitCode := gateEligibleExitCode(output.ExitCode)
	completedAt := time.Now().UTC().Format(time.RFC3339Nano)
	raw := strings.TrimSpace(output.Stdout)
	if runErr != nil {
		// Declared env vars are credentials by declaration, whatever their
		// spelling; redact their values even when isSecretEnvKey would not.
		message := redactDeclaredEnvValues(commandError(runErr, output.Stderr, runner.Env), runner.Env, adapter.config.Env)
		if json.Valid([]byte(raw)) {
			return ScannerResult{
				Status: "completed", StartedAt: startedAt, CompletedAt: completedAt, Command: fullCommand,
				Error: message, ExitCode: exitCode, Raw: json.RawMessage(raw),
			}, nil
		}
		return ScannerResult{
			Status: "failed", StartedAt: startedAt, CompletedAt: completedAt, Command: fullCommand,
			Error: message, ExitCode: exitCode,
		}, nil
	}
	if !json.Valid([]byte(raw)) {
		return ScannerResult{
			Status: "failed", StartedAt: startedAt, CompletedAt: completedAt, Command: fullCommand,
			Error: fmt.Sprintf("User-defined scanner %s returned invalid JSON", adapter.config.ID), ExitCode: exitCode,
		}, nil
	}
	return ScannerResult{
		Status: "completed", StartedAt: startedAt, CompletedAt: completedAt, Command: fullCommand,
		ExitCode: exitCode, Raw: json.RawMessage(raw),
	}, nil
}

func gateEligibleExitCode(exitCode *int) *int {
	if exitCode == nil || *exitCode < 0 {
		return nil
	}
	return exitCode
}

func redactDeclaredEnvValues(value string, env map[string]string, declared []string) string {
	if value == "" || len(env) == 0 || len(declared) == 0 {
		return value
	}
	secrets := make([]string, 0, len(declared))
	for _, name := range declared {
		if secret := env[name]; strings.TrimSpace(secret) != "" {
			secrets = append(secrets, secret)
		}
	}
	sort.Slice(secrets, func(i int, j int) bool {
		return len(secrets[i]) > len(secrets[j])
	})
	redacted := value
	for _, secret := range secrets {
		redacted = strings.ReplaceAll(redacted, secret, "[redacted]")
	}
	return redacted
}

func userDefinedScannerShell(goos string, sandboxMode string) judgeShellSpec {
	if sandboxMode == SandboxModeDocker {
		return judgeShellForGOOS("linux")
	}
	return judgeShellForGOOS(goos)
}

var targetPlaceholderPattern = regexp.MustCompile(`\{\{\s*target\s*\}\}`)

func userDefinedScannerCWD(target string) string {
	parsed, err := url.Parse(target)
	if err == nil && parsed.Scheme != "" && parsed.Host != "" {
		return ""
	}
	info, err := os.Stat(target)
	if err == nil && info.IsDir() {
		return target
	}
	return filepath.Dir(target)
}

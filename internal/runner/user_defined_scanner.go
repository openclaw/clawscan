package runner

import (
	"encoding/json"
	"fmt"
	"os"
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
	// Never run with an untrusted working directory: CWD-sensitive commands
	// (python -m, npx) would resolve target-supplied code with scanner
	// credentials in env. An empty cwd inherits ClawScan's own process cwd,
	// which may itself be the untrusted target (clawscan .), so host runs get
	// a fresh empty directory. Docker runs keep "" — with no cwd nothing is
	// mounted and the container's own workdir is already isolated.
	cwd := ""
	if runner.SandboxMode != SandboxModeDocker {
		isolated, err := os.MkdirTemp("", "clawscan-scanner-")
		if err != nil {
			return ScannerResult{
				Status: "failed", StartedAt: startedAt, CompletedAt: time.Now().UTC().Format(time.RFC3339Nano),
				Error: fmt.Sprintf("User-defined scanner %s could not create an isolated working directory: %v", adapter.config.ID, err),
			}, nil
		}
		defer os.RemoveAll(isolated)
		cwd = isolated
	}
	output, runErr := runner.CommandRunner.Run(shell.command, args, cwd, timeout)
	exitCode := gateEligibleExitCode(output.ExitCode)
	completedAt := time.Now().UTC().Format(time.RFC3339Nano)
	// Raw stdout is persisted verbatim into the artifact and per-scanner
	// output files, so declared credential values must be scrubbed from it
	// too, not just from failure text. Redacting before the JSON validity
	// check keeps a leaked secret out of both the raw and failure paths.
	raw := redactDeclaredEnvValues(strings.TrimSpace(output.Stdout), runner.Env, adapter.config.Env)
	raw = redactDeclaredEnvValuesInJSON(raw, runner.Env, adapter.config.Env)
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
	secrets := make([]string, 0, len(declared)*2)
	for _, name := range declared {
		secret := env[name]
		if strings.TrimSpace(secret) == "" {
			continue
		}
		secrets = append(secrets, secret)
		// A secret inside JSON string output appears in its escaped form
		// ("pa\"ss" for pa"ss); the literal never occurs in the bytes, so
		// redact the JSON encoding too.
		if encoded, err := json.Marshal(secret); err == nil {
			if escaped := strings.Trim(string(encoded), `"`); escaped != secret {
				secrets = append(secrets, escaped)
			}
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

// redactDeclaredEnvValuesInJSON redacts at the decoded level: JSON permits
// alternative encodings of the same string ("a\/b", \u escapes), so byte
// matching on the serialized form cannot be complete. Valid JSON is decoded,
// every string containing a declared secret is scrubbed, and the document is
// re-serialized. Non-JSON input is returned unchanged — the byte-level pass
// already handled it.
func redactDeclaredEnvValuesInJSON(value string, env map[string]string, declared []string) string {
	if value == "" || len(env) == 0 || len(declared) == 0 || !json.Valid([]byte(value)) {
		return value
	}
	secrets := make([]string, 0, len(declared))
	for _, name := range declared {
		if secret := env[name]; strings.TrimSpace(secret) != "" {
			secrets = append(secrets, secret)
		}
	}
	if len(secrets) == 0 {
		return value
	}
	sort.Slice(secrets, func(i int, j int) bool {
		return len(secrets[i]) > len(secrets[j])
	})
	var document any
	decoder := json.NewDecoder(strings.NewReader(value))
	decoder.UseNumber()
	if err := decoder.Decode(&document); err != nil {
		return value
	}
	document, changed := redactJSONStrings(document, secrets)
	if !changed {
		return value
	}
	encoded, err := json.Marshal(document)
	if err != nil {
		return value
	}
	return string(encoded)
}

func redactJSONStrings(node any, secrets []string) (any, bool) {
	switch typed := node.(type) {
	case string:
		redacted := typed
		for _, secret := range secrets {
			redacted = strings.ReplaceAll(redacted, secret, "[redacted]")
		}
		return redacted, redacted != typed
	case map[string]any:
		changed := false
		for key, child := range typed {
			redactedChild, childChanged := redactJSONStrings(child, secrets)
			redactedKey, keyChanged := redactJSONStrings(key, secrets)
			if keyChanged {
				delete(typed, key)
				typed[redactedKey.(string)] = redactedChild
				changed = true
				continue
			}
			if childChanged {
				typed[key] = redactedChild
				changed = true
			}
		}
		return typed, changed
	case []any:
		changed := false
		for index, child := range typed {
			redactedChild, childChanged := redactJSONStrings(child, secrets)
			if childChanged {
				typed[index] = redactedChild
				changed = true
			}
		}
		return typed, changed
	default:
		return node, false
	}
}

func userDefinedScannerShell(goos string, sandboxMode string) judgeShellSpec {
	if sandboxMode == SandboxModeDocker {
		return judgeShellForGOOS("linux")
	}
	return judgeShellForGOOS(goos)
}

var targetPlaceholderPattern = regexp.MustCompile(`\{\{\s*target\s*\}\}`)

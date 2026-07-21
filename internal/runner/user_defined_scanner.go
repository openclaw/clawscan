package runner

import (
	"encoding/json"
	"fmt"
	"os"
	"regexp"
	"runtime"
	"sort"
	"strconv"
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
	} else if unsafeWindowsShellTarget(target) {
		return ScannerResult{
			Status: "failed", StartedAt: startedAt, CompletedAt: time.Now().UTC().Format(time.RFC3339Nano),
			Error: fmt.Sprintf(`User-defined scanner %s cannot receive targets containing %% or " on the Windows host shell; use the Docker sandbox or a target without those characters`, adapter.config.ID),
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
	// Raw stdout is persisted into the artifact and per-scanner output files,
	// so credentials must be scrubbed from it, not just from failure text.
	// Only valid JSON is ever persisted (both paths below gate on json.Valid),
	// so structural redaction of decoded strings suffices — and byte-level
	// replacement must not run first, or a short secret like "1" would corrupt
	// non-string JSON tokens and flip a healthy scan to failed.
	// Scrub this adapter's declared env plus everything else exposed to
	// scanners this run (sandbox allowlist, other adapters' credentials):
	// under Docker every scanner sees the whole passthrough set, and a name
	// like BETA_CREDENTIAL evades the isSecretEnvKey heuristic.
	scrubNames := append(append([]string(nil), adapter.config.Env...), runner.ExposedEnvNames...)
	raw := redactScannerStdout(strings.TrimSpace(output.Stdout), runner.Env, scrubNames)
	if runErr != nil {
		// Failure text needs the same coverage as stdout: declared env plus
		// everything exposed to scanners this run, whatever the spelling.
		message := redactDeclaredEnvValues(commandError(runErr, output.Stderr, runner.Env), runner.Env, scrubNames)
		// Valid JSON is completed evidence only for a normal nonzero exit
		// (findings-mean-nonzero scanners). A nil gate-eligible exit code
		// means timeout or signal: partial output must not report success
		// or let exit-code gates pass.
		if exitCode != nil && json.Valid([]byte(raw)) {
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

// unsafeWindowsShellTarget reports whether a target cannot be interpolated
// into a cmd.exe command line safely: %VAR% expands even inside double
// quotes, and backslash does not escape " for cmd.exe's parser, so a quote
// in a URL target could terminate the argument and inject host commands.
func unsafeWindowsShellTarget(target string) bool {
	return strings.ContainsAny(target, `%"`)
}

func gateEligibleExitCode(exitCode *int) *int {
	// Shells and docker run report a signal-killed child as 128+N (137 for
	// SIGKILL/OOM, 143 for SIGTERM) with a normal ProcessState, and reserve
	// 126/127 for not-executable/not-found. None of these are scanner
	// verdicts: treating them as gate-eligible would let partial output from
	// a killed scan pass an exit-code gate.
	if exitCode == nil || *exitCode < 0 || *exitCode >= 126 {
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

// redactScannerStdout scrubs credentials from scanner stdout before it is
// persisted. Only valid JSON ever reaches the artifact, and JSON permits
// alternative encodings of the same string ("a\/b", \u escapes), so redaction
// is structural: decode, scrub every string node, re-serialize. Byte-level
// replacement is deliberately not used here — a short secret such as "1"
// would corrupt non-string tokens ({"count":1}) and flip a healthy scan to
// failed. Non-JSON input is returned unchanged; the failure-text path redacts
// it separately.
//
// The scanner sees more than its declared env (--sandbox off inherits the
// process environment; Docker passes --sandbox-env and other adapters'
// credentials), so every secret-named env value is scrubbed too, not just
// declared ones.
func redactScannerStdout(value string, env map[string]string, declared []string) string {
	if value == "" || len(env) == 0 || !json.Valid([]byte(value)) {
		return value
	}
	secrets := scannerSecretValues(env, declared)
	if len(secrets) == 0 {
		return value
	}
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

// scannerSecretValues collects the env values to scrub from scanner output:
// declared env vars are credentials by declaration whatever their spelling,
// and secret-named vars (isSecretEnvKey) are included because the scanner may
// see them without declaring them. Longest-first so overlapping secrets
// redact fully.
func scannerSecretValues(env map[string]string, declared []string) []string {
	seen := map[string]bool{}
	secrets := make([]string, 0, len(declared))
	add := func(secret string) {
		if strings.TrimSpace(secret) == "" || seen[secret] {
			return
		}
		seen[secret] = true
		secrets = append(secrets, secret)
	}
	for _, name := range declared {
		add(env[name])
	}
	for name, secret := range env {
		if isSecretEnvKey(name) {
			add(secret)
		}
	}
	sort.Slice(secrets, func(i int, j int) bool {
		return len(secrets[i]) > len(secrets[j])
	})
	return secrets
}

func redactJSONStrings(node any, secrets []string) (any, bool) {
	switch typed := node.(type) {
	case string:
		redacted := typed
		for _, secret := range secrets {
			redacted = strings.ReplaceAll(redacted, secret, "[redacted]")
		}
		return redacted, redacted != typed
	case json.Number:
		// A numeric-looking secret (PIN=1234) may be emitted unquoted; the
		// scalar's exact text matching a secret is a leak like any other.
		for _, secret := range secrets {
			if string(typed) == secret {
				return "[redacted]", true
			}
		}
		return typed, false
	case bool:
		for _, secret := range secrets {
			if strconv.FormatBool(typed) == secret {
				return "[redacted]", true
			}
		}
		return typed, false
	case nil:
		for _, secret := range secrets {
			if secret == "null" {
				return "[redacted]", true
			}
		}
		return typed, false
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

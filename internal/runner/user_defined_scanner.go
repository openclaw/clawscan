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
	"unicode/utf16"
	"unicode/utf8"
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

// DeclaredCredentialEnv lists env vars that are credentials by declaration:
// whatever their spelling, a user-defined scanner's env: entries exist to
// hand the command secrets, so their values must always be redacted from
// persisted output.
func (adapter userDefinedScannerAdapter) DeclaredCredentialEnv() []string {
	return append([]string(nil), adapter.config.Env...)
}

func (adapter userDefinedScannerAdapter) Run(runner ExternalScannerRunner, target string, startedAt string) (ScannerResult, error) {
	// A missing local target must fail here, before mount inference: Docker
	// mount fallback binds a missing path's parent read-write (so scanners
	// can create output files), and a typo'd target would hand the container
	// writable access to the surrounding host directory.
	if runner.TargetKind != targetKindURL {
		if _, err := os.Stat(target); err != nil {
			return ScannerResult{
				Status: "failed", StartedAt: startedAt, CompletedAt: time.Now().UTC().Format(time.RFC3339Nano),
				Error: fmt.Sprintf("User-defined scanner %s target does not exist: %s", adapter.config.ID, target),
			}, nil
		}
	}
	shell := userDefinedScannerShell(runtime.GOOS, runner.SandboxMode)
	targetReplacement := shell.quote(target)
	usePositionalTarget := shell.command == "/bin/sh"
	if usePositionalTarget {
		targetReplacement = `"$1"`
	} else if unsafeWindowsShellTarget(target) {
		return ScannerResult{
			Status: "failed", StartedAt: startedAt, CompletedAt: time.Now().UTC().Format(time.RFC3339Nano),
			Error: fmt.Sprintf(`User-defined scanner %s cannot receive targets containing %%, !, or " on the Windows host shell; use the Docker sandbox or a target without those characters`, adapter.config.ID),
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
// quotes, !VAR! does too when delayed expansion is enabled (a system-wide
// or shell-level setting ClawScan cannot detect), and backslash does not
// escape " for cmd.exe's parser, so a quote in a URL target could terminate
// the argument and inject host commands.
func unsafeWindowsShellTarget(target string) bool {
	return strings.ContainsAny(target, `%"!`)
}

const redactionMarkerPreferred = "[redacted]"

var redactionMarkerRunes = []rune("#*~^@+=%&|:;")

// secretScrubber replaces secret values with a redaction marker and verifies
// the result no longer contains any secret. Naive replacement leaks twice
// over: a credential that is a substring of the marker (such as "act" or
// "redacted") survives inside the sentinel itself, and replacement can
// synthesize a secret from marker bytes joined with surrounding text.
type secretScrubber struct {
	secrets []string
	marker  string
}

func newSecretScrubber(secrets []string) secretScrubber {
	return secretScrubber{secrets: secrets, marker: redactionMarker(secrets)}
}

func (scrubber secretScrubber) containsSecret(value string) bool {
	for _, secret := range scrubber.secrets {
		if secret != "" && strings.Contains(value, secret) {
			return true
		}
	}
	return false
}

// scrub replaces every secret occurrence, then re-checks the result because
// a replacement can reintroduce a secret at marker/text boundaries. If
// bounded marker passes do not converge, it deletes the secret bytes
// outright, which always terminates because each pass strictly shrinks the
// text.
func (scrubber secretScrubber) scrub(value string) string {
	const maxMarkerPasses = 4
	redacted := value
	for pass := 0; pass < maxMarkerPasses; pass++ {
		if !scrubber.containsSecret(redacted) {
			return redacted
		}
		for _, secret := range scrubber.secrets {
			if secret == "" {
				continue
			}
			redacted = strings.ReplaceAll(redacted, secret, scrubber.marker)
		}
	}
	for scrubber.containsSecret(redacted) {
		for _, secret := range scrubber.secrets {
			if secret == "" {
				continue
			}
			redacted = strings.ReplaceAll(redacted, secret, "")
		}
	}
	return redacted
}

// redactionMarker picks the replacement sentinel. The preferred marker is
// only used when no secret is a substring of it. Otherwise the marker is a
// repeated rune absent from every secret, so the sentinel can neither
// contain a credential nor combine with neighboring text to rebuild one.
func redactionMarker(secrets []string) string {
	preferredSafe := true
	for _, secret := range secrets {
		if secret != "" && strings.Contains(redactionMarkerPreferred, secret) {
			preferredSafe = false
			break
		}
	}
	if preferredSafe {
		return redactionMarkerPreferred
	}
	runeSafe := func(r rune) bool {
		for _, secret := range secrets {
			if strings.ContainsRune(secret, r) {
				return false
			}
		}
		return true
	}
	for _, r := range redactionMarkerRunes {
		if runeSafe(r) {
			return strings.Repeat(string(r), 10)
		}
	}
	for r := rune(0x2580); r <= 0x25ff; r++ {
		if runeSafe(r) {
			return strings.Repeat(string(r), 10)
		}
	}
	// Unreachable for realistic secret sets (secrets would need to cover
	// every candidate rune); scrub then deletes the bytes as a last resort.
	return ""
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
	if value == "" || len(env) == 0 {
		return value
	}
	// Failure text needs the same secret set as stdout — declared env plus
	// every secret-named var the scanner may see undeclared (--sandbox off
	// inherits the whole host environment) — and each secret's JSON-escaped
	// form too: a value like pa"ss emitted inside JSON on stderr appears as
	// pa\"ss, so the literal never occurs in the bytes.
	base := scannerSecretValues(env, declared)
	secrets := make([]string, 0, len(base)*2)
	for _, secret := range base {
		secrets = append(secrets, secret)
		if encoded, err := json.Marshal(secret); err == nil {
			if escaped := strings.Trim(string(encoded), `"`); escaped != secret {
				secrets = append(secrets, escaped)
			}
		}
	}
	sort.Slice(secrets, func(i int, j int) bool {
		return len(secrets[i]) > len(secrets[j])
	})
	scrubber := newSecretScrubber(secrets)
	redacted := scrubber.scrub(value)
	// JSON permits alternate encodings of the same string (a\/b for a/b,
	// \u escapes) that byte replacement cannot enumerate. Decode escape
	// sequences and, if a secret surfaces, return the scrubbed decoded text
	// instead — losing the original escaping is acceptable, leaking is not.
	if decoded := decodeJSONStringEscapes(redacted); decoded != redacted {
		if scrubbed := scrubber.scrub(decoded); scrubbed != decoded {
			return scrubbed
		}
	}
	return redacted
}

// decodeJSONStringEscapes interprets JSON string escape sequences (\", \\,
// \/, \uXXXX including surrogate pairs) embedded in free-form text. Unknown
// or truncated sequences pass through unchanged.
func decodeJSONStringEscapes(value string) string {
	if !strings.Contains(value, `\`) {
		return value
	}
	var out strings.Builder
	out.Grow(len(value))
	for index := 0; index < len(value); {
		if value[index] != '\\' || index+1 >= len(value) {
			out.WriteByte(value[index])
			index++
			continue
		}
		switch value[index+1] {
		case '"', '\\', '/':
			out.WriteByte(value[index+1])
			index += 2
		case 'u':
			if index+6 > len(value) {
				out.WriteByte(value[index])
				index++
				continue
			}
			first, err := strconv.ParseUint(value[index+2:index+6], 16, 32)
			if err != nil {
				out.WriteByte(value[index])
				index++
				continue
			}
			decoded := rune(first)
			width := 6
			if utf16.IsSurrogate(decoded) && index+12 <= len(value) && value[index+6] == '\\' && value[index+7] == 'u' {
				if second, err := strconv.ParseUint(value[index+8:index+12], 16, 32); err == nil {
					if combined := utf16.DecodeRune(decoded, rune(second)); combined != utf8.RuneError {
						decoded = combined
						width = 12
					}
				}
			}
			out.WriteRune(decoded)
			index += width
		default:
			out.WriteByte(value[index])
			index++
		}
	}
	return out.String()
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
	document, changed := redactJSONStrings(document, newSecretScrubber(secrets))
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

func redactJSONStrings(node any, scrubber secretScrubber) (any, bool) {
	switch typed := node.(type) {
	case string:
		redacted := scrubber.scrub(typed)
		return redacted, redacted != typed
	case json.Number:
		// A numeric-looking secret (PIN=1234) may be emitted unquoted; the
		// scalar's exact text matching a secret is a leak like any other.
		for _, secret := range scrubber.secrets {
			if string(typed) == secret {
				return scrubber.marker, true
			}
		}
		return typed, false
	case bool:
		for _, secret := range scrubber.secrets {
			if strconv.FormatBool(typed) == secret {
				return scrubber.marker, true
			}
		}
		return typed, false
	case nil:
		for _, secret := range scrubber.secrets {
			if secret == "null" {
				return scrubber.marker, true
			}
		}
		return typed, false
	case map[string]any:
		changed := false
		for key, child := range typed {
			redactedChild, childChanged := redactJSONStrings(child, scrubber)
			redactedKey, keyChanged := redactJSONStrings(key, scrubber)
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
			redactedChild, childChanged := redactJSONStrings(child, scrubber)
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

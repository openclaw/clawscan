package runner

import (
	"encoding/json"
	"fmt"
	"math/big"
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
	for _, name := range sanitizedDeclaredEnvNames(adapter.config.Env) {
		requirements = append(requirements, EnvRequirement{EnvVar: name, Reason: adapter.config.ID + " scanner"})
	}
	return requirements
}

func (adapter userDefinedScannerAdapter) Info() ScannerInfo {
	return ScannerInfo{ID: adapter.config.ID, DisplayName: adapter.config.ID, RequiredEnv: sanitizedDeclaredEnvNames(adapter.config.Env)}
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
	return sanitizedDeclaredEnvNames(adapter.config.Env)
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
	// env: entries must be bare variable names: `env: [API_TOKEN=sk-live]`
	// would otherwise flow into the missing-variable diagnostic verbatim,
	// leaking the inline value into terminal and CI logs.
	if bad := invalidDeclaredEnvName(adapter.config.Env); bad != "" {
		return ScannerResult{
			Status: "failed", StartedAt: startedAt, CompletedAt: time.Now().UTC().Format(time.RFC3339Nano),
			Error: fmt.Sprintf("User-defined scanner %s env entry %s is not a variable name; declare bare names and set values in the environment", adapter.config.ID, bad),
		}, nil
	}
	// Environment assignments must arrive through env: declarations, never
	// inline in the command: an inline literal (INLINE_TOKEN=sk-live scanner
	// ...) is outside every redaction scope, so a scanner echoing it would
	// persist the value into evidence. Fail closed before running.
	if name := inlineCredentialAssignment(adapter.config.Command); name != "" {
		return ScannerResult{
			Status: "failed", StartedAt: startedAt, CompletedAt: time.Now().UTC().Format(time.RFC3339Nano),
			Error: fmt.Sprintf("User-defined scanner %s command embeds an inline environment assignment (%s=...); its value cannot be redacted — declare it under env: and reference it as an environment variable instead", adapter.config.ID, name),
		}, nil
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
	// The artifact records only the scanner ID, never the rendered command
	// line: a user-defined command is operator-authored config and may embed
	// inline credentials (API_TOKEN=sk-live scanner {{target}}), which must
	// not be persisted into evidence.
	fullCommand := []string{"user-defined-scanner", adapter.config.ID}
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
	// like BETA_LICENSE evades the isSecretEnvKey heuristic.
	scrubNames := append(append([]string(nil), adapter.config.Env...), runner.ExposedEnvNames...)
	// Under Docker only allowlisted names reach the container; scrubbing an
	// unrelated host secret's value (CI_TOKEN=clean) would corrupt evidence
	// without preventing any leak. --sandbox off keeps the full host env.
	visibleEnv := commandVisibleEnv(runner.Env, scrubNames, runner.SandboxMode)
	trimmed := strings.TrimSpace(output.Stdout)
	// Evidence is rejected outright — not repaired — when structural
	// redaction cannot see everything the raw bytes hold: invalid UTF-8
	// defeats byte-exact secret comparison after decoding, and duplicate
	// object members hide earlier values from the decoded walk while
	// re-encoding would silently rewrite the evidence.
	evidenceUnsafe := ""
	if json.Valid([]byte(trimmed)) {
		evidenceUnsafe = scannerEvidenceUnsafe(trimmed)
	}
	raw := redactScannerStdout(trimmed, visibleEnv, scrubNames)
	if evidenceUnsafe != "" {
		return ScannerResult{
			Status: "failed", StartedAt: startedAt, CompletedAt: completedAt, Command: fullCommand,
			Error: fmt.Sprintf("User-defined scanner %s output rejected: %s", adapter.config.ID, evidenceUnsafe), ExitCode: exitCode,
		}, nil
	}
	if runErr != nil {
		// Failure text needs the same coverage as stdout: declared env plus
		// everything exposed to scanners this run, whatever the spelling.
		// commandError's own secret-named sweep must also use the visible
		// env: pre-scrubbing with the whole host env would corrupt Docker
		// diagnostics matching an unexposed host value by coincidence.
		message := redactDeclaredEnvValues(commandError(runErr, output.Stderr, visibleEnv), visibleEnv, scrubNames)
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

// scrubDeep scrubs value and then decodes it to a fixed point: a secret can
// hide one JSON-escaping layer down ({"message":"{\"auth\":\"\\u0073ekret\"}"})
// where neither the raw bytes nor the once-decoded string contain the
// literal. Each decode layer that surfaces a secret is scrubbed in place;
// losing the original escaping is acceptable, leaking is not.
func (scrubber secretScrubber) scrubDeep(value string) string {
	result := scrubber.scrub(value)
	current := result
	// Decode to a fixed point. Termination is guaranteed: every escape
	// decodeJSONStringEscapes rewrites (\", \\, \/, \b, \f, \n, \r, \t,
	// \uXXXX) strictly
	// shrinks the string, and unknown escapes pass through unchanged, so
	// decoded != current implies len(decoded) < len(current).
	for {
		decoded := decodeJSONStringEscapes(current)
		if decoded == current {
			return result
		}
		if scrubber.containsSecret(decoded) {
			decoded = scrubber.scrub(decoded)
			result = decoded
		}
		current = decoded
	}
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
	if safe := secretFreeRune(secrets); safe != "" {
		return strings.Repeat(safe, 10)
	}
	// Unreachable for realistic secret sets (secrets would need to cover
	// every candidate rune); scrub then deletes the bytes as a last resort.
	return ""
}

// secretFreeRune returns a one-rune string absent from every secret, so text
// built from it can neither contain a credential nor combine with adjacent
// bytes to rebuild one. Empty only when the secrets cover every candidate
// rune, which no realistic secret set does.
func secretFreeRune(secrets []string) string {
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
			return string(r)
		}
	}
	for r := rune(0x2580); r <= 0x25ff; r++ {
		if runeSafe(r) {
			return string(r)
		}
	}
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
	// JSON permits alternate encodings of the same string (a\/b for a/b,
	// \u escapes) that byte replacement cannot enumerate, and a secret can
	// hide multiple escaping layers down (JSON embedded in a JSON string).
	// scrubDeep decodes to a fixed point and scrubs whatever surfaces —
	// losing the original escaping is acceptable, leaking is not.
	return newSecretScrubber(secrets).scrubDeep(value)
}

// decodeJSONStringEscapes interprets JSON string escape sequences (\", \\,
// \/, \b, \f, \n, \r, \t, and \uXXXX including surrogate pairs) embedded in
// free-form text. Unknown or truncated sequences pass through unchanged.
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
		case 'b':
			out.WriteByte('\b')
			index += 2
		case 'f':
			out.WriteByte('\f')
			index += 2
		case 'n':
			out.WriteByte('\n')
			index += 2
		case 'r':
			out.WriteByte('\r')
			index += 2
		case 't':
			out.WriteByte('\t')
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
	// Returning the original verbatim is only safe when the decoded walk saw
	// everything the raw bytes hold. Two cases defeat it: Go's decoder keeps
	// only an object's last duplicate member, hiding a secret in an earlier
	// duplicate ({"auth":"sekret","auth":"x"}), and invalid UTF-8 decodes to
	// U+FFFD so a byte-exact secret never matches. Re-encoding the decoded
	// document destroys both hazards the same way any JSON consumer would
	// read the text. Paths that persist scanner evidence reject these inputs
	// outright (scannerEvidenceUnsafe) before evidence acceptance; this
	// re-encode is the fail-safe for diagnostic and judge-output paths.
	if !changed && !hasDuplicateJSONKeys(value) && utf8.ValidString(value) {
		return value
	}
	encoded, err := json.Marshal(document)
	if err != nil {
		return value
	}
	return string(encoded)
}

// scannerEvidenceUnsafe reports why valid-JSON evidence cannot be safely
// persisted through structural redaction, or "" when it can. Invalid UTF-8
// survives json.Valid but decoding swaps the bytes for U+FFFD, so a
// byte-exact secret comparison misses and the original bytes would persist.
// Duplicate object members are invisible to the decoded walk (only the last
// survives), and re-encoding to drop them would silently rewrite evidence.
// Both cases fail closed: the callers reject the evidence outright.
func scannerEvidenceUnsafe(value string) string {
	if !utf8.ValidString(value) {
		return "contains invalid UTF-8"
	}
	if hasDuplicateJSONKeys(value) {
		return "contains duplicate JSON object members"
	}
	return ""
}

// hasDuplicateJSONKeys reports whether any object in the JSON text declares
// the same member name twice. Only valid JSON reaches this scan, so a token
// error just reports false and the caller keeps the original text.
func hasDuplicateJSONKeys(value string) bool {
	decoder := json.NewDecoder(strings.NewReader(value))
	decoder.UseNumber()
	type frame struct {
		object    bool
		keys      map[string]bool
		expectKey bool
	}
	var stack []*frame
	for {
		token, err := decoder.Token()
		if err != nil {
			return false
		}
		top := func() *frame {
			if len(stack) == 0 {
				return nil
			}
			return stack[len(stack)-1]
		}
		switch typed := token.(type) {
		case json.Delim:
			switch typed {
			case '{':
				stack = append(stack, &frame{object: true, keys: map[string]bool{}, expectKey: true})
			case '[':
				stack = append(stack, &frame{})
			case '}', ']':
				stack = stack[:len(stack)-1]
				if parent := top(); parent != nil && parent.object {
					parent.expectKey = true
				}
			}
		case string:
			if current := top(); current != nil && current.object && current.expectKey {
				if current.keys[typed] {
					return true
				}
				current.keys[typed] = true
				current.expectKey = false
				continue
			}
			if current := top(); current != nil && current.object {
				current.expectKey = true
			}
		default:
			if current := top(); current != nil && current.object {
				current.expectKey = true
			}
		}
		if len(stack) == 0 && decoder.More() == false {
			return false
		}
	}
}

// commandVisibleEnv returns the env whose values feed redaction for a
// command that ran under the given sandbox mode. With --sandbox off the
// command inherits the whole host environment, so every secret-named var is
// in scope. Under Docker only the allowlisted names reach the container:
// scrubbing an unrelated host value (CI_TOKEN=clean) would rewrite
// legitimate evidence like "verdict":"clean" without preventing any leak.
func commandVisibleEnv(env map[string]string, names []string, sandboxMode string) map[string]string {
	if sandboxMode != SandboxModeDocker {
		return env
	}
	visible := make(map[string]string, len(names))
	for _, name := range names {
		for key, value := range envEntriesForName(env, name) {
			visible[key] = value
		}
	}
	return visible
}

// envEntriesForName returns the env entries a declared name addresses,
// keyed by their real spelling. On Windows environment names are
// case-insensitive: a scanner declaring scanner_access receives the host's
// SCANNER_ACCESS=secret, so redaction must see that value under either
// spelling or the credential persists in evidence. Elsewhere names are
// distinct and only the exact key matches.
func envEntriesForName(env map[string]string, name string) map[string]string {
	return envEntriesForNameOnGOOS(env, name, runtime.GOOS)
}

func envEntriesForNameOnGOOS(env map[string]string, name string, goos string) map[string]string {
	entries := map[string]string{}
	if value, ok := env[name]; ok {
		entries[name] = value
	}
	if goos != "windows" {
		return entries
	}
	for key, value := range env {
		if strings.EqualFold(key, name) {
			entries[key] = value
		}
	}
	return entries
}

// envValueForName returns a non-empty value for name under the platform's
// name-equality rules (case-insensitive on Windows), or "".
func envValueForName(env map[string]string, name string) string {
	for _, value := range envEntriesForName(env, name) {
		if strings.TrimSpace(value) != "" {
			return value
		}
	}
	return ""
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
		// Windows env names are case-insensitive: a declared
		// scanner_access must also sweep the host's SCANNER_ACCESS value.
		for _, value := range envEntriesForName(env, name) {
			add(value)
		}
	}
	for name, secret := range env {
		// Exemptions are by name, never by value: DB_PASSWORD=default is a
		// weak credential, not configuration, and skipping "default" would
		// persist it unredacted. Names isSecretEnvKey over-matches are
		// listed in nonCredentialSecretNamedEnv instead.
		if isSecretEnvKey(name) && !nonCredentialSecretNamedEnv(name) {
			add(secret)
		}
	}
	sort.Slice(secrets, func(i int, j int) bool {
		return len(secrets[i]) > len(secrets[j])
	})
	return secrets
}

var envAssignmentNamePattern = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)

// assignmentWrapperWords are command words whose following NAME=value
// operand sets an environment variable in the child regardless of case.
var assignmentWrapperWords = map[string]bool{"env": true, "export": true, "set": true, "setx": true, "sudo": true}

// inlineCredentialAssignment reports the first rejected NAME=value token in
// an operator-authored command, or "". It rejects secret-named assignments,
// conventional ALL-UPPERCASE environment names, and any-case names in the
// leading assignment run, at a new command start after ;, &, or | separators
// wherever they appear or after a newline, or in an assignment-wrapper zone.
// Separator handling is not shell-quote-aware and therefore rejects
// conservatively. Wrapper options keep that zone active.
// Inline values sit outside every redaction scope, so name-based carve-outs
// let a bland credential name persist into evidence. Lowercase and mixed-case
// NAME=value operands outside assignment position remain allowed. Grouping and
// control punctuation plus $ are trimmed from token ends so subshell and
// brace-group syntax cannot hide an assignment.
func inlineCredentialAssignment(command string) string {
	commandStart := true
	wrapperZone := false
	for _, line := range strings.FieldsFunc(command, func(r rune) bool { return r == '\n' || r == '\r' }) {
		commandStart = true
		wrapperZone = false
		for _, field := range strings.Fields(line) {
			// Split attached separators (true;NAME=v, a|b, x&&NAME=v): the
			// shell treats each ;&| as a command boundary regardless of
			// surrounding whitespace, so each segment is inspected as if it
			// began a new token, and every boundary resets command-start.
			segments := strings.FieldsFunc(field, func(r rune) bool {
				return r == ';' || r == '&' || r == '|'
			})
			endsWithSeparator := strings.HasSuffix(field, ";") || strings.HasSuffix(field, "&") || strings.HasSuffix(field, "|")
			for si, segment := range segments {
				if si > 0 {
					// Interior separator: the segment starts a new command.
					commandStart = true
					wrapperZone = false
				}
				token := strings.Trim(segment, "'\"(){}$`")
				if token == "" {
					continue
				}
				eq := strings.IndexByte(token, '=')
				if eq > 0 && envAssignmentNamePattern.MatchString(token[:eq]) {
					name := token[:eq]
					if isSecretEnvKey(name) || upperCaseEnvName(name) || commandStart || wrapperZone {
						return name
					}
					// A non-rejected assignment operand does not move us past the
					// command word.
				} else if assignmentWrapperWords[strings.ToLower(token)] {
					wrapperZone = true
					commandStart = false
				} else if strings.HasPrefix(token, "-") && wrapperZone {
					// Wrapper options (env -i, sudo -E) keep the zone open.
				} else {
					wrapperZone = false
					commandStart = false
				}
			}
			if endsWithSeparator {
				commandStart = true
				wrapperZone = false
			}
		}
	}
	return ""
}

// upperCaseEnvName reports whether name looks like a conventional
// environment variable: at least one letter and no lowercase letters.
func upperCaseEnvName(name string) bool {
	hasLetter := false
	for _, r := range name {
		if r >= 'a' && r <= 'z' {
			return false
		}
		if r >= 'A' && r <= 'Z' {
			hasLetter = true
		}
	}
	return hasLetter
}

// sanitizedDeclaredEnvNames returns the adapter's env: declarations with any
// malformed assignment entry truncated to its name part. The text after = in
// a misconfigured entry (API_TOKEN=sk-live) may be a live credential and must
// never flow into artifact metadata, requirements diagnostics, or redaction
// name lists.
func sanitizedDeclaredEnvNames(declared []string) []string {
	sanitized := make([]string, 0, len(declared))
	for _, name := range declared {
		if !envAssignmentNamePattern.MatchString(name) {
			if eq := strings.IndexByte(name, '='); eq >= 0 {
				name = name[:eq]
			}
		}
		if name == "" {
			continue
		}
		sanitized = append(sanitized, name)
	}
	return sanitized
}

// invalidDeclaredEnvName reports the name portion of a scanner env:
// declaration that is not a bare variable name, or "". A misconfiguration
// like `env: [API_TOKEN=sk-live]` must be rejected without ever echoing
// the full entry — the value after = may be a live credential, and the
// missing-variable diagnostic would otherwise print it verbatim.
func invalidDeclaredEnvName(declared []string) string {
	for _, name := range declared {
		if envAssignmentNamePattern.MatchString(name) {
			continue
		}
		if eq := strings.IndexByte(name, '='); eq >= 0 {
			return name[:eq] + "=..."
		}
		if len(name) > 64 {
			name = name[:64] + "..."
		}
		return name
	}
	return ""
}

// InvalidUserDefinedEnvName reports the offending entry of a user-defined
// scanner env: list that is not a bare variable name, truncated so a value
// after = is never echoed, or "" when all entries are valid.
func InvalidUserDefinedEnvName(declared []string) string {
	return invalidDeclaredEnvName(declared)
}

// nonCredentialSecretNamedEnvNames lists names isSecretEnvKey matches that
// are well-known configuration switches, not credentials. Exempting by NAME
// is deliberate: exempting by value (skipping "true" or "default") would
// persist a weak real credential like DB_PASSWORD=default unredacted, while
// sweeping a toggle's value would corrupt every matching scalar in
// legitimate scanner evidence. Unknown secret-named vars stay fail-closed
// as credentials.
var nonCredentialSecretNamedEnvNames = map[string]bool{
	// pass(1) configuration (PASSWORD_STORE_* settings hold directories,
	// booleans, lengths, and seconds — never the store's secrets). Every
	// entry here must actually match isSecretEnvKey; names it already
	// ignores (GIT_ASKPASS, TOKENIZERS_PARALLELISM) do not belong.
	"PASSWORD_STORE_DIR":               true,
	"PASSWORD_STORE_ENABLE_EXTENSIONS": true,
	"PASSWORD_STORE_EXTENSIONS_DIR":    true,
	"PASSWORD_STORE_GENERATED_LENGTH":  true,
	"PASSWORD_STORE_CHARACTER_SET":     true,
	"PASSWORD_STORE_CLIP_TIME":         true,
	"PASSWORD_STORE_UMASK":             true,
	"PASSWORD_STORE_X_SELECTION":       true,
}

func nonCredentialSecretNamedEnv(name string) bool {
	return nonCredentialSecretNamedEnvNames[strings.ToUpper(name)]
}

func redactJSONStrings(node any, scrubber secretScrubber) (any, bool) {
	switch typed := node.(type) {
	case string:
		// scrubDeep also catches secrets one JSON-escaping layer down: a
		// string node holding embedded JSON ("{\"auth\":\"\\u0073ekret\"}")
		// never contains the secret's literal bytes.
		redacted := scrubber.scrubDeep(typed)
		return redacted, redacted != typed
	case json.Number:
		// A numeric-looking secret (PIN=1234) may be emitted unquoted; the
		// scalar's exact text matching a secret is a leak like any other,
		// and so is an alternate spelling of the same number (1e3 for a
		// secret of 1000) — compare canonical values too.
		for _, secret := range scrubber.secrets {
			if string(typed) == secret || sameCanonicalNumber(string(typed), secret) {
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
		// Two-phase rebuild: unchanged keys keep their entries first, then
		// redacted keys are inserted collision-safe. Assigning a redacted key
		// directly could overwrite an unrelated field whose key already
		// equals the marker (or a second secret key redacting to the same
		// marker), silently dropping evidence. Keys are processed in sorted
		// order so collision suffixes are deterministic.
		changed := false
		keys := make([]string, 0, len(typed))
		for key := range typed {
			keys = append(keys, key)
		}
		sort.Strings(keys)
		out := make(map[string]any, len(typed))
		var renamedKeys []string
		renamedChildren := map[string]any{}
		renames := map[string]string{}
		for _, key := range keys {
			redactedChild, childChanged := redactJSONStrings(typed[key], scrubber)
			redactedKey, keyChanged := redactJSONStrings(key, scrubber)
			if keyChanged {
				renamedKeys = append(renamedKeys, key)
				renamedChildren[key] = redactedChild
				renames[key] = redactedKey.(string)
				changed = true
				continue
			}
			out[key] = redactedChild
			if childChanged {
				changed = true
			}
		}
		for _, key := range renamedKeys {
			out[collisionFreeKey(renames[key], out, scrubber)] = renamedChildren[key]
		}
		return out, changed
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

// sameCanonicalNumber reports whether a JSON number token and a secret are
// the same numeric value in different spellings (1e3 vs 1000, 1.0 vs 1).
// Comparison is exact (arbitrary-precision rationals), not float64: two
// distinct 17-digit integers that round to the same float must not be
// conflated, or unrelated evidence would be scrubbed as a secret. Both
// sides must parse as numbers; a non-numeric secret never matches.
func sameCanonicalNumber(token string, secret string) bool {
	tokenValue, ok := new(big.Rat).SetString(token)
	if !ok {
		return false
	}
	secretValue, ok := new(big.Rat).SetString(secret)
	if !ok {
		return false
	}
	return tokenValue.Cmp(secretValue) == 0
}

// collisionFreeKey returns candidate if no map entry holds it, otherwise
// candidate extended with repetitions of a rune absent from every secret:
// any substring spanning the appended boundary contains that rune, so the
// suffix can neither be nor complete a credential. Terminates because taken
// is finite and each repetition count yields a distinct key.
func collisionFreeKey(candidate string, taken map[string]any, scrubber secretScrubber) string {
	if _, exists := taken[candidate]; !exists {
		return candidate
	}
	safe := secretFreeRune(scrubber.secrets)
	if safe == "" {
		// Unreachable for realistic secret sets (they would need to cover
		// every candidate rune); matches redactionMarker's last resort.
		safe = "␀"
	}
	for count := 1; ; count++ {
		next := candidate + strings.Repeat(safe, count)
		if _, exists := taken[next]; !exists {
			return next
		}
	}
}

func userDefinedScannerShell(goos string, sandboxMode string) judgeShellSpec {
	if sandboxMode == SandboxModeDocker {
		return judgeShellForGOOS("linux")
	}
	return judgeShellForGOOS(goos)
}

var targetPlaceholderPattern = regexp.MustCompile(`\{\{\s*target\s*\}\}`)

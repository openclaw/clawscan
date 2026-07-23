package runner

import (
	"encoding/json"
	"fmt"
	"math/big"
	"os"
	"path"
	"regexp"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode/utf16"
	"unicode/utf8"

	"mvdan.cc/sh/v3/syntax"
)

type UserDefinedScannerConfig struct {
	ID        string
	Command   string
	Env       []string
	SecretEnv []string
	Targets   []string
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
	requirements := make([]EnvRequirement, 0, len(adapter.config.Env)+len(adapter.config.SecretEnv))
	for _, name := range sanitizedDeclaredEnvNames(append(append([]string(nil), adapter.config.Env...), adapter.config.SecretEnv...)) {
		requirements = append(requirements, EnvRequirement{EnvVar: name, Reason: adapter.config.ID + " scanner"})
	}
	return requirements
}

func (adapter userDefinedScannerAdapter) Info() ScannerInfo {
	return ScannerInfo{ID: adapter.config.ID, DisplayName: adapter.config.ID, RequiredEnv: sanitizedDeclaredEnvNames(append(append([]string(nil), adapter.config.Env...), adapter.config.SecretEnv...))}
}

func (adapter userDefinedScannerAdapter) InstallPlan() InstallPlan {
	return InstallPlan{ScannerID: adapter.config.ID, InstallUnsupportedReason: "user-defined scanner"}
}

func (adapter userDefinedScannerAdapter) SupportsTargetKind(kind string) bool {
	return adapter.targets[kind]
}

func (adapter userDefinedScannerAdapter) CommandBacked() bool { return true }

// DeclaredCredentialEnv lists env vars that are credentials by declaration:
// only secretEnv: entries are credentials-by-declaration and always
// redacted; plain env: entries are passed through and shown unless the
// name-heuristic backstop (isSecretEnvKey) classifies them as a credential.
func (adapter userDefinedScannerAdapter) DeclaredCredentialEnv() []string {
	return sanitizedDeclaredEnvNames(adapter.config.SecretEnv)
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
	// env: and secretEnv: entries must be bare variable names: `env: [API_TOKEN=sk-live]`
	// would otherwise flow into the missing-variable diagnostic verbatim,
	// leaking the inline value into terminal and CI logs.
	if bad := invalidDeclaredEnvName(adapter.config.Env); bad != "" {
		return ScannerResult{
			Status: "failed", StartedAt: startedAt, CompletedAt: time.Now().UTC().Format(time.RFC3339Nano),
			Error: fmt.Sprintf("User-defined scanner %s env entry %s is not a variable name; declare bare names and set values in the environment", adapter.config.ID, bad),
		}, nil
	}
	if bad := invalidDeclaredEnvName(adapter.config.SecretEnv); bad != "" {
		return ScannerResult{
			Status: "failed", StartedAt: startedAt, CompletedAt: time.Now().UTC().Format(time.RFC3339Nano),
			Error: fmt.Sprintf("User-defined scanner %s secretEnv entry %s is not a variable name; declare bare names and set values in the environment", adapter.config.ID, bad),
		}, nil
	}
	if commandReparsesTarget(adapter.config.Command) {
		return ScannerResult{
			Status: "failed", StartedAt: startedAt, CompletedAt: time.Now().UTC().Format(time.RFC3339Nano),
			Error: fmt.Sprintf("User-defined scanner %s re-parses the interpolated target as shell code (eval, or a shell interpreter's -c/-Command operand); a target containing shell metacharacters would execute — remove the reparsing construct or drop the {{target}} placeholder", adapter.config.ID),
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
	// reachableNames narrows redaction's env view to what the scanner can
	// actually see (Docker allowlist), so the name-heuristic backstop still
	// catches a secret-named plain env: value. Both buckets are reachable.
	reachableNames := append(append(append([]string(nil), adapter.config.Env...), adapter.config.SecretEnv...), runner.ExposedEnvNames...)
	// scrubNames are the force-redacted credentials: secretEnv plus run-wide
	// declared credentials. Plain env: is intentionally excluded so non-secret
	// config stays in evidence; secret-named env: is still caught via the
	// heuristic sweep inside scannerSecretValues over visibleEnv.
	scrubNames := append(append([]string(nil), adapter.config.SecretEnv...), runner.ExposedEnvNames...)
	visibleEnv := commandVisibleEnv(runner.Env, reachableNames, runner.SandboxMode)
	stdout := output.Stdout
	// Evidence is rejected outright — not repaired — when structural
	// redaction cannot see everything the raw bytes hold: invalid UTF-8
	// defeats byte-exact secret comparison after decoding, and duplicate
	// object members hide earlier values from the decoded walk while
	// re-encoding would silently rewrite the evidence.
	evidenceUnsafe := ""
	if json.Valid([]byte(stdout)) {
		evidenceUnsafe = scannerEvidenceUnsafe(stdout)
	}
	raw := redactScannerStdout(stdout, visibleEnv, scrubNames)
	if evidenceUnsafe != "" {
		return ScannerResult{
			Status: "failed", StartedAt: startedAt, CompletedAt: completedAt, Command: fullCommand,
			Error: fmt.Sprintf("User-defined scanner %s output rejected: %s", adapter.config.ID, evidenceUnsafe), ExitCode: exitCode,
		}, nil
	}
	if runErr != nil {
		// Failure text needs the same coverage as stdout: declared env plus
		// everything exposed to scanners this run. secretEnv: and env: values
		// both reach the scanner, but only secretEnv: values are force-redacted;
		// env: values are shown unless the heuristic backstop catches them.
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
	// Shells and docker report a signal-killed child as 128+N (137 for
	// SIGKILL/OOM, 143 for SIGTERM) with a normal ProcessState. Docker reserves
	// 125 for docker-run failure, and shells reserve 126/127 for
	// not-executable/not-found. None of these are scanner verdicts: treating
	// them as gate-eligible would let partial output from a failed scan pass an
	// exit-code gate.
	if exitCode == nil || *exitCode < 0 || *exitCode >= 125 {
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
	addWithJSONLeaves := func(secret string) {
		add(secret)
		for _, leaf := range jsonSecretLeaves(secret) {
			add(leaf)
		}
	}
	for _, name := range declared {
		// Windows env names are case-insensitive: a declared
		// scanner_access must also sweep the host's SCANNER_ACCESS value.
		for _, value := range envEntriesForName(env, name) {
			addWithJSONLeaves(value)
		}
	}
	for name, secret := range env {
		// Exemptions are by name, never by value: DB_PASSWORD=default is a
		// weak credential, not configuration, and skipping "default" would
		// persist it unredacted. Names isSecretEnvKey over-matches are
		// listed in nonCredentialSecretNamedEnv instead.
		if isSecretEnvKey(name) && !nonCredentialSecretNamedEnv(name) {
			addWithJSONLeaves(secret)
		}
	}
	sort.Slice(secrets, func(i int, j int) bool {
		return len(secrets[i]) > len(secrets[j])
	})
	return secrets
}

// jsonSecretLeaves returns string and numeric scalar leaf values of secret when
// secret is a JSON object or array, so a structurally re-emitted JSON credential
// ({"token":"sk-live"} surfacing as {"auth":{"token":"sk-live"}}) is redacted
// leaf by leaf. Only scalars of length >= 5 are returned; booleans, nulls, and
// short scalars are excluded to avoid over-redacting legitimate evidence.
// Duplicate object members inside a credential value remain an exotic residual:
// JSON decoding keeps only the last member.
func jsonSecretLeaves(secret string) []string {
	trimmed := strings.TrimSpace(secret)
	if len(trimmed) == 0 || (trimmed[0] != '{' && trimmed[0] != '[') || !json.Valid([]byte(trimmed)) {
		return nil
	}
	var doc any
	decoder := json.NewDecoder(strings.NewReader(trimmed))
	decoder.UseNumber()
	if err := decoder.Decode(&doc); err != nil {
		return nil
	}
	var leaves []string
	var walk func(any)
	walk = func(node any) {
		switch value := node.(type) {
		case map[string]any:
			for _, child := range value {
				walk(child)
			}
		case []any:
			for _, child := range value {
				walk(child)
			}
		case string:
			if len(value) >= 5 {
				leaves = append(leaves, value)
			}
		case json.Number:
			if len(string(value)) >= 5 {
				leaves = append(leaves, string(value))
			}
		}
	}
	walk(doc)
	return leaves
}

var envAssignmentNamePattern = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)

// commandReparsesTarget reports whether a target placeholder is evaluated by
// eval, a shell interpreter's command-string operand, or command substitution.
func commandReparsesTarget(command string) bool {
	if !targetPlaceholderPattern.MatchString(command) {
		return false
	}
	file, err := syntax.NewParser().Parse(strings.NewReader(command), "")
	if err != nil {
		// Unparseable as bash means the default-path /bin/sh rejects it too, so
		// the reparsing construct never executes; the target's "$1" quoting is
		// the primary defense regardless. Treat as no reparse.
		return false
	}

	reparses := false
	syntax.Walk(file, func(node syntax.Node) bool {
		if reparses {
			return false
		}
		switch node := node.(type) {
		case *syntax.CmdSubst:
			reparses = nodeContainsTarget(command, node)
			return !reparses
		case *syntax.CallExpr:
			if len(node.Args) > 0 {
				// The command word is what actually executes. Fail closed if it
				// IS the interpolated target (running the scanned artifact as a
				// program) or is a dynamic word that could resolve to an
				// interpreter while the target appears elsewhere in the call.
				cmdWord := node.Args[0]
				_, static := staticWord(cmdWord)
				if nodeContainsTarget(command, cmdWord) || (!static && nodeContainsTarget(command, node)) {
					reparses = true
					return false
				}
			}
			interpreter, args, eval := reparsingCommand(node)
			if eval {
				reparses = true
				return false
			}
			if interpreter != "" {
				reparses = interpreterReparsesTarget(command, interpreter, args)
			}
		}
		return !reparses
	})
	return reparses
}

func interpreterReparsesTarget(command string, interpreter string, args []*syntax.Word) bool {
	for i := 1; i < len(args); i++ {
		word, ok := staticWord(args[i])
		if !ok || !isCommandStringFlag(interpreter, word) || i+1 >= len(args) {
			continue
		}
		switch interpreter {
		case "cmd", "cmd.exe", "powershell", "powershell.exe", "pwsh":
			for _, arg := range args[i+1:] {
				if nodeContainsTarget(command, arg) {
					return true
				}
			}
			return false
		default:
			return nodeContainsTarget(command, args[i+1])
		}
	}
	return false
}

func reparsingCommand(call *syntax.CallExpr) (interpreter string, args []*syntax.Word, eval bool) {
	if len(call.Args) == 0 {
		return "", nil, false
	}
	commandWord, ok := staticWord(call.Args[0])
	if !ok {
		return "", nil, false
	}
	base := strings.ToLower(path.Base(commandWord))
	if base == "eval" {
		return "", nil, true
	}
	if reparsingInterpreterWords[base] {
		return base, call.Args, false
	}
	if !launcherWords[base] {
		return "", nil, false
	}
	for i, arg := range call.Args[1:] {
		word, ok := staticWord(arg)
		if !ok {
			continue
		}
		base = strings.ToLower(path.Base(word))
		if base == "eval" {
			return "", nil, true
		}
		if reparsingInterpreterWords[base] {
			return base, call.Args[i+1:], false
		}
	}
	return "", nil, false
}

func nodeContainsTarget(command string, node syntax.Node) bool {
	start, end := int(node.Pos().Offset()), int(node.End().Offset())
	return start >= 0 && end >= start && end <= len(command) && targetPlaceholderPattern.MatchString(command[start:end])
}

// launcherWords exec their trailing arguments as a command, so the real
// interpreter (sh -c ...) can hide behind one. Skip them plus their own
// options and NAME=value assignments when locating the command word.
var launcherWords = map[string]bool{
	"env": true, "command": true, "exec": true, "sudo": true,
	"nohup": true, "nice": true, "timeout": true, "stdbuf": true,
}

var reparsingInterpreterWords = map[string]bool{
	"sh": true, "bash": true, "zsh": true, "dash": true, "ksh": true, "ash": true,
	"cmd": true, "cmd.exe": true,
	"powershell": true, "powershell.exe": true, "pwsh": true,
}

func isCommandStringFlag(interpreter string, token string) bool {
	switch interpreter {
	case "cmd", "cmd.exe":
		t := strings.ToLower(token)
		return t == "/c" || t == "/k"
	case "powershell", "powershell.exe", "pwsh":
		t := strings.ToLower(token)
		return t == "-c" || t == "-command" || t == "-encodedcommand"
	default:
		return !strings.HasPrefix(token, "--") && strings.HasPrefix(token, "-") && strings.ContainsRune(token[1:], 'c')
	}
}

func staticWord(word *syntax.Word) (string, bool) {
	var text strings.Builder
	if !appendStaticWordParts(&text, word.Parts, false) {
		return "", false
	}
	return text.String(), true
}

func appendStaticWordParts(text *strings.Builder, parts []syntax.WordPart, quoted bool) bool {
	for _, part := range parts {
		switch part := part.(type) {
		case *syntax.Lit:
			for i := 0; i < len(part.Value); i++ {
				if part.Value[i] == '\\' && !quoted && i+1 < len(part.Value) {
					i++
				}
				text.WriteByte(part.Value[i])
			}
		case *syntax.SglQuoted:
			text.WriteString(part.Value)
		case *syntax.DblQuoted:
			if !appendStaticWordParts(text, part.Parts, true) {
				return false
			}
		default:
			return false
		}
	}
	return true
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
	for i, name := range declared {
		if envAssignmentNamePattern.MatchString(name) {
			continue
		}
		if eq := strings.IndexByte(name, '='); eq >= 0 {
			return name[:eq] + "=..."
		}
		// A malformed entry with no '=' may itself be a pasted credential
		// (env: [sk-live-...]); never echo it. Identify it by position.
		return fmt.Sprintf("#%d", i+1)
	}
	return ""
}

// InvalidUserDefinedEnvName reports a safe descriptor for the offending entry
// of a user-defined scanner env: list that is not a bare variable name, or ""
// when all entries are valid.
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

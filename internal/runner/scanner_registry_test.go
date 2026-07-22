package runner

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"
)

type stubScannerAdapter struct {
	id              string
	requirements    []EnvRequirement
	info            ScannerInfo
	installPlan     InstallPlan
	supportsPlugins bool
	run             func(target string, startedAt string) (ScannerResult, error)
}

func (adapter stubScannerAdapter) ID() string {
	return adapter.id
}

func (adapter stubScannerAdapter) Requirements(env map[string]string) []EnvRequirement {
	return append([]EnvRequirement(nil), adapter.requirements...)
}

func (adapter stubScannerAdapter) Info() ScannerInfo {
	return adapter.info
}

func (adapter stubScannerAdapter) InstallPlan() InstallPlan {
	return adapter.installPlan
}

func (adapter stubScannerAdapter) SupportsTargetKind(kind string) bool {
	if kind == targetKindPlugin {
		return adapter.supportsPlugins
	}
	return true
}

func (adapter stubScannerAdapter) Run(_ ExternalScannerRunner, target string, startedAt string) (ScannerResult, error) {
	if adapter.run != nil {
		return adapter.run(target, startedAt)
	}
	return ScannerResult{
		Status:      "completed",
		StartedAt:   startedAt,
		CompletedAt: startedAt,
		Raw:         json.RawMessage(`{"ok":true}`),
	}, nil
}

func TestScannerRegistryReturnsSortedIDs(t *testing.T) {
	registry, err := NewScannerRegistry(
		stubScannerAdapter{id: "virustotal"},
		stubScannerAdapter{id: "clawscan-static"},
		stubScannerAdapter{id: "skillspector"},
	)
	if err != nil {
		t.Fatal(err)
	}
	if got := strings.Join(registry.IDs(), ","); got != "clawscan-static,skillspector,virustotal" {
		t.Fatalf("ids = %q", got)
	}
}

func TestScannerRegistryRejectsDuplicateIDs(t *testing.T) {
	_, err := NewScannerRegistry(
		stubScannerAdapter{id: "clawscan-static"},
		stubScannerAdapter{id: "clawscan-static"},
	)
	if err == nil || err.Error() != "Duplicate scanner adapter id: clawscan-static" {
		t.Fatalf("err = %v", err)
	}
}

func TestScannerRegistryRejectsEmptyIDs(t *testing.T) {
	_, err := NewScannerRegistry(stubScannerAdapter{id: " "})
	if err == nil || err.Error() != "Scanner adapter id cannot be empty" {
		t.Fatalf("err = %v", err)
	}
}

func TestDefaultScannerRegistryContainsAllBuiltIns(t *testing.T) {
	want := "agentverus,aig,cisco,clawscan-static,relyable,skillspector,snyk,socket,virustotal"
	if got := strings.Join(DefaultScannerRegistry().IDs(), ","); got != want {
		t.Fatalf("ids = %q, want %q", got, want)
	}
}

func TestScannerAdaptersDeclareTargetKindSupport(t *testing.T) {
	registry := DefaultScannerRegistry()
	for _, id := range registry.IDs() {
		adapter, ok := registry.Adapter(id)
		if !ok {
			t.Fatalf("missing adapter for %s", id)
		}
		if !adapter.SupportsTargetKind(targetKindSkill) {
			t.Fatalf("%s should support skill targets", id)
		}
		if !adapter.SupportsTargetKind(targetKindURL) {
			t.Fatalf("%s should support url targets", id)
		}
		wantPlugin := id == "clawscan-static" || id == "skillspector" || id == "socket" || id == "virustotal"
		if got := adapter.SupportsTargetKind(targetKindPlugin); got != wantPlugin {
			t.Fatalf("%s plugin support = %v, want %v", id, got, wantPlugin)
		}
	}
	if !scannerSupportsTargetKind("clawscan-static", targetKindPlugin) {
		t.Fatal("clawscan-static should support plugin targets")
	}
	if !scannerSupportsTargetKind("skillspector", targetKindPlugin) {
		t.Fatal("skillspector should support plugin targets")
	}
	if !scannerSupportsTargetKind("virustotal", targetKindPlugin) {
		t.Fatal("virustotal should support plugin targets")
	}
	if !scannerSupportsTargetKind("socket", targetKindPlugin) {
		t.Fatal("socket should support plugin targets")
	}
	if !scannerSupportsTargetKind("unknown-scanner", targetKindPlugin) {
		t.Fatal("unknown scanners should be permitted so the runner emits its own skipped result")
	}
}

func TestExternalScannerRunnerDispatchesThroughRegistry(t *testing.T) {
	wantErr := errors.New("adapter called")
	registry, err := NewScannerRegistry(stubScannerAdapter{
		id: "demo",
		run: func(target string, startedAt string) (ScannerResult, error) {
			if target != "/tmp/skill" {
				t.Fatalf("target = %q", target)
			}
			if startedAt != "2026-06-23T12:00:00Z" {
				t.Fatalf("startedAt = %q", startedAt)
			}
			return ScannerResult{}, wantErr
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	_, err = (ExternalScannerRunner{Registry: registry}).RunScanner("demo", "/tmp/skill", "2026-06-23T12:00:00Z")
	if !errors.Is(err, wantErr) {
		t.Fatalf("err = %v", err)
	}
}

func TestUserDefinedScannerPreservesValidJSONOnCommandFailure(t *testing.T) {
	adapter := NewUserDefinedScanner(UserDefinedScannerConfig{
		ID: "demo", Command: "demo {{target}}", Targets: []string{"skill"},
	})
	registry, err := NewScannerRegistry(adapter)
	if err != nil {
		t.Fatal(err)
	}
	// Normal nonzero exit (findings-mean-nonzero scanners): valid JSON stays
	// completed evidence. Abnormal termination is covered separately below.
	exitCode := 1
	commandRunner := &recordingCommandRunner{stdout: `{"findings":["detected"]}`, stderr: "findings detected", err: errCommandFailed, exitCode: &exitCode}
	result, err := (ExternalScannerRunner{
		Registry: registry, CommandRunner: commandRunner, Env: map[string]string{}, SandboxMode: SandboxModeOff,
	}).RunScanner("demo", t.TempDir(), "2026-07-21T00:00:00Z")
	if err != nil {
		t.Fatal(err)
	}
	if result.Status != "completed" || string(result.Raw) != `{"findings":["detected"]}` {
		t.Fatalf("result = %#v", result)
	}
	if !strings.Contains(result.Error, "findings detected") {
		t.Fatalf("error = %q", result.Error)
	}
}

func TestUserDefinedScannerRunsInIsolatedDirectoryOnHost(t *testing.T) {
	adapter := NewUserDefinedScanner(UserDefinedScannerConfig{
		ID: "demo", Command: "demo {{target}}", Targets: []string{"skill"},
	})
	registry, err := NewScannerRegistry(adapter)
	if err != nil {
		t.Fatal(err)
	}
	commandRunner := &recordingCommandRunner{stdout: `{}`}
	target := t.TempDir()
	if _, err := (ExternalScannerRunner{
		Registry: registry, CommandRunner: commandRunner, Env: map[string]string{}, SandboxMode: SandboxModeOff,
	}).RunScanner("demo", target, "2026-07-21T00:00:00Z"); err != nil {
		t.Fatal(err)
	}
	if len(commandRunner.calls) != 1 {
		t.Fatalf("calls = %d", len(commandRunner.calls))
	}
	cwd := commandRunner.calls[0].cwd
	if cwd == "" {
		t.Fatal("host scanner ran with empty cwd; would inherit ClawScan's process cwd, which may be the untrusted target")
	}
	if cwd == target || strings.HasPrefix(cwd, target+string(os.PathSeparator)) {
		t.Fatalf("scanner ran inside the untrusted target directory %q", cwd)
	}
	processCwd, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	if cwd == processCwd {
		t.Fatalf("scanner inherited ClawScan's process cwd %q", cwd)
	}
	if _, err := os.Stat(cwd); !os.IsNotExist(err) {
		t.Fatalf("isolated scanner cwd %q was not cleaned up (stat err = %v)", cwd, err)
	}
}

func TestUserDefinedScannerDockerRunKeepsEmptyCwd(t *testing.T) {
	adapter := NewUserDefinedScanner(UserDefinedScannerConfig{
		ID: "demo", Command: "demo {{target}}", Targets: []string{"skill"},
	})
	registry, err := NewScannerRegistry(adapter)
	if err != nil {
		t.Fatal(err)
	}
	commandRunner := &recordingCommandRunner{stdout: `{}`}
	if _, err := (ExternalScannerRunner{
		Registry: registry, CommandRunner: commandRunner, Env: map[string]string{}, SandboxMode: SandboxModeDocker,
	}).RunScanner("demo", t.TempDir(), "2026-07-21T00:00:00Z"); err != nil {
		t.Fatal(err)
	}
	if len(commandRunner.calls) != 1 {
		t.Fatalf("calls = %d", len(commandRunner.calls))
	}
	// Docker runs must not receive a host temp dir as cwd: dockerCommandRunner
	// would mount it and set it as the container workdir for no benefit.
	if cwd := commandRunner.calls[0].cwd; cwd != "" {
		t.Fatalf("docker scanner run got cwd %q, want empty", cwd)
	}
}

func TestUserDefinedScannerRejectsMissingTargetBeforeRunning(t *testing.T) {
	// A missing local target must fail before the command runs: Docker mount
	// inference binds a missing path's parent read-write, so a typo'd target
	// would expose the surrounding host directory writable to the container.
	adapter := NewUserDefinedScanner(UserDefinedScannerConfig{
		ID: "demo", Command: "demo {{target}}", Targets: []string{"skill"},
	})
	registry, err := NewScannerRegistry(adapter)
	if err != nil {
		t.Fatal(err)
	}
	commandRunner := &recordingCommandRunner{stdout: `{}`}
	result, err := (ExternalScannerRunner{
		Registry: registry, CommandRunner: commandRunner, Env: map[string]string{}, SandboxMode: SandboxModeDocker,
	}).RunScanner("demo", filepath.Join(t.TempDir(), "missing-skill"), "2026-07-21T00:00:00Z")
	if err != nil {
		t.Fatal(err)
	}
	if result.Status != "failed" || !strings.Contains(result.Error, "target does not exist") {
		t.Fatalf("result = %#v", result)
	}
	if len(commandRunner.calls) != 0 {
		t.Fatalf("scanner command ran despite missing target: %#v", commandRunner.calls)
	}
}

func TestUserDefinedScannerSkipsExistenceCheckForURLTargets(t *testing.T) {
	adapter := NewUserDefinedScanner(UserDefinedScannerConfig{
		ID: "demo", Command: "demo {{target}}", Targets: []string{"url"},
	})
	registry, err := NewScannerRegistry(adapter)
	if err != nil {
		t.Fatal(err)
	}
	commandRunner := &recordingCommandRunner{stdout: `{}`}
	result, err := (ExternalScannerRunner{
		Registry: registry, CommandRunner: commandRunner, Env: map[string]string{}, SandboxMode: SandboxModeDocker, TargetKind: "url",
	}).RunScanner("demo", "https://example.com/skill", "2026-07-21T00:00:00Z")
	if err != nil {
		t.Fatal(err)
	}
	if result.Status != "completed" || len(commandRunner.calls) != 1 {
		t.Fatalf("URL target must run without a local existence check: %#v calls=%d", result, len(commandRunner.calls))
	}
}

func TestUserDefinedScannerRedactsDeclaredEnvOnFailure(t *testing.T) {
	adapter := NewUserDefinedScanner(UserDefinedScannerConfig{
		ID: "demo", Command: "demo {{target}}", Env: []string{"SCANNER_ACCESS"}, Targets: []string{"skill"},
	})
	registry, err := NewScannerRegistry(adapter)
	if err != nil {
		t.Fatal(err)
	}
	commandRunner := &recordingCommandRunner{stderr: "auth failed: hunter2-credential rejected", err: errCommandFailed}
	result, err := (ExternalScannerRunner{
		Registry: registry, CommandRunner: commandRunner,
		Env:         map[string]string{"SCANNER_ACCESS": "hunter2-credential"},
		SandboxMode: SandboxModeOff,
	}).RunScanner("demo", t.TempDir(), "2026-07-21T00:00:00Z")
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(result.Error, "hunter2-credential") {
		t.Fatalf("declared env value leaked into error: %q", result.Error)
	}
	if !strings.Contains(result.Error, "[redacted]") {
		t.Fatalf("expected redaction marker in error: %q", result.Error)
	}
}

func TestUserDefinedScannerRedactsDeclaredEnvInRawJSON(t *testing.T) {
	adapter := NewUserDefinedScanner(UserDefinedScannerConfig{
		ID: "demo", Command: "demo {{target}}", Env: []string{"SCANNER_ACCESS"}, Targets: []string{"skill"},
	})
	registry, err := NewScannerRegistry(adapter)
	if err != nil {
		t.Fatal(err)
	}
	commandRunner := &recordingCommandRunner{stdout: `{"token":"hunter2-credential","findings":[]}`}
	result, err := (ExternalScannerRunner{
		Registry: registry, CommandRunner: commandRunner,
		Env:         map[string]string{"SCANNER_ACCESS": "hunter2-credential"},
		SandboxMode: SandboxModeOff,
	}).RunScanner("demo", t.TempDir(), "2026-07-21T00:00:00Z")
	if err != nil {
		t.Fatal(err)
	}
	if result.Status != "completed" {
		t.Fatalf("status = %q", result.Status)
	}
	if strings.Contains(string(result.Raw), "hunter2-credential") {
		t.Fatalf("declared env value persisted in raw scanner output: %s", result.Raw)
	}
	if !strings.Contains(string(result.Raw), "[redacted]") {
		t.Fatalf("expected redaction marker in raw output: %s", result.Raw)
	}
}

func TestRedactScannerStdoutCoversJSONEscapedSecrets(t *testing.T) {
	// JSON permits alternative encodings of the same string, so redaction must
	// operate on decoded values, not one serialized representation.
	for name, test := range map[string]struct {
		secret string
		raw    string
	}{
		"canonical escapes": {secret: `pa"ss\word`, raw: `{"token":"pa\"ss\\word","findings":[]}`},
		"solidus escape":    {secret: "a/b", raw: `{"token":"a\/b"}`},
		"unicode escapes":   {secret: "sécret", raw: `{"token":"s\u00e9cret"}`},
		"secret in key":     {secret: "hunter2", raw: `{"hunter2":"value"}`},
		"nested array":      {secret: "hunter2", raw: `{"findings":[{"evidence":["saw hunter2 here"]}]}`},
	} {
		env := map[string]string{"SCANNER_ACCESS": test.secret}
		declared := []string{"SCANNER_ACCESS"}
		redacted := redactScannerStdout(test.raw, env, declared)
		var decoded any
		if err := json.Unmarshal([]byte(redacted), &decoded); err != nil {
			t.Fatalf("%s: redacted output is not JSON: %v", name, err)
		}
		if strings.Contains(redacted, test.secret) {
			t.Fatalf("%s: secret survived redaction: %s", name, redacted)
		}
		if !strings.Contains(redacted, "[redacted]") {
			t.Fatalf("%s: expected redaction marker: %s", name, redacted)
		}
	}
}

func TestRedactScannerStdoutLeavesCleanOutputUntouched(t *testing.T) {
	env := map[string]string{"SCANNER_ACCESS": "hunter2"}
	raw := `{"findings": [],
  "note": "keeps formatting when nothing leaks"}`
	if got := redactScannerStdout(raw, env, []string{"SCANNER_ACCESS"}); got != raw {
		t.Fatalf("clean output was rewritten: %q", got)
	}
}

func TestUserDefinedScannerAbnormalExitWithValidJSONFails(t *testing.T) {
	adapter := NewUserDefinedScanner(UserDefinedScannerConfig{
		ID: "demo", Command: "demo {{target}}", Targets: []string{"skill"},
	})
	registry, err := NewScannerRegistry(adapter)
	if err != nil {
		t.Fatal(err)
	}
	// Timeout/signal: runErr set, no usable exit code, but stdout is valid
	// JSON. Partial output must not report success or satisfy exit-code gates.
	commandRunner := &recordingCommandRunner{stdout: `{"findings":[]}`, stderr: "killed", err: errCommandFailed}
	result, err := (ExternalScannerRunner{
		Registry: registry, CommandRunner: commandRunner, Env: map[string]string{}, SandboxMode: SandboxModeOff,
	}).RunScanner("demo", t.TempDir(), "2026-07-21T00:00:00Z")
	if err != nil {
		t.Fatal(err)
	}
	if result.Status != "failed" {
		t.Fatalf("status = %q, want failed for abnormal termination", result.Status)
	}
	if result.ExitCode != nil {
		t.Fatalf("exit code = %v, want nil", *result.ExitCode)
	}
	if result.Raw != nil {
		t.Fatalf("partial output persisted after abnormal termination: %s", result.Raw)
	}
}

func TestRedactScannerStdoutScrubsUndeclaredSecretEnv(t *testing.T) {
	// --sandbox off inherits the whole process env, and Docker passes
	// --sandbox-env and other adapters' credentials, so secret-named env vars
	// must be scrubbed even when this scanner never declared them.
	env := map[string]string{"OPENAI_API_KEY": "sekret-value"}
	raw := `{"token":"sekret-value"}`
	redacted := redactScannerStdout(raw, env, nil)
	if strings.Contains(redacted, "sekret-value") {
		t.Fatalf("undeclared secret env value survived: %s", redacted)
	}
	if !strings.Contains(redacted, "[redacted]") {
		t.Fatalf("expected redaction marker: %s", redacted)
	}
}

func TestRedactScannerStdoutRedactsScalarEncodedSecrets(t *testing.T) {
	// Numeric or boolean secrets may be emitted unquoted; the scalar's exact
	// text matching a secret is a leak like any other.
	for name, test := range map[string]struct {
		secret string
		raw    string
		leak   string
	}{
		"numeric scalar": {secret: "1234", raw: `{"token":1234,"count":7}`, leak: "1234"},
		"boolean scalar": {secret: "true", raw: `{"token":true}`, leak: "true"},
	} {
		env := map[string]string{"SCANNER_PIN": test.secret}
		redacted := redactScannerStdout(test.raw, env, []string{"SCANNER_PIN"})
		if strings.Contains(redacted, test.leak) {
			t.Fatalf("%s: scalar secret survived: %s", name, redacted)
		}
		if !strings.Contains(redacted, "[redacted]") {
			t.Fatalf("%s: expected redaction marker: %s", name, redacted)
		}
		if !json.Valid([]byte(redacted)) {
			t.Fatalf("%s: redacted output is not valid JSON: %s", name, redacted)
		}
	}
	// Non-matching scalars must survive untouched.
	env := map[string]string{"SCANNER_PIN": "1234"}
	redacted := redactScannerStdout(`{"count":7,"ok":true}`, env, []string{"SCANNER_PIN"})
	if !strings.Contains(redacted, `"count":7`) || !strings.Contains(redacted, `"ok":true`) {
		t.Fatalf("unrelated scalars were rewritten: %s", redacted)
	}
}

func TestUserDefinedScannerTreatsSignalStyleExitCodesAsFailed(t *testing.T) {
	adapter := NewUserDefinedScanner(UserDefinedScannerConfig{
		ID: "demo", Command: "demo {{target}}", Targets: []string{"skill"},
	})
	registry, err := NewScannerRegistry(adapter)
	if err != nil {
		t.Fatal(err)
	}
	// Shells and docker report signal-killed children as 128+N (137 OOM/KILL,
	// 143 TERM), while docker run and shells reserve 125-127; none are scanner
	// verdicts, so partial valid JSON must not become completed evidence or
	// satisfy a gate.
	for _, code := range []int{125, 126, 127, 137, 143} {
		exitCode := code
		commandRunner := &recordingCommandRunner{stdout: `{"findings":[]}`, stderr: "killed", err: errCommandFailed, exitCode: &exitCode}
		result, err := (ExternalScannerRunner{
			Registry: registry, CommandRunner: commandRunner, Env: map[string]string{}, SandboxMode: SandboxModeOff,
		}).RunScanner("demo", t.TempDir(), "2026-07-21T00:00:00Z")
		if err != nil {
			t.Fatal(err)
		}
		if result.Status != "failed" {
			t.Fatalf("exit %d: status = %q, want failed", code, result.Status)
		}
		if result.ExitCode != nil {
			t.Fatalf("exit %d: gate-eligible exit code = %v, want nil", code, *result.ExitCode)
		}
	}
}

func TestGateEligibleExitCodeBoundary(t *testing.T) {
	eligible := 124
	if got := gateEligibleExitCode(&eligible); got == nil || *got != eligible {
		t.Fatalf("gateEligibleExitCode(124) = %v, want 124", got)
	}
	reserved := 125
	if got := gateEligibleExitCode(&reserved); got != nil {
		t.Fatalf("gateEligibleExitCode(125) = %d, want nil", *got)
	}
}

func TestUserDefinedScannerRedactsOtherScannersExposedEnv(t *testing.T) {
	// Under Docker every scanner sees the whole passthrough set; scanner A's
	// output must be scrubbed of scanner B's credential even when its name
	// (BETA_LICENSE) evades the isSecretEnvKey heuristic.
	adapter := NewUserDefinedScanner(UserDefinedScannerConfig{
		ID: "alpha", Command: "alpha {{target}}", Targets: []string{"skill"},
	})
	registry, err := NewScannerRegistry(adapter)
	if err != nil {
		t.Fatal(err)
	}
	commandRunner := &recordingCommandRunner{stdout: `{"token":"beta-cred-value"}`}
	result, err := (ExternalScannerRunner{
		Registry: registry, CommandRunner: commandRunner,
		Env:             map[string]string{"BETA_LICENSE": "beta-cred-value"},
		ExposedEnvNames: []string{"BETA_LICENSE"},
		SandboxMode:     SandboxModeDocker,
	}).RunScanner("alpha", t.TempDir(), "2026-07-21T00:00:00Z")
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(result.Raw), "beta-cred-value") {
		t.Fatalf("another scanner's exposed credential persisted: %s", result.Raw)
	}
	if !strings.Contains(string(result.Raw), "[redacted]") {
		t.Fatalf("expected redaction marker: %s", result.Raw)
	}
}

func TestUserDefinedScannerDockerRedactionIgnoresUnexposedHostSecrets(t *testing.T) {
	// Under Docker only allowlisted names reach the container. A host-only
	// secret value that coincides with legitimate output (CI_TOKEN=clean)
	// must not rewrite scanner evidence — the container never saw it.
	adapter := NewUserDefinedScanner(UserDefinedScannerConfig{
		ID: "alpha", Command: "alpha {{target}}", Targets: []string{"skill"},
	})
	registry, err := NewScannerRegistry(adapter)
	if err != nil {
		t.Fatal(err)
	}
	commandRunner := &recordingCommandRunner{stdout: `{"verdict":"clean"}`}
	result, err := (ExternalScannerRunner{
		Registry: registry, CommandRunner: commandRunner,
		Env:             map[string]string{"CI_TOKEN": "clean"},
		ExposedEnvNames: nil,
		SandboxMode:     SandboxModeDocker,
	}).RunScanner("alpha", t.TempDir(), "2026-07-21T00:00:00Z")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(result.Raw), `"verdict":"clean"`) {
		t.Fatalf("unexposed host secret corrupted Docker evidence: %s", result.Raw)
	}
}

func TestUserDefinedScannerHostRedactionCoversStandardCredentialNames(t *testing.T) {
	// --sandbox off inherits the whole host env, so undeclared credentials
	// with standard spellings — a personal access token (GITHUB_PAT, whole
	// _-segment match) and a password-bearing connection string
	// (DATABASE_URL) — must be scrubbed even though no scanner declared
	// them and they carry no TOKEN/SECRET/KEY marker.
	adapter := NewUserDefinedScanner(UserDefinedScannerConfig{
		ID: "alpha", Command: "alpha {{target}}", Targets: []string{"skill"},
	})
	registry, err := NewScannerRegistry(adapter)
	if err != nil {
		t.Fatal(err)
	}
	commandRunner := &recordingCommandRunner{stdout: `{"pat":"ghp_hostpatvalue","db":"postgres://user:hostdbpass@db/x"}`}
	result, err := (ExternalScannerRunner{
		Registry: registry, CommandRunner: commandRunner,
		Env: map[string]string{
			"GITHUB_PAT":   "ghp_hostpatvalue",
			"DATABASE_URL": "postgres://user:hostdbpass@db/x",
		},
		SandboxMode: SandboxModeOff,
	}).RunScanner("alpha", t.TempDir(), "2026-07-21T00:00:00Z")
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(result.Raw), "ghp_hostpatvalue") {
		t.Fatalf("GITHUB_PAT value leaked on --sandbox off: %s", result.Raw)
	}
	if strings.Contains(string(result.Raw), "hostdbpass") {
		t.Fatalf("DATABASE_URL value leaked on --sandbox off: %s", result.Raw)
	}
}

func TestUserDefinedScannerArtifactOmitsRenderedCommand(t *testing.T) {
	// The rendered command line is operator-authored config and must never
	// be persisted into artifact evidence; only the scanner ID is recorded.
	adapter := NewUserDefinedScanner(UserDefinedScannerConfig{
		ID: "alpha", Command: "scanner --secret-free {{target}}", Targets: []string{"skill"},
	})
	registry, err := NewScannerRegistry(adapter)
	if err != nil {
		t.Fatal(err)
	}
	commandRunner := &recordingCommandRunner{stdout: `{}`}
	result, err := (ExternalScannerRunner{
		Registry: registry, CommandRunner: commandRunner,
		Env: map[string]string{}, SandboxMode: SandboxModeOff,
	}).RunScanner("alpha", t.TempDir(), "2026-07-21T00:00:00Z")
	if err != nil {
		t.Fatal(err)
	}
	if joined := strings.Join(result.Command, " "); joined != "user-defined-scanner alpha" {
		t.Fatalf("artifact command = %v, want scanner ID reference only", result.Command)
	}
}

func TestUserDefinedScannerRejectsInlineCredentialAssignment(t *testing.T) {
	// An inline credential literal (API_TOKEN=sk-live scanner ...) sits
	// outside every redaction scope; the run must fail closed before the
	// command executes, and the literal must not appear anywhere in the
	// result.
	adapter := NewUserDefinedScanner(UserDefinedScannerConfig{
		ID: "alpha", Command: "API_TOKEN=sk-live-inline scanner {{target}}", Targets: []string{"skill"},
	})
	registry, err := NewScannerRegistry(adapter)
	if err != nil {
		t.Fatal(err)
	}
	commandRunner := &recordingCommandRunner{stdout: `{}`}
	result, err := (ExternalScannerRunner{
		Registry: registry, CommandRunner: commandRunner,
		Env: map[string]string{}, SandboxMode: SandboxModeOff,
	}).RunScanner("alpha", t.TempDir(), "2026-07-21T00:00:00Z")
	if err != nil {
		t.Fatal(err)
	}
	if result.Status != "failed" || !strings.Contains(result.Error, "inline environment assignment") {
		t.Fatalf("result = %q / %q, want inline-credential rejection", result.Status, result.Error)
	}
	if len(commandRunner.calls) != 0 {
		t.Fatalf("command ran despite inline credential: %#v", commandRunner.calls)
	}
	encoded, err := json.Marshal(result)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(encoded), "sk-live-inline") {
		t.Fatalf("inline credential leaked into result: %s", encoded)
	}
}

func TestUserDefinedScannerRejectsUnsafeEvidence(t *testing.T) {
	// json.Valid accepts invalid UTF-8 inside strings, but decoding swaps
	// the bytes for U+FFFD so byte-exact secret comparison misses; and
	// duplicate object members hide earlier values from the decoded walk.
	// Both must fail the scan, not persist as evidence.
	for name, stdout := range map[string]string{
		"invalid-utf8":   "{\"note\":\"\xff\xfe\"}",
		"duplicate-keys": `{"auth":"a","auth":"b"}`,
	} {
		adapter := NewUserDefinedScanner(UserDefinedScannerConfig{
			ID: "alpha", Command: "alpha {{target}}", Targets: []string{"skill"},
		})
		registry, err := NewScannerRegistry(adapter)
		if err != nil {
			t.Fatal(err)
		}
		commandRunner := &recordingCommandRunner{stdout: stdout}
		result, err := (ExternalScannerRunner{
			Registry: registry, CommandRunner: commandRunner,
			Env: map[string]string{"CI_TOKEN": "unrelated"}, SandboxMode: SandboxModeOff,
		}).RunScanner("alpha", t.TempDir(), "2026-07-21T00:00:00Z")
		if err != nil {
			t.Fatal(err)
		}
		if result.Status != "failed" {
			t.Fatalf("%s: status = %q, want failed", name, result.Status)
		}
		if len(result.Raw) != 0 {
			t.Fatalf("%s: unsafe evidence persisted: %s", name, result.Raw)
		}
		if !strings.Contains(result.Error, "output rejected") {
			t.Fatalf("%s: error = %q", name, result.Error)
		}
	}
}

func TestUserDefinedScannerPreservesStdoutBytesAndRejectsNonJSONWhitespace(t *testing.T) {
	for name, test := range map[string]struct {
		stdout     string
		wantStatus string
		wantRaw    string
	}{
		"leading-nbsp": {
			stdout:     "\u00a0{}",
			wantStatus: "failed",
		},
		"trailing-newline": {
			stdout:     "{\"ok\":true}\n",
			wantStatus: "completed",
			wantRaw:    "{\"ok\":true}\n",
		},
	} {
		t.Run(name, func(t *testing.T) {
			adapter := NewUserDefinedScanner(UserDefinedScannerConfig{
				ID: "alpha", Command: "alpha {{target}}", Targets: []string{"skill"},
			})
			registry, err := NewScannerRegistry(adapter)
			if err != nil {
				t.Fatal(err)
			}
			result, err := (ExternalScannerRunner{
				Registry: registry, CommandRunner: &recordingCommandRunner{stdout: test.stdout},
				Env: map[string]string{}, SandboxMode: SandboxModeOff,
			}).RunScanner("alpha", t.TempDir(), "2026-07-21T00:00:00Z")
			if err != nil {
				t.Fatal(err)
			}
			if result.Status != test.wantStatus {
				t.Fatalf("status = %q, want %q (error = %q)", result.Status, test.wantStatus, result.Error)
			}
			if string(result.Raw) != test.wantRaw {
				t.Fatalf("raw = %q, want %q", result.Raw, test.wantRaw)
			}
		})
	}
}

func TestRedactScannerStdoutScrubsNestedJSONEncodings(t *testing.T) {
	// A secret can hide one JSON-escaping layer down: a string node holding
	// embedded JSON where the secret appears only via \u escapes. Neither
	// the raw bytes nor the once-decoded string contain the literal.
	env := map[string]string{"DEMO_TOKEN": "sekret"}
	raw := `{"message":"{\"auth\":\"sekret\"}"}`
	redacted := redactScannerStdout(raw, env, []string{"DEMO_TOKEN"})
	if strings.Contains(redacted, "sekret") {
		t.Fatalf("nested-encoded secret survived: %s", redacted)
	}
	// Two layers down (JSON in JSON in JSON) with mixed escaping.
	raw = `{"outer":"{\"inner\":\"{\\\"auth\\\":\\\"\\u0073ekret\\\"}\"}"}`
	redacted = redactScannerStdout(raw, env, []string{"DEMO_TOKEN"})
	if strings.Contains(decodeJSONStringEscapes(decodeJSONStringEscapes(redacted)), "sekret") {
		t.Fatalf("doubly nested secret survived: %s", redacted)
	}
}

func TestScrubDeepReachesArbitraryEncodingDepth(t *testing.T) {
	secret := "sk-deep-layer-credential"
	value := secret
	for range 6 {
		encoded, err := json.Marshal(value)
		if err != nil {
			t.Fatal(err)
		}
		value = string(encoded)
	}

	redacted := newSecretScrubber([]string{secret}).scrubDeep(value)
	for layer := 0; ; layer++ {
		if strings.Contains(redacted, secret) {
			t.Fatalf("layer %d contains secret", layer)
		}
		decoded := decodeJSONStringEscapes(redacted)
		if decoded == redacted {
			break
		}
		redacted = decoded
	}
}

func TestScrubDeepCatchesMultilineSecretUnderEscapeLayers(t *testing.T) {
	secret := "line1\nline2-secret-credential"
	inner, err := json.Marshal(map[string]string{"auth": secret})
	if err != nil {
		t.Fatal(err)
	}
	outer, err := json.Marshal(map[string]string{"message": string(inner)})
	if err != nil {
		t.Fatal(err)
	}

	redacted := newSecretScrubber([]string{secret}).scrubDeep(string(outer))
	for layer := 0; ; layer++ {
		if strings.Contains(redacted, secret) || strings.Contains(redacted, "line2-secret-credential") {
			t.Fatalf("layer %d contains multiline secret", layer)
		}
		decoded := decodeJSONStringEscapes(redacted)
		if decoded == redacted {
			break
		}
		redacted = decoded
	}
}

func TestRedactJSONStringsCanonicalNumberSecrets(t *testing.T) {
	// A numeric secret emitted in an alternate spelling (1e3 for 1000,
	// 1.0 for 1) reveals the same credential.
	scrubber := newSecretScrubber([]string{"1000"})
	node, changed := redactJSONStrings(json.Number("1e3"), scrubber)
	if !changed || node == json.Number("1e3") {
		t.Fatalf("alternate numeric spelling survived: %v", node)
	}
	// A non-numeric secret must never match numbers.
	scrubber = newSecretScrubber([]string{"abc"})
	if _, changed := redactJSONStrings(json.Number("123"), scrubber); changed {
		t.Fatal("non-numeric secret matched a number")
	}
	// Unrelated numbers pass through.
	scrubber = newSecretScrubber([]string{"1000"})
	if _, changed := redactJSONStrings(json.Number("1001"), scrubber); changed {
		t.Fatal("unrelated number scrubbed")
	}
}

func TestInlineCredentialAssignment(t *testing.T) {
	// Secret-named and uppercase assignments are rejected anywhere, while
	// any-case assignments are rejected in a leading run, after command
	// separators, or in wrapper zones that include options. Lowercase and
	// mixed-case operand-style NAME=value tokens stay allowed.
	for command, want := range map[string]string{
		"API_TOKEN=sk-live scanner {{target}}":            "API_TOKEN",
		"FOO=1 DB_PASSWORD=x scanner {{target}}":          "FOO",
		"env API_TOKEN=sk-live scanner {{target}}":        "API_TOKEN",
		"env 'API_TOKEN=sk-live' scanner {{target}}":      "API_TOKEN",
		"export API_TOKEN=sk-live; scanner {{target}}":    "API_TOKEN",
		"set API_TOKEN=sk-live && scanner {{target}}":     "API_TOKEN",
		`set "API_TOKEN=sk-live" && scanner {{target}}`:   "API_TOKEN",
		"scanner --arg API_TOKEN=inline {{target}}":       "API_TOKEN",
		"scanner --token abc {{target}}":                  "",
		"scanner {{target}}":                              "",
		"PATH=/usr/bin scanner {{target}}":                "PATH",
		"scanner --header 'PATH=/usr/bin'":                "PATH",
		"SCANNER_ACCESS=sk-live scanner {{target}}":       "SCANNER_ACCESS",
		"env myapp_token=x scanner {{target}}":            "myapp_token",
		"scanner --set output=json {{target}}":            "",
		"scanner --build-arg mode=fast":                   "",
		"scanner --url 'https://x.test/?a=b' {{target}}":  "",
		"scanner --retries=3 --api-version=2 {{target}}":  "",
		"(API_TOKEN=sk-live; printf x); : {{target}}":     "API_TOKEN",
		"(api_token=sk-live; scanner {{target}})":         "api_token",
		"`API_TOKEN=sk-live` scanner {{target}}":          "API_TOKEN",
		"scanner --filter '(mode=fast)'":                  "",
		"true; session=sk-live scanner {{target}}":        "session",
		"true;session=sk-live scanner {{target}}":         "session",
		"true&&session=sk-live scanner {{target}}":        "session",
		"scanner {{target}}|session=sk-live post":         "session",
		"scanner {{target}} && session=sk-live scanner2":  "session",
		"true\nsession=sk-live-cred scanner {{target}}":   "session",
		"true\r\nsession=sk-live-cred scanner {{target}}": "session",
		"scanner {{target}} \\\n  --flag value":           "",
		"scanner {{target}}\nout=report.json":             "out",
		// Deliberate conservative rejection: without a real shell parser, the
		// quoted ampersand cannot be distinguished from a command separator.
		"scanner --url 'https://x.test/?a=b&c=d' {{target}}":            "c",
		"FOO=1&&scanner {{target}}":                                     "FOO",
		"env -i session=sk-live scanner {{target}}":                     "session",
		"env -u UNUSED session=sk-live-cred scanner {{target}}":         "session",
		"env -u UNUSED PASSWORD=x scanner":                              "PASSWORD",
		"sudo -E deploy_key=x scanner {{target}}":                       "deploy_key",
		"/usr/bin/env access=sk-live-cred scanner {{target}}":           "access",
		"/usr/bin/sudo API_TOKEN=x scanner":                             "API_TOKEN",
		"sudo scanner --flag mode=fast":                                 "",
		"sudo -E scanner":                                               "",
		"env -i scanner mode=fast":                                      "mode",
		"scanner -o mode=fast":                                          "",
		"sh -c 'session=sk-live-cred; scanner {{target}}'":              "session",
		"/bin/sh -c 'session=sk-live-cred; scanner {{target}}'":         "session",
		"bash -lc 'session=sk-live-cred scanner'":                       "session",
		"sh -c 'scanner {{target}}'":                                    "",
		"sh -c 'scanner {{target}} mode=fast'":                          "",
		"sh script.sh mode=fast":                                        "",
		"eval 'access=sk-live-cred; export access'; scanner {{target}}": "access",
		"eval 'PASSWORD=x scanner'":                                     "PASSWORD",
		"eval scanner {{target}}":                                       "",
		"eval scanner mode=fast":                                        "",
		"if true; then scannerAccess=sk-" + "live-cred; fi":             "scannerAccess",
		"while :; do access=sk-" + "live-cred scanner; done":            "access",
		"if x=1; then scanner; fi":                                      "x",
		"scanner --then mode=fast":                                      "",
		"! access=sk-live scanner {{target}}":                           "access",
		"scanner --flag && ! db=secret run":                             "db",
		"scanner !notanassignment":                                      "",
		"scanner mode=fast":                                             "",
	} {
		if got := inlineCredentialAssignment(command); got != want {
			t.Fatalf("inlineCredentialAssignment(%q) = %q, want %q", command, got, want)
		}
	}
}

func TestCommandReparsesTarget(t *testing.T) {
	for command, want := range map[string]bool{
		"if true; then eval scanner {{target}}; fi": true,
		"while :; do eval scanner {{target}}; done": true,
		"eval scanner {{target}}":                   true,
		"/bin/eval scanner {{target}}":              true,
		"sh -c {{target}}":                          true,
		"bash -lc {{target}}":                       true,
		"/bin/sh -c {{target}}":                     true,
		"cmd /C {{target}}":                         true,
		"powershell -Command {{target}}":            true,
		"sh -c 'myscanner {{target}} | jq .'":       false,
		"myscanner -c {{target}}":                   false,
		"sh -c scan.sh {{target}}":                  false,
		"scanner {{target}}":                        false,
		// Conservative over-rejection: eval is a whole-word token even when
		// the scanner intends it as a literal argument.
		"myscanner --mode eval {{target}}": true,
		"myscanner --mode=eval {{target}}": false,
		"eval scanner --static":            false,
	} {
		if got := commandReparsesTarget(command); got != want {
			t.Fatalf("commandReparsesTarget(%q) = %t, want %t", command, got, want)
		}
	}
}

func TestUserDefinedScannerRejectsEvalTargetPlaceholder(t *testing.T) {
	adapter := NewUserDefinedScanner(UserDefinedScannerConfig{
		ID: "alpha", Command: "eval scanner {{target}}", Targets: []string{"skill"},
	})
	registry, err := NewScannerRegistry(adapter)
	if err != nil {
		t.Fatal(err)
	}
	commandRunner := &recordingCommandRunner{stdout: `{}`}
	result, err := (ExternalScannerRunner{
		Registry: registry, CommandRunner: commandRunner,
		Env: map[string]string{}, SandboxMode: SandboxModeOff,
	}).RunScanner("alpha", t.TempDir(), "2026-07-21T00:00:00Z")
	if err != nil {
		t.Fatal(err)
	}
	if result.Status != "failed" || !strings.Contains(result.Error, "re-parses the interpolated target as shell code") {
		t.Fatalf("result = %q / %q, want eval-target rejection", result.Status, result.Error)
	}
	if len(commandRunner.calls) != 0 {
		t.Fatalf("command ran despite eval-target rejection: %#v", commandRunner.calls)
	}
}

func TestUserDefinedScannerRejectsShellCommandTargetPlaceholder(t *testing.T) {
	adapter := NewUserDefinedScanner(UserDefinedScannerConfig{
		ID: "alpha", Command: "sh -c {{target}}", Targets: []string{"skill"},
	})
	registry, err := NewScannerRegistry(adapter)
	if err != nil {
		t.Fatal(err)
	}
	commandRunner := &recordingCommandRunner{stdout: `{}`}
	result, err := (ExternalScannerRunner{
		Registry: registry, CommandRunner: commandRunner,
		Env: map[string]string{}, SandboxMode: SandboxModeOff,
	}).RunScanner("alpha", t.TempDir(), "2026-07-21T00:00:00Z")
	if err != nil {
		t.Fatal(err)
	}
	if result.Status != "failed" || !strings.Contains(result.Error, "re-parses the interpolated target as shell code") {
		t.Fatalf("result = %q / %q, want shell-command-target rejection", result.Status, result.Error)
	}
	if len(commandRunner.calls) != 0 {
		t.Fatalf("command ran despite shell-command-target rejection: %#v", commandRunner.calls)
	}
}

func TestRunScannerRejectsUnsafeEvidenceFromAnyAdapter(t *testing.T) {
	// The unsafe-evidence gate must hold at the central boundary, not just
	// inside the user-defined adapter: a built-in scanner emitting
	// duplicate JSON members would otherwise be decoded and re-encoded by
	// redaction, silently dropping the earlier member.
	commandRunner := &recordingCommandRunner{stdout: `{"x":1,"x":2}`}
	result, err := (ExternalScannerRunner{
		Registry: DefaultScannerRegistry(), CommandRunner: commandRunner,
		Env:         map[string]string{"CI_TOKEN": "host-secret"},
		SandboxMode: SandboxModeOff,
	}).RunScanner("agentverus", t.TempDir(), "2026-07-21T00:00:00Z")
	if err != nil {
		t.Fatal(err)
	}
	if result.Status != "failed" || !strings.Contains(result.Error, "duplicate JSON object members") {
		t.Fatalf("result = %q / %q, want central unsafe-evidence rejection", result.Status, result.Error)
	}
	if len(result.Raw) != 0 {
		t.Fatalf("unsafe evidence persisted: %s", result.Raw)
	}
}

func TestEnvEntriesForNameWindowsIsCaseInsensitive(t *testing.T) {
	// Windows env names are case-insensitive: a scanner declaring
	// scanner_access receives the host's SCANNER_ACCESS value, so both
	// redaction scoping and the secret sweep must see it under either
	// spelling. Elsewhere only the exact key matches.
	env := map[string]string{"SCANNER_ACCESS": "secret-value"}
	windows := envEntriesForNameOnGOOS(env, "scanner_access", "windows")
	if windows["SCANNER_ACCESS"] != "secret-value" {
		t.Fatalf("windows lookup missed case-folded name: %v", windows)
	}
	linux := envEntriesForNameOnGOOS(env, "scanner_access", "linux")
	if len(linux) != 0 {
		t.Fatalf("non-windows lookup must be exact: %v", linux)
	}
}

func TestEnvValueForNameFindsNonEmptyExactMatch(t *testing.T) {
	env := map[string]string{"SCANNER_ACCESS": "secret-value"}
	if got := envValueForName(env, "SCANNER_ACCESS"); got != "secret-value" {
		t.Fatalf("envValueForName() = %q, want non-empty exact match", got)
	}
	if got := envValueForName(map[string]string{"SCANNER_ACCESS": "  "}, "SCANNER_ACCESS"); got != "" {
		t.Fatalf("envValueForName() = %q, want empty for whitespace-only value", got)
	}
}

func TestUserDefinedScannerInfoSanitizesMalformedEnvEntries(t *testing.T) {
	adapter := NewUserDefinedScanner(UserDefinedScannerConfig{
		ID: "alpha", Command: "scanner {{target}}",
		Env: []string{"API_TOKEN=sk-live-info-leak", "=sk-live-eqzero", "GOOD_NAME"}, Targets: []string{"skill"},
	})
	want := []string{"API_TOKEN", "GOOD_NAME"}
	if got := adapter.Info().RequiredEnv; !reflect.DeepEqual(got, want) {
		t.Fatalf("Info().RequiredEnv = %v, want %v", got, want)
	}
	declarer, ok := adapter.(interface{ DeclaredCredentialEnv() []string })
	if !ok {
		t.Fatal("user-defined scanner does not expose declared credential env")
	}
	if got := declarer.DeclaredCredentialEnv(); !reflect.DeepEqual(got, want) {
		t.Fatalf("DeclaredCredentialEnv() = %v, want %v", got, want)
	}
	for _, names := range [][]string{adapter.Info().RequiredEnv, declarer.DeclaredCredentialEnv()} {
		for _, name := range names {
			if strings.Contains(name, "sk-live") {
				t.Fatalf("sanitized env name leaked credential value: %q", name)
			}
			if name == "" {
				t.Fatal("sanitized env names contain an empty element")
			}
		}
	}
}

func TestUserDefinedScannerRejectsMalformedEnvDeclaration(t *testing.T) {
	// env: [API_TOKEN=sk-live] is a misconfiguration; the run must fail
	// without echoing the inline value anywhere (the missing-variable
	// diagnostic would otherwise print it into terminal and CI logs).
	if got := invalidDeclaredEnvName([]string{"API_TOKEN=sk-live"}); got != "API_TOKEN=..." {
		t.Fatalf("invalidDeclaredEnvName() = %q, want API_TOKEN=...", got)
	}
	adapter := NewUserDefinedScanner(UserDefinedScannerConfig{
		ID: "alpha", Command: "scanner {{target}}",
		Env: []string{"API_TOKEN=sk-live-declared"}, Targets: []string{"skill"},
	})
	requirements := adapter.Requirements(nil)
	for _, req := range requirements {
		if strings.Contains(req.EnvVar, "sk-live-declared") {
			t.Fatalf("requirement echoes inline value: %v", requirements)
		}
	}
	registry, err := NewScannerRegistry(adapter)
	if err != nil {
		t.Fatal(err)
	}
	commandRunner := &recordingCommandRunner{stdout: `{}`}
	result, err := (ExternalScannerRunner{
		Registry: registry, CommandRunner: commandRunner,
		Env: map[string]string{}, SandboxMode: SandboxModeOff,
	}).RunScanner("alpha", t.TempDir(), "2026-07-21T00:00:00Z")
	if err != nil {
		t.Fatal(err)
	}
	if result.Status != "failed" || !strings.Contains(result.Error, "not a variable name") {
		t.Fatalf("result = %q / %q, want malformed-env rejection", result.Status, result.Error)
	}
	if strings.Contains(result.Error, "sk-live-declared") {
		t.Fatalf("rejection echoes inline value: %s", result.Error)
	}
	if len(commandRunner.calls) != 0 {
		t.Fatalf("command ran despite malformed env: %#v", commandRunner.calls)
	}
}

func TestUserDefinedScannerRejectsMalformedBareEnvDeclarationWithoutEchoingIt(t *testing.T) {
	const pastedCredential = "sk-live-production-token"
	if got := invalidDeclaredEnvName([]string{pastedCredential}); got != "#1" {
		t.Fatalf("invalidDeclaredEnvName() = %q, want #1", got)
	}
	adapter := NewUserDefinedScanner(UserDefinedScannerConfig{
		ID: "alpha", Command: "scanner {{target}}",
		Env: []string{pastedCredential}, Targets: []string{"skill"},
	})
	registry, err := NewScannerRegistry(adapter)
	if err != nil {
		t.Fatal(err)
	}
	commandRunner := &recordingCommandRunner{stdout: `{}`}
	result, err := (ExternalScannerRunner{
		Registry: registry, CommandRunner: commandRunner,
		Env: map[string]string{}, SandboxMode: SandboxModeOff,
	}).RunScanner("alpha", t.TempDir(), "2026-07-21T00:00:00Z")
	if err != nil {
		t.Fatal(err)
	}
	if result.Status != "failed" || !strings.Contains(result.Error, "env entry #1 is not a variable name") {
		t.Fatalf("result = %q / %q, want positional malformed-env rejection", result.Status, result.Error)
	}
	if strings.Contains(result.Error, pastedCredential) {
		t.Fatalf("rejection echoes pasted credential: %s", result.Error)
	}
	if len(commandRunner.calls) != 0 {
		t.Fatalf("command ran despite malformed env: %#v", commandRunner.calls)
	}
}

func TestUserDefinedScannerRejectsMalformedEnvDeclarationAtEqualsZero(t *testing.T) {
	adapter := NewUserDefinedScanner(UserDefinedScannerConfig{
		ID: "alpha", Command: "scanner {{target}}",
		Env: []string{"=sk-live-eqzero"}, Targets: []string{"skill"},
	})
	registry, err := NewScannerRegistry(adapter)
	if err != nil {
		t.Fatal(err)
	}
	commandRunner := &recordingCommandRunner{stdout: `{}`}
	result, err := (ExternalScannerRunner{
		Registry: registry, CommandRunner: commandRunner,
		Env: map[string]string{}, SandboxMode: SandboxModeOff,
	}).RunScanner("alpha", t.TempDir(), "2026-07-21T00:00:00Z")
	if err != nil {
		t.Fatal(err)
	}
	if result.Status != "failed" || !strings.Contains(result.Error, "=...") {
		t.Fatalf("result = %q / %q, want safely truncated malformed-env rejection", result.Status, result.Error)
	}
	if strings.Contains(result.Error, "sk-live-eqzero") {
		t.Fatalf("rejection echoes inline value: %s", result.Error)
	}
	if len(commandRunner.calls) != 0 {
		t.Fatalf("command ran despite malformed env: %#v", commandRunner.calls)
	}
}

func TestSameCanonicalNumberIsExact(t *testing.T) {
	// float64 rounding must not conflate distinct 17-digit integers —
	// that would scrub unrelated evidence as a secret.
	if sameCanonicalNumber("9007199254740993", "9007199254740992") {
		t.Fatal("distinct integers conflated by float rounding")
	}
	if !sameCanonicalNumber("1e3", "1000") {
		t.Fatal("equal values in different spellings must match")
	}
	if !sameCanonicalNumber("1.0", "1") {
		t.Fatal("1.0 and 1 must match")
	}
	if sameCanonicalNumber("123", "abc") {
		t.Fatal("non-numeric secret matched")
	}
}

func TestUserDefinedScannerHostRedactionKeepsNonSecretSegmentNames(t *testing.T) {
	// Segment matching must not over-reach: GIT_AUTHOR_NAME contains AUTH
	// only inside AUTHOR, TOKENIZERS_PARALLELISM contains TOKEN only inside
	// TOKENIZERS, and PWD names the shell's working directory. Scrubbing any
	// of these values ("false" would rewrite every matching JSON boolean)
	// would corrupt legitimate evidence.
	adapter := NewUserDefinedScanner(UserDefinedScannerConfig{
		ID: "alpha", Command: "alpha {{target}}", Targets: []string{"skill"},
	})
	registry, err := NewScannerRegistry(adapter)
	if err != nil {
		t.Fatal(err)
	}
	commandRunner := &recordingCommandRunner{stdout: `{"author":"Jesse","cwd":"/skills/demo","clean":false}`}
	result, err := (ExternalScannerRunner{
		Registry: registry, CommandRunner: commandRunner,
		Env: map[string]string{
			"GIT_AUTHOR_NAME":        "Jesse",
			"PWD":                    "/skills/demo",
			"TOKENIZERS_PARALLELISM": "false",
		},
		SandboxMode: SandboxModeOff,
	}).RunScanner("alpha", t.TempDir(), "2026-07-21T00:00:00Z")
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{`"author":"Jesse"`, `"cwd":"/skills/demo"`, `"clean":false`} {
		if !strings.Contains(string(result.Raw), want) {
			t.Fatalf("non-secret env value scrubbed %s from evidence: %s", want, result.Raw)
		}
	}
}

func TestUserDefinedScannerHostRedactionStillCoversWholeEnv(t *testing.T) {
	// --sandbox off inherits the whole host env, so the secret-named sweep
	// must keep covering variables no scanner declared or allowlisted.
	adapter := NewUserDefinedScanner(UserDefinedScannerConfig{
		ID: "alpha", Command: "alpha {{target}}", Targets: []string{"skill"},
	})
	registry, err := NewScannerRegistry(adapter)
	if err != nil {
		t.Fatal(err)
	}
	commandRunner := &recordingCommandRunner{stdout: `{"echo":"host-secret-value"}`}
	result, err := (ExternalScannerRunner{
		Registry: registry, CommandRunner: commandRunner,
		Env:         map[string]string{"CI_TOKEN": "host-secret-value"},
		SandboxMode: SandboxModeOff,
	}).RunScanner("alpha", t.TempDir(), "2026-07-21T00:00:00Z")
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(result.Raw), "host-secret-value") {
		t.Fatalf("host secret leaked on --sandbox off: %s", result.Raw)
	}
}

func TestUnsafeWindowsShellTargetRejectsQuotesAndPercents(t *testing.T) {
	// cmd.exe cannot safely receive quotes (backslash does not escape " for
	// its parser, enabling breakout), percents (%VAR% expands inside double
	// quotes), or exclamation marks (!VAR! expands when delayed expansion is
	// enabled). All must be refused before interpolation.
	for _, target := range []string{`https://host/" & calc & "`, `C:\skill%path`, `https://host/!TEMP!`} {
		if !unsafeWindowsShellTarget(target) {
			t.Fatalf("target %q should be refused on the Windows host shell", target)
		}
	}
	for _, target := range []string{`C:\skills\my-skill`, "https://example.com/skill", "/tmp/skill with space"} {
		if unsafeWindowsShellTarget(target) {
			t.Fatalf("safe target %q was refused", target)
		}
	}
}

func TestUserDefinedScannerRedactsExposedEnvFromErrors(t *testing.T) {
	adapter := NewUserDefinedScanner(UserDefinedScannerConfig{
		ID: "alpha", Command: "alpha {{target}}", Targets: []string{"skill"},
	})
	registry, err := NewScannerRegistry(adapter)
	if err != nil {
		t.Fatal(err)
	}
	// Another scanner's credential (name evades isSecretEnvKey) written to
	// stderr must not persist in ScannerResult.Error.
	commandRunner := &recordingCommandRunner{stderr: "auth failed: beta-cred-value rejected", err: errCommandFailed}
	result, err := (ExternalScannerRunner{
		Registry: registry, CommandRunner: commandRunner,
		Env:             map[string]string{"BETA_LICENSE": "beta-cred-value"},
		ExposedEnvNames: []string{"BETA_LICENSE"},
		SandboxMode:     SandboxModeOff,
	}).RunScanner("alpha", t.TempDir(), "2026-07-21T00:00:00Z")
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(result.Error, "beta-cred-value") {
		t.Fatalf("exposed credential leaked into error: %q", result.Error)
	}
	if !strings.Contains(result.Error, "[redacted]") {
		t.Fatalf("expected redaction marker in error: %q", result.Error)
	}
}

func TestUserDefinedScannerRedactsEscapedUndeclaredSecretsFromErrors(t *testing.T) {
	adapter := NewUserDefinedScanner(UserDefinedScannerConfig{
		ID: "alpha", Command: "alpha {{target}}", Targets: []string{"skill"},
	})
	registry, err := NewScannerRegistry(adapter)
	if err != nil {
		t.Fatal(err)
	}
	// With --sandbox off the scanner inherits the whole host env. An
	// undeclared, unexposed secret-named var (OPENAI_API_KEY) whose value
	// appears JSON-escaped on stderr (pa\"ss for pa"ss) must still be
	// scrubbed from ScannerResult.Error.
	commandRunner := &recordingCommandRunner{stderr: `request body was {"auth":"pa\"ss"}`, err: errCommandFailed}
	result, err := (ExternalScannerRunner{
		Registry: registry, CommandRunner: commandRunner,
		Env:         map[string]string{"OPENAI_API_KEY": `pa"ss`},
		SandboxMode: SandboxModeOff,
	}).RunScanner("alpha", t.TempDir(), "2026-07-21T00:00:00Z")
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(result.Error, `pa\"ss`) || strings.Contains(result.Error, `pa"ss`) {
		t.Fatalf("escaped undeclared secret leaked into error: %q", result.Error)
	}
	if !strings.Contains(result.Error, "[redacted]") {
		t.Fatalf("expected redaction marker in error: %q", result.Error)
	}
}

func TestUserDefinedScannerRedactsAlternateEncodedSecretsFromErrors(t *testing.T) {
	adapter := NewUserDefinedScanner(UserDefinedScannerConfig{
		ID: "alpha", Command: "alpha {{target}}", Env: []string{"SCANNER_ACCESS"}, Targets: []string{"skill"},
	})
	registry, err := NewScannerRegistry(adapter)
	if err != nil {
		t.Fatal(err)
	}
	// json.Marshal never produces \/ or a, but a scanner echoing a
	// request body may: the escaped stderr text decodes back to the secret,
	// so failure-text redaction must catch alternate encodings too.
	tests := []struct {
		name   string
		secret string
		stderr string
	}{
		{name: "solidus escape", secret: "a/b-secret", stderr: `request failed: {"auth":"a\/b-secret"}`},
		{name: "unicode escape", secret: "s\u00e9cret", stderr: `request failed: {"auth":"s\u00e9cret"}`},
		{name: "surrogate pair", secret: "pass\U0001F600word", stderr: `request failed: {"auth":"pass\ud83d\ude00word"}`},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			commandRunner := &recordingCommandRunner{stderr: test.stderr, err: errCommandFailed}
			result, err := (ExternalScannerRunner{
				Registry: registry, CommandRunner: commandRunner,
				Env:         map[string]string{"SCANNER_ACCESS": test.secret},
				SandboxMode: SandboxModeOff,
			}).RunScanner("alpha", t.TempDir(), "2026-07-21T00:00:00Z")
			if err != nil {
				t.Fatal(err)
			}
			decoded := decodeJSONStringEscapes(result.Error)
			if strings.Contains(result.Error, test.secret) || strings.Contains(decoded, test.secret) {
				t.Fatalf("alternate-encoded secret survives in error: %q", result.Error)
			}
			if !strings.Contains(result.Error, "[redacted]") {
				t.Fatalf("expected redaction marker in error: %q", result.Error)
			}
		})
	}
}

func TestDecodeJSONStringEscapesPassesThroughUnknownSequences(t *testing.T) {
	for input, want := range map[string]string{
		`plain text`:        "plain text",
		`a\/b`:              "a/b",
		`s\u00e9cret`:       "s\u00e9cret",
		`pa\"ss and back\\`: `pa"ss and back\`,
		`\ud83d\ude00`:      "\U0001F600",
		`trailing\`:         `trailing\`,
		`\uZZZZ stays`:      `\uZZZZ stays`,
		`\b\f\n\r\t`:        "\b\f\n\r\t",
		`C:\new\table`:      "C:\new\table",
	} {
		if got := decodeJSONStringEscapes(input); got != want {
			t.Fatalf("decodeJSONStringEscapes(%q) = %q, want %q", input, got, want)
		}
	}
}

func TestRedactScannerStdoutRedactsNullScalarSecret(t *testing.T) {
	env := map[string]string{"SCANNER_PIN": "null"}
	redacted := redactScannerStdout(`{"token":null,"other":null}`, env, []string{"SCANNER_PIN"})
	if strings.Contains(redacted, "null") {
		t.Fatalf("null-valued secret survived: %s", redacted)
	}
	if !json.Valid([]byte(redacted)) {
		t.Fatalf("redacted output is not valid JSON: %s", redacted)
	}
}

func TestRedactScannerStdoutDoesNotCorruptNonStringTokens(t *testing.T) {
	// A short secret such as "1" must never break JSON syntax the way byte
	// replacement did (`{"count":[redacted]}` is invalid and flipped healthy
	// scans to failed). Scalars are redacted only on exact match: count:10
	// merely contains the secret's digits and must survive, while count:1
	// (exact match) becomes a redacted string — still valid JSON either way.
	env := map[string]string{"DEMO_TOKEN": "1"}
	raw := `{"count":10,"exact":1,"enabled":true,"note":"value 1 appears here"}`
	redacted := redactScannerStdout(raw, env, []string{"DEMO_TOKEN"})
	if !json.Valid([]byte(redacted)) {
		t.Fatalf("redacted output is not valid JSON: %s", redacted)
	}
	if !strings.Contains(redacted, `"count":10`) {
		t.Fatalf("non-matching numeric token was corrupted: %s", redacted)
	}
	if !strings.Contains(redacted, `"enabled":true`) {
		t.Fatalf("non-matching boolean token was corrupted: %s", redacted)
	}
	if strings.Contains(redacted, `"exact":1`) {
		t.Fatalf("exact-match scalar secret survived: %s", redacted)
	}
	if strings.Contains(redacted, "value 1 appears") {
		t.Fatalf("secret inside string survived: %s", redacted)
	}
}

func TestRedactionMarkerNeverContainsASecret(t *testing.T) {
	// A credential that is a substring of "[redacted]" ("act", "redacted",
	// even "a") would be re-inserted by the replacement itself, so the marker
	// must be swapped for one no secret can appear in.
	for name, secrets := range map[string][]string{
		"safe secrets keep preferred marker": {"hunter2", "s3cr3t"},
		"single letter":                      {"a"},
		"marker substring":                   {"act"},
		"whole marker word":                  {"redacted"},
		"marker with brackets":               {"[redacted]"},
		"fallback rune collision":            {"act", "##########"[:1]},
	} {
		t.Run(name, func(t *testing.T) {
			marker := redactionMarker(secrets)
			if marker == "" {
				t.Fatal("marker collapsed to empty for a realistic secret set")
			}
			for _, secret := range secrets {
				if strings.Contains(marker, secret) {
					t.Fatalf("marker %q contains secret %q", marker, secret)
				}
			}
		})
	}
	if got := redactionMarker([]string{"hunter2"}); got != "[redacted]" {
		t.Fatalf("safe secret set changed the preferred marker: %q", got)
	}
}

func TestRedactScannerStdoutMarkerSubstringSecrets(t *testing.T) {
	// Secrets that are substrings of the "[redacted]" sentinel must not
	// survive inside the replacement marker (scanner JSON path).
	for _, secret := range []string{"act", "redacted", "a"} {
		env := map[string]string{"SCANNER_ACCESS": secret}
		raw := `{"token":"` + secret + `","note":"before ` + secret + ` after"}`
		redacted := redactScannerStdout(raw, env, []string{"SCANNER_ACCESS"})
		if strings.Contains(redacted, secret) {
			t.Fatalf("secret %q survived redaction: %s", secret, redacted)
		}
		if !json.Valid([]byte(redacted)) {
			t.Fatalf("redacted output is not valid JSON: %s", redacted)
		}
	}
}

func TestUserDefinedScannerMarkerSubstringSecretInErrors(t *testing.T) {
	adapter := NewUserDefinedScanner(UserDefinedScannerConfig{
		ID: "alpha", Command: "alpha {{target}}", Env: []string{"SCANNER_ACCESS"}, Targets: []string{"skill"},
	})
	registry, err := NewScannerRegistry(adapter)
	if err != nil {
		t.Fatal(err)
	}
	// Failure-text path: a declared credential equal to "redacted" must not
	// ride back in inside the sentinel that replaces it.
	commandRunner := &recordingCommandRunner{stderr: "auth redacted rejected", err: errCommandFailed}
	result, err := (ExternalScannerRunner{
		Registry: registry, CommandRunner: commandRunner,
		Env:         map[string]string{"SCANNER_ACCESS": "redacted"},
		SandboxMode: SandboxModeOff,
	}).RunScanner("alpha", t.TempDir(), "2026-07-21T00:00:00Z")
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(result.Error, "redacted") {
		t.Fatalf("marker-substring secret survived in error: %q", result.Error)
	}
}

func TestSecretScrubberReplacementCannotRebuildSecret(t *testing.T) {
	// Replacement can splice marker bytes against surrounding text and
	// synthesize a secret that was not there before; scrub must re-check
	// until no secret remains.
	scrubber := newSecretScrubber([]string{"X["})
	if got := scrubber.scrub("XX[tail"); strings.Contains(got, "X[") {
		t.Fatalf("replacement reintroduced the secret: %q", got)
	}
}

func TestRedactScannerStdoutPreservesFieldsOnKeyCollision(t *testing.T) {
	// A JSON key containing a secret is renamed to the marker. If another
	// field's key already equals the marker, direct assignment would
	// overwrite it and silently drop evidence; the redacted key must land
	// under a collision-safe name instead.
	env := map[string]string{"SCANNER_ACCESS": "abc"}
	raw := `{"abc":1,"[redacted]":2}`
	redacted := redactScannerStdout(raw, env, []string{"SCANNER_ACCESS"})
	var parsed map[string]any
	if err := json.Unmarshal([]byte(redacted), &parsed); err != nil {
		t.Fatal(err)
	}
	if len(parsed) != 2 {
		t.Fatalf("field dropped on key collision: %s", redacted)
	}
	if strings.Contains(redacted, "abc") {
		t.Fatalf("secret key survived redaction: %s", redacted)
	}
	// Two secret keys redacting to the same marker must also both survive.
	raw = `{"abc-primary":1,"abc-fallback":2}`
	env = map[string]string{"SCANNER_ACCESS": "abc-primary", "SCANNER_ACCESS_2": "abc-fallback"}
	redacted = redactScannerStdout(raw, env, []string{"SCANNER_ACCESS", "SCANNER_ACCESS_2"})
	parsed = nil
	if err := json.Unmarshal([]byte(redacted), &parsed); err != nil {
		t.Fatal(err)
	}
	if len(parsed) != 2 {
		t.Fatalf("field dropped when two keys redact identically: %s", redacted)
	}
	for _, secret := range []string{"abc-primary", "abc-fallback"} {
		if strings.Contains(redacted, secret) {
			t.Fatalf("secret %q survived redaction: %s", secret, redacted)
		}
	}
}

func TestRedactScannerStdoutDropsSecretsInDuplicateJSONKeys(t *testing.T) {
	// Go's decoder keeps only an object's last duplicate member, so a
	// secret hidden in the earlier duplicate is invisible to the node walk
	// but still present in the raw bytes. The original text must not be
	// returned verbatim in that case.
	env := map[string]string{"DEMO_TOKEN": "sekret"}
	raw := `{"auth":"sekret","auth":"safe"}`
	redacted := redactScannerStdout(raw, env, []string{"DEMO_TOKEN"})
	if strings.Contains(redacted, "sekret") {
		t.Fatalf("duplicate-key secret survived redaction: %s", redacted)
	}
	if !json.Valid([]byte(redacted)) {
		t.Fatalf("redacted output is not valid JSON: %s", redacted)
	}
	// A duplicate secret value inside the duplicate key's value node too.
	raw = `{"a":{"tok":"sekret","tok":"x"},"b":1}`
	redacted = redactScannerStdout(raw, env, []string{"DEMO_TOKEN"})
	if strings.Contains(redacted, "sekret") {
		t.Fatalf("nested duplicate-key secret survived: %s", redacted)
	}
	// No duplicates and no secrets: input must pass through untouched,
	// preserving original formatting.
	clean := `{"findings": [],
  "note": "kept"}`
	if got := redactScannerStdout(clean, env, []string{"DEMO_TOKEN"}); got != clean {
		t.Fatalf("clean output was rewritten: %q", got)
	}
}

func TestHasDuplicateJSONKeys(t *testing.T) {
	for raw, want := range map[string]bool{
		`{"a":1,"a":2}`:             true,
		`{"a":{"b":1,"b":2}}`:       true,
		`[{"x":1},{"x":1,"x":2}]`:   true,
		`{"a":1,"b":{"a":2}}`:       false,
		`{"a":"a"}`:                 false,
		`[1,2,3]`:                   false,
		`{"a":["a","a"]}`:           false,
		`{"a":{"b":1},"c":{"b":1}}`: false,
	} {
		if got := hasDuplicateJSONKeys(raw); got != want {
			t.Fatalf("hasDuplicateJSONKeys(%s) = %v, want %v", raw, got, want)
		}
	}
}

func TestScannerSecretValuesExemptsByNameNeverByValue(t *testing.T) {
	// PASSWORD_STORE_ENABLE_EXTENSIONS is a known pass(1) toggle, exempted
	// by NAME. DB_PASSWORD=default must still be swept — a weak credential
	// holding a common-looking value is a credential all the same.
	env := map[string]string{
		"PASSWORD_STORE_ENABLE_EXTENSIONS": "true",
		"DB_PASSWORD":                      "default",
		"CI_TOKEN":                         "real-secret",
	}
	secrets := scannerSecretValues(env, nil)
	got := strings.Join(secrets, ",")
	if strings.Contains(got, "true") {
		t.Fatalf("known config toggle swept as secret: %v", secrets)
	}
	if !strings.Contains(got, "default") {
		t.Fatalf("weak credential exempted by value: %v", secrets)
	}
	if !strings.Contains(got, "real-secret") {
		t.Fatalf("real secret missing from sweep: %v", secrets)
	}
}

func TestScannerSecretValuesIncludesJSONCredentialLeaves(t *testing.T) {
	credential := "sk-" + "live-cred"
	jsonCredential := `{"to` + `ken":"` + credential + `"}`
	env := map[string]string{"SCANNER_ACCESS": jsonCredential}
	secrets := scannerSecretValues(env, []string{"SCANNER_ACCESS"})
	got := strings.Join(secrets, "\n")
	for _, want := range []string{jsonCredential, credential} {
		if !strings.Contains(got, want) {
			t.Fatalf("secret %q missing from %v", want, secrets)
		}
	}
}

func TestJSONSecretLeavesIncludesNumericCredential(t *testing.T) {
	leaves := jsonSecretLeaves(`{"pin":123456}`)
	if !slices.Contains(leaves, "123456") {
		t.Fatalf("numeric JSON credential leaf missing from %v", leaves)
	}
}

func TestUserDefinedScannerRedactsNumericJSONCredentialLeaf(t *testing.T) {
	adapter := NewUserDefinedScanner(UserDefinedScannerConfig{
		ID: "demo", Command: "demo {{target}}", Env: []string{"SCANNER_ACCESS"}, Targets: []string{"skill"},
	})
	registry, err := NewScannerRegistry(adapter)
	if err != nil {
		t.Fatal(err)
	}
	commandRunner := &recordingCommandRunner{stdout: `{"pin":123456}`}
	result, err := (ExternalScannerRunner{
		Registry: registry, CommandRunner: commandRunner,
		Env:         map[string]string{"SCANNER_ACCESS": `{"pin":123456}`},
		SandboxMode: SandboxModeOff,
	}).RunScanner("demo", t.TempDir(), "2026-07-21T00:00:00Z")
	if err != nil {
		t.Fatal(err)
	}
	if result.Status != "completed" {
		t.Fatalf("status = %q, want completed", result.Status)
	}
	if strings.Contains(string(result.Raw), "123456") {
		t.Fatalf("numeric JSON credential leaf survived redaction: %s", result.Raw)
	}
	if !strings.Contains(string(result.Raw), "[redacted]") {
		t.Fatalf("expected redaction marker: %s", result.Raw)
	}
}

func TestRedactScannerStdoutScrubsReemittedJSONCredentialLeaves(t *testing.T) {
	credential := "sk-" + "live-cred"
	env := map[string]string{"SCANNER_ACCESS": `{"to` + `ken":"` + credential + `"}`}
	redacted := redactScannerStdout(`{"auth":{"to`+`ken":"`+credential+`"}}`, env, []string{"SCANNER_ACCESS"})
	if strings.Contains(redacted, credential) {
		t.Fatalf("JSON credential leaf survived redaction: %s", redacted)
	}
	if !strings.Contains(redacted, "[redacted]") {
		t.Fatalf("expected redaction marker: %s", redacted)
	}
}

func TestScannerSecretValuesExcludesShortJSONCredentialLeaves(t *testing.T) {
	env := map[string]string{"X": `{"v":"ab"}`}
	secrets := scannerSecretValues(env, []string{"X"})
	for _, secret := range secrets {
		if secret == "ab" {
			t.Fatalf("short JSON credential leaf was included: %v", secrets)
		}
	}
}

func TestJSONSecretLeavesExcludesShortNumericCredential(t *testing.T) {
	leaves := jsonSecretLeaves(`{"count":42}`)
	if slices.Contains(leaves, "42") {
		t.Fatalf("short numeric JSON credential leaf was included: %v", leaves)
	}
	raw := `{"count":42}`
	env := map[string]string{"SCANNER_ACCESS": raw}
	if got := redactScannerStdout(raw, env, []string{"SCANNER_ACCESS"}); got != raw {
		t.Fatalf("short numeric evidence was changed: got %s, want %s", got, raw)
	}
}

func TestRunScannerRedactsUndeclaredHostSecretsWithNoExposedNames(t *testing.T) {
	// A built-in command scanner with no declared or passthrough env still
	// inherits the whole host env with --sandbox off; the central redaction
	// boundary must run despite ExposedEnvNames being empty.
	commandRunner := &recordingCommandRunner{stdout: `{"echo":"host-secret-value"}`}
	result, err := (ExternalScannerRunner{
		Registry: DefaultScannerRegistry(), CommandRunner: commandRunner,
		Env:             map[string]string{"CI_TOKEN": "host-secret-value"},
		ExposedEnvNames: nil,
		SandboxMode:     SandboxModeOff,
	}).RunScanner("agentverus", t.TempDir(), "2026-07-21T00:00:00Z")
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(result.Raw), "host-secret-value") {
		t.Fatalf("built-in scanner leaked undeclared host secret with empty exposed names: %s", result.Raw)
	}
}

func TestUserDefinedScannerRecordsExitCode(t *testing.T) {
	exitCode := 2
	adapter := NewUserDefinedScanner(UserDefinedScannerConfig{
		ID: "demo", Command: "demo {{target}}", Targets: []string{"skill"},
	})
	registry, err := NewScannerRegistry(adapter)
	if err != nil {
		t.Fatal(err)
	}
	commandRunner := &recordingCommandRunner{stdout: `{}`, err: errCommandFailed, exitCode: &exitCode}
	result, err := (ExternalScannerRunner{
		Registry: registry, CommandRunner: commandRunner, Env: map[string]string{}, SandboxMode: SandboxModeOff,
	}).RunScanner("demo", t.TempDir(), "2026-07-21T00:00:00Z")
	if err != nil {
		t.Fatal(err)
	}
	if result.ExitCode == nil || *result.ExitCode != 2 {
		t.Fatalf("exit code = %#v", result.ExitCode)
	}
}

func TestUserDefinedScannerOmitsAbnormalExitCode(t *testing.T) {
	exitCode := -1
	adapter := NewUserDefinedScanner(UserDefinedScannerConfig{
		ID: "demo", Command: "demo {{target}}", Targets: []string{"skill"},
	})
	registry, err := NewScannerRegistry(adapter)
	if err != nil {
		t.Fatal(err)
	}
	commandRunner := &recordingCommandRunner{stdout: `{}`, err: errCommandFailed, exitCode: &exitCode}
	result, err := (ExternalScannerRunner{
		Registry: registry, CommandRunner: commandRunner, Env: map[string]string{}, SandboxMode: SandboxModeOff,
	}).RunScanner("demo", t.TempDir(), "2026-07-21T00:00:00Z")
	if err != nil {
		t.Fatal(err)
	}
	if result.ExitCode != nil {
		t.Fatalf("abnormal exit code recorded = %d", *result.ExitCode)
	}
}

func TestUserDefinedScannerInterpolatesDollarTargetLiterally(t *testing.T) {
	adapter := NewUserDefinedScanner(UserDefinedScannerConfig{
		ID: "demo", Command: "demo {{target}}", Targets: []string{"skill"},
	})
	registry, err := NewScannerRegistry(adapter)
	if err != nil {
		t.Fatal(err)
	}
	commandRunner := &recordingCommandRunner{stdout: `{}`}
	target := filepath.Join(t.TempDir(), "skill-$USER")
	if err := os.Mkdir(target, 0o755); err != nil {
		t.Fatal(err)
	}
	result, err := (ExternalScannerRunner{
		Registry: registry, CommandRunner: commandRunner, Env: map[string]string{}, SandboxMode: SandboxModeOff,
	}).RunScanner("demo", target, "2026-07-21T00:00:00Z")
	if err != nil {
		t.Fatal(err)
	}
	if result.Status != "completed" {
		t.Fatalf("result = %#v", result)
	}
	if len(commandRunner.calls) != 1 {
		t.Fatalf("calls = %#v", commandRunner.calls)
	}
	args := commandRunner.calls[0].args
	if len(args) != 4 || !strings.Contains(args[1], `"$1"`) || strings.Contains(args[1], target) || args[3] != target {
		t.Fatalf("target was not passed as a separate shell argument: %#v", args)
	}
}

func TestUserDefinedScannerUsesContainerShellInDockerMode(t *testing.T) {
	dockerShell := userDefinedScannerShell("windows", SandboxModeDocker)
	if dockerShell.command != "/bin/sh" || strings.Join(dockerShell.args, " ") != "-c" {
		t.Fatalf("docker shell = %#v", dockerShell)
	}
	hostShell := userDefinedScannerShell("windows", SandboxModeOff)
	if hostShell.command != "cmd.exe" || strings.Join(hostShell.args, " ") != "/C" {
		t.Fatalf("host shell = %#v", hostShell)
	}
}

func TestScannerAdapterRequirementsFeedValidation(t *testing.T) {
	requirements := stubScannerAdapter{
		id: "demo",
		requirements: []EnvRequirement{
			{EnvVar: "DEMO_TOKEN", Reason: "scanner demo"},
		},
	}.Requirements(map[string]string{})
	if len(requirements) != 1 || requirements[0].EnvVar != "DEMO_TOKEN" {
		t.Fatalf("requirements = %#v", requirements)
	}
}

func TestDefaultScannerRegistryProvidesInstallPlans(t *testing.T) {
	registry := DefaultScannerRegistry()
	for _, id := range registry.IDs() {
		adapter, ok := registry.Adapter(id)
		if !ok {
			t.Fatalf("missing adapter for %s", id)
		}
		plan := adapter.InstallPlan()
		if plan.ScannerID != id {
			t.Fatalf("%s install plan scanner id = %q", id, plan.ScannerID)
		}
		if strings.TrimSpace(plan.Name) == "" {
			t.Fatalf("%s install plan missing name", id)
		}
	}
}

func TestDefaultScannerRegistryProvidesCatalogInfo(t *testing.T) {
	registry := DefaultScannerRegistry()
	for _, id := range registry.IDs() {
		info, ok := registry.Info(id)
		if !ok {
			t.Fatalf("missing info for %s", id)
		}
		if info.ID != id {
			t.Fatalf("%s info id = %q", id, info.ID)
		}
		if strings.TrimSpace(info.DisplayName) == "" {
			t.Fatalf("%s info missing display name", id)
		}
		if strings.TrimSpace(info.Description) == "" {
			t.Fatalf("%s info missing description", id)
		}
		if strings.TrimSpace(info.RepositoryURL) == "" {
			t.Fatalf("%s info missing repository URL", id)
		}
	}

	skillspector, _ := registry.Info("skillspector")
	if got := strings.Join(skillspector.OptionalEnv, ","); got != "SKILLSPECTOR_PROVIDER,SKILLSPECTOR_MODEL,SKILLSPECTOR_MODEL_REGISTRY,SKILLSPECTOR_LOG_LEVEL,SKILLSPECTOR_SSL_VERIFY,NVIDIA_INFERENCE_KEY,OPENAI_API_KEY,OPENAI_BASE_URL,ANTHROPIC_API_KEY,ANTHROPIC_PROXY_ENDPOINT_URL,ANTHROPIC_PROXY_API_KEY,ANTHROPIC_PROXY_API_VERSION" {
		t.Fatalf("skillspector optional env = %q", got)
	}

	cisco, _ := registry.Info("cisco")
	if got := strings.Join(cisco.OptionalEnv, ","); got != "SKILL_SCANNER_LLM_API_KEY,SKILL_SCANNER_LLM_PROVIDER,SKILL_SCANNER_LLM_MODEL,SKILL_SCANNER_LLM_BASE_URL,SKILL_SCANNER_LLM_USER,SKILL_SCANNER_LLM_API_VERSION,SKILL_SCANNER_LLM_FORCE_JSON_OBJECT,SKILL_SCANNER_META_LLM_API_KEY,SKILL_SCANNER_META_LLM_MODEL,SKILL_SCANNER_META_LLM_BASE_URL,SKILL_SCANNER_META_LLM_API_VERSION,AWS_PROFILE,AWS_REGION,GOOGLE_APPLICATION_CREDENTIALS,VIRUSTOTAL_API_KEY,AI_DEFENSE_API_KEY,AI_DEFENSE_API_URL" {
		t.Fatalf("cisco optional env = %q", got)
	}

	socket, _ := registry.Info("socket")
	if got := strings.Join(socket.RequiredEnv, ","); got != "SOCKET_CLI_API_TOKEN" {
		t.Fatalf("socket required env = %q", got)
	}

	aig, _ := registry.Info("aig")
	if got := strings.Join(aig.RequiredEnv, ","); got != "LLM_API_KEY" {
		t.Fatalf("aig required env = %q", got)
	}
	if got := strings.Join(aig.OptionalEnv, ","); got != "OPENAI_API_KEY,DEFAULT_MODEL,DEFAULT_BASE_URL,DEFAULT_MODEL_CONTEXT_WINDOW,LOG_LEVEL" {
		t.Fatalf("aig optional env = %q", got)
	}
	if aig.InstallHint != "pip install aig-skill-scan" {
		t.Fatalf("aig install hint = %q", aig.InstallHint)
	}
	if !aig.Installable {
		t.Fatal("aig should be installable")
	}
}

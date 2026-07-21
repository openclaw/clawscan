package runner

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
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
	commandRunner := &recordingCommandRunner{stdout: `{"findings":["detected"]}`, stderr: "findings detected", err: errCommandFailed}
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

func TestUserDefinedScannerRedactsDeclaredEnvOnFailure(t *testing.T) {
	adapter := NewUserDefinedScanner(UserDefinedScannerConfig{
		ID: "demo", Command: "demo {{target}}", Env: []string{"SCANNER_AUTH"}, Targets: []string{"skill"},
	})
	registry, err := NewScannerRegistry(adapter)
	if err != nil {
		t.Fatal(err)
	}
	commandRunner := &recordingCommandRunner{stderr: "auth failed: hunter2-credential rejected", err: errCommandFailed}
	result, err := (ExternalScannerRunner{
		Registry: registry, CommandRunner: commandRunner,
		Env:         map[string]string{"SCANNER_AUTH": "hunter2-credential"},
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
		ID: "demo", Command: "demo {{target}}", Env: []string{"SCANNER_AUTH"}, Targets: []string{"skill"},
	})
	registry, err := NewScannerRegistry(adapter)
	if err != nil {
		t.Fatal(err)
	}
	commandRunner := &recordingCommandRunner{stdout: `{"token":"hunter2-credential","findings":[]}`}
	result, err := (ExternalScannerRunner{
		Registry: registry, CommandRunner: commandRunner,
		Env:         map[string]string{"SCANNER_AUTH": "hunter2-credential"},
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
		env := map[string]string{"SCANNER_AUTH": test.secret}
		declared := []string{"SCANNER_AUTH"}
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
	env := map[string]string{"SCANNER_AUTH": "hunter2"}
	raw := `{"findings": [],
  "note": "keeps formatting when nothing leaks"}`
	if got := redactScannerStdout(raw, env, []string{"SCANNER_AUTH"}); got != raw {
		t.Fatalf("clean output was rewritten: %q", got)
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

func TestRedactScannerStdoutDoesNotCorruptNonStringTokens(t *testing.T) {
	// A short secret such as "1" must never rewrite numeric or boolean JSON
	// tokens; that would invalidate the JSON and flip a healthy scan to failed.
	env := map[string]string{"DEMO_TOKEN": "1"}
	raw := `{"count":1,"enabled":true,"note":"value 1 appears here"}`
	redacted := redactScannerStdout(raw, env, []string{"DEMO_TOKEN"})
	if !json.Valid([]byte(redacted)) {
		t.Fatalf("redacted output is not valid JSON: %s", redacted)
	}
	if !strings.Contains(redacted, `"count":1`) {
		t.Fatalf("numeric token was corrupted: %s", redacted)
	}
	if strings.Contains(redacted, "value 1 appears") {
		t.Fatalf("secret inside string survived: %s", redacted)
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

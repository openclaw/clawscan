package runner

import (
	"strings"
	"testing"
)

// declaredCredentialEnv reaches DeclaredCredentialEnv, which is exposed via a
// type assertion (the ScannerAdapter interface does not declare it).
func declaredCredentialEnv(t *testing.T, adapter ScannerAdapter) []string {
	t.Helper()
	declarer, ok := adapter.(interface{ DeclaredCredentialEnv() []string })
	if !ok {
		t.Fatalf("adapter %T does not expose DeclaredCredentialEnv", adapter)
	}
	return declarer.DeclaredCredentialEnv()
}

// TestSecretEnvScrubbedPlainEnvShownEndToEnd is the core behavior contract:
// a secretEnv value is scrubbed from persisted stdout while a non-secret-named
// plain env value stays in evidence, both through a real adapter.Run.
func TestSecretEnvScrubbedPlainEnvShownEndToEnd(t *testing.T) {
	scanner := NewUserDefinedScanner(UserDefinedScannerConfig{
		ID:        "alpha",
		Command:   "alpha {{target}}",
		Env:       []string{"MODE"},
		SecretEnv: []string{"BETA_LICENSE"},
		Targets:   []string{"skill"},
	})
	registry, err := NewScannerRegistry(scanner)
	if err != nil {
		t.Fatal(err)
	}
	env := map[string]string{"MODE": "fastmode-shown", "BETA_LICENSE": "beta-secret-xyz"}
	run := ExternalScannerRunner{
		Registry:      registry,
		CommandRunner: &recordingCommandRunner{stdout: `{"mode":"fastmode-shown","license":"beta-secret-xyz"}`},
		Env:           env, SandboxMode: SandboxModeOff,
	}
	result, err := run.RunScanner("alpha", t.TempDir(), "2026-07-21T00:00:00Z")
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(result.Raw), "beta-secret-xyz") {
		t.Fatalf("secretEnv value leaked into raw evidence: %s", result.Raw)
	}
	if !strings.Contains(string(result.Raw), "fastmode-shown") {
		t.Fatalf("non-secret plain env value was scrubbed from evidence: %s", result.Raw)
	}
}

// TestSecretNamedPlainEnvStillScrubbedByBackstop verifies the safety net: a
// secret-NAMED value placed in plain env (not secretEnv) is still redacted by
// the isSecretEnvKey heuristic, so a migration cannot silently un-redact it.
func TestSecretNamedPlainEnvStillScrubbedByBackstop(t *testing.T) {
	scanner := NewUserDefinedScanner(UserDefinedScannerConfig{
		ID:      "alpha",
		Command: "alpha {{target}}",
		Env:     []string{"MY_TOKEN"},
		Targets: []string{"skill"},
	})
	registry, err := NewScannerRegistry(scanner)
	if err != nil {
		t.Fatal(err)
	}
	env := map[string]string{"MY_TOKEN": "tokenvalue-abc"}
	run := ExternalScannerRunner{
		Registry:      registry,
		CommandRunner: &recordingCommandRunner{stdout: `{"seen":"tokenvalue-abc"}`},
		Env:           env, SandboxMode: SandboxModeOff,
	}
	result, err := run.RunScanner("alpha", t.TempDir(), "2026-07-21T00:00:00Z")
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(result.Raw), "tokenvalue-abc") {
		t.Fatalf("secret-named plain env value escaped the heuristic backstop: %s", result.Raw)
	}
}

// TestSecretEnvScrubbedFromErrorText verifies secretEnv values are scrubbed
// from failure text (OS error + stderr), not just stdout.
func TestSecretEnvScrubbedFromErrorText(t *testing.T) {
	scanner := NewUserDefinedScanner(UserDefinedScannerConfig{
		ID:        "alpha",
		Command:   "alpha {{target}}",
		SecretEnv: []string{"BETA_LICENSE"},
		Targets:   []string{"skill"},
	})
	registry, err := NewScannerRegistry(scanner)
	if err != nil {
		t.Fatal(err)
	}
	env := map[string]string{"BETA_LICENSE": "beta-secret-xyz"}
	run := ExternalScannerRunner{
		Registry:      registry,
		CommandRunner: &recordingCommandRunner{stderr: "auth beta-secret-xyz rejected", err: errCommandFailed},
		Env:           env, SandboxMode: SandboxModeOff,
	}
	result, err := run.RunScanner("alpha", t.TempDir(), "2026-07-21T00:00:00Z")
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(result.Error, "beta-secret-xyz") {
		t.Fatalf("secretEnv value leaked into error text: %q", result.Error)
	}
}

// TestDeclaredCredentialEnvOnlyIncludesSecretEnv: only secretEnv entries are
// credentials-by-declaration; plain env entries are not.
func TestDeclaredCredentialEnvOnlyIncludesSecretEnv(t *testing.T) {
	adapter := NewUserDefinedScanner(UserDefinedScannerConfig{
		ID:        "test-scanner",
		Command:   "test {{target}}",
		Env:       []string{"CONFIG_VAR", "SECRET_TOKEN"},
		SecretEnv: []string{"API_KEY", "PASSWORD"},
	})
	declared := declaredCredentialEnv(t, adapter)
	got := map[string]bool{}
	for _, name := range declared {
		got[name] = true
	}
	if len(declared) != 2 || !got["API_KEY"] || !got["PASSWORD"] {
		t.Fatalf("DeclaredCredentialEnv() = %v, want exactly [API_KEY PASSWORD]", declared)
	}
	if got["CONFIG_VAR"] || got["SECRET_TOKEN"] {
		t.Fatalf("DeclaredCredentialEnv() must not include plain env entries: %v", declared)
	}
}

// TestRequirementsAndInfoIncludeBothBuckets: both env and secretEnv must reach
// the scanner, so both surface as requirements/required env.
func TestRequirementsAndInfoIncludeBothBuckets(t *testing.T) {
	adapter := NewUserDefinedScanner(UserDefinedScannerConfig{
		ID:        "test-scanner",
		Command:   "test {{target}}",
		Env:       []string{"CONFIG_VAR"},
		SecretEnv: []string{"API_KEY"},
	})
	reqNames := map[string]bool{}
	for _, req := range adapter.Requirements(nil) {
		reqNames[req.EnvVar] = true
	}
	if !reqNames["CONFIG_VAR"] || !reqNames["API_KEY"] {
		t.Fatalf("Requirements() = %v, want both CONFIG_VAR and API_KEY", reqNames)
	}
	infoNames := map[string]bool{}
	for _, name := range adapter.Info().RequiredEnv {
		infoNames[name] = true
	}
	if !infoNames["CONFIG_VAR"] || !infoNames["API_KEY"] {
		t.Fatalf("Info().RequiredEnv = %v, want both CONFIG_VAR and API_KEY", infoNames)
	}
}

// TestSecretEnvEntriesValidatedAsBareNames: secretEnv rejects NAME=value
// entries exactly like env does.
func TestSecretEnvEntriesValidatedAsBareNames(t *testing.T) {
	if InvalidUserDefinedEnvName([]string{"API_KEY=sk-live"}) == "" {
		t.Fatal("secretEnv validation must reject NAME=value entries")
	}
	if bad := InvalidUserDefinedEnvName([]string{"API_KEY", "BETA_LICENSE"}); bad != "" {
		t.Fatalf("bare names must be accepted, rejected %q", bad)
	}
}

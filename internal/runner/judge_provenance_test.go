package runner

import (
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

func TestConfiguredJudgeModelConservative(t *testing.T) {
	for _, tc := range []struct{ name, command, want string }{
		{"literal", "codex exec --model gpt-6.1-sol", "gpt-6.1-sol"},
		{"quoted", "codex exec -m 'gpt-6.1-sol'", "gpt-6.1-sol"},
		{"inline", "codex exec --model=gpt-6.1-sol", "gpt-6.1-sol"},
		{"override", "codex exec --model gpt-6-luna", "gpt-6-luna"},
		{"auth prelude", `[ -n "$CODEX_API_KEY" ] || export CODEX_API_KEY="$OPENAI_API_KEY"; codex exec --model gpt-6.1-sol --cd '/workspace' --sandbox read-only --ignore-user-config -c approval_policy=never -c model_reasoning_effort=high -c 'shell_environment_policy.inherit="core"' --skip-git-repo-check --output-schema '/tmp/schema' --output-last-message '/tmp/output' --ephemeral --json - < '/tmp/prompt'`, "gpt-6.1-sol"},
		{"quoted prompt", `printf '%s' 'codex exec --model gpt-6.1-sol'`, ""},
		{"comment", "printf '{}' # codex exec --model gpt-6.1-sol", ""},
		{"dynamic model", `codex exec --model "$MODEL"`, ""},
		{"dynamic argv", `codex exec --model gpt-6.1-sol $EXTRA_ARGS`, ""},
		{"substitution", "codex exec --model $(printf gpt-6.1-sol)", ""},
		{"glob", "codex exec --model gpt-*", ""},
		{"empty", "codex exec --model ''", ""},
		{"missing", "codex exec --model", ""},
		{"missing inline", "codex exec --model=", ""},
		{"duplicate", "codex exec --model gpt-6.1-sol -m gpt-6-luna", ""},
		{"config model", `codex exec --model gpt-6.1-sol -c 'model="gpt-6-luna"'`, ""},
		{"inline config", `codex exec --model gpt-6.1-sol --config='model="gpt-6-luna"'`, ""},
		{"compact config", `codex exec --model gpt-6.1-sol -cmodel='"gpt-6-luna"'`, ""},
		{"multiple calls", "codex exec --model gpt-6.1-sol; codex exec --model gpt-6-luna", ""},
		{"conditional", "false && codex exec --model gpt-6.1-sol", ""},
		{"background", "codex exec --model gpt-6.1-sol &", ""},
		{"function", "codex() { printf '{}'; }; codex exec --model gpt-6.1-sol", ""},
		{"different harness", "other exec --model gpt-6.1-sol", ""},
		{"non-model secret", "codex exec --model sk-fixture-secret", ""},
		{"unsupported flags", "codex exec --unknown --model gpt-6.1-sol", ""},
		{"option value not model", "codex exec --cd --model gpt-6.1-sol", ""},
		{"prompt flag not model", "codex exec -- --model gpt-6.1-sol", ""},
		{"malformed", "codex exec --model 'gpt-6.1-sol", ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := configuredJudgeModel(tc.command, "linux", nil); got != tc.want {
				t.Fatalf("model = %q, want %q", got, tc.want)
			}
		})
	}
	if got := configuredJudgeModel("codex exec --model gpt-6.1-sol", "windows", nil); got != "" {
		t.Fatalf("Windows model = %q", got)
	}
	if got := configuredJudgeModel("codex exec --model gpt-secret-fixture", "linux", map[string]string{"OPENAI_API_KEY": "gpt-secret-fixture"}); got != "" {
		t.Fatalf("secret persisted as model = %q", got)
	}
}

func TestRunJudgeSubprocessRecordsConfiguredModelNotModelAuthoredClaim(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX subprocess fixture")
	}
	dir := t.TempDir()
	target := filepath.Join(dir, "skill")
	if err := os.Mkdir(target, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(target, "SKILL.md"), []byte("# Harmless fixture"), 0o644); err != nil {
		t.Fatal(err)
	}
	argv := filepath.Join(dir, "observed-argv")
	binary := filepath.Join(dir, "codex")
	script := "#!/bin/sh\nprintf '%s\\n' \"$@\" > \"$ARGV_FILE\"\nprintf '%s\\n' '{\"model\":\"gpt-model-authored-lie\",\"ok\":true}'\n"
	if err := os.WriteFile(binary, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	env := map[string]string{"PATH": dir, "ARGV_FILE": argv, "OPENAI_API_KEY": "fixture-credential-value"}
	artifact := NewArtifact(Options{Target: target}, target, "2026-01-01T00:00:00Z", "2026-01-01T00:00:00Z", env)
	command := "AUTH_TOKEN=fixture-command-secret " + posixShellQuote(binary) + " exec --model gpt-6.1-sol --ignore-user-config -c model_reasoning_effort=high"
	result, err := RunJudge(JudgeOptions{Command: command}, artifact, defaultCommandRunner{Env: env}, time.Second*5, env, SandboxModeOff)
	if err != nil {
		t.Fatal(err)
	}
	if result.Status != "completed" || result.ConfiguredModel != "gpt-6.1-sol" {
		t.Fatalf("judge result = %#v", result)
	}
	observed, err := os.ReadFile(argv)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(observed), "--model\ngpt-6.1-sol\n") {
		t.Fatalf("unexpected subprocess argv: %q", observed)
	}
	raw, err := json.Marshal(result)
	if err != nil {
		t.Fatal(err)
	}
	if result.Command != "" || strings.Contains(string(raw), "fixture-command-secret") || strings.Contains(string(raw), "fixture-credential-value") {
		t.Fatalf("command/credential leaked: %s", raw)
	}
	if result.Result.(map[string]any)["model"] != "gpt-model-authored-lie" {
		t.Fatal("model-authored evidence should remain raw, not become execution provenance")
	}
	if !strings.Contains(string(raw), `"configuredModel":"gpt-6.1-sol"`) {
		t.Fatalf("missing provenance JSON: %s", raw)
	}
}

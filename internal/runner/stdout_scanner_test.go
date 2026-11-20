package runner

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"
)

func TestStdoutScannerResults(t *testing.T) {
	for _, adapter := range []struct {
		id, token, name, policyJSON string
	}{
		{"snyk", "SNYK_TOKEN", "Snyk", `{"ok":false,"issues":[{"id":"prompt-injection"}]}`},
		{"socket", "SOCKET_CLI_API_TOKEN", "Socket", `{"id":"scan_123","status":"failed","alerts":[]}`},
	} {
		t.Run(adapter.id, func(t *testing.T) {
			target := filepath.Join(t.TempDir(), "SKILL.md")
			if err := os.WriteFile(target, []byte("# Demo"), 0o600); err != nil {
				t.Fatal(err)
			}
			opts, err := ParseArgs([]string{target, "--scanner", adapter.id})
			if err != nil {
				t.Fatal(err)
			}
			policyExit := 1
			for _, tc := range []struct {
				name            string
				command         stdoutCommandRunner
				status, message string
				raw             json.RawMessage
				exitCode        *int
			}{
				{
					name: "nonzero with evidence",
					command: stdoutCommandRunner{
						stdout: adapter.policyJSON, stderr: "policy violation",
						err: errors.New("exit status 1"), exitCode: &policyExit,
					},
					status: "completed", message: "exit status 1: policy violation",
					raw: json.RawMessage(adapter.policyJSON), exitCode: &policyExit,
				},
				{
					name: "nonzero without evidence",
					command: stdoutCommandRunner{
						stdout: "not json", stderr: "authentication failed for fixture-secret",
						err: errors.New("exit status 2"),
					},
					status: "failed", message: "exit status 2: authentication failed for [redacted]",
				},
				{
					name:   "empty output",
					status: "failed", message: adapter.name + " scanner did not return JSON on stdout.",
				},
				{
					name: "invalid output", command: stdoutCommandRunner{stdout: "not json"},
					status: "failed", message: adapter.name + " scanner returned invalid JSON",
				},
			} {
				t.Run(tc.name, func(t *testing.T) {
					artifact, err := Run(opts, RunContext{Env: map[string]string{adapter.token: "fixture-secret"}, CommandRunner: &tc.command})
					if err != nil {
						t.Fatal(err)
					}
					result := artifact.Scanners[adapter.id]
					if result.Status != tc.status || result.Error != tc.message || !reflect.DeepEqual(result.Raw, tc.raw) {
						t.Fatalf("result = %#v", result)
					}
					if !reflect.DeepEqual(result.ExitCode, tc.exitCode) {
						t.Fatalf("exit code = %v, want %v", result.ExitCode, tc.exitCode)
					}
				})
			}
			t.Run("fixture skips token and command", func(t *testing.T) {
				fixture := filepath.Join(t.TempDir(), "report.json")
				const report = `{"ok":true}`
				if err := os.WriteFile(fixture, []byte(report), 0o600); err != nil {
					t.Fatal(err)
				}
				opts, err := ParseArgs([]string{target, "--scanner", adapter.id, "--scanner-result", adapter.id + "=" + fixture})
				if err != nil {
					t.Fatal(err)
				}
				if err := ValidateRequirements(opts, map[string]string{}); err != nil {
					t.Fatal(err)
				}
				command := &stdoutCommandRunner{}
				artifact, err := Run(opts, RunContext{Env: map[string]string{}, CommandRunner: command})
				if err != nil {
					t.Fatal(err)
				}
				result := artifact.Scanners[adapter.id]
				if len(command.calls) != 0 || result.Status != "completed" || string(result.Raw) != report {
					t.Fatalf("calls = %v, result = %#v", command.calls, result)
				}
			})
		})
	}
}

type stdoutCommandRunner struct {
	calls    []commandCall
	stdout   string
	stderr   string
	err      error
	exitCode *int
}

func (r *stdoutCommandRunner) Run(command string, args []string, cwd string, timeout time.Duration) (CommandOutput, error) {
	r.calls = append(r.calls, commandCall{command: command, args: append([]string(nil), args...), cwd: cwd})
	return CommandOutput{Stdout: r.stdout, Stderr: r.stderr, ExitCode: r.exitCode}, r.err
}

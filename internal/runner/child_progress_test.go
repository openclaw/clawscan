package runner

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"
)

const privateChildEvents = `{"type":"thread.started","thread_id":"private-thread"}
{"type":"turn.started"}
{"type":"item.started","item":{"id":"private-id","type":"command_execution","command":"private-command","status":"in_progress"}}
{"type":"item.completed","item":{"id":"private-id","type":"command_execution","command":"private-command","aggregated_output":"private-output","status":"failed","exit_code":77}}
{"type":"error","message":"private-provider-error"}
{"type":"turn.failed","error":{"message":"private-error"}}
`

func TestJudgeChildProgressArrivesBeforeCommandExit(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("controlled command uses a POSIX shell")
	}
	root := t.TempDir()
	input, release := filepath.Join(root, "input"), filepath.Join(root, "release")
	if err := os.WriteFile(input, []byte(privateChildEvents), 0o600); err != nil {
		t.Fatal(err)
	}
	defer os.WriteFile(release, nil, 0o600)
	observed := make(chan struct{}, 1)
	var diagnostics bytes.Buffer
	progress := newRunProgress(childSignalWriter{output: &diagnostics, observed: observed})
	progress.startPhase("judge")
	env := EnvMap(os.Environ())
	env["CLAWSCAN_CHILD_PROGRESS"] = "1"
	finished := make(chan struct{})
	var output CommandOutput
	var runErr error
	go func() {
		defer close(finished)
		output, runErr = (defaultCommandRunner{Env: env, Progress: progress}).Run("sh", []string{"-c", `cat "$1"; while [ ! -f "$2" ]; do sleep 0.02; done; printf private-stderr >&2; exit 7`, "sh", input, release}, root, 5*time.Second)
	}()
	seen := false
	select {
	case <-observed:
		seen = true
	case <-finished:
		t.Error("child exited before the release signal")
	case <-time.After(time.Second):
	}
	if err := os.WriteFile(release, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	<-finished
	if !seen {
		t.Error("child lifecycle remained buffered until command exit")
	}
	if runErr == nil || output.ExitCode == nil || *output.ExitCode != 7 || output.Stdout != privateChildEvents || output.Stderr != "private-stderr" {
		t.Fatalf("command semantics changed: %+v, %v", output, runErr)
	}
	events := readProgressEvents(t, diagnostics.String())
	if len(events) < 3 || events[1].Event != "command_start" || events[len(events)-1].Event != "command_end" {
		t.Fatalf("command boundaries not preserved: %s", diagnostics.String())
	}
	assertChildProgressSafe(t, diagnostics.String())
}

type childSignalWriter struct {
	output   *bytes.Buffer
	observed chan struct{}
}

func (writer childSignalWriter) Write(data []byte) (int, error) {
	if bytes.Contains(data, []byte(`"event":"child_event"`)) {
		select {
		case writer.observed <- struct{}{}:
		default:
		}
	}
	return writer.output.Write(data)
}

func assertChildProgressSafe(t *testing.T, diagnostics string) {
	t.Helper()
	for _, forbidden := range []string{"private-", "aggregated_output", "thread_id", "exit_code", "message", "command\""} {
		if strings.Contains(diagnostics, forbidden) {
			t.Fatalf("diagnostic disclosed child data: %q", forbidden)
		}
	}
}

func TestJudgeChildProgressOptInAndPhase(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("controlled command uses a POSIX shell")
	}
	for _, test := range []struct{ value, phase string }{{"", "judge"}, {"0", "judge"}, {"true", "judge"}, {"1", "scanner:aig"}, {"1", "judge"}} {
		t.Run(test.value+test.phase, func(t *testing.T) {
			var diagnostics bytes.Buffer
			progress := newRunProgress(&diagnostics)
			progress.startPhase(test.phase)
			env := EnvMap(os.Environ())
			env["CLAWSCAN_CHILD_PROGRESS"] = test.value
			output, err := (defaultCommandRunner{Env: env, Progress: progress}).Run("sh", []string{"-c", `printf '%s\n' '{"type":"turn.started"}'`}, "", time.Second)
			if err != nil || output.Stdout != "{\"type\":\"turn.started\"}\n" {
				t.Fatalf("command failed: %+v %v", output, err)
			}
			want := test.value == "1" && test.phase == "judge"
			if strings.Contains(diagnostics.String(), `"event":"child_event"`) != want {
				t.Fatalf("incorrect child opt-in: %s", diagnostics.String())
			}
		})
	}
}

func TestJudgeChildProgressConcurrentCommands(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("controlled command uses a POSIX shell")
	}
	var diagnostics bytes.Buffer
	progress := newRunProgress(&diagnostics)
	progress.startPhase("judge")
	env := EnvMap(os.Environ())
	env["CLAWSCAN_CHILD_PROGRESS"] = "1"
	var workers sync.WaitGroup
	for range 12 {
		workers.Go(func() {
			_, err := (defaultCommandRunner{Env: env, Progress: progress}).Run("sh", []string{"-c", `printf '%s\n' '{"type":"turn.started"}'`}, "", 5*time.Second)
			if err != nil {
				t.Error(err)
			}
		})
	}
	workers.Wait()
	seen := map[int]bool{}
	count := 0
	for _, line := range strings.Split(strings.TrimSpace(diagnostics.String()), "\n") {
		var event struct {
			Event string `json:"event"`
			PID   int    `json:"pid"`
		}
		if err := json.Unmarshal([]byte(strings.TrimPrefix(line, "[clawscan-progress] ")), &event); err != nil {
			t.Fatal(err)
		}
		if event.Event == "command_start" {
			seen[event.PID] = true
		}
		if event.Event == "child_event" {
			count++
			if !seen[event.PID] {
				t.Fatal("child event preceded its direct command start")
			}
		}
	}
	if count != 12 {
		t.Fatalf("child events = %d, want 12", count)
	}
}

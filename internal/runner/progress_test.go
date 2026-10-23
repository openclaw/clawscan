package runner

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

func readProgressEvents(t *testing.T, output string) []progressEvent {
	t.Helper()
	events := []progressEvent{}
	var previous int64
	for _, line := range strings.Split(strings.TrimSpace(output), "\n") {
		if !strings.HasPrefix(line, "[clawscan-progress] ") {
			t.Fatalf("unexpected progress line: %s", line)
		}
		var event progressEvent
		if err := json.Unmarshal([]byte(strings.TrimPrefix(line, "[clawscan-progress] ")), &event); err != nil {
			t.Fatal(err)
		}
		if event.SchemaVersion != "clawscan-progress-v1" || event.ElapsedMs < previous {
			t.Fatalf("invalid version or non-monotonic progress: %+v", event)
		}
		previous = event.ElapsedMs
		events = append(events, event)
	}
	return events
}

func TestProgressDoesNotChangeStaticArtifactOrInventExternalCommand(t *testing.T) {
	target := t.TempDir()
	writeSkill(t, target, "# Fixture\n")
	var progress bytes.Buffer
	artifact, err := Run(Options{Target: target, Scanners: []string{"clawscan-static"}, Sandbox: SandboxOptions{Mode: SandboxModeOff}}, RunContext{
		Env: map[string]string{"OPENAI_API_KEY": "fixture-private-value"}, Progress: &progress,
	})
	if err != nil {
		t.Fatal(err)
	}
	if artifact.Scanners["clawscan-static"].Status != "completed" || artifact.Judge != nil {
		t.Fatalf("unexpected artifact: %+v", artifact)
	}
	events := readProgressEvents(t, progress.String())
	if len(events) != 4 || events[2].Event != "phase_start" || events[2].Phase != "scanner:clawscan-static" || events[3].Event != "phase_end" {
		t.Fatalf("static progress = %+v", events)
	}
	for _, forbidden := range []string{target, "fixture-private-value", "OPENAI_API_KEY", "Fixture", "command_start"} {
		if strings.Contains(progress.String(), forbidden) {
			t.Fatalf("unexpected data in progress: %s", forbidden)
		}
	}
	encoded, err := json.Marshal(artifact)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(encoded), "clawscan-progress-v1") {
		t.Fatal("diagnostics leaked into the verdict artifact")
	}
}

func TestProgressRecordsFailedScannerWithoutErrorContent(t *testing.T) {
	target := t.TempDir()
	writeSkill(t, target, "# Fixture\n")
	var progress bytes.Buffer
	_, err := Run(Options{Target: target, Scanners: []string{"clawscan-static"}, Sandbox: SandboxOptions{Mode: SandboxModeOff}}, RunContext{
		Env: map[string]string{}, Progress: &progress, ScannerRunner: errorScannerRunner{},
	})
	if err == nil {
		t.Fatal("expected scanner error")
	}
	events := readProgressEvents(t, progress.String())
	last := events[len(events)-1]
	if last.Event != "phase_end" || last.Phase != "scanner:clawscan-static" || !last.Failed {
		t.Fatalf("missing failed scanner phase: %+v", last)
	}
	if strings.Contains(progress.String(), err.Error()) {
		t.Fatal("diagnostics included raw error content")
	}
}

func TestProgressCommandSuccessFailureAndTimeout(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("controlled external commands use a POSIX shell")
	}
	for _, test := range []struct {
		name    string
		command string
		timeout time.Duration
		failed  bool
		exit    *int
	}{
		{"success", "printf fixture-private-output", time.Second, false, intPointer(0)},
		{"failure", "printf fixture-private-output >&2; exit 7", time.Second, true, intPointer(7)},
		{"timeout", "exec sleep 5", 30 * time.Millisecond, true, nil},
	} {
		t.Run(test.name, func(t *testing.T) {
			var output bytes.Buffer
			progress := newRunProgress(&output)
			progress.startPhase("judge")
			_, err := (defaultCommandRunner{Env: EnvMap(os.Environ()), Progress: progress}).Run("sh", []string{"-c", test.command}, "", test.timeout)
			if (err != nil) != test.failed {
				t.Fatalf("command error = %v", err)
			}
			events := readProgressEvents(t, output.String())
			if len(events) != 3 || events[1].Event != "command_start" || events[1].PID <= 0 || events[2].Event != "command_end" || events[2].PID != events[1].PID || events[2].Failed != test.failed || events[2].DurationMs == nil {
				t.Fatalf("invalid command progress: %+v", events)
			}
			if test.exit == nil && events[2].ExitCode != nil || test.exit != nil && (events[2].ExitCode == nil || *events[2].ExitCode != *test.exit) {
				t.Fatalf("invalid command exit evidence: %+v", events[2])
			}
			if strings.Contains(output.String(), "fixture-private") || strings.Contains(output.String(), "sleep") {
				t.Fatal("command data disclosed")
			}
		})
	}
}

func TestProgressCommandStartFailure(t *testing.T) {
	var output bytes.Buffer
	progress := newRunProgress(&output)
	progress.startPhase("judge")
	_, err := (defaultCommandRunner{Progress: progress}).Run(filepath.Join(t.TempDir(), "missing-private-command"), nil, "", time.Second)
	if err == nil {
		t.Fatal("expected start failure")
	}
	events := readProgressEvents(t, output.String())
	if len(events) != 2 || events[1].Event != "command_end" || events[1].PID != 0 || !events[1].Failed || events[1].ExitCode != nil {
		t.Fatalf("start failure progress = %+v", events)
	}
	if strings.Contains(output.String(), "missing-private-command") {
		t.Fatal("start failure disclosed command")
	}
}

type unavailableProgressWriter struct{}

func (unavailableProgressWriter) Write([]byte) (int, error) {
	return 0, errors.New("progress sink unavailable")
}

func TestProgressSinkFailureDoesNotCreateOrChangeVerdict(t *testing.T) {
	target := t.TempDir()
	writeSkill(t, target, "# Fixture\n")
	artifact, err := Run(Options{Target: target, Scanners: []string{"clawscan-static"}, Sandbox: SandboxOptions{Mode: SandboxModeOff}}, RunContext{
		Env: map[string]string{}, Progress: unavailableProgressWriter{},
	})
	if err != nil || artifact.Scanners["clawscan-static"].Status != "completed" {
		t.Fatalf("diagnostic sink changed scan behavior: %v", err)
	}
	if phase := scannerProgressPhase("fixture-private-config-value"); phase != "scanner:custom" {
		t.Fatalf("custom scanner name leaked: %q", phase)
	}
}

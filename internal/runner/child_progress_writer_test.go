package runner

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

func TestChildProgressWriterChunkingAndSanitization(t *testing.T) {
	input := privateChildEvents + `{"type":"private-event"}` + "\n" +
		`{"type":"item.completed","item":{"type":"private-tool","status":"private-state"}}` + "\n" +
		`{"type":"item.updated","item":{"type":"reasoning","status":"private-state","text":"private-model-text"}}` + "\n" +
		`{"type":"turn.completed","usage":{"input_tokens":999999999999999999999}}`
	for _, chunkSize := range []int{1, 13, len(input)} {
		var diagnostics bytes.Buffer
		progress := newRunProgress(&diagnostics)
		progress.startPhase("judge")
		writer := newChildProgressWriter(progress, map[string]string{"CLAWSCAN_CHILD_PROGRESS": "1"})
		writer.start(123)
		for offset := 0; offset < len(input); offset += chunkSize {
			end := min(offset+chunkSize, len(input))
			if size, err := writer.Write([]byte(input[offset:end])); err != nil || size != end-offset {
				t.Fatalf("write changed command semantics: %d %v", size, err)
			}
		}
		writer.finish()
		events := readProgressEvents(t, diagnostics.String())
		if len(events) != 9 || events[3].ChildItem != "command_execution" || events[4].ChildState != "failed" || events[7].ChildState != "" || events[8].ChildEvent != "turn.completed" {
			t.Fatalf("wrong enum projection: %s", diagnostics.String())
		}
		for index, event := range events[1:] {
			if event.Sequence != index+1 || event.PID != 123 {
				t.Fatalf("unbounded sequence or wrong direct PID: %+v", event)
			}
		}
		assertChildProgressSafe(t, diagnostics.String())
		for _, line := range strings.Split(strings.TrimSpace(diagnostics.String()), "\n")[1:] {
			var fields map[string]json.RawMessage
			if err := json.Unmarshal([]byte(strings.TrimPrefix(line, "[clawscan-progress] ")), &fields); err != nil {
				t.Fatal(err)
			}
			for key := range fields {
				switch key {
				case "schemaVersion", "event", "phase", "elapsedMs", "pid", "childEvent", "childItem", "childState", "sequence":
				default:
					t.Fatalf("non-allowlisted child field %q", key)
				}
			}
		}
	}
}

func TestChildProgressWriterBoundsAndResynchronizes(t *testing.T) {
	var diagnostics bytes.Buffer
	progress := newRunProgress(&diagnostics)
	progress.startPhase("judge")
	writer := newChildProgressWriter(progress, map[string]string{"CLAWSCAN_CHILD_PROGRESS": "1"})
	writer.start(123)
	_, _ = writer.Write(bytes.Repeat([]byte("x"), childProgressLineLimit+1))
	if len(writer.line) != 0 || !writer.oversize {
		t.Fatal("oversized record retained")
	}
	_, _ = writer.Write([]byte(`{"type":"error","message":"private-tail"}` + "\n"))
	_, _ = writer.Write([]byte("invalid\n{\"type\":\"turn.started\"}\n"))
	for range childProgressEventLimit + 20 {
		_, _ = writer.Write([]byte("{\"type\":\"turn.started\"}\n"))
	}
	writer.finish()
	events := readProgressEvents(t, diagnostics.String())
	if len(events) != childProgressEventLimit+2 || events[1].Event != "child_event_dropped" || events[2].ChildEvent != "turn.started" || events[len(events)-1].Event != "child_event_limit" {
		t.Fatalf("diagnostics not bounded/resynchronized: %d events", len(events))
	}
	assertChildProgressSafe(t, diagnostics.String())
}

func TestJudgeChildProgressFailurePaths(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("controlled command uses a POSIX shell")
	}
	env := EnvMap(os.Environ())
	env["CLAWSCAN_CHILD_PROGRESS"] = "1"
	var diagnostics bytes.Buffer
	progress := newRunProgress(&diagnostics)
	progress.startPhase("judge")
	output, err := (defaultCommandRunner{Env: env, Progress: progress}).Run("sh", []string{"-c", `printf '%s\n' '{"type":"turn.started"}'; exec sleep 60`}, "", time.Second)
	if err == nil || output.ExitCode != nil || !strings.Contains(diagnostics.String(), `"childEvent":"turn.started"`) {
		t.Fatalf("timeout lost live evidence or changed exit semantics: %+v %v", output, err)
	}
	last := readProgressEvents(t, diagnostics.String())
	if !last[len(last)-1].Failed {
		t.Fatal("timeout became success")
	}
	_, err = (defaultCommandRunner{Env: env, Progress: progress}).Run(filepath.Join(t.TempDir(), "missing"), nil, "", time.Second)
	if err == nil {
		t.Fatal("start failure became success")
	}
	for _, sink := range []*runProgress{nil, newRunProgress(unavailableProgressWriter{})} {
		sink.startPhase("judge")
		output, err := (defaultCommandRunner{Env: env, Progress: sink}).Run("sh", []string{"-c", `printf '%s\n' '{"type":"turn.started"}'`}, "", time.Second)
		if err != nil || output.Stdout != "{\"type\":\"turn.started\"}\n" || output.ExitCode == nil || *output.ExitCode != 0 {
			t.Fatalf("diagnostic sink affected command: %+v %v", output, err)
		}
	}
}

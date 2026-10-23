package runner

import (
	"encoding/json"
	"io"
	"os"
	"time"
)

type progressEvent struct {
	SchemaVersion string `json:"schemaVersion"`
	Event         string `json:"event"`
	Phase         string `json:"phase"`
	ElapsedMs     int64  `json:"elapsedMs"`
	PID           int    `json:"pid,omitempty"`
	DurationMs    *int64 `json:"durationMs,omitempty"`
	ExitCode      *int   `json:"exitCode,omitempty"`
	Failed        bool   `json:"failed,omitempty"`
}

type runProgress struct {
	writer       io.Writer
	started      time.Time
	phase        string
	phaseStarted time.Time
}

func newRunProgress(writer io.Writer) *runProgress {
	if writer == nil {
		return nil
	}
	return &runProgress{writer: writer, started: time.Now()}
}

func (progress *runProgress) emit(event progressEvent) {
	if progress == nil {
		return
	}
	event.SchemaVersion = "clawscan-progress-v1"
	event.Phase = progress.phase
	event.ElapsedMs = time.Since(progress.started).Milliseconds()
	encoded, err := json.Marshal(event)
	if err == nil {
		_, _ = progress.writer.Write(append(append([]byte("[clawscan-progress] "), encoded...), '\n'))
	}
}

func (progress *runProgress) startPhase(phase string) {
	if progress == nil {
		return
	}
	progress.phase = phase
	progress.phaseStarted = time.Now()
	progress.emit(progressEvent{Event: "phase_start", PID: os.Getpid()})
}

func (progress *runProgress) endPhase(failed bool) {
	if progress == nil {
		return
	}
	duration := time.Since(progress.phaseStarted).Milliseconds()
	progress.emit(progressEvent{Event: "phase_end", PID: os.Getpid(), DurationMs: &duration, Failed: failed})
}

func scannerProgressPhase(scanner string) string {
	switch scanner {
	case "agentverus", "aig", "cisco", "clawscan-static", "relyable", "skillspector", "snyk", "socket", "virustotal":
		return "scanner:" + scanner
	default:
		return "scanner:custom"
	}
}

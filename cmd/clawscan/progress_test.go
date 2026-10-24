package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"time"
)

func TestProgressRequiresExplicitOptIn(t *testing.T) {
	for _, value := range []string{"", "0", "true", "1"} {
		ctx := scanRunContext([]string{"CLAWSCAN_PROGRESS=" + value})
		if (ctx.Progress != nil) != (value == "1") {
			t.Fatalf("unexpected progress opt-in for %q", value)
		}
	}
}

func TestProgressSurvivesOuterKill(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("controlled external command uses a POSIX shell")
	}
	root := t.TempDir()
	target := filepath.Join(root, "target")
	if err := os.Mkdir(target, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(target, "SKILL.md"), []byte("# Controlled fixture\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	pidPath := filepath.Join(root, "child.pid")
	command := "#!/bin/sh\nprintf '%s' $$ > \"$CLAWSCAN_TEST_PID_FILE\"\nprintf 'fixture-private-stdout'\nprintf 'fixture-private-stderr' >&2\nexec sleep 60\n"
	if err := os.WriteFile(filepath.Join(root, "aig-skill-scan"), []byte(command), 0o700); err != nil {
		t.Fatal(err)
	}
	artifactPath := filepath.Join(root, "artifact.json")
	child := exec.Command(os.Args[0], "-test.run=^TestProgressCLIHelper$")
	child.Env = append(os.Environ(),
		"CLAWSCAN_TEST_HELPER=1", "CLAWSCAN_TEST_TARGET="+target,
		"CLAWSCAN_TEST_OUTPUT="+artifactPath, "CLAWSCAN_TEST_PID_FILE="+pidPath,
		"PATH="+root+string(os.PathListSeparator)+os.Getenv("PATH"),
		"LLM_API_KEY=fixture-private-key",
		"CLAWSCAN_PROGRESS=1",
	)
	var stdout, stderr bytes.Buffer
	child.Stdout, child.Stderr = &stdout, &stderr
	if err := child.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = child.Process.Kill() })
	var commandPID int
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		data, err := os.ReadFile(pidPath)
		if err == nil {
			commandPID, _ = strconv.Atoi(string(data))
			if commandPID > 0 {
				break
			}
		}
		time.Sleep(10 * time.Millisecond)
	}
	if commandPID > 0 {
		t.Cleanup(func() {
			process, err := os.FindProcess(commandPID)
			if err == nil {
				_ = process.Kill()
			}
		})
	}
	if err := child.Process.Kill(); err != nil {
		t.Fatal(err)
	}
	if err := child.Wait(); err == nil {
		t.Fatal("outer kill unexpectedly succeeded")
	}
	if commandPID == 0 {
		t.Fatalf("external command never started: %s", stderr.String())
	}
	assertInterruptedCheckpoint(t, artifactPath)
	foundStage, foundCommand := false, false
	for _, line := range strings.Split(stderr.String(), "\n") {
		if !strings.HasPrefix(line, "[clawscan-progress] ") {
			continue
		}
		var event struct {
			Event string `json:"event"`
			Phase string `json:"phase"`
			PID   int    `json:"pid"`
		}
		if err := json.Unmarshal([]byte(strings.TrimPrefix(line, "[clawscan-progress] ")), &event); err != nil {
			t.Fatal(err)
		}
		if event.Phase == "scanner:aig" {
			foundStage = foundStage || event.Event == "phase_start"
			foundCommand = foundCommand || event.Event == "command_start" && event.PID == commandPID
			if event.Event == "phase_end" || event.Event == "command_end" {
				t.Fatalf("unfinished phase claimed completion: %s", line)
			}
		}
	}
	if !foundStage || !foundCommand {
		t.Fatalf("outer kill lost active scanner/PID evidence: %s", stderr.String())
	}
	for _, forbidden := range []string{"fixture-private", target, root, "sleep", "LLM_API_KEY"} {
		if strings.Contains(stderr.String(), forbidden) {
			t.Fatalf("progress disclosed command/input data: %q", forbidden)
		}
	}
}

func TestProgressCLIHelper(t *testing.T) {
	if os.Getenv("CLAWSCAN_TEST_HELPER") != "1" {
		return
	}
	err := run([]string{os.Getenv("CLAWSCAN_TEST_TARGET"), "--scanner", "aig", "--sandbox", "off", "--output", os.Getenv("CLAWSCAN_TEST_OUTPUT")}, os.Environ())
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	os.Exit(0)
}

func TestJudgeChildProgressSurvivesOuterKill(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("controlled judge uses a POSIX shell")
	}
	root := t.TempDir()
	target := filepath.Join(root, "target")
	if err := os.Mkdir(target, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(target, "SKILL.md"), []byte("# Controlled fixture\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	pidPath, artifactPath := filepath.Join(root, "child.pid"), filepath.Join(root, "artifact.json")
	diagnosticPath := filepath.Join(root, "stderr")
	diagnostics, err := os.Create(diagnosticPath)
	if err != nil {
		t.Fatal(err)
	}
	defer diagnostics.Close()
	judgePath := filepath.Join(root, "judge.sh")
	script := "#!/bin/sh\nprintf '%s' $$ > \"$CLAWSCAN_TEST_PID_FILE\"\nprintf '%s\\n' '{\"type\":\"turn.started\"}' '{\"type\":\"item.started\",\"item\":{\"type\":\"command_execution\",\"command\":\"private-command\",\"status\":\"in_progress\"}}'\nprintf private-stderr >&2\nexec sleep 60\n"
	if err := os.WriteFile(judgePath, []byte(script), 0o700); err != nil {
		t.Fatal(err)
	}
	child := exec.Command(os.Args[0], "-test.run=^TestJudgeChildProgressCLIHelper$")
	child.Env = append(os.Environ(), "CLAWSCAN_TEST_JUDGE_HELPER=1", "CLAWSCAN_TEST_TARGET="+target,
		"CLAWSCAN_TEST_OUTPUT="+artifactPath, "CLAWSCAN_TEST_PID_FILE="+pidPath,
		"CLAWSCAN_TEST_JUDGE="+strconv.Quote(judgePath), "CLAWSCAN_PROGRESS=1", "CLAWSCAN_CHILD_PROGRESS=1")
	var stdout bytes.Buffer
	child.Stdout, child.Stderr = &stdout, diagnostics
	if err := child.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = child.Process.Kill() })
	var commandPID int
	found := false
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		data, _ := os.ReadFile(pidPath)
		commandPID, _ = strconv.Atoi(string(data))
		data, _ = os.ReadFile(diagnosticPath)
		if commandPID > 0 && bytes.Contains(data, []byte(`"childItem":"command_execution"`)) {
			found = true
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if commandPID > 0 {
		t.Cleanup(func() {
			if process, err := os.FindProcess(commandPID); err == nil {
				_ = process.Kill()
			}
		})
	}
	if err := child.Process.Kill(); err != nil {
		t.Fatal(err)
	}
	if err := child.Wait(); err == nil {
		t.Fatal("outer kill unexpectedly succeeded")
	}
	data, err := os.ReadFile(diagnosticPath)
	if err != nil {
		t.Fatal(err)
	}
	if !found {
		t.Fatalf("inner judge event did not arrive before outer kill: %s", data)
	}
	for _, forbidden := range []string{"private-", root, "sleep", `"event":"command_end"`, `"event":"phase_end","phase":"judge"`} {
		if bytes.Contains(data, []byte(forbidden)) {
			t.Fatalf("unfinished judge leaked data or claimed completion: %q", forbidden)
		}
	}
	assertInterruptedCheckpoint(t, artifactPath)
	if stdout.Len() != 0 {
		t.Fatal("interrupted judge emitted terminal stdout")
	}
}

func assertInterruptedCheckpoint(t *testing.T, artifactPath string) {
	t.Helper()
	raw, err := os.ReadFile(artifactPath)
	if err != nil {
		t.Fatal(err)
	}
	var artifact struct {
		Status      string `json:"status"`
		Complete    bool   `json:"complete"`
		CompletedAt string `json:"completedAt"`
	}
	if err := json.Unmarshal(raw, &artifact); err != nil {
		t.Fatal(err)
	}
	if artifact.Status != "running" || artifact.Complete || artifact.CompletedAt != "" {
		t.Fatalf("forced kill must not manufacture a terminal outcome: %s", raw)
	}
}

func TestJudgeChildProgressCLIHelper(t *testing.T) {
	if os.Getenv("CLAWSCAN_TEST_JUDGE_HELPER") != "1" {
		return
	}
	err := run([]string{os.Getenv("CLAWSCAN_TEST_TARGET"), "--scanner", "clawscan-static", "--sandbox", "off",
		"--judge", os.Getenv("CLAWSCAN_TEST_JUDGE"), "--output", os.Getenv("CLAWSCAN_TEST_OUTPUT")}, os.Environ())
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	os.Exit(0)
}

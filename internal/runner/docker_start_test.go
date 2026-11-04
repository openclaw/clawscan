package runner

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"
)

type dockerRetryFixture struct {
	attempts int
}

func (fixture *dockerRetryFixture) Run(command string, args []string, cwd string, timeout time.Duration) (CommandOutput, error) {
	if command != "docker" {
		return CommandOutput{}, errors.New("expected inert Docker client")
	}
	fixture.attempts++
	if fixture.attempts == 1 {
		return CommandOutput{Stdout: "generated invalid first output", Started: boolPointer(true)}, nil
	}
	return CommandOutput{Stdout: `{"verdict":"suspicious"}`, Started: boolPointer(true)}, nil
}

func TestDockerUnknownShellStartPreservesOutputRetryRecovery(t *testing.T) {
	target := filepath.Join(t.TempDir(), "SKILL.md")
	if err := os.WriteFile(target, []byte("# Inert retry\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	host := &dockerRetryFixture{}
	artifact, err := Run(Options{Target: target, Profile: "clawhub", Scanners: []string{fixtureScannerID}, ScannerRegistry: fixtureScannerRegistry(t), Judge: &JudgeOptions{Command: "inert-harness"}}, RunContext{
		Env: map[string]string{}, HostCommandRunner: host, DockerAvailability: func() error { return nil },
	})
	if err != nil || !artifact.Complete || artifact.Judge == nil || artifact.Judge.Status != "completed" || host.attempts != 2 {
		t.Fatalf("valid output retry recovery changed: err=%v complete=%v judge=%+v attempts=%d", err, artifact.Complete, artifact.Judge, host.attempts)
	}
	if artifact.Judge.CommandStarted != nil || len(artifact.Judge.Attempts) != 2 || artifact.Judge.Attempts[0].Status != "failed" || artifact.Judge.Attempts[1].Status != "completed" {
		t.Fatal("retry or shell-start history changed")
	}
	for _, attempt := range artifact.Judge.Attempts {
		if attempt.CommandStarted != nil {
			t.Fatal("Docker-client start was promoted to judge shell start")
		}
	}
}

type dockerStartFixture struct {
	started bool
}

func (fixture dockerStartFixture) Run(command string, args []string, cwd string, timeout time.Duration) (CommandOutput, error) {
	if command != "docker" {
		return CommandOutput{}, errors.New("fixture received a non-Docker command")
	}
	return CommandOutput{Started: boolPointer(fixture.started), Stderr: "inert Docker client failed before container creation"}, errors.New("inert Docker client failure")
}

func TestDockerClientStartDoesNotProveJudgeShellStart(t *testing.T) {
	for _, clientStarted := range []bool{false, true} {
		t.Run(map[bool]string{false: "client-not-started", true: "client-started"}[clientStarted], func(t *testing.T) {
			target := filepath.Join(t.TempDir(), "SKILL.md")
			if err := os.WriteFile(target, []byte("# Inert\n"), 0o600); err != nil {
				t.Fatal(err)
			}
			artifact, _ := Run(Options{Target: target, Scanners: []string{fixtureScannerID}, ScannerRegistry: fixtureScannerRegistry(t), Judge: &JudgeOptions{Command: "inert-harness"}}, RunContext{
				Env: map[string]string{}, HostCommandRunner: dockerStartFixture{started: clientStarted}, DockerAvailability: func() error { return nil },
			})
			if artifact.Judge == nil || artifact.Judge.Status != "failed" || artifact.Complete {
				t.Fatal("fixture did not fail the required judge")
			}
			started := artifact.Judge.CommandStarted
			if clientStarted && started != nil {
				t.Fatalf("Docker-client start claimed shell start=%v", *started)
			}
			if !clientStarted && (started == nil || *started) {
				t.Fatal("lost proven not-started state")
			}
		})
	}
}

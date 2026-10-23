package runner

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"
)

type dockerReceiptFixture struct {
	attempts int
}

func (fixture *dockerReceiptFixture) Run(command string, args []string, cwd string, timeout time.Duration) (CommandOutput, error) {
	if command != "docker" {
		return CommandOutput{}, errors.New("expected inert Docker client")
	}
	for index, arg := range args[:len(args)-1] {
		if arg == "-w" {
			cwd = args[index+1]
		}
	}
	raw, err := os.ReadFile(filepath.Join(cwd, "artifact-inspection.json"))
	if err != nil {
		return CommandOutput{}, err
	}
	var challenge artifactInspectionChallenge
	if err := json.Unmarshal(raw, &challenge); err != nil {
		return CommandOutput{}, err
	}
	content, err := os.ReadFile(filepath.Join(cwd, filepath.FromSlash(challenge.RequiredFile)))
	if err != nil {
		return CommandOutput{}, err
	}
	fixture.attempts++
	fileHash := sha256BytesHex(content)
	if fixture.attempts == 1 {
		fileHash = "invalid-generated-first-receipt"
	}
	receipt := fmt.Sprintf(`{"verdict":"suspicious","artifact_inspection":{"version":2,"status":"completed","challenge":%q,"required_file_sha256":%q,"required_file":%q,"additional_files_inspected":[]}}`, challenge.Challenge, fileHash, challenge.RequiredFile)
	return CommandOutput{Stdout: receipt, Started: boolPointer(true)}, nil
}

func TestDockerUnknownShellStartPreservesValidReceiptRecovery(t *testing.T) {
	target := filepath.Join(t.TempDir(), "SKILL.md")
	if err := os.WriteFile(target, []byte("# Inert full receipt\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	host := &dockerReceiptFixture{}
	artifact, err := Run(Options{Target: target, Profile: "clawhub", Scanners: []string{"clawscan-static"}, Judge: &JudgeOptions{Command: "inert-harness"}}, RunContext{
		Env: map[string]string{}, HostCommandRunner: host, DockerAvailability: func() error { return nil },
	})
	if err != nil || !artifact.Complete || artifact.Judge == nil || artifact.Judge.Status != "completed" || host.attempts != 2 {
		t.Fatalf("valid full receipt recovery changed: err=%v complete=%v judge=%+v attempts=%d", err, artifact.Complete, artifact.Judge, host.attempts)
	}
	if artifact.Judge.CommandStarted != nil || len(artifact.Judge.Attempts) != 2 || artifact.Judge.Attempts[0].Status != "failed" || artifact.Judge.Attempts[1].Status != "completed" {
		t.Fatal("receipt or shell-start history changed")
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
			artifact, _ := Run(Options{Target: target, Scanners: []string{"clawscan-static"}, Judge: &JudgeOptions{Command: "inert-harness"}}, RunContext{
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

package runner

import (
	"errors"
	"strings"
	"testing"
	"time"
)

type recordingInstallRunner struct {
	paths   map[string]bool
	errs    map[string]error
	lookups []string
	calls   []installCall
}

type installCall struct {
	command string
	args    []string
}

func (runner *recordingInstallRunner) LookPath(file string) (string, error) {
	runner.lookups = append(runner.lookups, file)
	if runner.paths[file] {
		return "/bin/" + file, nil
	}
	return "", errors.New("not found")
}

func (runner *recordingInstallRunner) Run(command string, args []string, cwd string, timeout time.Duration) (CommandOutput, error) {
	runner.calls = append(runner.calls, installCall{command: command, args: append([]string(nil), args...)})
	if err := runner.errs[command]; err != nil {
		return CommandOutput{Stderr: "install failed"}, err
	}
	joinedArgs := strings.Join(args, " ")
	if command == "uv" && joinedArgs == "pip install cisco-ai-skill-scanner" {
		runner.paths["skill-scanner"] = true
	}
	if command == "uv" && joinedArgs == "tool install git+https://github.com/NVIDIA/skillspector.git" {
		runner.paths["skillspector"] = true
	}
	if command == "npm" && joinedArgs == "install -g socket" {
		runner.paths["socket"] = true
	}
	if command == "npm" && joinedArgs == "install --save-dev agentverus-scanner" {
		runner.paths["npx"] = true
	}
	return CommandOutput{}, nil
}

func TestInstallScannersSkipsNoInstallNeededScanner(t *testing.T) {
	results, err := InstallScanners([]string{"clawscan-static"}, InstallOptions{
		Runner: &recordingInstallRunner{},
	})
	if err != nil {
		t.Fatalf("InstallScanners returned error: %v", err)
	}
	if len(results) != 1 {
		t.Fatalf("results = %#v", results)
	}
	if results[0].Status != InstallStatusSkipped {
		t.Fatalf("status = %q", results[0].Status)
	}
	if !strings.Contains(results[0].Message, "built in") {
		t.Fatalf("message = %q", results[0].Message)
	}
}

func TestInstallScannersReturnsAlreadyAvailableWhenExecutableIsOnPath(t *testing.T) {
	fake := &recordingInstallRunner{paths: map[string]bool{"skill-scanner": true}}
	results, err := InstallScanners([]string{"cisco"}, InstallOptions{Runner: fake})
	if err != nil {
		t.Fatalf("InstallScanners returned error: %v", err)
	}
	if got := results[0].Status; got != InstallStatusAlreadyAvailable {
		t.Fatalf("status = %q", got)
	}
	if len(fake.calls) != 0 {
		t.Fatalf("commands = %#v", fake.calls)
	}
}

func TestInstallScannersRunsInstallPlansInRequestedOrder(t *testing.T) {
	fake := &recordingInstallRunner{paths: map[string]bool{
		"uv": true,
	}}
	results, err := InstallScanners([]string{"cisco", "skillspector"}, InstallOptions{Runner: fake})
	if err != nil {
		t.Fatalf("InstallScanners returned error: %v", err)
	}
	if len(results) != 2 {
		t.Fatalf("results = %#v", results)
	}
	if results[0].ScannerID != "cisco" || results[1].ScannerID != "skillspector" {
		t.Fatalf("results out of order: %#v", results)
	}
	if got := len(fake.calls); got != 4 {
		t.Fatalf("commands = %#v, want 4", fake.calls)
	}
	if fake.calls[0].command != "uv" || strings.Join(fake.calls[0].args, " ") != "pip install cisco-ai-skill-scanner" {
		t.Fatalf("first command = %#v", fake.calls[0])
	}
	if fake.calls[2].command != "uv" || strings.Join(fake.calls[2].args, " ") != "tool install git+https://github.com/NVIDIA/skillspector.git" {
		t.Fatalf("third command = %#v", fake.calls[2])
	}
}

func TestInstallScannersUsesNodeScannerUpstreamInstallCommands(t *testing.T) {
	fake := &recordingInstallRunner{paths: map[string]bool{
		"npm": true,
		"npx": true,
	}}
	results, err := InstallScanners([]string{"agentverus", "socket"}, InstallOptions{Runner: fake})
	if err != nil {
		t.Fatalf("InstallScanners returned error: %v", err)
	}
	if len(results) != 2 {
		t.Fatalf("results = %#v", results)
	}
	if results[0].ScannerID != "agentverus" || results[1].ScannerID != "socket" {
		t.Fatalf("results out of order: %#v", results)
	}
	if got := len(fake.calls); got != 4 {
		t.Fatalf("commands = %#v, want 4", fake.calls)
	}
	if fake.calls[0].command != "npm" || strings.Join(fake.calls[0].args, " ") != "install --save-dev agentverus-scanner" {
		t.Fatalf("first command = %#v", fake.calls[0])
	}
	if fake.calls[1].command != "npx" || strings.Join(fake.calls[1].args, " ") != "agentverus --help" {
		t.Fatalf("second command = %#v", fake.calls[1])
	}
	if fake.calls[2].command != "npm" || strings.Join(fake.calls[2].args, " ") != "install -g socket" {
		t.Fatalf("third command = %#v", fake.calls[2])
	}
	if fake.calls[3].command != "socket" || strings.Join(fake.calls[3].args, " ") != "--help" {
		t.Fatalf("fourth command = %#v", fake.calls[3])
	}
}

func TestInstallScannersReportsFailureAndContinues(t *testing.T) {
	fake := &recordingInstallRunner{
		paths: map[string]bool{
			"uv": true,
		},
		errs: map[string]error{"uv": errors.New("exit status 1")},
	}
	results, err := InstallScanners([]string{"skillspector", "clawscan-static"}, InstallOptions{Runner: fake})
	if err == nil {
		t.Fatal("expected error")
	}
	if len(results) != 2 {
		t.Fatalf("results = %#v", results)
	}
	if results[0].Status != InstallStatusFailed {
		t.Fatalf("first status = %q", results[0].Status)
	}
	if results[1].Status != InstallStatusSkipped {
		t.Fatalf("second status = %q", results[1].Status)
	}
}

func TestInstallScannersRejectsUnknownScanner(t *testing.T) {
	_, err := InstallScanners([]string{"bogus"}, InstallOptions{})
	if err == nil || !strings.Contains(err.Error(), "Unknown scanner: bogus") {
		t.Fatalf("err = %v", err)
	}
}

func TestInstallScannersRejectsServiceBackedScanner(t *testing.T) {
	_, err := InstallScanners([]string{"ai-infra-guard"}, InstallOptions{})
	if err == nil {
		t.Fatal("expected error")
	}
	if !strings.Contains(err.Error(), "ai-infra-guard has no local scanner CLI to install") {
		t.Fatalf("err = %v", err)
	}
	_, installIDs, ok := strings.Cut(err.Error(), "Accepted install scanner IDs:")
	if !ok {
		t.Fatalf("err missing accepted install scanner IDs: %v", err)
	}
	if strings.Contains(installIDs, "ai-infra-guard") {
		t.Fatalf("installable scanner list should not include ai-infra-guard: %v", err)
	}
}

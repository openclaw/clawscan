package runner

import (
	"fmt"
	"os/exec"
	"strings"
	"time"
)

const defaultInstallTimeout = 20 * time.Minute

type InstallStatus string

const (
	InstallStatusAlreadyAvailable InstallStatus = "already available"
	InstallStatusInstalled        InstallStatus = "installed"
	InstallStatusSkipped          InstallStatus = "skipped"
	InstallStatusFailed           InstallStatus = "failed"
)

type InstallCommand struct {
	Command string
	Args    []string
}

type InstallPlan struct {
	ScannerID                string
	Name                     string
	CheckExecutables         []string
	Commands                 []InstallCommand
	VerifyCommand            InstallCommand
	NoInstallReason          string
	InstallUnsupportedReason string
}

type InstallResult struct {
	ScannerID string
	Name      string
	Status    InstallStatus
	Message   string
	Commands  []InstallCommand
	Error     string
}

type InstallOptions struct {
	Registry ScannerRegistry
	Runner   InstallCommandRunner
	Env      map[string]string
	Timeout  time.Duration
}

type InstallCommandRunner interface {
	LookPath(file string) (string, error)
	Run(command string, args []string, cwd string, timeout time.Duration) (CommandOutput, error)
}

func InstallScanners(scannerIDs []string, opts InstallOptions) ([]InstallResult, error) {
	if len(scannerIDs) == 0 {
		return nil, fmt.Errorf("Usage: clawscan install <scanner-id> [scanner-id ...]")
	}
	registry := opts.Registry
	if registry.isZero() {
		registry = DefaultScannerRegistry()
	}
	plans := make([]InstallPlan, 0, len(scannerIDs))
	for _, scannerID := range scannerIDs {
		id := strings.TrimSpace(scannerID)
		adapter, ok := registry.Adapter(id)
		if id == "" || !ok {
			return nil, fmt.Errorf("Unknown scanner: %s. Accepted install scanner IDs: %s", scannerID, strings.Join(registry.InstallScannerIDs(), ", "))
		}
		plan := adapter.InstallPlan()
		if plan.ScannerID == "" {
			plan.ScannerID = id
		}
		if strings.TrimSpace(plan.InstallUnsupportedReason) != "" {
			return nil, fmt.Errorf("Scanner %s has no local scanner CLI to install. %s Accepted install scanner IDs: %s", id, plan.InstallUnsupportedReason, strings.Join(registry.InstallScannerIDs(), ", "))
		}
		plans = append(plans, plan)
	}

	commandRunner := opts.Runner
	if commandRunner == nil {
		commandRunner = defaultInstallRunner{Env: opts.Env}
	}
	timeout := opts.Timeout
	if timeout == 0 {
		timeout = defaultInstallTimeout
	}
	results := make([]InstallResult, 0, len(plans))
	failed := []string{}
	for _, plan := range plans {
		result := runInstallPlan(plan, commandRunner, timeout, opts.Env)
		results = append(results, result)
		if result.Status == InstallStatusFailed {
			failed = append(failed, result.ScannerID)
		}
	}
	if len(failed) > 0 {
		return results, fmt.Errorf("Scanner install failed: %s", strings.Join(failed, ", "))
	}
	return results, nil
}

func runInstallPlan(plan InstallPlan, runner InstallCommandRunner, timeout time.Duration, env map[string]string) InstallResult {
	result := InstallResult{
		ScannerID: plan.ScannerID,
		Name:      plan.Name,
	}
	if plan.NoInstallReason != "" {
		result.Status = InstallStatusSkipped
		result.Message = plan.NoInstallReason
		return result
	}
	if len(plan.CheckExecutables) > 0 {
		missing := missingExecutables(runner, plan.CheckExecutables)
		if len(missing) == 0 {
			result.Status = InstallStatusAlreadyAvailable
			result.Message = "found " + strings.Join(plan.CheckExecutables, ", ") + " on PATH"
			return result
		}
		if len(plan.Commands) == 0 {
			result.Status = InstallStatusFailed
			result.Error = "required executable not found on PATH: " + strings.Join(missing, ", ")
			return result
		}
	}
	for _, command := range plan.Commands {
		result.Commands = append(result.Commands, command)
		if _, err := runner.LookPath(command.Command); err != nil {
			result.Status = InstallStatusFailed
			result.Error = "installer command not found on PATH: " + command.Command
			return result
		}
		output, err := runner.Run(command.Command, command.Args, "", timeout)
		if err != nil {
			result.Status = InstallStatusFailed
			result.Error = commandError(err, output.Stderr, env)
			return result
		}
	}
	if plan.VerifyCommand.Command != "" {
		if _, err := runner.LookPath(plan.VerifyCommand.Command); err != nil {
			result.Status = InstallStatusFailed
			result.Error = "verification command not found on PATH: " + plan.VerifyCommand.Command
			return result
		}
		result.Commands = append(result.Commands, plan.VerifyCommand)
		output, err := runner.Run(plan.VerifyCommand.Command, plan.VerifyCommand.Args, "", timeout)
		if err != nil {
			result.Status = InstallStatusFailed
			result.Error = commandError(err, output.Stderr, env)
			return result
		}
	}
	result.Status = InstallStatusInstalled
	if plan.VerifyCommand.Command != "" {
		result.Message = "verified " + formatInstallCommand(plan.VerifyCommand)
	}
	return result
}

func missingExecutables(runner InstallCommandRunner, executables []string) []string {
	missing := []string{}
	for _, executable := range executables {
		if _, err := runner.LookPath(executable); err != nil {
			missing = append(missing, executable)
		}
	}
	return missing
}

func formatInstallCommand(command InstallCommand) string {
	parts := append([]string{command.Command}, command.Args...)
	return strings.Join(parts, " ")
}

type defaultInstallRunner struct {
	Env map[string]string
}

func (runner defaultInstallRunner) LookPath(file string) (string, error) {
	return exec.LookPath(file)
}

func (runner defaultInstallRunner) Run(command string, args []string, cwd string, timeout time.Duration) (CommandOutput, error) {
	return defaultCommandRunner{Env: runner.Env}.Run(command, args, cwd, timeout)
}

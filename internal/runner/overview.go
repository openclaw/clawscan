package runner

import (
	"context"
	"errors"
	"fmt"
	"time"
)

// OverviewResult records the optional overview step: a readable summary of the
// judge verdict. Consumers read prose from overview.result and the verdict from
// judge.result. A failed, skipped, or timed-out overview never changes the
// verdict, gate, status, or completeness of the run.
type OverviewResult struct {
	CommandStarted   *bool       `json:"commandStarted,omitempty"`
	Status           string      `json:"status"`
	Command          string      `json:"command,omitempty"`
	ConfiguredModel  string      `json:"configuredModel,omitempty"`
	PromptPath       string      `json:"promptPath,omitempty"`
	OutputSchemaPath string      `json:"outputSchemaPath,omitempty"`
	PromptSHA        string      `json:"promptSha256,omitempty"`
	OutputSchemaSHA  string      `json:"outputSchemaSha256,omitempty"`
	Error            string      `json:"error"`
	Result           interface{} `json:"result"`
	DurationMs       int64       `json:"durationMs"`
}

// overviewTimeout bounds the overview command. It is separate from the judge
// budget so a slow overview cannot consume verdict time, and its expiry is a
// recorded overview failure rather than a run failure.
var overviewTimeout = 5 * time.Minute

func runOverviewStep(ctx RunContext, opts Options, artifact *Artifact, commands *boundCommandRunner, checkpointOpts Options, env map[string]string, sandboxMode string) error {
	if err := ctx.Context.Err(); err != nil {
		return err
	}
	if artifact.Judge == nil || artifact.Judge.Status != "completed" {
		artifact.Overview = &OverviewResult{
			Status:         "skipped",
			CommandStarted: boolPointer(false),
			Error:          "Overview requires a completed judge verdict.",
		}
		return nil
	}
	progress := ctx.progress
	progress.startPhase("overview")
	artifact.Overview = &OverviewResult{Status: "running"}
	if err := checkpointArtifact(checkpointOpts, artifact, ctx.Context); err != nil {
		artifact.Overview = &OverviewResult{Status: "not_started", CommandStarted: boolPointer(false)}
		progress.endPhase(true)
		return err
	}
	result := RunOverviewContext(ctx.Context, *opts.Overview, *artifact, commands, overviewTimeout, env, sandboxMode)
	progress.endPhase(result.Status != "completed")
	artifact.Overview = result
	// Caller cancellation still cancels the run; only the overview's own
	// failures and timeout are contained.
	return ctx.Context.Err()
}

// RunOverviewContext runs the overview command once in a fresh workspace with
// the judge verdict in judge.json. It never returns an error for overview
// failures; they are recorded on the result.
func RunOverviewContext(ctx context.Context, opts OverviewOptions, artifact Artifact, commandRunner CommandRunner, timeout time.Duration, env map[string]string, sandboxMode string) *OverviewResult {
	ctx = workContext(ctx)
	if timeout <= 0 {
		timeout = overviewTimeout
	}
	overviewCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	deadline, _ := overviewCtx.Deadline()
	started := time.Now()
	// A bound runner scoped to the overview keeps an overview timeout from
	// marking the run's own command runner as failed.
	inner := commandRunner
	outer, wrapped := commandRunner.(*boundCommandRunner)
	if wrapped {
		inner = outer.runner
	}
	scoped := &boundCommandRunner{ctx: ctx, runner: inner}
	if _, contextual := inner.(ContextCommandRunner); contextual {
		scoped.ctx = overviewCtx
	}
	outcome, err := runHarnessAttempt(overviewCtx, overviewHarness, opts.Command, opts.Files, artifact, scoped, deadline, env, sandboxMode)
	if wrapped && scoped.attempted {
		outer.attempted = true
	}
	result := &OverviewResult{Status: "failed", DurationMs: time.Since(started).Milliseconds()}
	if err != nil {
		result.CommandStarted = boolPointer(false)
		result.Error = overviewError(ctx, overviewCtx, timeout, redactEnvValues(err.Error(), env))
		return result
	}
	attempt := outcome.result
	result.CommandStarted = attempt.CommandStarted
	result.Status = attempt.Status
	result.ConfiguredModel = attempt.ConfiguredModel
	result.PromptPath = attempt.PromptPath
	result.OutputSchemaPath = attempt.OutputSchemaPath
	result.PromptSHA = attempt.PromptSHA
	result.OutputSchemaSHA = attempt.OutputSchemaSHA
	result.Result = attempt.Result
	result.Error = attempt.Error
	if ctx.Err() == nil && errors.Is(overviewCtx.Err(), context.DeadlineExceeded) {
		result.Status = "failed"
		result.Error = overviewError(ctx, overviewCtx, timeout, result.Error)
	}
	return result
}

func overviewError(parent context.Context, overviewCtx context.Context, timeout time.Duration, message string) string {
	if parent.Err() == nil && errors.Is(overviewCtx.Err(), context.DeadlineExceeded) {
		prefix := fmt.Sprintf("Overview timed out after %s", timeout)
		if message == "" {
			return prefix + "."
		}
		return prefix + ": " + message
	}
	return message
}

type harnessCommand struct {
	command string
	files   map[string][]byte
}

// harnessCommands lists the configured judge and overview commands, whose
// prompt and schema placeholders are run inputs.
func harnessCommands(opts Options) []harnessCommand {
	var commands []harnessCommand
	if opts.Judge != nil {
		commands = append(commands, harnessCommand{command: opts.Judge.Command, files: opts.Judge.Files})
	}
	if opts.Overview != nil {
		commands = append(commands, harnessCommand{command: opts.Overview.Command, files: opts.Overview.Files})
	}
	return commands
}

package runner

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strings"
	"time"
)

type ContextCommandRunner interface {
	RunContext(context.Context, string, []string, string, time.Duration) (CommandOutput, error)
}

type ContextScannerRunner interface {
	RunScannerContext(context.Context, string, string, string) (ScannerResult, error)
}

func workContext(ctx context.Context) context.Context {
	if ctx == nil {
		return context.Background()
	}
	return ctx
}

type boundCommandRunner struct {
	ctx       context.Context
	runner    CommandRunner
	failure   error
	attempted bool
}

func (runner *boundCommandRunner) Run(command string, args []string, cwd string, timeout time.Duration) (CommandOutput, error) {
	if err := runner.ctx.Err(); err != nil {
		runner.failure = err
		return CommandOutput{Started: boolPointer(false)}, err
	}
	if deadline, ok := runner.ctx.Deadline(); ok && (timeout <= 0 || time.Until(deadline) < timeout) {
		timeout = time.Until(deadline)
	}
	var output CommandOutput
	var err error
	runner.attempted = true
	if contextual, ok := runner.runner.(ContextCommandRunner); ok {
		output, err = contextual.RunContext(runner.ctx, command, args, cwd, timeout)
	} else {
		if runner.ctx.Done() != nil {
			err = errors.New("cancelable work requires a ContextCommandRunner")
			runner.failure = err
			return CommandOutput{Started: boolPointer(false)}, err
		}
		output, err = runner.runner.Run(command, args, cwd, timeout)
	}
	if callerErr := runner.ctx.Err(); callerErr != nil {
		err = errors.Join(callerErr, err)
		output.ExitCode = nil
	}
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) || errors.Is(err, exec.ErrWaitDelay) {
		runner.failure = err
		output.ExitCode = nil
	}
	return output, err
}

func (runner *boundCommandRunner) RunContext(ctx context.Context, command string, args []string, cwd string, timeout time.Duration) (CommandOutput, error) {
	bound := &boundCommandRunner{ctx: ctx, runner: runner.runner}
	output, err := bound.Run(command, args, cwd, timeout)
	runner.attempted = runner.attempted || bound.attempted
	if bound.failure != nil {
		runner.failure = bound.failure
	}
	return output, err
}

func boolPointer(value bool) *bool { return &value }

func pendingArtifact(opts Options, startedAt string, env map[string]string) Artifact {
	artifact := NewArtifact(opts, "", startedAt, "", env)
	artifact.Status = "running"
	for _, scanner := range opts.Scanners {
		artifact.Scanners[scanner] = ScannerResult{Status: "not_started"}
	}
	if opts.Judge != nil {
		artifact.Judge = &JudgeResult{Status: "not_started", CommandStarted: boolPointer(false)}
	}
	return artifact
}

type contextReader struct {
	ctx    context.Context
	reader io.Reader
}

func (reader contextReader) Read(buffer []byte) (int, error) {
	if err := reader.ctx.Err(); err != nil {
		return 0, err
	}
	return reader.reader.Read(buffer)
}

func readContextFile(ctx context.Context, path string) ([]byte, error) {
	ctx = workContext(ctx)
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	info, err := os.Stat(path)
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() {
		return nil, fmt.Errorf("refusing non-regular input: %s", path)
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	return io.ReadAll(contextReader{ctx: ctx, reader: file})
}

func finishArtifact(artifact *Artifact, opts Options, ctx context.Context, now func() time.Time, runErr *error) {
	*runErr = errors.Join(*runErr, ctx.Err())
	artifact.Gate = "pass"
	artifact.GateRules = []FiredGateRule{}
	evaluateGate(artifact, opts)
	artifact.Status = "completed"
	artifact.Complete = *runErr == nil
	for _, result := range artifact.Scanners {
		if result.Status != "completed" && result.Status != "skipped" {
			artifact.Complete = false
		}
	}
	if artifact.Judge != nil && artifact.Judge.Status != "completed" {
		artifact.Complete = false
	}
	if !artifact.Complete {
		artifact.Status = "failed"
		artifact.Gate = "error"
	}
	if errors.Is(*runErr, context.Canceled) {
		artifact.Status = "canceled"
	}
	if errors.Is(*runErr, context.DeadlineExceeded) {
		artifact.Status = "deadline_exceeded"
	}
	if *runErr != nil {
		artifact.Error = (*runErr).Error()
	}
	artifact.CompletedAt = now().UTC().Format(time.RFC3339Nano)
	if opts.OutputPath != "" {
		outputErr := WriteRunTargetsResultBundle(opts.OutputPath, RunTargetsResult{Single: artifact})
		*runErr = errors.Join(*runErr, outputErr)
		if outputErr != nil {
			artifact.Complete = false
			if artifact.Status == "completed" {
				artifact.Status = "failed"
			}
			artifact.Gate = "error"
			artifact.Error = strings.TrimSpace(artifact.Error + "\n" + outputErr.Error())
		}
		if err := ctx.Err(); err != nil && artifact.Complete {
			artifact.Complete = false
			artifact.Status = "canceled"
			if errors.Is(err, context.DeadlineExceeded) {
				artifact.Status = "deadline_exceeded"
			}
			artifact.Gate = "error"
			artifact.Error = err.Error()
			*runErr = errors.Join(*runErr, err, WriteRunTargetsResultBundle(opts.OutputPath, RunTargetsResult{Single: artifact}))
		}
	}
}

func (result RunTargetsResult) OperationalError() error {
	if result.Single != nil && result.Single.Status != "" && !result.Single.Complete {
		return errors.New("scan incomplete: " + result.Single.Status)
	}
	if result.Batch != nil {
		if len(result.Batch.Errors) > 0 {
			return errors.New("profile batch incomplete")
		}
		for _, artifact := range result.Batch.Runs {
			if artifact.Status != "" && !artifact.Complete {
				return errors.New("scan batch incomplete")
			}
		}
	}
	return nil
}

func checkpointArtifact(opts Options, artifact *Artifact, ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if opts.OutputPath == "" {
		return nil
	}
	return writeJSONFile(outputBundleSpecFor(opts.OutputPath).ArtifactPath, artifact)
}

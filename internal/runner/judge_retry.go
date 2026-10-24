package runner

import (
	"context"
	"errors"
	"time"
)

type JudgeAttempt struct {
	CommandStarted *bool       `json:"commandStarted,omitempty"`
	Status         string      `json:"status"`
	Error          string      `json:"error"`
	Result         interface{} `json:"result"`
	DurationMs     int64       `json:"durationMs"`
	Challenge      string      `json:"challenge,omitempty"`
	RequiredFile   string      `json:"requiredFile,omitempty"`
	RequiredSHA256 string      `json:"requiredFileSha256,omitempty"`
}

type judgeAttemptOutcome struct {
	result     *JudgeResult
	inspection *artifactInspectionChallenge
	retryable  bool
}

func RunJudge(opts JudgeOptions, artifact Artifact, commandRunner CommandRunner, timeout time.Duration, env map[string]string, sandboxMode string) (*JudgeResult, error) {
	return RunJudgeContext(context.Background(), opts, artifact, commandRunner, timeout, env, sandboxMode)
}

func RunJudgeContext(ctx context.Context, opts JudgeOptions, artifact Artifact, commandRunner CommandRunner, timeout time.Duration, env map[string]string, sandboxMode string) (*JudgeResult, error) {
	ctx = workContext(ctx)
	if timeout == 0 {
		timeout = 20 * time.Minute
	}
	deadline := time.Now().Add(timeout)
	if callerDeadline, ok := ctx.Deadline(); ok && callerDeadline.Before(deadline) {
		deadline = callerDeadline
	}
	commands := &boundCommandRunner{ctx: ctx, runner: commandRunner}
	attempts := []JudgeAttempt{}
	var lastResult *JudgeResult
	for {
		startedAt := time.Now()
		outcome, err := runJudgeAttempt(ctx, opts, artifact, commands, deadline, env, sandboxMode)
		if err != nil {
			failed := &JudgeResult{Status: "failed", CommandStarted: boolPointer(false), Error: redactEnvValues(err.Error(), env)}
			if lastResult != nil {
				retryError := "Judge retry could not start: " + redactEnvValues(err.Error(), env)
				lastResult.Error = retryError
				lastResult.Attempts = append(attempts, JudgeAttempt{
					Status: "failed", Error: retryError, DurationMs: time.Since(startedAt).Milliseconds(), CommandStarted: boolPointer(false),
				})
				return lastResult, ctx.Err()
			}
			return failed, err
		}
		attempt := JudgeAttempt{
			CommandStarted: outcome.result.CommandStarted,
			Status:         outcome.result.Status, Error: outcome.result.Error, Result: outcome.result.Result,
			DurationMs: time.Since(startedAt).Milliseconds(),
		}
		if outcome.inspection != nil {
			attempt.Challenge = outcome.inspection.Challenge
			attempt.RequiredFile = outcome.inspection.RequiredFile
			attempt.RequiredSHA256 = outcome.inspection.RequiredSHA256
		}
		if outcome.inspection != nil {
			attempts = append(attempts, attempt)
		}
		outcome.result.Attempts = attempts
		lastResult = outcome.result
		if err := errors.Join(commands.failure, ctx.Err()); err != nil {
			lastResult.Status = "failed"
			lastResult.Error = commandError(err, lastResult.Error, env)
			return lastResult, err
		}
		if !outcome.retryable || len(attempts) >= 2 || time.Until(deadline) <= 0 {
			return outcome.result, nil
		}
	}
}

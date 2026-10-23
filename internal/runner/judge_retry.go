package runner

import "time"

type JudgeAttempt struct {
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
	if timeout == 0 {
		timeout = 20 * time.Minute
	}
	deadline := time.Now().Add(timeout)
	attempts := []JudgeAttempt{}
	var lastResult *JudgeResult
	for {
		startedAt := time.Now()
		outcome, err := runJudgeAttempt(opts, artifact, commandRunner, deadline, env, sandboxMode)
		if err != nil {
			if lastResult != nil {
				retryError := "Judge retry could not start: " + redactEnvValues(err.Error(), env)
				lastResult.Error = retryError
				lastResult.Attempts = append(attempts, JudgeAttempt{
					Status: "failed", Error: retryError, DurationMs: time.Since(startedAt).Milliseconds(),
				})
				return lastResult, nil
			}
			return nil, err
		}
		if outcome.inspection != nil {
			attempts = append(attempts, JudgeAttempt{
				Status: outcome.result.Status, Error: outcome.result.Error, Result: outcome.result.Result,
				DurationMs: time.Since(startedAt).Milliseconds(),
				Challenge:  outcome.inspection.Challenge, RequiredFile: outcome.inspection.RequiredFile,
				RequiredSHA256: outcome.inspection.RequiredSHA256,
			})
		}
		outcome.result.Attempts = attempts
		lastResult = outcome.result
		if !outcome.retryable || len(attempts) >= 2 || time.Until(deadline) <= 0 {
			return outcome.result, nil
		}
	}
}

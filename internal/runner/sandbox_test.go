package runner

import (
	"strings"
	"testing"
)

func TestDockerSandboxLabelsForWorkerCleanup(t *testing.T) {
	for _, runID := range []string{"", "worker-123", "invalid id", strings.Repeat("a", 65)} {
		t.Run(runID, func(t *testing.T) {
			host := &recordingCommandRunner{stdout: `{}`}
			commandRunner, _, err := commandRunnerForOptions(Options{}, RunContext{HostCommandRunner: host}, map[string]string{SandboxRunIDEnv: runID})
			if err != nil {
				t.Fatal(err)
			}
			var previousCommandID string
			for range 2 {
				_, err := commandRunner.Run("scanner", nil, "", 0)
				if strings.Contains(runID, " ") || len(runID) > 64 {
					if err == nil || len(host.calls) != 0 {
						t.Fatalf("invalid ID executed Docker: calls=%v err=%v", host.calls, err)
					}
					return
				}
				if err != nil {
					t.Fatal(err)
				}
				args := host.calls[len(host.calls)-1].args
				if runID == "" {
					if containsArg(args, "--label") {
						t.Fatalf("unsupervised run has worker labels: %v", args)
					}
					continue
				}
				if !containsArgPair(args, "--label", SandboxRunIDLabel+"="+runID) || containsArgPair(args, "-e", SandboxRunIDEnv) {
					t.Fatalf("worker ID must be a label, not container environment: %v", args)
				}
				var commandID string
				for i, arg := range args[:len(args)-1] {
					if arg == "--label" && strings.HasPrefix(args[i+1], SandboxCommandIDLabel+"=") {
						commandID = strings.TrimPrefix(args[i+1], SandboxCommandIDLabel+"=")
					}
				}
				if commandID == previousCommandID || !sandboxRunIDPattern.MatchString(commandID) {
					t.Fatalf("command ID %q must be valid and unique", commandID)
				}
				previousCommandID = commandID
			}
		})
	}
}

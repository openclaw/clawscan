package runner

func (runner ExternalScannerRunner) runSocket(target string, startedAt string) (ScannerResult, error) {
	command := "npx"
	args := []string{"--yes", "socket", "scan", "create", "--no-banner", "--no-spinner", "--no-interactive", "--json", target}
	if runner.SandboxMode == SandboxModeDocker {
		command = "socket"
		args = []string{"scan", "create", "--no-banner", "--no-spinner", "--no-interactive", "--json", target}
	}
	return runner.runJSONStdout(command, args, startedAt, "Socket", "Socket scanner returned invalid JSON"), nil
}

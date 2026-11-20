package runner

func (runner ExternalScannerRunner) runSnyk(target string, startedAt string) (ScannerResult, error) {
	command := "uvx"
	args := []string{"snyk-agent-scan@latest", "scan", "--json", "--no-bootstrap", "--skills", target}
	if runner.SandboxMode == SandboxModeDocker {
		command = "snyk-agent-scan"
		args = []string{"scan", "--json", "--no-bootstrap", "--skills", target}
	}
	return runner.runJSONStdout(command, args, startedAt, "Snyk", "Snyk scanner returned invalid JSON"), nil
}

package main

import (
	"fmt"
	"os"
	"strings"

	"github.com/openclaw/clawscan/internal/runner"
)

var (
	version = "dev"
	commit  = "unknown"
	date    = "unknown"
)

func main() {
	if err := run(os.Args[1:], os.Environ()); err != nil {
		fmt.Fprintln(os.Stderr, err.Error())
		os.Exit(1)
	}
}

func run(args []string, environ []string) error {
	if len(args) == 1 && (args[0] == "--help" || args[0] == "-h") {
		fmt.Fprint(os.Stdout, helpText())
		return nil
	}
	if len(args) == 1 && args[0] == "--version" {
		fmt.Fprintln(os.Stdout, versionString())
		return nil
	}
	opts, err := runner.ParseArgs(args)
	if err != nil {
		return err
	}
	artifact, err := runner.Run(opts, runner.RunContext{Env: runner.EnvMap(environ)})
	if err != nil {
		return err
	}
	if opts.JSON {
		return runner.WriteJSON(os.Stdout, artifact)
	}
	if opts.OutputPath != "" {
		fmt.Fprintf(os.Stdout, "Wrote %s\n", opts.OutputPath)
		return nil
	}
	fmt.Fprintf(os.Stdout, "clawscan %s: %d scanner(s)\n", artifact.SchemaVersion, len(artifact.Scanners))
	return nil
}

func versionString() string {
	return fmt.Sprintf("clawscan %s (commit %s, built %s)", version, commit, date)
}

func helpText() string {
	return fmt.Sprintf(`ClawScan runs agent-skill scanners, preserves raw evidence, and can hand results to an external judge.

Usage:
  clawscan <target> --scanner <scanner-id> [flags]
  clawscan --version
  clawscan --help

Core flags:
  --scanner <id>              Scanner to run. Repeat for multiple scanners.
  --scanner-result <id=path>  Use a JSON fixture instead of running that scanner.
  --output <path>             Write the run artifact JSON to a file.
  --json                      Print the run artifact JSON to stdout.
  --judge <cmd>               Optional external judge harness command.
  --version                   Print build metadata.
  -h, --help                  Print this help.

Accepted scanner IDs:
  %s

Required environment variables:
  ai-infra-guard: AIG_BASE_URL, AIG_MODEL, AIG_MODEL_API_KEY
  snyk: SNYK_TOKEN
  virustotal: VIRUSTOTAL_API_KEY
  skillspector: CLAWSCAN_SKILLSPECTOR_LLM=1 requires the configured provider key.
  judge: provider credentials belong to the command passed to --judge.

Target notes:
  Most scanners use a local skill file or directory target.
  AI-Infra-Guard uses the self-hosted A.I.G taskapi; local targets are uploaded as a temporary zip.
  Gen Digital supports URL targets only in v1; use a ClawHub skill URL such as https://clawhub.ai/owner/skill.

Judge summary:
  If --judge is omitted, ClawScan only records scanner evidence.
  If --judge is present, ClawScan runs it through the platform shell and expects a JSON object on stdout or at {{ output }}.
  Placeholders: {{ workspace }}, {{ prompt[:path] }}, {{ output_schema[:path] }}, {{ output }}.
`, strings.Join(runner.ScannerIDs(), ", "))
}

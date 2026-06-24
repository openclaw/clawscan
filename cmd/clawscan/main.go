package main

import (
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/openclaw/clawscan/internal/profiles"
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
	cwd, err := os.Getwd()
	if err != nil {
		return err
	}
	opts, err := profiles.ResolveArgs(args, cwd)
	if err != nil {
		return err
	}
	if opts.Benchmark != nil {
		artifact, err := runner.RunBenchmark(opts, runner.RunContext{Env: runner.EnvMap(environ)})
		if err != nil {
			return err
		}
		if opts.JSON {
			return runner.WriteJSON(os.Stdout, artifact)
		}
		if opts.OutputPath != "" {
			if predictionsPath := runner.BenchmarkPredictionsOutputPath(opts); predictionsPath != "" {
				fmt.Fprintf(os.Stdout, "Wrote %s\nWrote %s\n", opts.OutputPath, predictionsPath)
				return nil
			}
			fmt.Fprintf(os.Stdout, "Wrote %s\n", opts.OutputPath)
			return nil
		}
		if predictionsPath := runner.BenchmarkPredictionsOutputPath(opts); predictionsPath != "" {
			fmt.Fprintf(os.Stdout, "Wrote %s\n", predictionsPath)
			return nil
		}
		fmt.Fprintf(os.Stdout, "clawscan %s: %d case(s)\n", artifact.SchemaVersion, len(artifact.Cases))
		return nil
	}
	result, err := runner.RunTargets(opts, runner.RunContext{Env: runner.EnvMap(environ)}, cwd)
	if err != nil {
		return err
	}
	if opts.JSON {
		return runner.WriteJSON(os.Stdout, result.JSONValue())
	}
	if opts.OutputPath != "" {
		fmt.Fprintf(os.Stdout, "Wrote %s\n", opts.OutputPath)
		return nil
	}
	printRunSummary(os.Stdout, result)
	return nil
}

func versionString() string {
	return fmt.Sprintf("clawscan %s (commit %s, built %s)", version, commit, date)
}

func printRunSummary(w io.Writer, result runner.RunTargetsResult) {
	if result.Batch != nil {
		fmt.Fprintf(w, "clawscan %s: %d target(s)\n", result.Batch.SchemaVersion, len(result.Batch.Runs))
		for _, run := range result.Batch.Runs {
			fmt.Fprintf(w, "- %s: %d scanner(s)\n", run.Target.Input, len(run.Scanners))
		}
		return
	}
	if result.Single != nil {
		fmt.Fprintf(w, "clawscan %s: %d scanner(s)\n", result.Single.SchemaVersion, len(result.Single.Scanners))
	}
}

func helpText() string {
	return fmt.Sprintf(`ClawScan runs agent-skill scanners, preserves raw evidence, and can hand results to an external judge.

Usage:
  clawscan [target] [flags]
  clawscan --profile skills-sh [flags]
  clawscan --benchmark --scanner <scanner-id> [flags]
  clawscan --benchmark SkillTrustBench --scanner <scanner-id> [flags]
  clawscan --benchmark OpenClaw/clawhub-security-signals --scanner <scanner-id> [flags]
  clawscan --version
  clawscan --help

Core flags:
  --profile <name>            Profile to run. Defaults to clawhub.
  --config <path>             Load profiles from a specific .clawscan.yml file instead of discovery.
  --scanner <id>              Scanner to run. Repeat for multiple scanners.
  --scanner-result <id=path>  Use a JSON fixture instead of running that scanner.
  --output <path>             Write the run artifact JSON to a file.
  --json                      Print the run artifact JSON to stdout.
  --judge <cmd>               Optional external judge harness command.
  --benchmark [id]            Run a supported benchmark dataset instead of one target. Defaults to SkillTrustBench.
  --split <name>              Benchmark split. Defaults to benchmark for SkillTrustBench and eval_holdout for OpenClaw.
  --limit <n>                 Maximum benchmark rows to run. 0 means all rows.
  --offset <n>                Benchmark row offset. Defaults to 0.
  --predictions-output <path> Write benchmark predictions JSONL. Defaults next to --output for OpenClaw benchmarks.
  --version                   Print build metadata.
  -h, --help                  Print this help.

Supported benchmarks:
  cuhk-zhuque/SkillTrustBench (alias: SkillTrustBench, default)
  OpenClaw/clawhub-security-signals

Accepted scanner IDs:
  %s

Built-in profiles:
  %s

Required environment variables:
  ai-infra-guard: AIG_BASE_URL, AIG_MODEL, AIG_MODEL_API_KEY
  snyk: SNYK_TOKEN
  virustotal: VIRUSTOTAL_API_KEY
  skillspector: CLAWSCAN_SKILLSPECTOR_LLM=1 requires the configured provider key.
  judge: provider credentials belong to the command passed to --judge.

Target notes:
  No target scans child skill directories under ./skills.
  Most scanners use a local skill file or directory target.
  AI-Infra-Guard uses the self-hosted A.I.G taskapi; local targets are uploaded as a temporary zip.
  Gen Digital supports URL targets only in v1; use a ClawHub skill URL such as https://clawhub.ai/owner/skill.

Judge summary:
  If --judge is omitted, ClawScan only records scanner evidence.
  If --judge is present, ClawScan runs it through the platform shell and expects a JSON object on stdout or at {{ output }}.
  Placeholders: {{ workspace }}, {{ prompt[:path] }}, {{ output_schema[:path] }}, {{ output }}.
`, strings.Join(runner.ScannerIDs(), ", "), strings.Join(runner.ProfileIDs(), ", "))
}

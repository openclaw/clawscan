package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"text/tabwriter"

	"github.com/openclaw/clawscan/internal/profiles"
	"github.com/openclaw/clawscan/internal/runner"
)

const defaultOutputPath = "clawscan-results/artifact.json"

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
	if len(args) > 0 && args[0] == "scanners" {
		return runScanners(args[1:])
	}
	if len(args) > 0 && args[0] == "benchmark" {
		return runBenchmarkCommand(args[1:], environ)
	}
	if len(args) > 0 && args[0] == "profiles" {
		return runProfiles(args[1:])
	}
	if len(args) > 0 && args[0] == "install" {
		return runInstall(args[1:], environ)
	}
	if len(args) > 0 && looksLikeCommand(args[0]) {
		return fmt.Errorf("Unknown command: %s", args[0])
	}
	cwd, err := os.Getwd()
	if err != nil {
		return err
	}
	resolved, err := profiles.ResolveRunSet(args, cwd)
	if err != nil {
		return err
	}
	if resolved.AllProfiles {
		return runAllProfiles(resolved, environ, cwd)
	}
	opts := resolved.Options[0]
	if !opts.JSON && opts.OutputPath == "" {
		opts.OutputPath = defaultOutputPath
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
			printBenchmarkSummary(os.Stdout, artifact, opts.OutputPath)
			if predictionsPath := runner.BenchmarkPredictionsOutputPath(opts); predictionsPath != "" {
				fmt.Fprintf(os.Stdout, "predictions_results: %s\n", displayOutputPath(predictionsPath))
			}
			return nil
		}
		if predictionsPath := runner.BenchmarkPredictionsOutputPath(opts); predictionsPath != "" {
			fmt.Fprintf(os.Stdout, "predictions_results: %s\n", displayOutputPath(predictionsPath))
			return nil
		}
		printBenchmarkSummary(os.Stdout, artifact, "")
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
		printRunSummary(os.Stdout, result, opts.OutputPath)
		return nil
	}
	printRunSummary(os.Stdout, result, "")
	return nil
}

func runBenchmarkCommand(args []string, environ []string) error {
	switch {
	case len(args) == 1 && args[0] == "list":
		printBenchmarkCatalog(os.Stdout, runner.DefaultBenchmarkRegistry())
		return nil
	case len(args) == 0:
		return errors.New("Usage: clawscan benchmark <benchmark-id> [flags]\n       clawscan benchmark list")
	case args[0] == "list":
		return errors.New("Usage: clawscan benchmark list")
	}

	cwd, err := os.Getwd()
	if err != nil {
		return err
	}
	resolved, err := profiles.ResolveBenchmarkRunSet(args[0], args[1:], cwd)
	if err != nil {
		return err
	}
	if resolved.AllProfiles {
		return errors.New("clawscan benchmark does not support --config without --profile")
	}
	opts := resolved.Options[0]
	if !opts.JSON && opts.OutputPath == "" {
		opts.OutputPath = defaultOutputPath
	}
	artifact, err := runner.RunBenchmark(opts, runner.RunContext{Env: runner.EnvMap(environ)})
	if err != nil {
		return err
	}
	if opts.JSON {
		return runner.WriteJSON(os.Stdout, artifact)
	}
	if opts.OutputPath != "" {
		printBenchmarkSummary(os.Stdout, artifact, opts.OutputPath)
		if predictionsPath := runner.BenchmarkPredictionsOutputPath(opts); predictionsPath != "" {
			fmt.Fprintf(os.Stdout, "predictions_results: %s\n", displayOutputPath(predictionsPath))
		}
		return nil
	}
	if predictionsPath := runner.BenchmarkPredictionsOutputPath(opts); predictionsPath != "" {
		fmt.Fprintf(os.Stdout, "predictions_results: %s\n", displayOutputPath(predictionsPath))
		return nil
	}
	printBenchmarkSummary(os.Stdout, artifact, "")
	return nil
}

func runAllProfiles(resolved profiles.ResolvedRunSet, environ []string, cwd string) error {
	if !resolved.JSON && resolved.OutputPath == "" {
		resolved.OutputPath = defaultOutputPath
	}
	batch, err := runner.RunProfileBatch(resolved.Options, runner.RunContext{Env: runner.EnvMap(environ)}, cwd)
	if err != nil {
		return err
	}
	if resolved.JSON {
		return runner.WriteJSON(os.Stdout, batch)
	}
	if resolved.OutputPath != "" {
		if err := runner.WriteRunTargetsResultBundle(resolved.OutputPath, runner.RunTargetsResult{Batch: &batch}); err != nil {
			return err
		}
		printRunSummary(os.Stdout, runner.RunTargetsResult{Batch: &batch}, resolved.OutputPath)
		return nil
	}
	printRunSummary(os.Stdout, runner.RunTargetsResult{Batch: &batch}, "")
	return nil
}

func printBenchmarkCatalog(w io.Writer, registry runner.BenchmarkRegistry) {
	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	fmt.Fprintln(tw, "ID\tName\tDefault split\tSplits\tRequired env")
	for _, info := range registry.Infos() {
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\n", info.ID, info.DisplayName, info.DefaultSplit, strings.Join(info.Splits, ", "), info.RequiredEnv)
	}
	_ = tw.Flush()
}

func runScanners(args []string) error {
	registry := runner.DefaultScannerRegistry()
	if len(args) == 0 || (len(args) == 1 && args[0] == "list") {
		printScannerCatalog(os.Stdout, registry)
		return nil
	}
	if len(args) == 1 {
		info, ok := registry.Info(args[0])
		if !ok {
			return fmt.Errorf("Unknown scanner: %s. Accepted scanner IDs: %s", args[0], strings.Join(registry.IDs(), ", "))
		}
		printScannerDetail(os.Stdout, info)
		return nil
	}
	return errors.New("Usage: clawscan scanners [list|<scanner-id>]")
}

func printScannerCatalog(w io.Writer, registry runner.ScannerRegistry) {
	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	fmt.Fprintln(tw, "ID\tName\tRequired env\tInstall")
	for _, info := range registry.Infos() {
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\n", info.ID, info.DisplayName, formatEnvList(info.RequiredEnv), info.InstallHint)
	}
	_ = tw.Flush()
}

func printScannerDetail(w io.Writer, info runner.ScannerInfo) {
	fmt.Fprintf(w, "%s\n", info.DisplayName)
	fmt.Fprintf(w, "ID: %s\n", info.ID)
	fmt.Fprintf(w, "Repository: %s\n", info.RepositoryURL)
	fmt.Fprintf(w, "Description: %s\n", info.Description)
	fmt.Fprintf(w, "Required env vars: %s\n", formatEnvList(info.RequiredEnv))
	if len(info.OptionalEnv) > 0 {
		fmt.Fprintf(w, "Optional env vars: %s\n", strings.Join(info.OptionalEnv, ", "))
	}
	fmt.Fprintf(w, "Install: %s\n", info.InstallHint)
}

func runProfiles(args []string) error {
	verbose := false
	switch {
	case len(args) == 0:
	case len(args) == 1 && (args[0] == "-v" || args[0] == "--verbose"):
		verbose = true
	default:
		return errors.New("Usage: clawscan profiles [-v|--verbose]")
	}
	cwd, err := os.Getwd()
	if err != nil {
		return err
	}
	catalog, err := profiles.InspectProfiles(cwd)
	if err != nil {
		return err
	}
	if verbose {
		data, err := catalog.YAML()
		if err != nil {
			return err
		}
		_, err = os.Stdout.Write(data)
		return err
	}
	printProfileCatalog(os.Stdout, catalog, cwd)
	return nil
}

func printProfileCatalog(w io.Writer, catalog profiles.ProfileCatalog, cwd string) {
	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	fmt.Fprintln(tw, "Profile\tSource\tScanners\tJudge")
	for _, id := range catalog.IDs() {
		info, _ := catalog.Profile(id)
		judge := "none"
		if info.Profile.Judge != nil {
			judge = "configured"
		}
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\n", info.ID, displayProfileSource(info.Source, cwd), strings.Join(info.Profile.Scanners, ", "), judge)
	}
	_ = tw.Flush()
}

func displayProfileSource(source string, cwd string) string {
	if source == "" || source == "built-in" {
		return "built-in"
	}
	rel, err := filepath.Rel(cwd, source)
	if err == nil && rel != "" && !strings.HasPrefix(rel, ".."+string(filepath.Separator)) && rel != ".." {
		return rel
	}
	return source
}

func formatEnvList(envVars []string) string {
	if len(envVars) == 0 {
		return "none"
	}
	return strings.Join(envVars, ", ")
}

func runInstall(args []string, environ []string) error {
	results, err := runner.InstallScanners(args, runner.InstallOptions{Env: runner.EnvMap(environ)})
	for _, result := range results {
		printInstallResult(os.Stdout, result)
	}
	return err
}

func printInstallResult(w io.Writer, result runner.InstallResult) {
	fmt.Fprintf(w, "%s: %s", result.ScannerID, result.Status)
	details := []string{}
	if result.Name != "" {
		details = append(details, result.Name)
	}
	switch {
	case result.Message != "":
		details = append(details, result.Message)
	case result.Error != "":
		details = append(details, result.Error)
	}
	if len(details) > 0 {
		fmt.Fprintf(w, " (%s)", strings.Join(details, "; "))
	}
	fmt.Fprintln(w)
	for _, command := range result.Commands {
		fmt.Fprintf(w, "  command: %s\n", formatCommand(command.Command, command.Args))
	}
}

func formatCommand(command string, args []string) string {
	parts := append([]string{command}, args...)
	return strings.Join(parts, " ")
}

func versionString() string {
	return fmt.Sprintf("clawscan %s (commit %s, built %s)", version, commit, date)
}

func printRunSummary(w io.Writer, result runner.RunTargetsResult, outputPath string) {
	summary := summarizeRunTargets(result)
	if summary.Profile != "" {
		fmt.Fprintf(w, "profile: %s\n", summary.Profile)
	}
	if summary.Profiles > 0 {
		fmt.Fprintf(w, "profiles: %d\n", summary.Profiles)
	}
	fmt.Fprintf(w, "targets: %d\n", summary.Targets)
	fmt.Fprintf(w, "scanner_completed: %d\n", summary.ScannerCompleted)
	fmt.Fprintf(w, "scanner_failed: %d\n", summary.ScannerFailed)
	fmt.Fprintf(w, "scanner_skipped: %d\n", summary.ScannerSkipped)
	if summary.ScannerOther > 0 {
		fmt.Fprintf(w, "scanner_other: %d\n", summary.ScannerOther)
	}
	fmt.Fprintf(w, "issues_found: %d\n", summary.IssuesFound)
	if summary.HasJudge {
		fmt.Fprintf(w, "judge_completed: %d\n", summary.JudgeCompleted)
		fmt.Fprintf(w, "judge_failed: %d\n", summary.JudgeFailed)
		fmt.Fprintf(w, "clean: %d\n", summary.Clean)
		fmt.Fprintf(w, "needs_review: %d\n", summary.NeedsReview)
		fmt.Fprintf(w, "malicious: %d\n", summary.Malicious)
		if summary.VerdictUnknown > 0 {
			fmt.Fprintf(w, "verdict_unknown: %d\n", summary.VerdictUnknown)
		}
	}
	fmt.Fprintf(w, "errors: %d\n", summary.Errors)
	if outputPath != "" {
		fmt.Fprintf(w, "full_results: %s\n", displayOutputPath(outputPath))
	}
}

func printBenchmarkSummary(w io.Writer, artifact runner.BenchmarkArtifact, outputPath string) {
	fmt.Fprintf(w, "benchmark: %s\n", artifact.Benchmark.ID)
	fmt.Fprintf(w, "split: %s\n", artifact.Benchmark.Split)
	fmt.Fprintf(w, "cases: %d\n", len(artifact.Cases))
	printStatusMap(w, "scanner", artifact.Summary.ScannerStatuses)
	if len(artifact.Summary.JudgeStatuses) > 0 {
		for _, status := range []string{"completed", "failed", "skipped"} {
			fmt.Fprintf(w, "judge_%s: %d\n", status, artifact.Summary.JudgeStatuses[status])
		}
	}
	fmt.Fprintf(w, "scored: %d\n", artifact.Summary.Evaluation.Scored)
	fmt.Fprintf(w, "correct: %d\n", artifact.Summary.Evaluation.Correct)
	fmt.Fprintf(w, "incorrect: %d\n", artifact.Summary.Evaluation.Incorrect)
	fmt.Fprintf(w, "abstained: %d\n", artifact.Summary.Evaluation.Abstained)
	fmt.Fprintf(w, "unscorable: %d\n", artifact.Summary.Evaluation.Unscorable)
	fmt.Fprintf(w, "accuracy: %.4f\n", artifact.Summary.Evaluation.Accuracy)
	if outputPath != "" {
		fmt.Fprintf(w, "full_results: %s\n", displayOutputPath(outputPath))
	}
}

func printStatusMap(w io.Writer, prefix string, statuses map[string]map[string]int) {
	counts := map[string]int{}
	for _, scannerStatuses := range statuses {
		for status, count := range scannerStatuses {
			counts[status] += count
		}
	}
	for _, status := range []string{"completed", "failed", "skipped"} {
		fmt.Fprintf(w, "%s_%s: %d\n", prefix, status, counts[status])
	}
	other := 0
	for status, count := range counts {
		if status != "completed" && status != "failed" && status != "skipped" {
			other += count
		}
	}
	if other > 0 {
		fmt.Fprintf(w, "%s_other: %d\n", prefix, other)
	}
}

type runSummary struct {
	Profile          string
	Profiles         int
	Targets          int
	ScannerCompleted int
	ScannerFailed    int
	ScannerSkipped   int
	ScannerOther     int
	IssuesFound      int
	HasJudge         bool
	JudgeCompleted   int
	JudgeFailed      int
	Clean            int
	NeedsReview      int
	Malicious        int
	VerdictUnknown   int
	Errors           int
}

func summarizeRunTargets(result runner.RunTargetsResult) runSummary {
	var summary runSummary
	if result.Batch != nil {
		summary.Profile = result.Batch.Profile
		summary.Profiles = result.Batch.Summary.ProfileCount
		summary.Errors = len(result.Batch.Errors)
		for _, run := range result.Batch.Runs {
			summary.addArtifact(run)
		}
		return summary
	}
	if result.Single != nil {
		summary.addArtifact(*result.Single)
	}
	return summary
}

func (summary *runSummary) addArtifact(artifact runner.Artifact) {
	if summary.Profile == "" {
		summary.Profile = artifact.Profile
	}
	summary.Targets++
	for _, result := range artifact.Scanners {
		switch result.Status {
		case "completed":
			summary.ScannerCompleted++
		case "failed":
			summary.ScannerFailed++
		case "skipped":
			summary.ScannerSkipped++
		default:
			summary.ScannerOther++
		}
		summary.IssuesFound += scannerIssueCount(result.Raw)
	}
	if artifact.Judge == nil {
		return
	}
	summary.HasJudge = true
	switch artifact.Judge.Status {
	case "completed":
		summary.JudgeCompleted++
	default:
		summary.JudgeFailed++
	}
	switch judgeVerdict(artifact.Judge.Result) {
	case "clean":
		summary.Clean++
	case "review":
		summary.NeedsReview++
	case "malicious":
		summary.Malicious++
	default:
		summary.VerdictUnknown++
	}
}

func scannerIssueCount(raw json.RawMessage) int {
	if len(raw) == 0 {
		return 0
	}
	var decoded interface{}
	if err := json.Unmarshal(raw, &decoded); err != nil {
		return 0
	}
	return countIssueArrays(decoded)
}

func countIssueArrays(value interface{}) int {
	switch typed := value.(type) {
	case map[string]interface{}:
		total := 0
		for key, nested := range typed {
			if isIssueArrayKey(key) {
				if items, ok := nested.([]interface{}); ok {
					total += len(items)
					continue
				}
			}
			total += countIssueArrays(nested)
		}
		return total
	case []interface{}:
		total := 0
		for _, nested := range typed {
			total += countIssueArrays(nested)
		}
		return total
	default:
		return 0
	}
}

func isIssueArrayKey(key string) bool {
	switch strings.ToLower(key) {
	case "findings", "issues", "vulnerabilities":
		return true
	default:
		return false
	}
}

func judgeVerdict(result interface{}) string {
	typed, ok := result.(map[string]interface{})
	if !ok {
		return ""
	}
	for _, key := range []string{"verdict", "prediction", "status"} {
		if value, ok := typed[key].(string); ok {
			switch strings.ToLower(strings.TrimSpace(value)) {
			case "benign", "clean", "ok":
				return "clean"
			case "suspicious", "review", "needs_review", "needs review":
				return "review"
			case "malicious":
				return "malicious"
			}
		}
	}
	return ""
}

func displayOutputPath(path string) string {
	if path == "" || filepath.IsAbs(path) || strings.HasPrefix(path, ".") {
		return path
	}
	return "./" + path
}

func looksLikeCommand(arg string) bool {
	return arg != "" && !strings.HasPrefix(arg, "--") && !strings.ContainsAny(arg, `/\.`)
}

func helpText() string {
	return fmt.Sprintf(`ClawScan runs agent-skill scanners, preserves raw evidence, and can hand results to an external judge.

Usage:
  clawscan install <scanner-id> [scanner-id ...]
  clawscan scanners [list|<scanner-id>]
  clawscan profiles [-v]
  clawscan benchmark list
  clawscan benchmark <benchmark-id> --scanner <scanner-id> [flags]
  clawscan benchmark <benchmark-id> --profile <profile-name> [flags]
  clawscan <target> --scanner <scanner-id> [flags]
  clawscan --scanner <scanner-id> [flags]
  clawscan --profile clawhub [flags]
  clawscan --profile skills-sh [flags]
  clawscan --version
  clawscan --help

Core flags:
  --profile <name>            Profile to run. Use --profile clawhub for ClawHub parity.
  --config <path>             Load profiles from a specific .clawscan.yml file; omit --profile to run them all.
  --scanner <id>              Scanner to run. Repeat for multiple scanners.
  --scanner-result <id=path>  Use a JSON fixture instead of running that scanner.
  --output <path>             Write the full artifact JSON to a specific file.
                              Defaults to ./clawscan-results/artifact.json unless --json is passed.
                              Explicit .json paths keep the artifact file and write scanner JSON beside it.
  --json                      Print the full artifact JSON to stdout and skip default file writes unless --output is passed.
  --judge <cmd>               Optional external judge harness command.

Benchmark command flags:
  --split <name>              Benchmark split. Defaults to benchmark for SkillTrustBench and eval_holdout for clawhub-security-signals.
  --limit <n>                 Maximum benchmark rows to run. 0 means all rows.
  --offset <n>                Benchmark row offset. Defaults to 0.
  --predictions-output <path> Write benchmark predictions JSONL. Defaults next to --output for clawhub-security-signals.
  --version                   Print build metadata.
  -h, --help                  Print this help.

Install command:
  clawscan install <scanner-id> [scanner-id ...]
                              Install scanner dependencies without running scans.
                              Each scanner contributes its install plan through the registry.

Catalog commands:
  clawscan scanners           List supported scanners with required env vars.
  clawscan scanners list      Alias for clawscan scanners.
  clawscan scanners <id>      Show scanner repository, description, env vars, and install guidance.
  clawscan profiles           List built-in plus nearest project .clawscan.yml/.clawscan.yaml profiles.
  clawscan profiles -v        Print the resolved profile catalog as pasteable YAML.
  clawscan benchmark list     List supported benchmarks with source datasets and splits.

Supported benchmarks:
  cuhk-zhuque/SkillTrustBench (alias: SkillTrustBench)
  clawhub-security-signals

Accepted scanner IDs:
  %s

Built-in profiles:
  %s

Required environment variables:
  aig: no ClawScan-required env vars; AIG_BASE_URL defaults to http://localhost:8088. Use "clawscan scanners aig" for optional service/model vars and the private-network warning.
  socket: SOCKET_CLI_API_TOKEN
  snyk: SNYK_TOKEN
  virustotal: VIRUSTOTAL_API_KEY
  skillspector: no ClawScan-required env vars; provider env vars enable LLM mode, otherwise --no-llm is used. Use "clawscan scanners skillspector" for provider vars.
  cisco: no ClawScan-required env vars; optional upstream env vars enable LLM, VirusTotal, and Cisco AI Defense analyzers.
  judge: provider credentials belong to the command passed to --judge.

Target notes:
  No target with --scanner, --profile, or --config scans child skill directories under ./skills.
  Plain clawscan without --scanner, --profile, or --config is invalid.
  Most scanners use a local skill file or directory target.
  Socket runs the public Socket CLI full-scan path over local dependency manifests.

Judge summary:
  A selected profile may configure a judge; --judge overrides that command for one run.
  If no judge is configured, ClawScan only records scanner evidence.
  If a judge is configured, ClawScan runs it through the platform shell and expects a JSON object on stdout or at {{ output }}.
  Placeholders: {{ workspace }}, {{ prompt[:path] }}, {{ output_schema[:path] }}, {{ output }}.
`, strings.Join(runner.ScannerIDs(), ", "), strings.Join(profiles.ProfileIDs(), ", "))
}

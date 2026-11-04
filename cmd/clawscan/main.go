package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"text/tabwriter"

	"github.com/openclaw/clawscan/internal/installpolicy"
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
	ctx := context.Background()
	stop := func() {}
	if len(os.Args) < 2 || os.Args[1] != "install" {
		ctx, stop = signal.NotifyContext(ctx, os.Interrupt, syscall.SIGTERM)
	}
	restoreSignals := context.AfterFunc(ctx, stop)
	err := runContext(ctx, os.Args[1:], os.Environ())
	restoreSignals()
	stop()
	if err != nil {
		fmt.Fprintln(os.Stderr, err.Error())
		os.Exit(1)
	}
}

func run(args []string, environ []string) error {
	return runContext(context.Background(), args, environ)
}

func runContext(ctx context.Context, args []string, environ []string) error {
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
		return runBenchmarkCommand(ctx, args[1:], environ)
	}
	if len(args) > 0 && args[0] == "profiles" {
		return runProfiles(args[1:])
	}
	if len(args) > 0 && args[0] == "install" {
		return runInstall(args[1:], environ)
	}
	if len(args) > 0 && args[0] == "openclaw-install-policy" {
		return runOpenClawInstallPolicyContext(ctx, args[1:], environ, os.Stdin, os.Stdout)
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
		return runAllProfiles(ctx, resolved, environ, cwd)
	}
	opts := resolved.Options[0]
	if !opts.JSON && opts.OutputPath == "" {
		opts.OutputPath = defaultOutputPath
	}
	if opts.Benchmark != nil {
		artifact, err := runner.RunBenchmark(opts, scanRunContextWithCaller(ctx, environ))
		if err != nil {
			if opts.JSON && artifact.SchemaVersion != "" {
				err = errors.Join(err, runner.WriteJSON(os.Stdout, artifact))
			}
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
	result, err := runner.RunTargets(opts, scanRunContextWithCaller(ctx, environ), cwd)
	err = errors.Join(err, result.OperationalError())
	if err != nil {
		if opts.JSON && result.JSONValue() != nil {
			err = errors.Join(err, runner.WriteJSON(os.Stdout, result.JSONValue()))
		}
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

func runOpenClawInstallPolicy(
	args []string,
	environ []string,
	input io.Reader,
	output io.Writer,
) error {
	return runOpenClawInstallPolicyContext(context.Background(), args, environ, input, output)
}

func runOpenClawInstallPolicyContext(ctx context.Context, args []string, environ []string, input io.Reader, output io.Writer) error {
	failClosed := func(err error) error {
		return installpolicy.WriteResponse(output, installpolicy.FailureResponse(err.Error()))
	}
	request, err := installpolicy.DecodeRequest(input)
	if err != nil {
		return failClosed(err)
	}
	cwd, err := os.Getwd()
	if err != nil {
		return failClosed(err)
	}
	if !hasProfileSelection(args) {
		args = append(args, "--profile", "openclaw-install-policy")
	}
	resolved, err := profiles.ResolveRunSet(append([]string{request.SourcePath}, args...), cwd)
	if err != nil {
		return failClosed(err)
	}
	if resolved.AllProfiles || len(resolved.Options) != 1 {
		return failClosed(errors.New("OpenClaw install policy requires exactly one ClawScan profile"))
	}
	opts := resolved.Options[0]
	opts.TargetKind = request.TargetType
	opts.JSON = false
	opts.OutputPath = ""
	if opts.Judge != nil || opts.Overview != nil {
		return failClosed(errors.New(
			"OpenClaw install policy does not support judge-backed profiles; use scanner gate rules",
		))
	}
	metadataPreflight := request.IsNPMMetadataStage()
	if metadataPreflight {
		if err := installpolicy.ValidateNPMMetadataPreflight(request); err != nil {
			return failClosed(err)
		}
	}
	if installPolicyMetadataValidationOnly(opts, args, metadataPreflight) {
		response := installpolicy.Response{ProtocolVersion: 1, Decision: "allow"}
		addNPMMetadataPreflightFinding(&response)
		return installpolicy.WriteResponse(output, response)
	}
	if request.IsDependencyTree() {
		scanTarget, cleanup, empty, err := installpolicy.PrepareDependencyTreeScanTarget(
			request.SourcePath,
			request.AllowsManagedNPMRootPeerLinks(),
		)
		if err != nil {
			return failClosed(err)
		}
		defer cleanup()
		if empty {
			response := installpolicy.Response{ProtocolVersion: 1, Decision: "allow"}
			installpolicy.AddFinding(&response, installpolicy.Finding{
				RuleID:   "clawscan.empty-dependency-tree",
				Severity: "info",
				Message:  "OpenClaw reported no installed runtime dependencies in this dependency-tree phase.",
			})
			return installpolicy.WriteResponse(output, response)
		}
		opts.Target = scanTarget
	}
	if installPolicyWindowsUnscanned(opts, args, runtime.GOOS) {
		return installpolicy.WriteResponse(output, windowsUnscannedResponse())
	}
	result, err := runner.RunTargets(opts, scanRunContextWithCaller(ctx, environ), cwd)
	if err != nil {
		return failClosed(err)
	}
	if result.Single == nil || result.Batch != nil {
		return failClosed(errors.New("ClawScan install policy expected one scan artifact"))
	}
	response := installpolicy.ResponseFromArtifact(*result.Single)
	if metadataPreflight {
		addNPMMetadataPreflightFinding(&response)
	}
	return installpolicy.WriteResponse(output, response)
}

func addNPMMetadataPreflightFinding(response *installpolicy.Response) {
	installpolicy.AddFinding(response, installpolicy.Finding{
		RuleID:   "clawscan.npm-metadata-preflight",
		Severity: "info",
		Message:  "ClawScan validated npm registry metadata in this preflight phase; OpenClaw submits the resolved package and dependency tree for separate code scans.",
	})
}

// windowsUnscannedResponse is the visible native-Windows response for the
// built-in profile: its scanners need the Linux Docker runtime, which cannot
// consume native Windows staging paths, so nothing was scanned and OpenClaw
// must obtain explicit confirmation.
func windowsUnscannedResponse() installpolicy.Response {
	response := installpolicy.Response{
		ProtocolVersion: 1,
		Decision:        "warn",
		Reason:          "ClawScan could not scan on native Windows; Docker scanner coverage was unavailable",
	}
	installpolicy.AddFinding(&response, installpolicy.Finding{
		RuleID:   "clawscan.windows-unscanned",
		Severity: "warn",
		Message:  "Docker scanning is unavailable in the native Windows policy path; ClawScan did not scan this candidate.",
	})
	return response
}

func hasProfileSelection(args []string) bool {
	for _, arg := range args {
		if arg == "--profile" || strings.HasPrefix(arg, "--profile=") ||
			arg == "--config" || strings.HasPrefix(arg, "--config=") {
			return true
		}
	}
	return false
}

// installPolicyWindowsUnscanned reports whether the built-in profile would
// need Docker on native Windows. Explicit --scanner or --sandbox arguments and
// operator-owned configs keep their own execution.
func installPolicyWindowsUnscanned(opts runner.Options, args []string, goos string) bool {
	return goos == "windows" &&
		opts.Profile == "openclaw-install-policy" &&
		opts.ConfigSource == "built-in" &&
		!hasInstallPolicyExecutionOverride(args) &&
		!hasInstallPolicyConfigOverride(args)
}

// installPolicyMetadataValidationOnly reports whether a validated npm metadata
// preflight under the built-in profile needs no scan: the metadata is not
// plugin code, and OpenClaw submits the package and dependency tree for
// separate code scans.
func installPolicyMetadataValidationOnly(opts runner.Options, args []string, metadataPreflight bool) bool {
	return metadataPreflight &&
		opts.Profile == "openclaw-install-policy" &&
		opts.ConfigSource == "built-in" &&
		!hasInstallPolicyExecutionOverride(args) &&
		!hasInstallPolicyConfigOverride(args)
}

func hasInstallPolicyExecutionOverride(args []string) bool {
	for _, arg := range args {
		if arg == "--scanner" || strings.HasPrefix(arg, "--scanner=") ||
			arg == "--sandbox" || strings.HasPrefix(arg, "--sandbox=") {
			return true
		}
	}
	return false
}

func hasInstallPolicyConfigOverride(args []string) bool {
	for _, arg := range args {
		if arg == "--config" || strings.HasPrefix(arg, "--config=") {
			return true
		}
	}
	return false
}

func benchmarkRunContext(environ []string) runner.RunContext {
	return scanRunContext(environ)
}

func scanRunContext(environ []string) runner.RunContext {
	return scanRunContextWithCaller(nil, environ)
}

func scanRunContextWithCaller(caller context.Context, environ []string) runner.RunContext {
	ctx := runner.RunContext{Context: caller, Env: runner.EnvMap(environ)}
	if ctx.Env["CLAWSCAN_PROGRESS"] == "1" {
		ctx.Progress = os.Stderr
	}
	return ctx
}

func runBenchmarkCommand(ctx context.Context, args []string, environ []string) error {
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
	artifact, err := runner.RunBenchmark(opts, scanRunContextWithCaller(ctx, environ))
	if err != nil {
		if opts.JSON && artifact.SchemaVersion != "" {
			err = errors.Join(err, runner.WriteJSON(os.Stdout, artifact))
		}
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

func runAllProfiles(ctx context.Context, resolved profiles.ResolvedRunSet, environ []string, cwd string) error {
	if !resolved.JSON && resolved.OutputPath == "" {
		resolved.OutputPath = defaultOutputPath
	}
	if err := runner.ValidateOutputPaths(resolved.Options, resolved.OutputPath, cwd); err != nil {
		return err
	}
	batch, err := runner.RunProfileBatch(resolved.Options, scanRunContextWithCaller(ctx, environ), cwd)
	err = errors.Join(err, (runner.RunTargetsResult{Batch: &batch}).OperationalError())
	if err != nil {
		if resolved.OutputPath != "" {
			err = errors.Join(err, runner.WriteRunTargetsResultBundle(resolved.OutputPath, runner.RunTargetsResult{Batch: &batch}))
		}
		if resolved.JSON {
			err = errors.Join(err, runner.WriteJSON(os.Stdout, batch))
		}
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
	catalog, err := profiles.InspectProfiles()
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
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\n", info.ID, displayProfileSource(info.Source, cwd), strings.Join(info.Profile.ScannerIDs(), ", "), judge)
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
	fmt.Fprintf(w, "gate: %s", summary.Gate)
	if len(summary.GateRules) > 0 {
		details := make([]string, 0, len(summary.GateRules))
		for _, rule := range summary.GateRules {
			details = append(details, gateRuleSummary(rule))
		}
		fmt.Fprintf(w, " (%s)", strings.Join(details, ", "))
	}
	fmt.Fprintln(w)
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
	if summary.HasOverview {
		fmt.Fprintf(w, "overview_completed: %d\n", summary.OverviewDone)
		fmt.Fprintf(w, "overview_not_completed: %d\n", summary.OverviewFailed)
	}
	fmt.Fprintf(w, "errors: %d\n", summary.Errors)
	if outputPath != "" {
		fmt.Fprintf(w, "full_results: %s\n", displayOutputPath(outputPath))
	}
}

func gateRuleSummary(rule runner.FiredGateRule) string {
	if rule.ExitCode != nil {
		return fmt.Sprintf("%s exit %d -> %s", rule.Scanner, *rule.ExitCode, rule.Action)
	}
	if rule.Path != "" && len(rule.Value) > 0 {
		return fmt.Sprintf("%s %s %s=%s -> %s", rule.Scanner, rule.Rule, rule.Path, rule.Value, rule.Action)
	}
	if rule.Path != "" {
		return fmt.Sprintf("%s %s %s -> %s", rule.Scanner, rule.Rule, rule.Path, rule.Action)
	}
	return fmt.Sprintf("%s %s -> %s", rule.Scanner, rule.Rule, rule.Action)
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
	Gate             string
	GateRules        []runner.FiredGateRule
	HasJudge         bool
	JudgeCompleted   int
	JudgeFailed      int
	HasOverview      bool
	OverviewDone     int
	OverviewFailed   int
	Clean            int
	NeedsReview      int
	Malicious        int
	VerdictUnknown   int
	Errors           int
}

func summarizeRunTargets(result runner.RunTargetsResult) runSummary {
	summary := runSummary{Gate: "pass"}
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
	summary.GateRules = append(summary.GateRules, artifact.GateRules...)
	if artifact.Gate == "block" || (artifact.Gate == "warn" && summary.Gate == "pass") {
		summary.Gate = artifact.Gate
	}
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
	if artifact.Overview != nil {
		summary.HasOverview = true
		if artifact.Overview.Status == "completed" {
			summary.OverviewDone++
		} else {
			summary.OverviewFailed++
		}
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
	return countIssues(decoded)
}

func countIssues(value interface{}) int {
	switch typed := value.(type) {
	case map[string]interface{}:
		total := 0
		for key, nested := range typed {
			// Risk-based reports store named findings in a map, including empty maps for clean components.
			if key == "risk_indexes" {
				if risks, ok := nested.(map[string]interface{}); ok {
					total += len(risks)
					continue
				}
			}
			if isIssueArrayKey(key) {
				if items, ok := nested.([]interface{}); ok {
					total += len(items)
					continue
				}
			}
			total += countIssues(nested)
		}
		return total
	case []interface{}:
		total := 0
		for _, nested := range typed {
			total += countIssues(nested)
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
  clawscan openclaw-install-policy [--profile <profile-name>] [flags]
  clawscan <target> --scanner <scanner-id> [flags]
  clawscan --scanner <scanner-id> [flags]
  clawscan --profile clawhub [flags]
  clawscan --version
  clawscan --help

Core flags:
  --profile <name>            Profile to run. Use --profile clawhub for ClawHub parity.
  --config <path>             Load profiles from a specific .clawscan.yml file; omit --profile to run them all.
  --discover-config           Find and load the nearest .clawscan.yml/.clawscan.yaml in the current directory or a parent. Requires --profile. Off by default: config files can define scanners that run arbitrary commands, so ClawScan never loads config it was not explicitly told to trust.
  --scanner <id>              Scanner to run. Repeat for multiple scanners.
  --scanner-result <id=path>  Use a JSON fixture instead of running that scanner.
  --context <path>            Load profile runtime context from a JSON file.
  --output <path>             Write the full artifact JSON to a specific file.
                              Defaults to ./clawscan-results/artifact.json unless --json is passed.
                              Explicit .json paths keep the artifact file and write scanner JSON beside it.
  --json                      Print the full artifact JSON to stdout and skip default file writes unless --output is passed.
  --judge <cmd>               Optional external judge harness command.
  --overview <cmd>            Optional overview command that summarizes a completed judge verdict.
  --no-overview               Skip the selected profile's overview step for this run.
  --sandbox <docker|off>      Command sandbox mode. Defaults to docker.
  --sandbox-image <image>     Docker runtime image. Defaults to %s or CLAWSCAN_SANDBOX_IMAGE.
  --sandbox-env <name>        Allow an env var through the Docker sandbox. Repeat for multiple vars.
  --sandbox-mount <path[:rw]>  Bind-mount a host path into the Docker sandbox (read-only; append :rw for writable). Repeat for multiple.

OpenClaw install policy:
  openclaw-install-policy     Read an OpenClaw security.installPolicy request from stdin and
                             return its protocol v1 allow/warn/block response on stdout.
                             Defaults to the composable openclaw-install-policy profile.

Benchmark command flags:
  --split <name>              Benchmark split. Defaults to benchmark for SkillTrustBench and eval_holdout for clawhub-security-signals.
  --ids <path-or-url>         Run selected benchmark IDs from a streamed text or JSONL source (max 5520 IDs). SkillTrustBench only.
                             Max 256 bytes per trimmed ID and 256 KiB total ID text, not source size; lines must be under 1 MiB.
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
  clawscan profiles           List built-in profiles.
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
  aig: LLM_API_KEY or OPENAI_API_KEY. Use "clawscan scanners aig" for local scanner details and optional model configuration.
  socket: SOCKET_CLI_API_TOKEN
  snyk: SNYK_TOKEN
  skillspector: no ClawScan-required env vars; provider env vars enable LLM mode, otherwise --no-llm is used. Use "clawscan scanners skillspector" for provider vars.
  cisco: no ClawScan-required env vars; optional upstream env vars enable LLM, VirusTotal, and Cisco AI Defense analyzers.
  judge: provider credentials belong to the command passed to --judge.
         The clawhub judge (clawscan-decisions-judge) uses DECISIONS_API_KEY or OPENAI_API_KEY,
         DECISIONS_BASE_URL or OPENAI_BASE_URL, and DECISIONS_MODEL (default gpt-6-luna).
  overview: the clawhub overview runs Codex with CODEX_API_KEY or OPENAI_API_KEY, OVERVIEW_MODEL
            (default gpt-6-luna), and OPENAI_BASE_URL when set.
  sandbox: CLAWSCAN_SANDBOX=off disables Docker by default; CLAWSCAN_SANDBOX_IMAGE overrides the runtime image.
           Process supervisors can set CLAWSCAN_SANDBOX_RUN_ID to identify only that process's Docker containers for cleanup.

Target notes:
  No target with --scanner, --profile, or --config scans child skill directories under ./skills.
  Plain clawscan without --scanner, --profile, or --config is invalid.
  Most scanners use a local skill file or directory target.
  A directory holding openclaw.plugin.json is scanned as an OpenClaw plugin.
  The clawhub profile runs SkillSpector for plugins as it does for skills.
  Other skill-only scanners return a skipped result for plugins.
  Plugins are never auto-discovered; pass the plugin directory explicitly.
  Socket runs the public Socket CLI full-scan path over local dependency manifests.

Judge summary:
  A selected profile may configure a judge; --judge overrides that command for one run.
  If no judge is configured, ClawScan only records scanner evidence.
  If a judge is configured, ClawScan runs it through the platform shell and expects a JSON object on stdout or at {{ output }}.
  Placeholders: {{ workspace }}, {{ prompt[:path] }}, {{ output_schema[:path] }}, {{ output }}.
  A profile may also configure an overview command; --overview overrides it and --no-overview skips it.
  The overview runs after a completed verdict with the same placeholders and judge.json in the workspace.
  Its result is recorded under overview and never changes the verdict, gate, or exit status.
`, runner.DefaultSandboxImage, strings.Join(runner.ScannerIDs(), ", "), strings.Join(profiles.ProfileIDs(), ", "))
}

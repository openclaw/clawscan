package runner

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/url"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/openclaw/clawscan/internal/clawhubprompt"
)

type Options struct {
	Target             string
	Profile            string
	ContextPath        string
	Benchmark          *BenchmarkOptions
	Scanners           []string
	ScannerResultPaths map[string]string
	OutputPath         string
	JSON               bool
	Judge              *JudgeOptions
	Sandbox            SandboxOptions
}

type BenchmarkOptions struct {
	ID                    string
	Split                 string
	Limit                 int
	Offset                int
	PredictionsOutputPath string
	IDsSource             string
	IDs                   []string
	IDsSHA256             string
}

type JudgeOptions struct {
	Command string
	Files   map[string][]byte
}

type EnvRequirement struct {
	EnvVar string
	Reason string
}

type RunContext struct {
	Env                  map[string]string
	Now                  func() time.Time
	CommandRunner        CommandRunner
	HostCommandRunner    CommandRunner
	DockerAvailability   func() error
	ScannerRunner        ScannerRunner
	SkillSpectorCommand  []string
	VirusTotalHTTPClient VirusTotalHTTPClient
	BenchmarkClient      BenchmarkClient
}

type ScannerRunner interface {
	RunScanner(name string, target string, startedAt string) (ScannerResult, error)
}

type CommandRunner interface {
	Run(command string, args []string, cwd string, timeout time.Duration) (CommandOutput, error)
}

type CommandOutput struct {
	Stdout string
	Stderr string
}

type Artifact struct {
	SchemaVersion string                   `json:"schemaVersion"`
	Profile       string                   `json:"profile,omitempty"`
	Context       json.RawMessage          `json:"context,omitempty"`
	Target        Target                   `json:"target"`
	StartedAt     string                   `json:"startedAt"`
	CompletedAt   string                   `json:"completedAt"`
	Env           map[string]string        `json:"env"`
	Sandbox       SandboxMetadata          `json:"sandbox"`
	Scanners      map[string]ScannerResult `json:"scanners"`
	Judge         *JudgeResult             `json:"judge"`
}

type RunTargetsResult struct {
	Single *Artifact
	Batch  *BatchArtifact
}

func (result RunTargetsResult) JSONValue() interface{} {
	if result.Batch != nil {
		return result.Batch
	}
	if result.Single != nil {
		return result.Single
	}
	return nil
}

type BatchArtifact struct {
	SchemaVersion string            `json:"schemaVersion"`
	Profile       string            `json:"profile,omitempty"`
	StartedAt     string            `json:"startedAt"`
	CompletedAt   string            `json:"completedAt"`
	Env           map[string]string `json:"env"`
	Sandbox       SandboxMetadata   `json:"sandbox"`
	Runs          []Artifact        `json:"runs"`
	Errors        []BatchError      `json:"errors,omitempty"`
	Summary       BatchSummary      `json:"summary"`
}

type BatchError struct {
	Profile string `json:"profile"`
	Error   string `json:"error"`
}

type BatchSummary struct {
	ProfileCount    int                       `json:"profileCount,omitempty"`
	TargetCount     int                       `json:"targetCount"`
	ScannerStatuses map[string]map[string]int `json:"scannerStatuses"`
}

type Target struct {
	Kind         string `json:"kind"`
	Input        string `json:"input"`
	ResolvedPath string `json:"resolvedPath"`
	// ID is a stable, host-path-free target identity. It is populated for
	// plugin targets from their manifest and left empty for skills and
	// URLs, which are already identified by their input.
	ID string `json:"id,omitempty"`
}

type ScannerResult struct {
	Status      string          `json:"status"`
	StartedAt   string          `json:"startedAt"`
	CompletedAt string          `json:"completedAt"`
	DurationMs  int64           `json:"durationMs"`
	Command     []string        `json:"command"`
	Error       string          `json:"error"`
	OutputPath  string          `json:"outputPath,omitempty"`
	Raw         json.RawMessage `json:"raw"`
}

type TargetWorkspaceManifest struct {
	Copied            []TargetWorkspaceFile     `json:"copied"`
	Omitted           []TargetWorkspaceOmission `json:"omitted"`
	TotalCopiedBytes  int64                     `json:"totalCopiedBytes"`
	SuppressedCopied  int                       `json:"suppressedCopied"`
	SuppressedOmitted int                       `json:"suppressedOmitted"`
	TotalOmittedBytes int64                     `json:"totalOmittedBytes"`
}

type TargetWorkspaceFile struct {
	Path  string `json:"path"`
	Bytes int64  `json:"bytes"`
}

type TargetWorkspaceOmission struct {
	Path   string `json:"path"`
	Reason string `json:"reason"`
	Bytes  int64  `json:"bytes,omitempty"`
}

type JudgeResult struct {
	Status           string      `json:"status"`
	Command          string      `json:"command,omitempty"`
	PromptPath       string      `json:"promptPath,omitempty"`
	OutputSchemaPath string      `json:"outputSchemaPath,omitempty"`
	OutputPath       string      `json:"outputPath,omitempty"`
	PromptSHA        string      `json:"promptSha256,omitempty"`
	OutputSchemaSHA  string      `json:"outputSchemaSha256,omitempty"`
	Error            string      `json:"error"`
	Result           interface{} `json:"result"`
}

func ScannerIDs() []string {
	return DefaultScannerRegistry().IDs()
}

func NewBenchmarkOptions(id string, split string, limit int, offset int, predictionsOutputPath string, idsSource string) (*BenchmarkOptions, error) {
	if strings.TrimSpace(id) == "" {
		return nil, errors.New("Benchmark id is required")
	}
	if limit < 0 {
		return nil, errors.New("Benchmark limit cannot be negative")
	}
	if offset < 0 {
		return nil, errors.New("Benchmark offset cannot be negative")
	}
	canonicalID, err := canonicalBenchmarkID(id)
	if err != nil {
		return nil, err
	}
	if split == "" {
		split = defaultBenchmarkSplit(canonicalID)
	}
	if err := validateBenchmarkSplit(canonicalID, split); err != nil {
		return nil, err
	}
	if idsSource != "" {
		if canonicalID != skillTrustBenchID {
			return nil, errors.New("--ids is currently supported for SkillTrustBench only")
		}
		if limit != 0 || offset != 0 {
			return nil, errors.New("--ids is mutually exclusive with --limit and --offset")
		}
	}
	return &BenchmarkOptions{
		ID:                    canonicalID,
		Split:                 split,
		Limit:                 limit,
		Offset:                offset,
		PredictionsOutputPath: predictionsOutputPath,
		IDsSource:             idsSource,
	}, nil
}

func ParseArgs(args []string) (Options, error) {
	opts := Options{ScannerResultPaths: map[string]string{}}
	start := 0
	if len(args) > 0 && !strings.HasPrefix(args[0], "--") {
		opts.Target = args[0]
		start = 1
	}
	var judge string
	for i := start; i < len(args); i++ {
		arg := args[i]
		switch arg {
		case "--scanner":
			value, next, err := readValue(args, i, arg)
			if err != nil {
				return Options{}, err
			}
			if !DefaultScannerRegistry().Contains(value) {
				return Options{}, fmt.Errorf("Unknown scanner: %s", value)
			}
			opts.Scanners = append(opts.Scanners, value)
			i = next
		case "--profile":
			value, next, err := readValue(args, i, arg)
			if err != nil {
				return Options{}, err
			}
			opts.Profile = value
			i = next
		case "--context":
			value, next, err := readValue(args, i, arg)
			if err != nil {
				return Options{}, err
			}
			opts.ContextPath = value
			i = next
		case "--scanner-result":
			value, next, err := readValue(args, i, arg)
			if err != nil {
				return Options{}, err
			}
			scanner, path, ok := strings.Cut(value, "=")
			if !ok || scanner == "" || path == "" {
				return Options{}, errors.New("Expected --scanner-result value as scanner=path")
			}
			if !DefaultScannerRegistry().Contains(scanner) {
				return Options{}, fmt.Errorf("Unknown scanner: %s", scanner)
			}
			opts.ScannerResultPaths[scanner] = path
			i = next
		case "--output":
			value, next, err := readValue(args, i, arg)
			if err != nil {
				return Options{}, err
			}
			opts.OutputPath = value
			i = next
		case "--json":
			opts.JSON = true
		case "--judge":
			value, next, err := readValue(args, i, arg)
			if err != nil {
				return Options{}, err
			}
			judge = value
			i = next
		case "--sandbox":
			value, next, err := readValue(args, i, arg)
			if err != nil {
				return Options{}, err
			}
			value = strings.ToLower(strings.TrimSpace(value))
			if err := validateSandboxMode(value, "--sandbox"); err != nil {
				return Options{}, err
			}
			opts.Sandbox.Mode = value
			i = next
		case "--sandbox-image":
			value, next, err := readValue(args, i, arg)
			if err != nil {
				return Options{}, err
			}
			opts.Sandbox.Image = value
			i = next
		case "--sandbox-env":
			value, next, err := readValue(args, i, arg)
			if err != nil {
				return Options{}, err
			}
			opts.Sandbox.Env = append(opts.Sandbox.Env, value)
			i = next
		default:
			return Options{}, fmt.Errorf("Unknown argument: %s", arg)
		}
	}
	if len(opts.Scanners) == 0 {
		return Options{}, errors.New("At least one --scanner is required")
	}
	requestedScanners := map[string]bool{}
	for _, scanner := range opts.Scanners {
		requestedScanners[scanner] = true
	}
	for scanner := range opts.ScannerResultPaths {
		if !requestedScanners[scanner] {
			return Options{}, fmt.Errorf("Scanner result provided for unrequested scanner: %s", scanner)
		}
	}
	if judge != "" {
		opts.Judge = &JudgeOptions{Command: judge}
	}
	return opts, nil
}

func ValidateRequirements(opts Options, env map[string]string) error {
	var missing []EnvRequirement
	for _, req := range requirements(opts, env) {
		if strings.TrimSpace(env[req.EnvVar]) == "" {
			missing = append(missing, req)
		}
	}
	if len(missing) == 0 {
		return nil
	}
	lines := []string{"Missing required environment variables:", ""}
	for _, req := range missing {
		lines = append(lines, fmt.Sprintf("- %s required by %s", req.EnvVar, req.Reason))
	}
	return errors.New(strings.Join(lines, "\n"))
}

func Run(opts Options, ctx RunContext) (Artifact, error) {
	env := ctx.Env
	if env == nil {
		env = EnvMap(os.Environ())
	}
	applyRuntimeEnvDefaults(opts, env)
	target, err := resolveTarget(opts.Target)
	if err != nil {
		return Artifact{}, err
	}
	// Requirement validation and sandbox gating only consider scanners that
	// will run for this target kind; a scanner that can only skip must not
	// demand credentials or Docker.
	gatingOpts := opts
	gatingOpts.Scanners = runnableScanners(opts, target.kind)
	if err := ValidateRequirements(gatingOpts, env); err != nil {
		return Artifact{}, err
	}
	now := ctx.Now
	if now == nil {
		now = time.Now
	}
	startedAt := now().UTC().Format(time.RFC3339Nano)
	commandRunner, sandbox, err := commandRunnerForOptions(gatingOpts, ctx, env)
	if err != nil {
		return Artifact{}, err
	}
	scannerRunner := ctx.ScannerRunner
	if scannerRunner == nil {
		scannerSandboxMode := sandbox.Mode
		if ctx.CommandRunner != nil {
			scannerSandboxMode = SandboxModeOff
		}
		scannerRunner = ExternalScannerRunner{
			CommandRunner:        commandRunner,
			Env:                  env,
			Profile:              opts.Profile,
			SandboxMode:          scannerSandboxMode,
			SkillSpectorCommand:  ctx.SkillSpectorCommand,
			VirusTotalHTTPClient: ctx.VirusTotalHTTPClient,
			Timeout:              20 * time.Minute,
		}
	}
	artifact := NewArtifact(opts, target.resolvedPath, startedAt, startedAt, env)
	artifact.Sandbox = sandbox
	artifact.Target.Kind = target.kind
	artifact.Target.ID = target.id
	if opts.ContextPath != "" {
		context, err := os.ReadFile(opts.ContextPath)
		if err != nil {
			return Artifact{}, fmt.Errorf("read context JSON: %w", err)
		}
		if !json.Valid(context) {
			return Artifact{}, fmt.Errorf("context JSON is not valid: %s", opts.ContextPath)
		}
		artifact.Context = json.RawMessage(context)
	}
	for _, scanner := range opts.Scanners {
		scannerStartedAt := now().UTC().Format(time.RFC3339Nano)
		scannerTimerStarted := time.Now()
		result, err := scannerResult(opts, scanner, target, scannerStartedAt, scannerRunner)
		if err != nil {
			return Artifact{}, err
		}
		result.DurationMs = time.Since(scannerTimerStarted).Milliseconds()
		artifact.Scanners[scanner] = result
	}
	if opts.Judge != nil {
		result, err := RunJudge(*opts.Judge, artifact, commandRunner, 20*time.Minute, env, sandbox.Mode)
		if err != nil {
			return Artifact{}, err
		}
		artifact.Judge = result
	}
	artifact.CompletedAt = now().UTC().Format(time.RFC3339Nano)
	if opts.OutputPath != "" {
		if err := WriteRunTargetsResultBundle(opts.OutputPath, RunTargetsResult{Single: &artifact}); err != nil {
			return Artifact{}, err
		}
	}
	return artifact, nil
}

func RunTargets(opts Options, ctx RunContext, cwd string) (RunTargetsResult, error) {
	targetInputs, err := ResolveTargetInputs(opts, cwd)
	if err != nil {
		return RunTargetsResult{}, err
	}
	if len(targetInputs) == 1 {
		runOpts := opts
		runOpts.Target = targetInputs[0]
		outputPath := runOpts.OutputPath
		runOpts.OutputPath = ""
		artifact, err := Run(runOpts, ctx)
		if err != nil {
			return RunTargetsResult{}, err
		}
		if outputPath != "" {
			if err := WriteRunTargetsResultBundle(outputPath, RunTargetsResult{Single: &artifact}); err != nil {
				return RunTargetsResult{}, err
			}
		}
		return RunTargetsResult{Single: &artifact}, nil
	}

	env := ctx.Env
	if env == nil {
		env = EnvMap(os.Environ())
	}
	now := ctx.Now
	if now == nil {
		now = time.Now
	}
	startedAt := now().UTC().Format(time.RFC3339Nano)
	runCtx := ctx
	runCtx.Env = env
	runCtx.Now = now
	batch := BatchArtifact{
		SchemaVersion: "clawscan-batch-v1",
		Profile:       opts.Profile,
		StartedAt:     startedAt,
		Env:           envPresence(opts, env),
		Sandbox:       mustSandboxMetadata(opts, env),
		Runs:          []Artifact{},
		Summary: BatchSummary{
			TargetCount:     len(targetInputs),
			ScannerStatuses: map[string]map[string]int{},
		},
	}
	for _, targetInput := range targetInputs {
		runOpts := opts
		runOpts.Target = targetInput
		runOpts.OutputPath = ""
		artifact, err := Run(runOpts, runCtx)
		if err != nil {
			return RunTargetsResult{}, err
		}
		batch.Runs = append(batch.Runs, artifact)
		for scanner, result := range artifact.Scanners {
			if batch.Summary.ScannerStatuses[scanner] == nil {
				batch.Summary.ScannerStatuses[scanner] = map[string]int{}
			}
			batch.Summary.ScannerStatuses[scanner][result.Status]++
		}
	}
	batch.CompletedAt = now().UTC().Format(time.RFC3339Nano)
	if opts.OutputPath != "" {
		if err := WriteRunTargetsResultBundle(opts.OutputPath, RunTargetsResult{Batch: &batch}); err != nil {
			return RunTargetsResult{}, err
		}
	}
	return RunTargetsResult{Batch: &batch}, nil
}

func RunProfileBatch(optsList []Options, ctx RunContext, cwd string) (BatchArtifact, error) {
	env := ctx.Env
	if env == nil {
		env = EnvMap(os.Environ())
	}
	now := ctx.Now
	if now == nil {
		now = time.Now
	}
	startedAt := now().UTC().Format(time.RFC3339Nano)
	runCtx := ctx
	runCtx.Env = env
	runCtx.Now = now
	batch := BatchArtifact{
		SchemaVersion: "clawscan-batch-v1",
		StartedAt:     startedAt,
		Env:           map[string]string{},
		Sandbox:       sandboxMetadataForOptionList(optsList, env),
		Runs:          []Artifact{},
		Summary: BatchSummary{
			ProfileCount:    len(optsList),
			ScannerStatuses: map[string]map[string]int{},
		},
	}
	targets := map[string]bool{}
	for _, opts := range optsList {
		runOpts := opts
		runOpts.OutputPath = ""
		for key, value := range envPresence(runOpts, env) {
			batch.Env[key] = value
		}
		result, err := RunTargets(runOpts, runCtx, cwd)
		if err != nil {
			batch.Errors = append(batch.Errors, BatchError{Profile: runOpts.Profile, Error: err.Error()})
			continue
		}
		if result.Single != nil {
			addBatchRun(&batch, *result.Single, targets)
		}
		if result.Batch != nil {
			for _, run := range result.Batch.Runs {
				addBatchRun(&batch, run, targets)
			}
		}
	}
	batch.Summary.TargetCount = len(targets)
	batch.CompletedAt = now().UTC().Format(time.RFC3339Nano)
	return batch, nil
}

func addBatchRun(batch *BatchArtifact, artifact Artifact, targets map[string]bool) {
	batch.Runs = append(batch.Runs, artifact)
	targets[artifact.Target.Input] = true
	for scanner, result := range artifact.Scanners {
		if batch.Summary.ScannerStatuses[scanner] == nil {
			batch.Summary.ScannerStatuses[scanner] = map[string]int{}
		}
		batch.Summary.ScannerStatuses[scanner][result.Status]++
	}
}

func WriteJSONFile(path string, value interface{}) error {
	return writeJSONFile(path, value)
}

func WriteRunTargetsResultBundle(outputPath string, result RunTargetsResult) error {
	if outputPath == "" {
		return errors.New("output path is required")
	}
	spec := outputBundleSpecFor(outputPath)
	switch {
	case result.Single != nil:
		if err := writeScannerOutputFiles(spec, []*Artifact{result.Single}); err != nil {
			return err
		}
		return writeJSONFile(spec.ArtifactPath, result.Single)
	case result.Batch != nil:
		runs := make([]*Artifact, 0, len(result.Batch.Runs))
		for i := range result.Batch.Runs {
			runs = append(runs, &result.Batch.Runs[i])
		}
		if err := writeScannerOutputFiles(spec, runs); err != nil {
			return err
		}
		return writeJSONFile(spec.ArtifactPath, result.Batch)
	default:
		return errors.New("run targets result is empty")
	}
}

type outputBundleSpec struct {
	ArtifactPath string
	RootDir      string
	PathPrefix   string
}

func outputBundleSpecFor(outputPath string) outputBundleSpec {
	clean := filepath.Clean(outputPath)
	rootDir := filepath.Dir(clean)
	prefix := ""
	base := filepath.Base(clean)
	ext := filepath.Ext(base)
	if !strings.EqualFold(base, "artifact.json") {
		stem := strings.TrimSuffix(base, ext)
		if ext == "" {
			stem = base + "-scanners"
		}
		prefix = safeOutputPathSegment(stem)
	}
	return outputBundleSpec{ArtifactPath: clean, RootDir: rootDir, PathPrefix: prefix}
}

func writeScannerOutputFiles(spec outputBundleSpec, artifacts []*Artifact) error {
	usedRunPaths := map[string]int{}
	for _, artifact := range artifacts {
		runPath := uniqueOutputPath(scannerRunOutputPath(*artifact), usedRunPaths)
		scanners := make([]string, 0, len(artifact.Scanners))
		for scanner := range artifact.Scanners {
			scanners = append(scanners, scanner)
		}
		sort.Strings(scanners)
		for _, scanner := range scanners {
			result := artifact.Scanners[scanner]
			if len(result.Raw) == 0 {
				result.OutputPath = ""
				artifact.Scanners[scanner] = result
				continue
			}
			relPath := filepath.ToSlash(filepath.Join(spec.PathPrefix, runPath, safeOutputPathSegment(scanner)+".json"))
			absPath := filepath.Join(spec.RootDir, filepath.FromSlash(relPath))
			if err := os.MkdirAll(filepath.Dir(absPath), 0o755); err != nil {
				return err
			}
			if err := os.WriteFile(absPath, result.Raw, 0o644); err != nil {
				return err
			}
			result.OutputPath = relPath
			artifact.Scanners[scanner] = result
		}
	}
	return nil
}

func scannerRunOutputPath(artifact Artifact) string {
	targetPath := targetOutputPath(artifact.Target.Input)
	if targetPath == "" {
		targetPath = targetOutputPath(artifact.Target.ResolvedPath)
	}
	if targetPath == "" {
		targetPath = "target"
	}
	if artifact.Profile == "" {
		return targetPath
	}
	return filepath.ToSlash(filepath.Join("profiles", safeOutputPathSegment(artifact.Profile), targetPath))
}

func targetOutputPath(input string) string {
	input = strings.TrimSpace(input)
	if input == "" {
		return ""
	}
	if isURLTarget(input) {
		parsed, _ := url.Parse(input)
		label := safeOutputPathSegment(parsed.Host + parsed.EscapedPath())
		if label == "" {
			label = "url"
		}
		return filepath.ToSlash(filepath.Join("targets", label+"-"+shortSHA(input)))
	}
	clean := filepath.Clean(input)
	if filepath.IsAbs(clean) {
		return safeOutputPathSegment(filepath.Base(clean))
	}
	parts := strings.Split(filepath.ToSlash(clean), "/")
	safeParts := make([]string, 0, len(parts))
	for _, part := range parts {
		switch part {
		case "", ".":
			continue
		case "..":
			safeParts = append(safeParts, "up")
		default:
			safeParts = append(safeParts, safeOutputPathSegment(part))
		}
	}
	return strings.Join(safeParts, "/")
}

func uniqueOutputPath(base string, used map[string]int) string {
	used[base]++
	if used[base] == 1 {
		return base
	}
	dir, file := path.Split(base)
	return dir + file + "-" + strconv.Itoa(used[base])
}

func safeOutputPathSegment(value string) string {
	value = strings.TrimSpace(strings.ToLower(value))
	var builder strings.Builder
	lastDash := false
	for _, r := range value {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') {
			builder.WriteRune(r)
			lastDash = false
			continue
		}
		if r == '-' || r == '_' {
			builder.WriteRune(r)
			lastDash = false
			continue
		}
		if !lastDash {
			builder.WriteByte('-')
			lastDash = true
		}
	}
	safe := strings.Trim(builder.String(), "-")
	if safe == "" {
		return "item"
	}
	return safe
}

func shortSHA(value string) string {
	sum := sha256.Sum256([]byte(value))
	return hex.EncodeToString(sum[:])[:8]
}

func ResolveTargetInputs(opts Options, cwd string) ([]string, error) {
	if opts.Benchmark != nil {
		return nil, errors.New("benchmark runs do not use scan target discovery")
	}
	if opts.Target != "" {
		return []string{opts.Target}, nil
	}
	if cwd == "" {
		var err error
		cwd, err = os.Getwd()
		if err != nil {
			return nil, err
		}
	}
	skillsDir := filepath.Join(cwd, "skills")
	info, err := os.Stat(skillsDir)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, errors.New("No scan target provided and ./skills was not found. Pass a target path or run from a repository root with skills/<skill>/SKILL.md.")
		}
		return nil, err
	}
	if !info.IsDir() {
		return nil, errors.New("No scan target provided and ./skills is not a directory. Pass a target path or run from a repository root with skills/<skill>/SKILL.md.")
	}
	entries, err := os.ReadDir(skillsDir)
	if err != nil {
		return nil, err
	}
	var targets []string
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		skillFile := filepath.Join(skillsDir, entry.Name(), "SKILL.md")
		if info, err := os.Stat(skillFile); err == nil && !info.IsDir() {
			targets = append(targets, filepath.ToSlash(filepath.Join("skills", entry.Name())))
		}
	}
	sort.Strings(targets)
	if len(targets) == 0 {
		return nil, errors.New("No valid skills found under ./skills. Expected child skill directories containing SKILL.md.")
	}
	return targets, nil
}

func writeJSONFile(path string, value interface{}) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	file, err := os.Create(path)
	if err != nil {
		return err
	}
	defer file.Close()
	return WriteJSON(file, value)
}

func scannerResult(opts Options, scanner string, target resolvedTarget, startedAt string, scannerRunner ScannerRunner) (ScannerResult, error) {
	if path := opts.ScannerResultPaths[scanner]; path != "" {
		raw, err := os.ReadFile(path)
		if err != nil {
			return ScannerResult{}, err
		}
		if !json.Valid(raw) {
			return ScannerResult{}, fmt.Errorf("scanner result %s is not valid JSON: %s", scanner, path)
		}
		return ScannerResult{
			Status:      "completed",
			StartedAt:   startedAt,
			CompletedAt: startedAt,
			Command:     []string{"scanner-result", scanner + "=" + path},
			Error:       "",
			Raw:         json.RawMessage(raw),
		}, nil
	}
	if !scannerSupportsTargetKind(scanner, target.kind) {
		return unsupportedTargetKindResult(scanner, target.kind, startedAt), nil
	}
	return scannerRunner.RunScanner(scanner, target.resolvedPath, startedAt)
}

var promptPlaceholderPattern = regexp.MustCompile(`\{\{\s*(scanners\.([a-zA-Z0-9_-]+)|target\.files)\s*\}\}`)
var judgePlaceholderPattern = regexp.MustCompile(`\{\{\s*([a-zA-Z_][a-zA-Z0-9_]*)(?::([^}]+))?\s*\}\}`)

const maxTargetFileBytes = 64 * 1024
const maxTargetFilesBytes = 256 * 1024
const maxOmittedTargetFileMarkers = 25
const defaultJudgePromptPath = "./prompt.md"
const defaultJudgeOutputSchemaPath = "./schema.json"

func RenderPromptTemplate(template string, artifact Artifact) (string, error) {
	var renderErr error
	var targetFiles string
	targetFilesRendered := false
	rendered := promptPlaceholderPattern.ReplaceAllStringFunc(template, func(match string) string {
		if renderErr != nil {
			return match
		}
		parts := promptPlaceholderPattern.FindStringSubmatch(match)
		if len(parts) != 3 {
			return match
		}
		if parts[1] == "target.files" {
			if !targetFilesRendered {
				targetFiles, renderErr = renderTargetFiles(artifact.Target.ResolvedPath)
				targetFilesRendered = true
			}
			return targetFiles
		}
		scanner := parts[2]
		result, ok := artifact.Scanners[scanner]
		if !ok {
			renderErr = fmt.Errorf("prompt references scanner %s, but it was not requested", scanner)
			return match
		}
		if len(result.Raw) == 0 {
			return "null"
		}
		var buffer bytes.Buffer
		if err := json.Indent(&buffer, result.Raw, "", "  "); err != nil {
			renderErr = fmt.Errorf("format scanner %s JSON: %w", scanner, err)
			return match
		}
		return buffer.String()
	})
	if renderErr != nil {
		return "", renderErr
	}
	return rendered, nil
}

func renderTargetFiles(target string) (string, error) {
	var paths []string
	type targetFileOmission struct {
		path   string
		reason string
	}
	var precomputedOmissions []targetFileOmission
	targetInfo, err := os.Stat(target)
	if err != nil {
		return "", err
	}
	if !targetInfo.IsDir() {
		paths = append(paths, target)
	} else {
		if err := filepath.WalkDir(target, func(path string, entry os.DirEntry, err error) error {
			if err != nil {
				precomputedOmissions = append(precomputedOmissions, targetFileOmission{path: path, reason: "read failed"})
				if entry != nil && entry.IsDir() {
					return filepath.SkipDir
				}
				return nil
			}
			if entry.IsDir() {
				if shouldSkipTargetPath(target, path) {
					precomputedOmissions = append(precomputedOmissions, targetFileOmission{path: path, reason: "skipped path"})
					return filepath.SkipDir
				}
				return nil
			}
			info, err := entry.Info()
			if err != nil {
				return err
			}
			if info.Mode().IsRegular() {
				paths = append(paths, path)
			}
			return nil
		}); err != nil {
			return "", err
		}
	}
	sort.SliceStable(paths, func(i int, j int) bool {
		leftPriority := targetFilePriority(target, paths[i])
		rightPriority := targetFilePriority(target, paths[j])
		if leftPriority != rightPriority {
			return leftPriority < rightPriority
		}
		return paths[i] < paths[j]
	})
	var blocks []string
	totalBytes := 0
	omittedMarkers := 0
	suppressedOmissions := 0
	addOmission := func(path string, reason string) {
		if omittedMarkers < maxOmittedTargetFileMarkers {
			blocks = append(blocks, omittedTargetFileBlock(target, path, reason))
			omittedMarkers++
			return
		}
		suppressedOmissions++
	}
	for _, path := range paths {
		if shouldSkipTargetPath(target, path) {
			addOmission(path, "skipped path")
			continue
		}
		info, err := os.Stat(path)
		if err != nil {
			return "", err
		}
		if info.Size() > maxTargetFileBytes {
			addOmission(path, "file exceeds size limit")
			continue
		}
		if totalBytes+int(info.Size()) > maxTargetFilesBytes {
			addOmission(path, "total file budget exceeded")
			continue
		}
		content, err := os.ReadFile(path)
		if err != nil {
			if isSourceReadError(err, path) {
				addOmission(path, "read failed")
				continue
			}
			return "", err
		}
		if bytes.IndexByte(content, 0) >= 0 {
			addOmission(path, "binary file")
			continue
		}
		totalBytes += len(content)
		label := filepath.Base(path)
		if targetInfo.IsDir() {
			rel, err := filepath.Rel(target, path)
			if err != nil {
				return "", err
			}
			label = rel
		}
		text := strings.TrimRight(string(content), "\n")
		fence := fenceForContent(text)
		blocks = append(blocks, fmt.Sprintf("### %s\n%s%s\n%s\n%s", markdownPathLabel(label), fence, languageForPath(path), text, fence))
	}
	sort.SliceStable(precomputedOmissions, func(i int, j int) bool {
		leftPriority := targetFilePriority(target, precomputedOmissions[i].path)
		rightPriority := targetFilePriority(target, precomputedOmissions[j].path)
		if leftPriority != rightPriority {
			return leftPriority < rightPriority
		}
		return precomputedOmissions[i].path < precomputedOmissions[j].path
	})
	for _, omission := range precomputedOmissions {
		addOmission(omission.path, omission.reason)
	}
	if suppressedOmissions > 0 {
		blocks = append(blocks, fmt.Sprintf("### Additional omitted files\n[omitted: %d additional files]", suppressedOmissions))
	}
	return strings.Join(blocks, "\n\n"), nil
}

func targetFilePriority(root string, path string) int {
	rel, err := filepath.Rel(root, path)
	if err != nil {
		rel = path
	}
	if strings.EqualFold(filepath.ToSlash(rel), "SKILL.md") {
		return 0
	}
	return 1
}

func omittedTargetFileBlock(root string, path string, reason string) string {
	rel, err := filepath.Rel(root, path)
	if err != nil {
		rel = path
	}
	if rel == "." {
		rel = filepath.Base(path)
	}
	return fmt.Sprintf("### %s\n[omitted: %s]", markdownPathLabel(rel), reason)
}

func markdownPathLabel(label string) string {
	quoted := strconv.Quote(filepath.ToSlash(label))
	return quoted[1 : len(quoted)-1]
}

func shouldSkipTargetPath(root string, path string) bool {
	rel, err := filepath.Rel(root, path)
	if err != nil {
		return true
	}
	for _, part := range strings.Split(rel, string(filepath.Separator)) {
		switch part {
		case ".git", "node_modules", "vendor", ".venv", "__pycache__":
			return true
		}
	}
	return false
}

func fenceForContent(content string) string {
	fence := "```"
	for strings.Contains(content, fence) {
		fence += "`"
	}
	return fence
}

func languageForPath(path string) string {
	switch strings.ToLower(filepath.Ext(path)) {
	case ".md", ".markdown":
		return "markdown"
	case ".json":
		return "json"
	case ".js", ".mjs", ".cjs":
		return "javascript"
	case ".ts", ".tsx":
		return "typescript"
	case ".sh", ".bash", ".zsh":
		return "bash"
	default:
		return "text"
	}
}

func sha256Hex(value string) string {
	sum := sha256.Sum256([]byte(value))
	return hex.EncodeToString(sum[:])
}

type judgeCommandState struct {
	workspace        string
	judgeSandbox     string
	outputPath       string
	outputUsed       bool
	promptSource     string
	promptPath       string
	promptSHA        string
	outputSchemaPath string
	outputSchemaSHA  string
	schemaSource     string
	files            map[string][]byte
	inspection       *artifactInspectionChallenge
}

type judgeShellSpec struct {
	command string
	args    []string
	quote   func(string) string
}

func RunJudge(opts JudgeOptions, artifact Artifact, commandRunner CommandRunner, timeout time.Duration, env map[string]string, sandboxMode string) (*JudgeResult, error) {
	workspace, err := os.MkdirTemp("", "clawscan-judge-*")
	if err != nil {
		return nil, err
	}
	defer os.RemoveAll(workspace)
	if err := prepareJudgeWorkspace(workspace, artifact); err != nil {
		return nil, err
	}
	if timeout == 0 {
		timeout = 20 * time.Minute
	}
	state := &judgeCommandState{
		workspace:    workspace,
		judgeSandbox: judgeSandboxMode(sandboxMode),
		outputPath:   filepath.Join(workspace, "judge-output.json"),
		files:        opts.Files,
	}
	if isClawHubParityProfile(artifact.Profile) {
		state.outputPath = filepath.Join(workspace, "codex-result.json")
		state.inspection, err = prepareArtifactInspectionChallenge(workspace)
		if err != nil {
			return nil, err
		}
	}
	shell := judgeShellForGOOS(runtime.GOOS)
	command, err := renderJudgeCommand(opts.Command, artifact, state, shell.quote)
	if err != nil {
		return nil, err
	}
	output, runErr := commandRunner.Run(shell.command, append(shell.args, command), workspace, timeout)
	raw := strings.TrimSpace(output.Stdout)
	if state.outputUsed {
		outputBytes, readErr := os.ReadFile(state.outputPath)
		if readErr == nil {
			raw = strings.TrimSpace(string(outputBytes))
		} else if runErr == nil {
			runErr = readErr
		}
	}
	result := &JudgeResult{
		Status:           "completed",
		PromptPath:       state.promptSource,
		OutputSchemaPath: state.schemaSource,
		OutputPath:       state.outputPath,
		PromptSHA:        state.promptSHA,
		OutputSchemaSHA:  state.outputSchemaSHA,
		Error:            "",
		Result:           nil,
	}
	if runErr != nil {
		result.Status = "failed"
		result.Error = commandError(runErr, output.Stderr, env)
	}
	if raw == "" {
		if result.Status == "failed" {
			return result, nil
		}
		result.Status = "failed"
		result.Error = "Judge command did not produce JSON output."
		return result, nil
	}
	var parsed any
	if err := json.Unmarshal([]byte(raw), &parsed); err != nil {
		if result.Status == "failed" {
			result.Result = redactEnvValues(raw, env)
			return result, nil
		}
		result.Status = "failed"
		result.Error = fmt.Sprintf("Judge command produced invalid JSON: %v", err)
		result.Result = redactEnvValues(raw, env)
		return result, nil
	}
	parsed = redactJudgeResult(parsed, env)
	parsedObject, ok := parsed.(map[string]any)
	if !ok {
		result.Status = "failed"
		result.Error = fmt.Sprintf("Judge command produced %s; expected JSON object.", judgeJSONType(parsed))
		result.Result = parsed
		return result, nil
	}
	result.Result = parsed
	if state.inspection != nil {
		if err := validateArtifactInspectionReceipt(parsedObject, *state.inspection); err != nil {
			result.Status = "failed"
			result.Error = err.Error()
		}
	}
	return result, nil
}

func judgeSandboxMode(outerSandboxMode string) string {
	if outerSandboxMode == SandboxModeDocker {
		return "danger-full-access"
	}
	return "read-only"
}

type artifactInspectionChallenge struct {
	Challenge      string `json:"challenge"`
	RequiredFile   string `json:"required_file"`
	RequiredSHA256 string `json:"-"`
}

func prepareArtifactInspectionChallenge(workspace string) (*artifactInspectionChallenge, error) {
	random := make([]byte, 32)
	if _, err := rand.Read(random); err != nil {
		return nil, fmt.Errorf("generate artifact inspection challenge: %w", err)
	}
	requiredFile, requiredSHA256, err := selectArtifactInspectionFile(workspace)
	if err != nil {
		return nil, err
	}
	challenge := &artifactInspectionChallenge{
		Challenge:      hex.EncodeToString(random),
		RequiredFile:   requiredFile,
		RequiredSHA256: requiredSHA256,
	}
	raw, err := json.MarshalIndent(challenge, "", "  ")
	if err != nil {
		return nil, err
	}
	raw = append(raw, '\n')
	if err := os.WriteFile(filepath.Join(workspace, "artifact-inspection.json"), raw, 0o600); err != nil {
		return nil, fmt.Errorf("write artifact inspection challenge: %w", err)
	}
	return challenge, nil
}

func selectArtifactInspectionFile(workspace string) (string, string, error) {
	artifactDir := filepath.Join(workspace, "artifact")
	candidates := []string{}
	for _, preferred := range []string{"SKILL.md", "package.json"} {
		info, err := os.Stat(filepath.Join(artifactDir, preferred))
		if err == nil && info.Mode().IsRegular() {
			candidates = append(candidates, preferred)
		}
	}
	if len(candidates) == 0 {
		err := filepath.WalkDir(artifactDir, func(path string, entry os.DirEntry, walkErr error) error {
			if walkErr != nil {
				return walkErr
			}
			if entry.Type().IsRegular() {
				relative, err := filepath.Rel(artifactDir, path)
				if err != nil {
					return err
				}
				candidates = append(candidates, relative)
			}
			return nil
		})
		if err != nil {
			return "", "", fmt.Errorf("select artifact inspection file: %w", err)
		}
	}
	if len(candidates) == 0 {
		return "", "", errors.New("artifact inspection requires at least one regular artifact file")
	}
	sort.Strings(candidates)
	relative := candidates[0]
	file, err := os.Open(filepath.Join(artifactDir, relative))
	if err != nil {
		return "", "", fmt.Errorf("open artifact inspection file: %w", err)
	}
	defer file.Close()
	hash := sha256.New()
	if _, err := io.Copy(hash, file); err != nil {
		return "", "", fmt.Errorf("hash artifact inspection file: %w", err)
	}
	return "artifact/" + filepath.ToSlash(relative), hex.EncodeToString(hash.Sum(nil)), nil
}

func validateArtifactInspectionReceipt(result map[string]any, expected artifactInspectionChallenge) error {
	inspection, ok := result["artifact_inspection"].(map[string]any)
	if !ok {
		return errors.New("Judge did not provide the required artifact inspection receipt.")
	}
	if status, _ := inspection["status"].(string); status != "completed" {
		return fmt.Errorf("Judge artifact inspection status was %q; expected completed.", status)
	}
	challenge, _ := inspection["challenge"].(string)
	if challenge != expected.Challenge {
		return errors.New("Judge artifact inspection challenge did not match the workspace challenge.")
	}
	requiredSHA256, _ := inspection["required_file_sha256"].(string)
	if requiredSHA256 != expected.RequiredSHA256 {
		return errors.New("Judge artifact inspection file hash did not match the required artifact file.")
	}
	files, ok := inspection["files_inspected"].([]any)
	if !ok || len(files) == 0 {
		return errors.New("Judge artifact inspection did not report any inspected artifact files.")
	}
	requiredFileInspected := false
	for _, value := range files {
		file, ok := value.(string)
		if !ok {
			continue
		}
		clean := filepath.ToSlash(filepath.Clean(file))
		if clean == expected.RequiredFile {
			requiredFileInspected = true
		}
	}
	if !requiredFileInspected {
		return fmt.Errorf("Judge artifact inspection did not include required file %s.", expected.RequiredFile)
	}
	return nil
}

func judgeJSONType(value any) string {
	switch value.(type) {
	case nil:
		return "null"
	case []any:
		return "JSON array"
	case string:
		return "JSON string"
	case float64:
		return "JSON number"
	case bool:
		return "JSON boolean"
	default:
		return "JSON value"
	}
}

func renderJudgeCommand(command string, artifact Artifact, state *judgeCommandState, quote func(string) string) (string, error) {
	var renderErr error
	rendered := judgePlaceholderPattern.ReplaceAllStringFunc(command, func(match string) string {
		if renderErr != nil {
			return match
		}
		parts := judgePlaceholderPattern.FindStringSubmatch(match)
		if len(parts) != 3 {
			return match
		}
		name := parts[1]
		value := strings.TrimSpace(parts[2])
		switch name {
		case "workspace":
			if value != "" {
				renderErr = fmt.Errorf("{{ workspace }} does not accept a path")
				return match
			}
			return quote(state.workspace)
		case "judge_sandbox":
			if value != "" {
				renderErr = fmt.Errorf("{{ judge_sandbox }} does not accept a value")
				return match
			}
			return quote(state.judgeSandbox)
		case "output":
			if value != "" {
				renderErr = fmt.Errorf("{{ output }} does not accept a path")
				return match
			}
			state.outputUsed = true
			return quote(state.outputPath)
		case "prompt":
			path, err := prepareJudgePrompt(value, artifact, state)
			if err != nil {
				renderErr = err
				return match
			}
			return quote(path)
		case "output_schema":
			path, err := prepareJudgeOutputSchema(value, state)
			if err != nil {
				renderErr = err
				return match
			}
			return quote(path)
		default:
			renderErr = fmt.Errorf("unknown judge placeholder: %s", name)
			return match
		}
	})
	if renderErr != nil {
		return "", renderErr
	}
	return rendered, nil
}

func judgeShellForGOOS(goos string) judgeShellSpec {
	if goos == "windows" {
		return judgeShellSpec{
			command: "cmd.exe",
			args:    []string{"/C"},
			quote:   windowsCmdQuote,
		}
	}
	return judgeShellSpec{
		command: "/bin/sh",
		args:    []string{"-c"},
		quote:   posixShellQuote,
	}
}

func posixShellQuote(value string) string {
	if value == "" {
		return "''"
	}
	return "'" + strings.ReplaceAll(value, "'", "'\"'\"'") + "'"
}

func windowsCmdQuote(value string) string {
	if value == "" {
		return `""`
	}
	return `"` + strings.ReplaceAll(value, `"`, `\"`) + `"`
}

func prepareJudgePrompt(source string, artifact Artifact, state *judgeCommandState) (string, error) {
	if source == "" {
		source = defaultJudgePromptPath
	}
	if state.promptSource != "" {
		if state.promptSource != source {
			return "", errors.New("multiple judge prompt paths are not supported")
		}
		return state.promptPath, nil
	}
	promptTemplate, err := readJudgeSource(source, state)
	if err != nil {
		return "", err
	}
	prompt, err := renderJudgePromptSource(source, string(promptTemplate), artifact)
	if err != nil {
		return "", err
	}
	path := filepath.Join(state.workspace, "prompt.md")
	if err := os.WriteFile(path, []byte(prompt), 0o644); err != nil {
		return "", err
	}
	state.promptSource = source
	state.promptPath = path
	state.promptSHA = sha256Hex(prompt)
	return path, nil
}

func renderJudgePromptSource(source string, template string, artifact Artifact) (string, error) {
	if isClawHubParityProfile(artifact.Profile) && judgeSourceKey(source) == "clawhub/prompt.md" {
		return RenderClawHubPrompt(template, artifact)
	}
	return RenderPromptTemplate(template, artifact)
}

func RenderClawHubPrompt(systemPromptSource string, artifact Artifact) (string, error) {
	systemPrompt := clawHubSystemPrompt(systemPromptSource)
	context, err := parseClawHubContext(artifact.Context)
	if err != nil {
		return "", err
	}
	skillSpector, err := clawHubSkillSpectorAnalysis(artifact, context.SkillSpectorCheckedAt)
	if err != nil {
		return "", err
	}
	var supplemental []clawhubprompt.ScannerEvidence
	if artifact.Profile == clawHubAIGProfileID {
		supplemental = append(supplemental, clawhubprompt.ScannerEvidence{
			Label: "A.I.G SARIF evidence supplied to Codex",
			Value: clawHubAIGAnalysis(artifact),
		})
	}
	return clawhubprompt.Build(
		systemPrompt,
		clawHubPromptJob(artifact, context),
		clawHubInjectionSignals(artifact, context),
		skillSpector,
		supplemental...,
	)
}

func clawHubSystemPrompt(source string) string {
	marker := "\n\nAdditional ClawHub policy for this Codex run:"
	if before, _, ok := strings.Cut(source, marker); ok {
		return before
	}
	return source
}

func clawHubPromptJob(artifact Artifact, context clawHubContext) clawhubprompt.Job {
	targetKind := context.TargetKind
	if targetKind == "" {
		targetKind = "skillVersion"
	}
	source := context.Source
	if source == "" {
		source = "publish"
	}
	hasMaliciousSignal := clawHubHasMaliciousSignal(artifact)
	if context.HasMaliciousSignal != nil {
		hasMaliciousSignal = *context.HasMaliciousSignal
	}
	return clawhubprompt.Job{
		Job: clawhubprompt.JobMetadata{
			TargetKind:         targetKind,
			Source:             source,
			HasMaliciousSignal: hasMaliciousSignal,
		},
		Target: clawhubprompt.Target{
			TrustedOpenClawPlugin: context.TrustedOpenClawPlugin,
			Version: &clawhubprompt.Version{
				SkillSpectorAnalysis: nil,
			},
		},
	}
}

func clawHubAIGAnalysis(artifact Artifact) any {
	result, ok := artifact.Scanners["aig"]
	if !ok || len(result.Raw) == 0 {
		return nil
	}
	return clawhubprompt.RawJSON(result.Raw)
}

func clawHubHasMaliciousSignal(artifact Artifact) bool {
	if artifact.Profile == clawHubAIGProfileID {
		result, ok := artifact.Scanners["aig"]
		if !ok || len(result.Raw) == 0 {
			return false
		}
		prediction, ok := aigSARIFPrediction(result.Raw)
		return ok && prediction == "malicious"
	}
	staticResult, ok := artifact.Scanners["clawscan-static"]
	if !ok || len(staticResult.Raw) == 0 {
		return false
	}
	var report staticScannerReport
	if err := json.Unmarshal(staticResult.Raw, &report); err != nil {
		return false
	}
	for _, finding := range report.Findings {
		if strings.EqualFold(finding.Severity, "high") {
			return true
		}
	}
	return false
}

func clawHubInjectionSignals(artifact Artifact, context clawHubContext) []string {
	if context.InjectionSignals != nil {
		return append([]string(nil), context.InjectionSignals...)
	}
	staticResult, ok := artifact.Scanners["clawscan-static"]
	if !ok || len(staticResult.Raw) == 0 {
		return nil
	}
	var report staticScannerReport
	if err := json.Unmarshal(staticResult.Raw, &report); err != nil {
		return nil
	}
	seen := map[string]bool{}
	var signals []string
	for _, finding := range report.Findings {
		if finding.ID != "static.prompt_injection" {
			continue
		}
		if !seen["html-comment-injection"] {
			seen["html-comment-injection"] = true
			signals = append(signals, "html-comment-injection")
		}
	}
	return signals
}

func prepareJudgeOutputSchema(source string, state *judgeCommandState) (string, error) {
	if source == "" {
		source = defaultJudgeOutputSchemaPath
	}
	if state.schemaSource != "" {
		if state.schemaSource != source {
			return "", errors.New("multiple judge output schema paths are not supported")
		}
		return state.outputSchemaPath, nil
	}
	schema, err := readJudgeSource(source, state)
	if err != nil {
		return "", err
	}
	path := filepath.Join(state.workspace, "schema.json")
	if err := os.WriteFile(path, schema, 0o644); err != nil {
		return "", err
	}
	state.schemaSource = source
	state.outputSchemaPath = path
	state.outputSchemaSHA = sha256Hex(string(schema))
	return path, nil
}

func readJudgeSource(source string, state *judgeCommandState) ([]byte, error) {
	if state.files != nil {
		if data, ok := state.files[judgeSourceKey(source)]; ok {
			return data, nil
		}
	}
	return os.ReadFile(source)
}

func judgeSourceKey(source string) string {
	return filepath.ToSlash(filepath.Clean(source))
}

func prepareJudgeWorkspace(workspace string, artifact Artifact) error {
	if artifact.Target.Kind == "url" {
		return fmt.Errorf("judge workspace copying is unsupported for URL targets: %s", artifact.Target.Input)
	}
	// Every profile receives the complete artifact before its metadata layout is written.
	manifest, err := copyTargetToWorkspace(artifact.Target.ResolvedPath, filepath.Join(workspace, "artifact"))
	if err != nil {
		return err
	}
	if isClawHubParityProfile(artifact.Profile) {
		context, err := parseClawHubContext(artifact.Context)
		if err != nil {
			return err
		}
		if result, ok := artifact.Scanners["skillspector"]; ok && len(result.Raw) > 0 {
			if err := os.WriteFile(filepath.Join(workspace, "skillspector-report-0.json"), result.Raw, 0o644); err != nil {
				return err
			}
		}
		metadata := context.Metadata
		if len(metadata) == 0 {
			metadata = json.RawMessage(`{}`)
		}
		var formatted bytes.Buffer
		if err := json.Indent(&formatted, metadata, "", "  "); err != nil {
			return fmt.Errorf("format clawhub metadata JSON: %w", err)
		}
		formatted.WriteByte('\n')
		return os.WriteFile(filepath.Join(workspace, "metadata.json"), formatted.Bytes(), 0o644)
	}
	scannersDir := filepath.Join(workspace, "scanners")
	if err := os.MkdirAll(scannersDir, 0o755); err != nil {
		return err
	}
	for name, result := range artifact.Scanners {
		raw := result.Raw
		if len(raw) == 0 {
			raw = json.RawMessage("null")
		}
		if err := os.WriteFile(filepath.Join(scannersDir, name+".json"), raw, 0o644); err != nil {
			return err
		}
	}
	metadata := map[string]any{
		"schemaVersion": artifact.SchemaVersion,
		"target":        artifact.Target,
		"scanners":      artifact.Scanners,
		"workspace": map[string]any{
			"artifact": manifest,
		},
	}
	rawMetadata, err := json.MarshalIndent(metadata, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(workspace, "metadata.json"), append(rawMetadata, '\n'), 0o644)
}

func copyTargetToWorkspace(source string, destRoot string) (TargetWorkspaceManifest, error) {
	manifest := TargetWorkspaceManifest{}
	info, err := os.Lstat(source)
	if err != nil {
		return manifest, err
	}
	if !info.IsDir() {
		if err := os.MkdirAll(destRoot, 0o755); err != nil {
			return manifest, err
		}
		if !info.Mode().IsRegular() {
			return manifest, fmt.Errorf("refusing non-regular judge target: %s", source)
		}
		if err := copyFile(source, filepath.Join(destRoot, filepath.Base(source))); err != nil {
			return manifest, err
		}
		manifest.addCopied(filepath.Base(source), info.Size())
		return manifest, nil
	}
	if err := os.MkdirAll(destRoot, 0o755); err != nil {
		return manifest, err
	}
	type workspaceFileCandidate struct {
		path       string
		rel        string
		info       os.FileInfo
		linkTarget string
	}
	var candidates []workspaceFileCandidate
	err = filepath.WalkDir(source, func(path string, entry os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if shouldSkipWorkspacePath(source, path) {
			if entry.IsDir() {
				return filepath.SkipDir
			}
			return nil
		}
		if entry.IsDir() {
			return nil
		}
		rel, err := filepath.Rel(source, path)
		if err != nil {
			return err
		}
		if entry.Type()&os.ModeSymlink != 0 {
			linkTarget, err := safeWorkspaceSymlinkTarget(source, destRoot, path, rel)
			if err != nil {
				return err
			}
			candidates = append(candidates, workspaceFileCandidate{
				path:       path,
				rel:        rel,
				linkTarget: linkTarget,
			})
			return nil
		}
		info, err := entry.Info()
		if err != nil {
			return err
		}
		if !info.Mode().IsRegular() {
			return fmt.Errorf("refusing non-regular artifact entry: %s", relativeManifestPath(source, path))
		}
		candidates = append(candidates, workspaceFileCandidate{
			path: path,
			rel:  rel,
			info: info,
		})
		return nil
	})
	if err != nil {
		return manifest, err
	}
	sort.SliceStable(candidates, func(i int, j int) bool {
		leftPriority := targetFilePriority(source, candidates[i].path)
		rightPriority := targetFilePriority(source, candidates[j].path)
		if leftPriority != rightPriority {
			return leftPriority < rightPriority
		}
		return filepath.ToSlash(candidates[i].rel) < filepath.ToSlash(candidates[j].rel)
	})
	// Complete workspaces are a parity invariant: fail the run on copy errors
	// instead of silently giving scanners or the judge a truncated artifact.
	for _, candidate := range candidates {
		if candidate.linkTarget != "" {
			dest := filepath.Join(destRoot, candidate.rel)
			if err := os.MkdirAll(filepath.Dir(dest), 0o755); err != nil {
				return manifest, err
			}
			if err := os.Symlink(candidate.linkTarget, dest); err != nil {
				return manifest, err
			}
			manifest.addCopied(candidate.rel, 0)
			continue
		}
		info := candidate.info
		rel := candidate.rel
		if err := copyFile(candidate.path, filepath.Join(destRoot, rel)); err != nil {
			return manifest, err
		}
		manifest.addCopied(rel, info.Size())
	}
	return manifest, nil
}

func shouldSkipWorkspacePath(root string, path string) bool {
	rel, err := filepath.Rel(root, path)
	if err != nil {
		return true
	}
	return rel == ".git" ||
		strings.HasPrefix(rel, ".git"+string(filepath.Separator)) ||
		rel == "clawscan-results" ||
		strings.HasPrefix(rel, "clawscan-results"+string(filepath.Separator))
}

func safeWorkspaceSymlinkTarget(source string, destRoot string, linkPath string, linkRel string) (string, error) {
	target, err := os.Readlink(linkPath)
	if err != nil {
		return "", err
	}
	resolved := target
	if !filepath.IsAbs(resolved) {
		resolved = filepath.Join(filepath.Dir(linkPath), resolved)
	}
	resolved = filepath.Clean(resolved)
	resolvedRel, err := filepath.Rel(source, resolved)
	if err != nil || resolvedRel == ".." || strings.HasPrefix(resolvedRel, ".."+string(filepath.Separator)) {
		return "", fmt.Errorf("refusing artifact symlink outside target: %s", filepath.ToSlash(linkRel))
	}
	destLink := filepath.Join(destRoot, linkRel)
	destTarget := filepath.Join(destRoot, resolvedRel)
	relativeTarget, err := filepath.Rel(filepath.Dir(destLink), destTarget)
	if err != nil {
		return "", err
	}
	return relativeTarget, nil
}

func (manifest *TargetWorkspaceManifest) addCopied(path string, bytes int64) {
	manifest.TotalCopiedBytes += bytes
	if len(manifest.Copied) >= maxOmittedTargetFileMarkers {
		manifest.SuppressedCopied++
		return
	}
	manifest.Copied = append(manifest.Copied, TargetWorkspaceFile{
		Path:  filepath.ToSlash(path),
		Bytes: bytes,
	})
}

func relativeManifestPath(root string, path string) string {
	rel, err := filepath.Rel(root, path)
	if err != nil {
		return path
	}
	return rel
}

func copyFile(source string, dest string) error {
	if err := os.MkdirAll(filepath.Dir(dest), 0o755); err != nil {
		return err
	}
	in, err := os.Open(source)
	if err != nil {
		return err
	}
	defer in.Close()
	out, err := os.Create(dest)
	if err != nil {
		return err
	}
	defer out.Close()
	if _, err := io.Copy(out, in); err != nil {
		return err
	}
	return out.Close()
}

func isSourceReadError(err error, source string) bool {
	var pathErr *os.PathError
	if !errors.As(err, &pathErr) {
		return false
	}
	return filepath.Clean(pathErr.Path) == filepath.Clean(source) && (pathErr.Op == "open" || pathErr.Op == "read")
}

type ExternalScannerRunner struct {
	CommandRunner        CommandRunner
	Env                  map[string]string
	Profile              string
	Registry             ScannerRegistry
	SandboxMode          string
	SkillSpectorCommand  []string
	VirusTotalHTTPClient VirusTotalHTTPClient
	Timeout              time.Duration
}

func (runner ExternalScannerRunner) RunScanner(name string, target string, startedAt string) (ScannerResult, error) {
	registry := runner.Registry
	if registry.isZero() {
		registry = DefaultScannerRegistry()
	}
	adapter, ok := registry.Adapter(name)
	if !ok {
		return ScannerResult{
			Status:      "skipped",
			StartedAt:   startedAt,
			CompletedAt: time.Now().UTC().Format(time.RFC3339Nano),
			Command:     nil,
			Error:       "Scanner adapter not implemented in foundation slice.",
			Raw:         nil,
		}, nil
	}
	return adapter.Run(runner, target, startedAt)
}

func (runner ExternalScannerRunner) runAgentVerus(target string, startedAt string) (ScannerResult, error) {
	command := "npx"
	args := []string{"--yes", "agentverus-scanner", "scan", target, "--json"}
	if runner.SandboxMode == SandboxModeDocker {
		command = "agentverus-scanner"
		args = []string{"scan", target, "--json"}
	}
	fullCommand := append([]string{command}, args...)
	timeout := runner.Timeout
	if timeout == 0 {
		timeout = 20 * time.Minute
	}
	output, runErr := runner.CommandRunner.Run(command, args, "", timeout)
	completedAt := time.Now().UTC().Format(time.RFC3339Nano)
	raw := strings.TrimSpace(output.Stdout)
	if runErr != nil {
		message := commandError(runErr, output.Stderr, runner.Env)
		if json.Valid([]byte(raw)) {
			return ScannerResult{
				Status:      "completed",
				StartedAt:   startedAt,
				CompletedAt: completedAt,
				Command:     fullCommand,
				Error:       message,
				Raw:         json.RawMessage(raw),
			}, nil
		}
		return ScannerResult{
			Status:      "failed",
			StartedAt:   startedAt,
			CompletedAt: completedAt,
			Command:     fullCommand,
			Error:       message,
			Raw:         nil,
		}, nil
	}
	if raw == "" {
		return ScannerResult{
			Status:      "failed",
			StartedAt:   startedAt,
			CompletedAt: completedAt,
			Command:     fullCommand,
			Error:       "AgentVerus scanner did not return JSON on stdout.",
			Raw:         nil,
		}, nil
	}
	if !json.Valid([]byte(raw)) {
		return ScannerResult{
			Status:      "failed",
			StartedAt:   startedAt,
			CompletedAt: completedAt,
			Command:     fullCommand,
			Error:       "AgentVerus scanner returned invalid JSON",
			Raw:         nil,
		}, nil
	}
	return ScannerResult{
		Status:      "completed",
		StartedAt:   startedAt,
		CompletedAt: completedAt,
		Command:     fullCommand,
		Error:       "",
		Raw:         json.RawMessage(raw),
	}, nil
}

func (runner ExternalScannerRunner) runSkillSpector(target string, startedAt string) (ScannerResult, error) {
	defaultSkillSpectorOpenAIProvider(runner.Env)
	commandParts := runner.SkillSpectorCommand
	if len(commandParts) == 0 {
		if runner.SandboxMode == SandboxModeDocker {
			commandParts = []string{"skillspector"}
		} else {
			commandParts = discoverSkillSpectorCommand()
		}
	}
	command := commandParts[0]
	args := append([]string{}, commandParts[1:]...)
	resultDir, err := os.MkdirTemp("", "clawscan-skillspector-*")
	if err != nil {
		return ScannerResult{}, err
	}
	defer os.RemoveAll(resultDir)
	scanTarget := target
	cwd := ""
	resultName := "skillspector-report.json"
	if isClawHubParityProfile(runner.Profile) {
		if _, err := copyTargetToWorkspace(target, filepath.Join(resultDir, "artifact")); err != nil {
			return ScannerResult{}, fmt.Errorf("prepare ClawHub SkillSpector workspace: %w", err)
		}
		scanTarget = "artifact"
		cwd = resultDir
		resultName = "skillspector-report-0.json"
	}
	resultPath := filepath.Join(resultDir, resultName)
	args = append(args, "scan", scanTarget, "--format", "json", "--output", resultPath)
	if !skillSpectorLLMEnabled(runner.Env) {
		args = append(args, "--no-llm")
	}
	fullCommand := append([]string{command}, args...)
	timeout := runner.Timeout
	if timeout == 0 {
		timeout = 20 * time.Minute
	}
	output, runErr := runner.CommandRunner.Run(command, args, cwd, timeout)
	raw, readErr := os.ReadFile(resultPath)
	completedAt := time.Now().UTC().Format(time.RFC3339Nano)
	if runErr != nil {
		message := commandError(runErr, output.Stderr, runner.Env)
		if readErr == nil {
			if !json.Valid(raw) {
				return ScannerResult{
					Status:      "failed",
					StartedAt:   startedAt,
					CompletedAt: completedAt,
					Command:     fullCommand,
					Error:       message + ": SkillSpector scanner returned invalid JSON",
					Raw:         nil,
				}, nil
			}
			return ScannerResult{
				Status:      "completed",
				StartedAt:   startedAt,
				CompletedAt: completedAt,
				Command:     fullCommand,
				Error:       message,
				Raw:         json.RawMessage(raw),
			}, nil
		}
		return ScannerResult{
			Status:      "failed",
			StartedAt:   startedAt,
			CompletedAt: completedAt,
			Command:     fullCommand,
			Error:       message,
			Raw:         nil,
		}, nil
	}
	if readErr != nil {
		return ScannerResult{
			Status:      "failed",
			StartedAt:   startedAt,
			CompletedAt: completedAt,
			Command:     fullCommand,
			Error:       "SkillSpector scanner did not write JSON output.",
			Raw:         nil,
		}, nil
	}
	if !json.Valid(raw) {
		return ScannerResult{
			Status:      "failed",
			StartedAt:   startedAt,
			CompletedAt: completedAt,
			Command:     fullCommand,
			Error:       "SkillSpector scanner returned invalid JSON",
			Raw:         nil,
		}, nil
	}
	return ScannerResult{
		Status:      "completed",
		StartedAt:   startedAt,
		CompletedAt: completedAt,
		Command:     fullCommand,
		Error:       "",
		Raw:         json.RawMessage(raw),
	}, nil
}

func defaultSkillSpectorOpenAIProvider(env map[string]string) {
	if env == nil {
		return
	}
	if strings.TrimSpace(env["SKILLSPECTOR_PROVIDER"]) != "" {
		return
	}
	if strings.TrimSpace(env["OPENAI_API_KEY"]) == "" {
		return
	}
	env["SKILLSPECTOR_PROVIDER"] = "openai"
}

func applyRuntimeEnvDefaults(opts Options, env map[string]string) {
	if scannerRequested(opts, "skillspector") {
		defaultSkillSpectorOpenAIProvider(env)
	}
}

func discoverSkillSpectorCommand() []string {
	if _, err := exec.LookPath("skillspector"); err == nil {
		return []string{"skillspector"}
	}
	return []string{"uvx", "--from", "git+https://github.com/NVIDIA/skillspector", "skillspector"}
}

type defaultCommandRunner struct {
	Env map[string]string
}

func (runner defaultCommandRunner) Run(command string, args []string, cwd string, timeout time.Duration) (CommandOutput, error) {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, command, args...)
	cmd.Dir = cwd
	if runner.Env != nil {
		cmd.Env = envMapToEnviron(runner.Env)
	}
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	err := cmd.Run()
	if ctx.Err() == context.DeadlineExceeded {
		err = fmt.Errorf("command timed out after %s", timeout)
	}
	return CommandOutput{Stdout: stdout.String(), Stderr: stderr.String()}, err
}

func NewArtifact(opts Options, resolvedPath string, startedAt string, completedAt string, env map[string]string) Artifact {
	scanners := map[string]ScannerResult{}
	for _, scanner := range opts.Scanners {
		scanners[scanner] = ScannerResult{
			Status:      "skipped",
			StartedAt:   startedAt,
			CompletedAt: completedAt,
			Command:     nil,
			Error:       "Scanner adapter not implemented in foundation slice.",
			Raw:         nil,
		}
	}
	return Artifact{
		SchemaVersion: "clawscan-run-v1",
		Profile:       opts.Profile,
		Target: Target{
			Kind:         "skill",
			Input:        opts.Target,
			ResolvedPath: resolvedPath,
		},
		StartedAt:   startedAt,
		CompletedAt: completedAt,
		Env:         envPresence(opts, env),
		Sandbox:     mustSandboxMetadata(opts, env),
		Scanners:    scanners,
		Judge:       nil,
	}
}

func WriteJSON(w io.Writer, value interface{}) error {
	encoder := json.NewEncoder(w)
	encoder.SetIndent("", "  ")
	return encoder.Encode(value)
}

func EnvMap(environ []string) map[string]string {
	env := map[string]string{}
	for _, entry := range environ {
		key, value, ok := strings.Cut(entry, "=")
		if ok {
			env[key] = value
		}
	}
	return env
}

func envMapToEnviron(env map[string]string) []string {
	keys := make([]string, 0, len(env))
	for key := range env {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	environ := make([]string, 0, len(keys))
	for _, key := range keys {
		environ = append(environ, key+"="+env[key])
	}
	return environ
}

func commandError(runErr error, stderr string, env map[string]string) string {
	message := redactEnvValues(runErr.Error(), env)
	if strings.TrimSpace(stderr) != "" {
		message += ": " + redactEnvValues(strings.TrimSpace(stderr), env)
	}
	return message
}

func redactEnvValues(value string, env map[string]string) string {
	if value == "" || len(env) == 0 {
		return value
	}
	secrets := make([]string, 0)
	for key, secret := range env {
		if strings.TrimSpace(secret) == "" || !isSecretEnvKey(key) {
			continue
		}
		secrets = append(secrets, secret)
	}
	sort.Slice(secrets, func(i int, j int) bool {
		return len(secrets[i]) > len(secrets[j])
	})
	redacted := value
	for _, secret := range secrets {
		redacted = strings.ReplaceAll(redacted, secret, "[redacted]")
	}
	return redacted
}

func redactJudgeResult(value any, env map[string]string) any {
	switch typed := value.(type) {
	case string:
		return redactEnvValues(typed, env)
	case []any:
		redacted := make([]any, len(typed))
		for index, item := range typed {
			redacted[index] = redactJudgeResult(item, env)
		}
		return redacted
	case map[string]any:
		redacted := make(map[string]any, len(typed))
		for key, item := range typed {
			redacted[redactEnvValues(key, env)] = redactJudgeResult(item, env)
		}
		return redacted
	default:
		return value
	}
}

func isSecretEnvKey(key string) bool {
	upper := strings.ToUpper(key)
	return strings.Contains(upper, "TOKEN") ||
		strings.Contains(upper, "SECRET") ||
		strings.Contains(upper, "PASSWORD") ||
		strings.HasSuffix(upper, "_KEY") ||
		strings.Contains(upper, "API_KEY")
}

func requirements(opts Options, env map[string]string) []EnvRequirement {
	var reqs []EnvRequirement
	for _, scanner := range opts.Scanners {
		if opts.ScannerResultPaths[scanner] != "" {
			continue
		}
		if adapter, ok := DefaultScannerRegistry().Adapter(scanner); ok {
			reqs = append(reqs, adapter.Requirements(env)...)
		}
	}
	return dedupe(reqs)
}

func envPresence(opts Options, env map[string]string) map[string]string {
	out := map[string]string{}
	for _, req := range requirements(opts, env) {
		if strings.TrimSpace(env[req.EnvVar]) == "" {
			out[req.EnvVar] = "missing"
		} else {
			out[req.EnvVar] = "present"
		}
	}
	return out
}

func skillSpectorLLMEnabled(env map[string]string) bool {
	value := strings.TrimSpace(strings.ToLower(env["CLAWSCAN_SKILLSPECTOR_LLM"]))
	switch value {
	case "0", "false", "no", "off":
		return false
	case "1", "true", "yes", "on":
		return true
	}
	return skillSpectorProviderKeyPresent(env)
}

func skillSpectorProviderKeyPresent(env map[string]string) bool {
	switch strings.TrimSpace(strings.ToLower(env["SKILLSPECTOR_PROVIDER"])) {
	case "":
		return strings.TrimSpace(env["NVIDIA_INFERENCE_KEY"]) != "" ||
			strings.TrimSpace(env["OPENAI_API_KEY"]) != "" ||
			strings.TrimSpace(env["ANTHROPIC_API_KEY"]) != "" ||
			strings.TrimSpace(env["ANTHROPIC_PROXY_API_KEY"]) != ""
	case "openai":
		return strings.TrimSpace(env["OPENAI_API_KEY"]) != ""
	case "anthropic":
		return strings.TrimSpace(env["ANTHROPIC_API_KEY"]) != ""
	case "anthropic_proxy":
		return strings.TrimSpace(env["ANTHROPIC_PROXY_API_KEY"]) != "" &&
			strings.TrimSpace(env["ANTHROPIC_PROXY_ENDPOINT_URL"]) != ""
	case "nv_inference", "nv_build", "nvidia":
		return strings.TrimSpace(env["NVIDIA_INFERENCE_KEY"]) != ""
	default:
		return true
	}
}

func dedupe(reqs []EnvRequirement) []EnvRequirement {
	seen := map[string]bool{}
	var out []EnvRequirement
	for _, req := range reqs {
		key := req.EnvVar + ":" + req.Reason
		if !seen[key] {
			seen[key] = true
			out = append(out, req)
		}
	}
	return out
}

func readValue(args []string, index int, flag string) (string, int, error) {
	next := index + 1
	if next >= len(args) || args[next] == "" || strings.HasPrefix(args[next], "--") {
		return "", index, fmt.Errorf("Missing value for %s", flag)
	}
	return args[next], next, nil
}

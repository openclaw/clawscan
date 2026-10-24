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
	"maps"
	"math/big"
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
	ScannerEnvDefaults map[string]string
	Target             string
	TargetKind         string
	Profile            string
	ConfigSource       string
	LoadedConfigPath   string
	DiscoverConfig     bool
	ContextPath        string
	Benchmark          *BenchmarkOptions
	Scanners           []string
	ScannerRegistry    ScannerRegistry
	ScannerResultPaths map[string]string
	OutputPath         string
	JSON               bool
	Judge              *JudgeOptions
	Sandbox            SandboxOptions
	GateRules          map[string]ScannerGatePolicy
}

type ExitCodeRule struct {
	Codes   []int
	Nonzero bool
}

// MaxGateExitCode excludes shell and container runtime infrastructure failures
// from scanner verdict policy.
const MaxGateExitCode = 124

func (rule ExitCodeRule) Matches(exitCode int) bool {
	if rule.Nonzero {
		return exitCode != 0
	}
	for _, code := range rule.Codes {
		if code == exitCode {
			return true
		}
	}
	return false
}

type ScannerGatePolicy struct {
	BlockOnExitCode *ExitCodeRule
	WarnOnExitCode  *ExitCodeRule
	JSONRules       []JSONGateRule
}

type JSONGateRule struct {
	ID        string
	Paths     []string
	Equals    json.RawMessage
	Exists    bool
	Normalize string
	Fallback  string
	Action    string
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
	Context              context.Context
	Progress             io.Writer
	progress             *runProgress
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
	Stdout   string
	Stderr   string
	ExitCode *int
	Started  *bool
}

type Artifact struct {
	outputSafety   outputSafety
	targetConsumed bool
	ProcessCleanup string `json:"processCleanup,omitempty"`
	Status         string `json:"status,omitempty"`
	Complete       bool   `json:"complete"`
	Error          string `json:"error,omitempty"`
	SchemaVersion  string `json:"schemaVersion"`
	Profile        string `json:"profile,omitempty"`
	// ConfigSource deliberately lacks omitempty: null positively claims no config
	// influenced the run, unlike older artifacts that omitted the field.
	ConfigSource *string                  `json:"configSource"`
	Context      json.RawMessage          `json:"context,omitempty"`
	Target       Target                   `json:"target"`
	StartedAt    string                   `json:"startedAt"`
	CompletedAt  string                   `json:"completedAt"`
	Env          map[string]string        `json:"env"`
	Sandbox      SandboxMetadata          `json:"sandbox"`
	Scanners     map[string]ScannerResult `json:"scanners"`
	Gate         string                   `json:"gate"`
	GateRules    []FiredGateRule          `json:"gateRules"`
	Judge        *JudgeResult             `json:"judge"`
}

type FiredGateRule struct {
	Scanner  string          `json:"scanner"`
	Rule     string          `json:"rule"`
	ExitCode *int            `json:"exitCode,omitempty"`
	Path     string          `json:"path,omitempty"`
	Value    json.RawMessage `json:"value,omitempty"`
	Action   string          `json:"action"`
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
	outputSafety  outputSafety
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
	ExitCode    *int            `json:"exitCode,omitempty"`
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
	CommandStarted   *bool          `json:"commandStarted,omitempty"`
	Status           string         `json:"status"`
	Command          string         `json:"command,omitempty"`
	ConfiguredModel  string         `json:"configuredModel,omitempty"`
	PromptPath       string         `json:"promptPath,omitempty"`
	OutputSchemaPath string         `json:"outputSchemaPath,omitempty"`
	OutputPath       string         `json:"outputPath,omitempty"`
	PromptSHA        string         `json:"promptSha256,omitempty"`
	OutputSchemaSHA  string         `json:"outputSchemaSha256,omitempty"`
	Error            string         `json:"error"`
	Result           interface{}    `json:"result"`
	Attempts         []JudgeAttempt `json:"attempts,omitempty"`
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
	return ParseArgsWithRegistry(args, DefaultScannerRegistry())
}

func ParseArgsWithRegistry(args []string, registry ScannerRegistry) (Options, error) {
	opts := Options{ScannerResultPaths: map[string]string{}}
	opts.ScannerRegistry = registry
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
			if !registry.Contains(value) {
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
			if !registry.Contains(scanner) {
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
		case "--sandbox-mount":
			value, next, err := readValue(args, i, arg)
			if err != nil {
				return Options{}, err
			}
			mount, err := parseSandboxMountFlag(value)
			if err != nil {
				return Options{}, err
			}
			opts.Sandbox.Mounts = append(opts.Sandbox.Mounts, mount)
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

// parseSandboxMountFlag parses a --sandbox-mount value: "<path>" is read-only,
// "<path>:rw" or "<path>:write" is writable.
func parseSandboxMountFlag(value string) (SandboxMount, error) {
	if i := strings.LastIndexByte(value, ':'); i >= 0 {
		suffix := value[i+1:]
		if suffix == "rw" || suffix == "write" {
			path := value[:i]
			if strings.TrimSpace(path) == "" {
				return SandboxMount{}, fmt.Errorf("--sandbox-mount requires a path before %q", ":"+suffix)
			}
			return SandboxMount{Path: path, Write: true}, nil
		}
	}
	return SandboxMount{Path: value, Write: false}, nil
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

func Run(opts Options, ctx RunContext) (artifact Artifact, runErr error) {
	validationOpts := opts
	if validationOpts.Target == "" {
		var err error
		validationOpts.Target, err = os.Getwd()
		if err != nil {
			return artifact, err
		}
	}
	safety, err := prepareOutputSafety([]Options{validationOpts}, opts.OutputPath, "")
	if err != nil {
		return artifact, err
	}
	ctx.Context = workContext(ctx.Context)
	now := ctx.Now
	if now == nil {
		now = time.Now
	}
	env := ctx.Env
	if env == nil {
		env = EnvMap(os.Environ())
	}
	env = maps.Clone(env)
	applyRuntimeEnvDefaults(opts, env)
	startedAt := now().UTC().Format(time.RFC3339Nano)
	artifact = pendingArtifact(opts, startedAt, env)
	artifact.outputSafety = safety
	defer finishArtifact(&artifact, opts, ctx.Context, now, &runErr)
	if err := ctx.Context.Err(); err != nil {
		return artifact, err
	}
	progress := newRunProgress(ctx.Progress)
	ctx.progress = progress
	progress.startPhase("prepare")
	if err := ValidateScannerEnvDefaults(opts.ScannerEnvDefaults); err != nil {
		return artifact, err
	}
	if err := validateGateRuleScanners(opts); err != nil {
		return artifact, err
	}
	target, err := resolveTargetForOptions(opts)
	if err != nil {
		return artifact, err
	}
	artifact.Target.ResolvedPath = target.resolvedPath
	artifact.Target.Kind = target.kind
	artifact.Target.ID = target.id
	checkpointOpts := opts
	withinTarget, err := outputWithinTarget(opts, target)
	if err != nil {
		return artifact, err
	}
	if withinTarget || opts.OutputPath != "" && safety.validateWrite(opts.OutputPath) != nil {
		checkpointOpts.OutputPath = ""
	}
	if err := ctx.Context.Err(); err != nil {
		return artifact, err
	}
	// Requirement validation and sandbox gating only consider scanners that
	// will run for this target kind; a scanner that can only skip must not
	// demand credentials or Docker.
	gatingOpts := opts
	gatingOpts.Scanners = runnableScanners(opts, target.kind)
	if err := ValidateRequirements(gatingOpts, env); err != nil {
		return artifact, err
	}
	commandRunner, sandbox, err := commandRunnerForOptions(gatingOpts, ctx, env)
	if err != nil {
		return artifact, err
	}
	commands := &boundCommandRunner{ctx: ctx.Context, runner: commandRunner}
	defer func() {
		if commands.attempted {
			artifact.ProcessCleanup = "unknown"
		}
	}()
	commandRunner = commands
	scannerRunner := ctx.ScannerRunner
	if scannerRunner == nil {
		scannerSandboxMode := sandbox.Mode
		if ctx.CommandRunner != nil {
			scannerSandboxMode = SandboxModeOff
		}
		scannerRunner = ExternalScannerRunner{
			Context:              ctx.Context,
			CommandRunner:        commandRunner,
			Env:                  env,
			Profile:              opts.Profile,
			TargetKind:           target.kind,
			TargetID:             target.id,
			Registry:             registryForOptions(opts),
			SandboxMode:          scannerSandboxMode,
			SkillSpectorCommand:  ctx.SkillSpectorCommand,
			VirusTotalHTTPClient: ctx.VirusTotalHTTPClient,
			Timeout:              20 * time.Minute,
		}
	}
	artifact.Sandbox = sandbox
	artifact.Target.Kind = target.kind
	artifact.Target.ID = target.id
	if opts.ContextPath != "" {
		context, err := readContextFile(ctx.Context, opts.ContextPath)
		if err != nil {
			return artifact, fmt.Errorf("read context JSON: %w", err)
		}
		if !json.Valid(context) {
			return artifact, fmt.Errorf("context JSON is not valid: %s", opts.ContextPath)
		}
		artifact.Context = json.RawMessage(context)
	}
	scanned := make(map[string]bool, len(opts.Scanners))
	progress.endPhase(false)
	for _, scanner := range opts.Scanners {
		if err := ctx.Context.Err(); err != nil {
			return artifact, err
		}
		if scanned[scanner] {
			continue
		}
		scanned[scanner] = true
		scannerStartedAt := now().UTC().Format(time.RFC3339Nano)
		scannerTimerStarted := time.Now()
		progress.startPhase(scannerProgressPhase(scanner))
		artifact.Scanners[scanner] = ScannerResult{Status: "running", StartedAt: scannerStartedAt}
		if err := checkpointArtifact(checkpointOpts, &artifact, ctx.Context); err != nil {
			artifact.Scanners[scanner] = ScannerResult{Status: "not_started"}
			return artifact, err
		}
		result, err := scannerResultContext(ctx.Context, opts, scanner, target, scannerStartedAt, scannerRunner)
		err = errors.Join(err, commands.failure, ctx.Context.Err())
		progress.endPhase(err != nil || result.Status == "failed")
		if err != nil {
			result.Status = "failed"
			result.StartedAt = scannerStartedAt
			result.CompletedAt = now().UTC().Format(time.RFC3339Nano)
			result.Error = commandError(err, result.Error, env)
		}
		result.DurationMs = time.Since(scannerTimerStarted).Milliseconds()
		artifact.Scanners[scanner] = result
		if err != nil {
			return artifact, err
		}
		if result.Status == "completed" && opts.ScannerResultPaths[scanner] == "" {
			artifact.targetConsumed = true
		}
	}
	evaluateGate(&artifact, opts)
	if opts.Judge != nil {
		if err := ctx.Context.Err(); err != nil {
			return artifact, err
		}
		for scanner, result := range artifact.Scanners {
			if result.Status == "failed" {
				return artifact, fmt.Errorf("judge not started: scanner %s failed", scanner)
			}
		}
		progress.startPhase("judge")
		artifact.Judge = &JudgeResult{Status: "running"}
		if err := checkpointArtifact(checkpointOpts, &artifact, ctx.Context); err != nil {
			artifact.Judge = &JudgeResult{Status: "not_started", CommandStarted: boolPointer(false)}
			return artifact, err
		}
		result, err := RunJudgeContext(ctx.Context, *opts.Judge, artifact, commandRunner, 20*time.Minute, env, sandbox.Mode)
		progress.endPhase(err != nil || result != nil && result.Status == "failed")
		if result != nil {
			artifact.Judge = result
			if err == nil && result.Status == "completed" {
				artifact.targetConsumed = true
			}
		}
		if err != nil {
			return artifact, err
		}
	}
	return artifact, nil
}

func RunTargets(opts Options, ctx RunContext, cwd string) (RunTargetsResult, error) {
	safety, err := prepareOutputSafety([]Options{opts}, opts.OutputPath, cwd)
	if err != nil {
		return RunTargetsResult{}, err
	}
	ctx.Context = workContext(ctx.Context)
	targetInputs, err := ResolveTargetInputs(opts, cwd)
	if err != nil {
		now := ctx.Now
		if now == nil {
			now = time.Now
		}
		env := ctx.Env
		if env == nil {
			env = EnvMap(os.Environ())
		}
		artifact := pendingArtifact(opts, now().UTC().Format(time.RFC3339Nano), env)
		artifact.outputSafety = safety
		finishArtifact(&artifact, opts, ctx.Context, now, &err)
		return RunTargetsResult{Single: &artifact}, err
	}
	if len(targetInputs) == 1 {
		runOpts := opts
		runOpts.Target = targetInputs[0]
		artifact, err := Run(runOpts, ctx)
		return RunTargetsResult{Single: &artifact}, err
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
		outputSafety:  safety,
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
	var runErrors error
	var stopErr error
	for _, targetInput := range targetInputs {
		runOpts := opts
		runOpts.Target = targetInput
		runOpts.OutputPath = ""
		var artifact Artifact
		if stopErr != nil {
			pendingEnv := maps.Clone(env)
			applyRuntimeEnvDefaults(runOpts, pendingEnv)
			artifact = pendingArtifact(runOpts, now().UTC().Format(time.RFC3339Nano), pendingEnv)
			artifact.outputSafety = safety
			pendingErr := fmt.Errorf("not started after prior target error: %w", stopErr)
			finishArtifact(&artifact, runOpts, ctx.Context, now, &pendingErr)
		} else {
			var err error
			artifact, err = Run(runOpts, runCtx)
			runErrors = errors.Join(runErrors, err)
			if err != nil && ctx.Context.Err() == nil {
				stopErr = err
			}
		}
		batch.Runs = append(batch.Runs, artifact)
		for scanner, result := range artifact.Scanners {
			if batch.Summary.ScannerStatuses[scanner] == nil {
				batch.Summary.ScannerStatuses[scanner] = map[string]int{}
			}
			batch.Summary.ScannerStatuses[scanner][result.Status]++
		}
	}
	runErrors = errors.Join(runErrors, ctx.Context.Err())
	batch.CompletedAt = now().UTC().Format(time.RFC3339Nano)
	if opts.OutputPath != "" {
		if err := WriteRunTargetsResultBundle(opts.OutputPath, RunTargetsResult{Batch: &batch}); err != nil {
			runErrors = errors.Join(runErrors, err)
		}
	}
	return RunTargetsResult{Batch: &batch}, runErrors
}

func RunProfileBatch(optsList []Options, ctx RunContext, cwd string) (BatchArtifact, error) {
	safety, err := prepareOutputSafety(optsList, "", cwd)
	if err != nil {
		return BatchArtifact{}, err
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
		outputSafety:  safety,
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
	return batch, workContext(ctx.Context).Err()
}

func addBatchRun(batch *BatchArtifact, artifact Artifact, targets map[string]bool) {
	batch.Runs = append(batch.Runs, artifact)
	if artifact.Target.Input != "" {
		targets[artifact.Target.Input] = true
	}
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
		safety := result.Single.outputSafety.withArtifacts([]*Artifact{result.Single})
		outputErr := writeScannerOutputFiles(spec, []*Artifact{result.Single}, safety)
		mainErr := safety.validateWrite(spec.ArtifactPath)
		outputErr = errors.Join(outputErr, mainErr)
		if outputErr != nil {
			result.Single.Complete = false
			if result.Single.Status == "completed" || result.Single.Status == "" {
				result.Single.Status = "failed"
			}
			result.Single.Gate = "error"
			result.Single.Error = strings.TrimSpace(result.Single.Error + "\n" + outputErr.Error())
		}
		if mainErr != nil {
			return outputErr
		}
		return errors.Join(outputErr, writeJSONFile(spec.ArtifactPath, result.Single))
	case result.Batch != nil:
		runs := make([]*Artifact, 0, len(result.Batch.Runs))
		for i := range result.Batch.Runs {
			runs = append(runs, &result.Batch.Runs[i])
		}
		safety := result.Batch.outputSafety.withArtifacts(runs)
		outputErr := writeScannerOutputFiles(spec, runs, safety)
		mainErr := safety.validateWrite(spec.ArtifactPath)
		outputErr = errors.Join(outputErr, mainErr)
		if outputErr != nil {
			result.Batch.Errors = append(result.Batch.Errors, BatchError{Error: outputErr.Error()})
		}
		if mainErr != nil {
			return outputErr
		}
		return errors.Join(outputErr, writeJSONFile(spec.ArtifactPath, result.Batch))
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

func writeScannerOutputFiles(spec outputBundleSpec, artifacts []*Artifact, safety outputSafety) error {
	paths := scannerOutputPaths(spec, artifacts)
	var outputErr error
	outputs := []string{spec.ArtifactPath}
	for _, runPaths := range paths {
		for _, path := range runPaths {
			outputs = append(outputs, filepath.Join(spec.RootDir, filepath.FromSlash(path)))
		}
	}
	if err := validateOutputInventory(outputs, nil); err != nil {
		return err
	}
	for index, artifact := range artifacts {
		for scanner, relPath := range paths[index] {
			result := artifact.Scanners[scanner]
			if len(result.Raw) == 0 || artifact.Status != "" && result.Status != "completed" {
				result.OutputPath = ""
				artifact.Scanners[scanner] = result
				continue
			}
			absPath := filepath.Join(spec.RootDir, filepath.FromSlash(relPath))
			if err := safety.validateWrite(absPath); err != nil {
				result.OutputPath = ""
				artifact.Scanners[scanner] = result
				outputErr = errors.Join(outputErr, err)
				continue
			}
			if err := writePrivateFile(absPath, result.Raw); err != nil {
				result.OutputPath = ""
				artifact.Scanners[scanner] = result
				outputErr = errors.Join(outputErr, err)
				continue
			}
			result.OutputPath = relPath
			artifact.Scanners[scanner] = result
		}
	}
	return outputErr
}

func scannerOutputPaths(spec outputBundleSpec, artifacts []*Artifact) []map[string]string {
	paths := make([]map[string]string, len(artifacts))
	usedRunPaths := map[string]int{}
	for index, artifact := range artifacts {
		paths[index] = map[string]string{}
		runPath := uniqueOutputPath(scannerRunOutputPath(*artifact), usedRunPaths)
		scanners := make([]string, 0, len(artifact.Scanners))
		for scanner := range artifact.Scanners {
			scanners = append(scanners, scanner)
		}
		sort.Strings(scanners)
		usedScannerPaths := map[string]int{}
		for _, scanner := range scanners {
			scannerPath := uniqueOutputPath(safeOutputPathSegment(scanner), usedScannerPaths)
			relPath := filepath.ToSlash(filepath.Join(spec.PathPrefix, runPath, scannerPath+".json"))
			paths[index][scanner] = relPath
		}
	}
	return paths
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
	if used[base] == 0 {
		used[base] = 1
		return base
	}
	dir, file := path.Split(base)
	for {
		used[base]++
		candidate := dir + file + "-" + strconv.Itoa(used[base])
		if used[candidate] == 0 {
			// Reserve generated names too: another input may already use a suffix.
			used[candidate] = 1
			return candidate
		}
	}
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
		if regularManifestExists(skillFile) {
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
	var buffer bytes.Buffer
	if err := WriteJSON(&buffer, value); err != nil {
		return err
	}
	return writePrivateFile(path, buffer.Bytes())
}

func writePrivateFile(path string, data []byte) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	mode := os.FileMode(0o600)
	if info, err := os.Lstat(path); err == nil {
		if !info.Mode().IsRegular() {
			return fmt.Errorf("refusing non-regular output: %s", path)
		}
		mode &= info.Mode().Perm()
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	file, err := os.CreateTemp(filepath.Dir(path), ".clawscan-*.json")
	if err != nil {
		return err
	}
	defer os.Remove(file.Name())
	info, err := file.Stat()
	if err != nil {
		file.Close()
		return err
	}
	mode &= info.Mode().Perm()
	writeErr := file.Chmod(mode)
	if writeErr == nil {
		_, writeErr = file.Write(data)
	}
	closeErr := file.Close()
	if err := errors.Join(writeErr, closeErr); err != nil {
		return err
	}
	return os.Rename(file.Name(), path)
}

func scannerResult(opts Options, scanner string, target resolvedTarget, startedAt string, scannerRunner ScannerRunner) (ScannerResult, error) {
	return scannerResultContext(context.Background(), opts, scanner, target, startedAt, scannerRunner)
}

func scannerResultContext(ctx context.Context, opts Options, scanner string, target resolvedTarget, startedAt string, scannerRunner ScannerRunner) (ScannerResult, error) {
	if err := ctx.Err(); err != nil {
		return ScannerResult{}, err
	}
	if path := opts.ScannerResultPaths[scanner]; path != "" {
		raw, err := readContextFile(ctx, path)
		if err != nil {
			return ScannerResult{}, err
		}
		if !json.Valid(raw) {
			return ScannerResult{}, fmt.Errorf("scanner result %s is not valid JSON: %s", scanner, path)
		}
		result := ScannerResult{
			Status:      "completed",
			StartedAt:   startedAt,
			CompletedAt: startedAt,
			Command:     []string{"scanner-result", scanner + "=" + path},
			Error:       "",
			Raw:         json.RawMessage(raw),
		}
		if scanner == "skillspector" {
			result = validateSkillSpectorReport(result)
		}
		return result, nil
	}
	if !scannerSupportsTargetKindInRegistry(registryForOptions(opts), scanner, target.kind) {
		return unsupportedTargetKindResult(scanner, target.kind, startedAt), nil
	}
	if contextual, ok := scannerRunner.(ContextScannerRunner); ok {
		return contextual.RunScannerContext(ctx, scanner, target.resolvedPath, startedAt)
	}
	if ctx.Done() != nil {
		return ScannerResult{}, errors.New("cancelable work requires a ContextScannerRunner")
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
const artifactInspectionRequiredFilePlaceholder = "{{ artifact_inspection.required_file }}"

func RenderPromptTemplate(template string, artifact Artifact) (string, error) {
	return renderPromptTemplateContext(context.Background(), template, artifact)
}

func renderPromptTemplateContext(ctx context.Context, template string, artifact Artifact) (string, error) {
	var renderErr error
	var targetFiles string
	targetFilesRendered := false
	rendered := promptPlaceholderPattern.ReplaceAllStringFunc(template, func(match string) string {
		if err := ctx.Err(); err != nil {
			renderErr = err
		}
		if renderErr != nil {
			return match
		}
		parts := promptPlaceholderPattern.FindStringSubmatch(match)
		if len(parts) != 3 {
			return match
		}
		if parts[1] == "target.files" {
			if !targetFilesRendered {
				targetFiles, renderErr = renderTargetFilesContext(ctx, artifact.Target.ResolvedPath)
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
	return renderTargetFilesContext(context.Background(), target)
}

func renderTargetFilesContext(ctx context.Context, target string) (string, error) {
	if err := ctx.Err(); err != nil {
		return "", err
	}
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
			if err := ctx.Err(); err != nil {
				return err
			}
			if err != nil {
				precomputedOmissions = append(precomputedOmissions, targetFileOmission{path: path, reason: "read failed"})
				if entry != nil && entry.IsDir() {
					return filepath.SkipDir
				}
				return nil
			}
			if entry.IsDir() {
				if shouldSkipTargetDirectory(target, path) {
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
		if err := ctx.Err(); err != nil {
			return "", err
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
		content, err := readContextFile(ctx, path)
		if err != nil {
			if isSourceReadError(err, path) {
				addOmission(path, "read failed")
				continue
			}
			return "", err
		}
		contentForPrompt := content
		nulWarning := ""
		if bytes.IndexByte(content, 0) >= 0 {
			inspection, _ := inspectNULContent(path, content)
			if !inspection.reviewable && len(scanStaticInspection(path, inspection)) == 0 {
				addOmission(path, "binary file")
				continue
			}
			contentForPrompt = inspection.content
			if inspection.textEncoding != "" {
				nulWarning = fmt.Sprintf("[decoded from %s for review]\n", inspection.textEncoding)
				if len(inspection.alternate) > 0 {
					contentForPrompt = []byte(fmt.Sprintf("%s\n\n[raw bytes with NULs removed for alternate review]\n%s", inspection.content, inspection.alternate))
				}
			} else {
				nulWarning = "[warning: NUL bytes removed from inspectable file for review]\n"
			}
		}
		renderedContentBytes := len(nulWarning) + len(contentForPrompt)
		if renderedContentBytes > maxTargetFileBytes {
			addOmission(path, "file exceeds size limit")
			continue
		}
		if totalBytes+renderedContentBytes > maxTargetFilesBytes {
			addOmission(path, "total file budget exceeded")
			continue
		}
		totalBytes += renderedContentBytes
		label := filepath.Base(path)
		if targetInfo.IsDir() {
			rel, err := filepath.Rel(target, path)
			if err != nil {
				return "", err
			}
			label = rel
		}
		text := nulWarning + strings.TrimRight(string(contentForPrompt), "\n")
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
	normalized := filepath.ToSlash(rel)
	if strings.EqualFold(normalized, skillManifestName) || strings.EqualFold(normalized, pluginManifestName) {
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

func shouldSkipTargetDirectory(root string, path string) bool {
	rel, err := filepath.Rel(root, path)
	if err != nil {
		return true
	}
	for _, part := range strings.Split(rel, string(filepath.Separator)) {
		switch part {
		case ".git", "node_modules", "vendor", ".venv":
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
	context          context.Context
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

func runJudgeAttempt(ctx context.Context, opts JudgeOptions, artifact Artifact, commandRunner CommandRunner, deadline time.Time, env map[string]string, sandboxMode string) (judgeAttemptOutcome, error) {
	if err := ctx.Err(); err != nil {
		return judgeAttemptOutcome{}, err
	}
	workspace, err := os.MkdirTemp("", "clawscan-judge-*")
	if err != nil {
		return judgeAttemptOutcome{}, err
	}
	defer os.RemoveAll(workspace)
	if err := prepareJudgeWorkspaceContext(ctx, workspace, artifact); err != nil {
		return judgeAttemptOutcome{}, err
	}
	state := &judgeCommandState{
		context:      ctx,
		workspace:    workspace,
		judgeSandbox: judgeSandboxMode(sandboxMode),
		outputPath:   filepath.Join(workspace, "judge-output.json"),
		files:        opts.Files,
	}
	if isClawHubParityProfile(artifact.Profile) {
		state.outputPath = filepath.Join(workspace, "codex-result.json")
		state.inspection, err = prepareArtifactInspectionChallengeContext(ctx, workspace)
		if err != nil {
			return judgeAttemptOutcome{}, err
		}
	}
	shell := judgeShellForGOOS(runtime.GOOS)
	command, err := renderJudgeCommand(opts.Command, artifact, state, shell.quote)
	if err != nil {
		return judgeAttemptOutcome{}, err
	}
	var output CommandOutput
	var runErr error
	if remaining := time.Until(deadline); remaining > 0 && ctx.Err() == nil {
		output, runErr = commandRunner.Run(shell.command, append(shell.args, command), workspace, remaining)
	} else {
		output.Started = boolPointer(false)
		runErr = context.DeadlineExceeded
		if ctx.Err() != nil {
			runErr = ctx.Err()
		}
	}
	raw := strings.TrimSpace(output.Stdout)
	if state.outputUsed {
		outputBytes, readErr := readContextFile(context.Background(), state.outputPath)
		if readErr == nil {
			raw = strings.TrimSpace(string(outputBytes))
		} else if runErr == nil {
			runErr = readErr
		}
	}
	result := &JudgeResult{
		CommandStarted:   output.Started,
		Status:           "completed",
		ConfiguredModel:  configuredJudgeModel(command, runtime.GOOS, env),
		PromptPath:       state.promptSource,
		OutputSchemaPath: state.schemaSource,
		OutputPath:       state.outputPath,
		PromptSHA:        state.promptSHA,
		OutputSchemaSHA:  state.outputSchemaSHA,
		Error:            "",
		Result:           nil,
	}
	outcome := judgeAttemptOutcome{result: result, inspection: state.inspection}
	if runErr != nil {
		result.Status = "failed"
		result.Error = commandError(runErr, output.Stderr, env)
	}
	if raw == "" {
		if result.Status == "failed" {
			return outcome, nil
		}
		result.Status = "failed"
		result.Error = "Judge command did not produce JSON output."
		return outcome, nil
	}
	var parsed any
	if err := json.Unmarshal([]byte(raw), &parsed); err != nil {
		if result.Status == "failed" {
			result.Result = redactEnvValues(raw, env)
			return outcome, nil
		}
		result.Status = "failed"
		result.Error = fmt.Sprintf("Judge command produced invalid JSON: %v", err)
		result.Result = redactEnvValues(raw, env)
		return outcome, nil
	}
	parsed = redactJudgeResult(parsed, env)
	parsedObject, ok := parsed.(map[string]any)
	if !ok {
		result.Status = "failed"
		result.Error = fmt.Sprintf("Judge command produced %s; expected JSON object.", judgeJSONType(parsed))
		result.Result = parsed
		return outcome, nil
	}
	result.Result = parsed
	if state.inspection != nil {
		if err := validateArtifactInspectionReceipt(parsedObject, *state.inspection); err != nil {
			result.Status = "failed"
			result.Error = err.Error()
			outcome.retryable = runErr == nil
		}
	}
	return outcome, nil
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
	return prepareArtifactInspectionChallengeContext(context.Background(), workspace)
}

func prepareArtifactInspectionChallengeContext(ctx context.Context, workspace string) (*artifactInspectionChallenge, error) {
	random := make([]byte, 32)
	if _, err := rand.Read(random); err != nil {
		return nil, fmt.Errorf("generate artifact inspection challenge: %w", err)
	}
	requiredFile, requiredSHA256, err := selectArtifactInspectionFileContext(ctx, workspace)
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
	return selectArtifactInspectionFileContext(context.Background(), workspace)
}

func selectArtifactInspectionFileContext(ctx context.Context, workspace string) (string, string, error) {
	if err := ctx.Err(); err != nil {
		return "", "", err
	}
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
			if err := ctx.Err(); err != nil {
				return err
			}
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
	if _, err := io.Copy(hash, contextReader{ctx: ctx, reader: file}); err != nil {
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
	if version, present := inspection["version"]; present {
		if version != float64(2) {
			return errors.New("Judge artifact inspection receipt version was unsupported.")
		}
		return validateArtifactInspectionReceiptV2(inspection, expected.RequiredFile)
	}
	for _, field := range []string{"required_file", "additional_files_inspected"} {
		if _, present := inspection[field]; present {
			return errors.New("Judge artifact inspection v2 fields require receipt version 2.")
		}
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
	if err := workContext(state.context).Err(); err != nil {
		return "", err
	}
	var renderErr error
	rendered := judgePlaceholderPattern.ReplaceAllStringFunc(command, func(match string) string {
		if err := workContext(state.context).Err(); err != nil {
			renderErr = err
		}
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
	template := string(promptTemplate)
	if strings.Contains(template, artifactInspectionRequiredFilePlaceholder) {
		if state.inspection == nil {
			return "", errors.New("prompt references artifact inspection, but no inspection challenge was prepared")
		}
		requiredFileJSON, err := json.Marshal(state.inspection.RequiredFile)
		if err != nil {
			return "", err
		}
		template = strings.ReplaceAll(template, artifactInspectionRequiredFilePlaceholder, string(requiredFileJSON))
	}
	var prompt string
	if isClawHubParityProfile(artifact.Profile) && judgeSourceKey(source) == "clawhub/prompt.md" {
		prompt, err = RenderClawHubPrompt(template, artifact)
	} else {
		prompt, err = renderPromptTemplateContext(workContext(state.context), template, artifact)
	}
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
	if aigAnalysis := clawHubAIGAnalysis(artifact); aigAnalysis != nil {
		supplemental = append(supplemental, clawhubprompt.ScannerEvidence{
			Label: "A.I.G SARIF evidence supplied to Codex",
			Value: aigAnalysis,
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
		if artifact.Target.Kind == targetKindPlugin {
			targetKind = "packageRelease"
		} else {
			targetKind = "skillVersion"
		}
	}
	source := context.Source
	if source == "" {
		source = "publish"
	}
	hasMaliciousSignal := clawHubHasMaliciousSignal(artifact)
	if context.HasMaliciousSignal != nil {
		hasMaliciousSignal = *context.HasMaliciousSignal
	}
	job := clawhubprompt.Job{
		Job: clawhubprompt.JobMetadata{
			TargetKind:         targetKind,
			Source:             source,
			HasMaliciousSignal: hasMaliciousSignal,
		},
		Target: clawhubprompt.Target{
			TrustedOpenClawPlugin: context.TrustedOpenClawPlugin,
		},
	}
	evidence := &clawhubprompt.Version{
		SkillSpectorAnalysis: nil,
	}
	if targetKind == "packageRelease" {
		job.Target.Release = evidence
	} else {
		job.Target.Version = evidence
	}
	return job
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
	if bytes.Contains(schema, []byte(artifactInspectionRequiredFilePlaceholder)) {
		if state.inspection == nil {
			return "", errors.New("output schema references artifact inspection, but no inspection challenge was prepared")
		}
		placeholderJSON, _ := json.Marshal(artifactInspectionRequiredFilePlaceholder)
		if bytes.Contains(bytes.ReplaceAll(schema, placeholderJSON, nil), []byte(artifactInspectionRequiredFilePlaceholder)) {
			return "", errors.New("output schema artifact inspection placeholder must be a complete JSON string")
		}
		requiredFileJSON, err := json.Marshal(state.inspection.RequiredFile)
		if err != nil {
			return "", err
		}
		schema = bytes.ReplaceAll(schema, placeholderJSON, requiredFileJSON)
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
	if err := workContext(state.context).Err(); err != nil {
		return nil, err
	}
	if state.files != nil {
		if data, ok := state.files[judgeSourceKey(source)]; ok {
			return data, nil
		}
	}
	return readContextFile(workContext(state.context), source)
}

func judgeSourceKey(source string) string {
	return filepath.ToSlash(filepath.Clean(source))
}

func prepareJudgeWorkspace(workspace string, artifact Artifact) error {
	return prepareJudgeWorkspaceContext(context.Background(), workspace, artifact)
}

func prepareJudgeWorkspaceContext(ctx context.Context, workspace string, artifact Artifact) error {
	if artifact.Target.Kind == "url" {
		return fmt.Errorf("judge workspace copying is unsupported for URL targets: %s", artifact.Target.Input)
	}
	// Every profile receives the complete artifact before its metadata layout is written.
	manifest, err := copyTargetToWorkspaceContext(ctx, artifact.Target.ResolvedPath, filepath.Join(workspace, "artifact"))
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
		if err := ctx.Err(); err != nil {
			return err
		}
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
	return copyTargetToWorkspaceContext(context.Background(), source, destRoot)
}

func copyTargetToWorkspaceContext(ctx context.Context, source string, destRoot string) (TargetWorkspaceManifest, error) {
	manifest := TargetWorkspaceManifest{}
	if err := ctx.Err(); err != nil {
		return manifest, err
	}
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
		if err := copyFileContext(ctx, source, filepath.Join(destRoot, filepath.Base(source))); err != nil {
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
		if err := ctx.Err(); err != nil {
			return err
		}
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
		if err := ctx.Err(); err != nil {
			return manifest, err
		}
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
		if err := copyFileContext(ctx, candidate.path, filepath.Join(destRoot, rel)); err != nil {
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
	return copyFileContext(context.Background(), source, dest)
}

func copyFileContext(ctx context.Context, source string, dest string) error {
	if err := ctx.Err(); err != nil {
		return err
	}
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
	if _, err := io.Copy(out, contextReader{ctx: ctx, reader: in}); err != nil {
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
	Context              context.Context
	CommandRunner        CommandRunner
	Env                  map[string]string
	Profile              string
	TargetKind           string
	TargetID             string
	Registry             ScannerRegistry
	SandboxMode          string
	SkillSpectorCommand  []string
	VirusTotalHTTPClient VirusTotalHTTPClient
	Timeout              time.Duration
}

func (runner ExternalScannerRunner) RunScanner(name string, target string, startedAt string) (ScannerResult, error) {
	if err := workContext(runner.Context).Err(); err != nil {
		return ScannerResult{}, err
	}
	if runner.CommandRunner != nil && runner.Context != nil {
		runner.CommandRunner = &boundCommandRunner{ctx: runner.Context, runner: runner.CommandRunner}
	}
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

func (runner ExternalScannerRunner) RunScannerContext(ctx context.Context, name string, target string, startedAt string) (ScannerResult, error) {
	runner.Context = ctx
	return runner.RunScanner(name, target, startedAt)
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
	exitCode := gateEligibleExitCode(output.ExitCode)
	completedAt := time.Now().UTC().Format(time.RFC3339Nano)
	raw := strings.TrimSpace(output.Stdout)
	if runErr != nil {
		message := commandError(runErr, output.Stderr, runner.Env)
		if json.Valid([]byte(raw)) {
			return ScannerResult{
				Status:      commandScannerResultStatus(output, runErr),
				StartedAt:   startedAt,
				CompletedAt: completedAt,
				Command:     fullCommand,
				Error:       message,
				ExitCode:    exitCode,
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
		ExitCode:    exitCode,
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
		if _, err := copyTargetToWorkspaceContext(workContext(runner.Context), target, filepath.Join(resultDir, "artifact")); err != nil {
			return ScannerResult{}, fmt.Errorf("prepare ClawHub SkillSpector workspace: %w", err)
		}
		scanTarget = "artifact"
		cwd = resultDir
		resultName = "skillspector-report-0.json"
	} else if runner.SandboxMode == SandboxModeDocker {
		cwd = resultDir
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
	exitCode := gateEligibleExitCode(output.ExitCode)
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
					ExitCode:    exitCode,
					Raw:         nil,
				}, nil
			}
			return validateSkillSpectorReport(ScannerResult{
				Status:      commandScannerResultStatus(output, runErr),
				StartedAt:   startedAt,
				CompletedAt: completedAt,
				Command:     fullCommand,
				Error:       message,
				ExitCode:    exitCode,
				Raw:         json.RawMessage(raw),
			}), nil
		}
		return ScannerResult{
			Status:      "failed",
			StartedAt:   startedAt,
			CompletedAt: completedAt,
			Command:     fullCommand,
			Error:       message,
			ExitCode:    exitCode,
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
			ExitCode:    exitCode,
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
			ExitCode:    exitCode,
			Raw:         nil,
		}, nil
	}
	return validateSkillSpectorReport(ScannerResult{
		Status:      "completed",
		StartedAt:   startedAt,
		CompletedAt: completedAt,
		Command:     fullCommand,
		Error:       "",
		ExitCode:    exitCode,
		Raw:         json.RawMessage(raw),
	}), nil
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

const (
	defaultAIGOpenAIModel   = "gpt-5.5"
	defaultAIGOpenAIBaseURL = "https://api.openai.com/v1"
)

// defaultAIGRuntimeEnv keeps credentials on their intended provider. AIG's
// upstream default is OpenRouter, so an OpenAI or Codex credential must also
// select OpenAI's endpoint and a compatible model. A dedicated LLM_API_KEY
// retains AIG's documented provider defaults.
func defaultAIGRuntimeEnv(env map[string]string) {
	if env == nil {
		return
	}
	if strings.TrimSpace(env["LLM_API_KEY"]) != "" {
		return
	}
	if strings.TrimSpace(env["OPENAI_API_KEY"]) == "" {
		codexKey := strings.TrimSpace(env["CODEX_API_KEY"])
		if codexKey == "" {
			return
		}
		env["LLM_API_KEY"] = codexKey
	}
	if strings.TrimSpace(env["DEFAULT_MODEL"]) == "" {
		env["DEFAULT_MODEL"] = defaultAIGOpenAIModel
	}
	if strings.TrimSpace(env["DEFAULT_BASE_URL"]) == "" {
		env["DEFAULT_BASE_URL"] = defaultAIGOpenAIBaseURL
	}
}

func applyRuntimeEnvDefaults(opts Options, env map[string]string) {
	applyScannerModelDefaults(opts, env)
	if scannerRequested(opts, "skillspector") {
		defaultSkillSpectorOpenAIProvider(env)
	}
	if scannerRequested(opts, "aig") {
		defaultAIGRuntimeEnv(env)
	}
}

func discoverSkillSpectorCommand() []string {
	if _, err := exec.LookPath("skillspector"); err == nil {
		return []string{"skillspector"}
	}
	return []string{"uvx", "--from", "git+https://github.com/NVIDIA/skillspector", "skillspector"}
}

type defaultCommandRunner struct {
	Env      map[string]string
	Progress *runProgress
}

func (runner defaultCommandRunner) Run(command string, args []string, cwd string, timeout time.Duration) (CommandOutput, error) {
	return runner.RunContext(context.Background(), command, args, cwd, timeout)
}

func (runner defaultCommandRunner) RunContext(parent context.Context, command string, args []string, cwd string, timeout time.Duration) (CommandOutput, error) {
	ctx, cancel := context.WithTimeout(workContext(parent), timeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, command, args...)
	cmd.WaitDelay = 100 * time.Millisecond
	cmd.Dir = cwd
	if runner.Env != nil {
		cmd.Env = envMapToEnviron(runner.Env)
	}
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	childProgress := newChildProgressWriter(runner.Progress, runner.Env)
	if childProgress != nil {
		cmd.Stdout = io.MultiWriter(&stdout, childProgress)
	}
	started := time.Now()
	err := cmd.Start()
	pid := 0
	if err == nil {
		pid = cmd.Process.Pid
		runner.Progress.emit(progressEvent{Event: "command_start", PID: pid})
		if childProgress != nil {
			childProgress.start(pid)
		}
		err = cmd.Wait()
		if childProgress != nil {
			childProgress.finish()
		}
	}
	if ctx.Err() != nil {
		err = fmt.Errorf("command stopped: %w", ctx.Err())
		if errors.Is(ctx.Err(), context.DeadlineExceeded) {
			err = fmt.Errorf("command timed out after %s: %w", timeout, ctx.Err())
		}
	}
	output := CommandOutput{Stdout: stdout.String(), Stderr: stderr.String(), Started: boolPointer(pid != 0)}
	if ctx.Err() == nil && !errors.Is(err, exec.ErrWaitDelay) && cmd.ProcessState != nil {
		exitCode := cmd.ProcessState.ExitCode()
		if exitCode >= 0 {
			output.ExitCode = &exitCode
		}
	}
	duration := time.Since(started).Milliseconds()
	runner.Progress.emit(progressEvent{Event: "command_end", PID: pid, DurationMs: &duration, ExitCode: output.ExitCode, Failed: err != nil})
	return output, err
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
	var configSource *string
	if opts.ConfigSource != "" {
		source := opts.ConfigSource
		configSource = &source
	}
	return Artifact{
		SchemaVersion: "clawscan-run-v1",
		Profile:       opts.Profile,
		ConfigSource:  configSource,
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
		Gate:        "pass",
		GateRules:   []FiredGateRule{},
		Judge:       nil,
	}
}

func validateGateRuleScanners(opts Options) error {
	requested := make(map[string]bool, len(opts.Scanners))
	for _, scanner := range opts.Scanners {
		requested[scanner] = true
	}
	var unrequested []string
	for scanner := range opts.GateRules {
		if !requested[scanner] {
			unrequested = append(unrequested, scanner)
		}
	}
	if len(unrequested) == 0 {
		return nil
	}
	sort.Strings(unrequested)
	return fmt.Errorf("gate rule references scanner %s, but it was not requested", unrequested[0])
}

func evaluateGate(artifact *Artifact, opts Options) {
	evaluated := make(map[string]bool, len(opts.Scanners))
	for _, scanner := range opts.Scanners {
		if evaluated[scanner] {
			continue
		}
		evaluated[scanner] = true
		result := artifact.Scanners[scanner]
		if result.Status != "completed" {
			continue
		}
		policy := opts.GateRules[scanner]
		if len(policy.JSONRules) > 0 {
			evaluateJSONGateRules(artifact, scanner, result.Raw, policy.JSONRules)
		}
		if result.ExitCode == nil {
			continue
		}
		if policy.BlockOnExitCode != nil && policy.BlockOnExitCode.Matches(*result.ExitCode) {
			artifact.GateRules = append(artifact.GateRules, FiredGateRule{
				Scanner: scanner, Rule: "blockOnExitCode", ExitCode: result.ExitCode, Action: "block",
			})
			setGateAction(artifact, "block")
		}
		if policy.WarnOnExitCode != nil && policy.WarnOnExitCode.Matches(*result.ExitCode) {
			artifact.GateRules = append(artifact.GateRules, FiredGateRule{
				Scanner: scanner, Rule: "warnOnExitCode", ExitCode: result.ExitCode, Action: "warn",
			})
			setGateAction(artifact, "warn")
		}
	}
}

func evaluateJSONGateRules(artifact *Artifact, scanner string, raw json.RawMessage, rules []JSONGateRule) {
	if len(raw) == 0 {
		return
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	var document any
	if err := decoder.Decode(&document); err != nil {
		return
	}

	for _, rule := range rules {
		matched := false
		matchedPath := ""
		var matchedValue json.RawMessage
		expected, equalsOK := decodeJSONGateScalar(rule.Equals)
		for _, path := range rule.Paths {
			values, present, emptyArray, rootPresent := jsonGatePathValues(document, path)
			if !present {
				if rule.Fallback == "root" && rootPresent {
					break
				}
				continue
			}
			if rule.Exists {
				for _, value := range values {
					if jsonGateValueIsNonEmpty(value) {
						matched = true
						matchedPath = path
						break
					}
				}
				if matched || emptyArray || rule.Fallback == "root" && rootPresent {
					break
				}
				continue
			}
			authoritative := emptyArray || rule.Fallback == "root" && rootPresent
			if equalsOK {
				for _, value := range values {
					if !jsonGateValueIsNonEmpty(value) {
						continue
					}
					authoritative = true
					if jsonGateValuesEqual(value, expected, rule.Normalize) {
						matched = true
						matchedPath = path
						matchedValue, _ = json.Marshal(value)
						break
					}
				}
			}
			if matched || authoritative {
				break
			}
		}
		if !matched {
			continue
		}
		artifact.GateRules = append(artifact.GateRules, FiredGateRule{
			Scanner: scanner,
			Rule:    rule.ID,
			Path:    matchedPath,
			Value:   matchedValue,
			Action:  rule.Action,
		})
		setGateAction(artifact, rule.Action)
	}
}

func ValidateJSONGatePath(path string) error {
	if path == "" {
		return errors.New("path must not be empty")
	}
	for _, segment := range strings.Split(path, ".") {
		if _, _, ok := parseJSONGatePathSegment(segment); !ok {
			return errors.New("path must use dotted object fields with optional [] array traversal")
		}
	}
	return nil
}

func jsonGatePathValues(document any, path string) ([]any, bool, bool, bool) {
	values := []any{document}
	rootPresent := false
	for index, segment := range strings.Split(path, ".") {
		if len(values) == 0 {
			return nil, true, true, rootPresent
		}
		keys, array, _ := parseJSONGatePathSegment(segment)
		next := make([]any, 0)
		present := false
		rootKeyPresent := false
		for _, value := range values {
			object, ok := value.(map[string]any)
			if !ok {
				continue
			}
			if array {
				child, ok := object[keys[0]]
				if !ok {
					continue
				}
				rootKeyPresent = true
				if child == nil {
					continue
				}
				items, ok := child.([]any)
				if ok {
					present = true
					next = append(next, items...)
				}
				continue
			}

			for _, key := range keys {
				child, ok := object[key]
				if !ok {
					continue
				}
				rootKeyPresent = true
				present = true
				next = append(next, child)
				break
			}
		}
		if index == 0 {
			rootPresent = rootKeyPresent
		}
		if !present {
			return nil, false, false, rootPresent
		}
		values = next
	}
	return values, true, len(values) == 0, rootPresent
}

func parseJSONGatePathSegment(segment string) ([]string, bool, bool) {
	array := strings.HasSuffix(segment, "[]")
	base := strings.TrimSuffix(segment, "[]")
	if base == "" || strings.ContainsAny(base, "[]") {
		return nil, false, false
	}
	keys := strings.Split(base, "|")
	if array && len(keys) > 1 {
		return nil, false, false
	}
	for _, key := range keys {
		if key == "" {
			return nil, false, false
		}
	}
	return keys, array, true
}

func jsonGateValueIsNonEmpty(value any) bool {
	if value == nil {
		return false
	}
	switch value := value.(type) {
	case string:
		return strings.TrimSpace(value) != ""
	case []any:
		return len(value) > 0
	case map[string]any:
		return len(value) > 0
	default:
		return true
	}
}

func decodeJSONGateScalar(raw json.RawMessage) (any, bool) {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	var value any
	if err := decoder.Decode(&value); err != nil {
		return nil, false
	}
	switch value.(type) {
	case string, bool, json.Number:
		return value, true
	default:
		return nil, false
	}
}

func jsonGateValuesEqual(actual any, expected any, normalize string) bool {
	switch expected := expected.(type) {
	case string:
		actual, ok := actual.(string)
		if ok && normalize == "identifier" {
			actual = normalizeJSONGateIdentifier(actual)
			expected = normalizeJSONGateIdentifier(expected)
		}
		return ok && actual == expected
	case bool:
		actual, ok := actual.(bool)
		return ok && actual == expected
	case json.Number:
		actual, ok := actual.(json.Number)
		if !ok {
			return false
		}
		actualNegative, actualDigits, actualExponent, actualOK := canonicalJSONGateNumber(actual)
		expectedNegative, expectedDigits, expectedExponent, expectedOK := canonicalJSONGateNumber(expected)
		return actualOK && expectedOK &&
			actualNegative == expectedNegative &&
			actualDigits == expectedDigits &&
			actualExponent.Cmp(expectedExponent) == 0
	default:
		return false
	}
}

func canonicalJSONGateNumber(value json.Number) (bool, string, *big.Int, bool) {
	text := value.String()
	negative := strings.HasPrefix(text, "-")
	if negative {
		text = strings.TrimPrefix(text, "-")
	}
	mantissa := text
	exponentText := ""
	if index := strings.IndexAny(text, "eE"); index >= 0 {
		mantissa = text[:index]
		exponentText = text[index+1:]
	}
	exponent := new(big.Int)
	if exponentText != "" {
		if _, ok := exponent.SetString(exponentText, 10); !ok {
			return false, "", nil, false
		}
	}
	integer, fraction, hasFraction := strings.Cut(mantissa, ".")
	digits := integer
	if hasFraction {
		digits += fraction
		exponent.Sub(exponent, big.NewInt(int64(len(fraction))))
	}
	digits = strings.TrimLeft(digits, "0")
	if digits == "" {
		return false, "0", new(big.Int), true
	}
	trimmed := strings.TrimRight(digits, "0")
	exponent.Add(exponent, big.NewInt(int64(len(digits)-len(trimmed))))
	return negative, trimmed, exponent, true
}

func normalizeJSONGateIdentifier(value string) string {
	value = strings.ToUpper(strings.TrimSpace(value))
	return strings.NewReplacer(" ", "_", "-", "_").Replace(value)
}

func commandScannerResultStatus(output CommandOutput, runErr error) string {
	if runErr != nil && gateEligibleExitCode(output.ExitCode) == nil {
		return "failed"
	}
	return "completed"
}

func setGateAction(artifact *Artifact, action string) {
	if action == "block" || action == "warn" && artifact.Gate == "pass" {
		artifact.Gate = action
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
	names := make([]string, 0)
	for key := range env {
		if isSecretEnvKey(key) {
			names = append(names, key)
		}
	}
	return commandErrorForEnvNames(runErr, stderr, env, names)
}

func commandErrorForEnvNames(runErr error, stderr string, env map[string]string, names []string) string {
	message := redactEnvValuesForNames(runErr.Error(), env, names)
	redactedStderr := strings.TrimSpace(redactEnvValuesForNames(stderr, env, names))
	if redactedStderr != "" {
		message += ": " + redactedStderr
	}
	return message
}

func redactEnvValues(value string, env map[string]string) string {
	names := make([]string, 0)
	for key := range env {
		if isSecretEnvKey(key) {
			names = append(names, key)
		}
	}
	return redactEnvValuesForNames(value, env, names)
}

func redactEnvValuesForNames(value string, env map[string]string, names []string) string {
	if value == "" || len(env) == 0 || len(names) == 0 {
		return value
	}
	secretSet := make(map[string]bool, len(names))
	for _, name := range names {
		secret := env[name]
		trimmed := strings.TrimSpace(secret)
		if trimmed == "" {
			continue
		}
		secretSet[secret] = true
		secretSet[trimmed] = true
	}
	secrets := make([]string, 0, len(secretSet))
	for secret := range secretSet {
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
		if adapter, ok := registryForOptions(opts).Adapter(scanner); ok {
			reqs = append(reqs, adapter.Requirements(env)...)
		}
	}
	return dedupe(reqs)
}

func registryForOptions(opts Options) ScannerRegistry {
	if opts.ScannerRegistry.isZero() {
		return DefaultScannerRegistry()
	}
	return opts.ScannerRegistry
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

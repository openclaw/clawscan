package runner

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"
)

type Options struct {
	Target             string
	Scanners           []string
	ScannerResultPaths map[string]string
	OutputPath         string
	JSON               bool
	Judge              *JudgeOptions
}

type JudgeOptions struct {
	Command string
}

type RunContext struct {
	Env                  map[string]string
	Now                  func() time.Time
	CommandRunner        CommandRunner
	ScannerRunner        ScannerRunner
	SkillSpectorCommand  []string
	VirusTotalHTTPClient VirusTotalHTTPClient
	GenDigitalHTTPClient GenDigitalHTTPClient
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
	Target        Target                   `json:"target"`
	StartedAt     string                   `json:"startedAt"`
	CompletedAt   string                   `json:"completedAt"`
	Env           map[string]string        `json:"env"`
	Scanners      map[string]ScannerResult `json:"scanners"`
	Judge         *JudgeResult             `json:"judge"`
}

type Target struct {
	Kind         string `json:"kind"`
	Input        string `json:"input"`
	ResolvedPath string `json:"resolvedPath"`
}

type resolvedTarget struct {
	kind         string
	input        string
	resolvedPath string
}

type ScannerResult struct {
	Status      string          `json:"status"`
	StartedAt   string          `json:"startedAt"`
	CompletedAt string          `json:"completedAt"`
	Command     []string        `json:"command"`
	Error       string          `json:"error"`
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

type requirement struct {
	envVar string
	reason string
}

var scannerSet = map[string]bool{
	"agentverus":   true,
	"skillspector": true,
	"snyk":         true,
	"cisco":        true,
	"virustotal":   true,
	"gendigital":   true,
	"static":       true,
}

func ScannerIDs() []string {
	ids := make([]string, 0, len(scannerSet))
	for id := range scannerSet {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	return ids
}

func ParseArgs(args []string) (Options, error) {
	if len(args) == 0 || strings.HasPrefix(args[0], "--") {
		return Options{}, errors.New("Missing scan target")
	}
	opts := Options{Target: args[0], ScannerResultPaths: map[string]string{}}
	var judge string
	for i := 1; i < len(args); i++ {
		arg := args[i]
		switch arg {
		case "--scanner":
			value, next, err := readValue(args, i, arg)
			if err != nil {
				return Options{}, err
			}
			if !scannerSet[value] {
				return Options{}, fmt.Errorf("Unknown scanner: %s", value)
			}
			opts.Scanners = append(opts.Scanners, value)
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
			if !scannerSet[scanner] {
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
	var missing []requirement
	for _, req := range requirements(opts, env) {
		if strings.TrimSpace(env[req.envVar]) == "" {
			missing = append(missing, req)
		}
	}
	if len(missing) == 0 {
		return nil
	}
	lines := []string{"Missing required environment variables:", ""}
	for _, req := range missing {
		lines = append(lines, fmt.Sprintf("- %s required by %s", req.envVar, req.reason))
	}
	return errors.New(strings.Join(lines, "\n"))
}

func Run(opts Options, ctx RunContext) (Artifact, error) {
	env := ctx.Env
	if env == nil {
		env = EnvMap(os.Environ())
	}
	if err := ValidateRequirements(opts, env); err != nil {
		return Artifact{}, err
	}
	now := ctx.Now
	if now == nil {
		now = time.Now
	}
	startedAt := now().UTC().Format(time.RFC3339Nano)
	target, err := resolveTarget(opts.Target)
	if err != nil {
		return Artifact{}, err
	}
	commandRunner := ctx.CommandRunner
	if commandRunner == nil {
		commandRunner = defaultCommandRunner{Env: env}
	}
	scannerRunner := ctx.ScannerRunner
	if scannerRunner == nil {
		scannerRunner = ExternalScannerRunner{
			CommandRunner:        commandRunner,
			Env:                  env,
			SkillSpectorCommand:  ctx.SkillSpectorCommand,
			VirusTotalHTTPClient: ctx.VirusTotalHTTPClient,
			GenDigitalHTTPClient: ctx.GenDigitalHTTPClient,
			Timeout:              20 * time.Minute,
		}
	}
	artifact := NewArtifact(opts, target.resolvedPath, startedAt, startedAt, env)
	artifact.Target.Kind = target.kind
	for _, scanner := range opts.Scanners {
		scannerStartedAt := now().UTC().Format(time.RFC3339Nano)
		result, err := scannerResult(opts, scanner, target.resolvedPath, scannerStartedAt, scannerRunner)
		if err != nil {
			return Artifact{}, err
		}
		artifact.Scanners[scanner] = result
	}
	if opts.Judge != nil {
		result, err := RunJudge(*opts.Judge, artifact, commandRunner, 20*time.Minute, env)
		if err != nil {
			return Artifact{}, err
		}
		artifact.Judge = result
	}
	artifact.CompletedAt = now().UTC().Format(time.RFC3339Nano)
	if opts.OutputPath != "" {
		if err := os.MkdirAll(filepath.Dir(opts.OutputPath), 0o755); err != nil {
			return Artifact{}, err
		}
		file, err := os.Create(opts.OutputPath)
		if err != nil {
			return Artifact{}, err
		}
		defer file.Close()
		if err := WriteJSON(file, artifact); err != nil {
			return Artifact{}, err
		}
	}
	return artifact, nil
}

func scannerResult(opts Options, scanner string, target string, startedAt string, scannerRunner ScannerRunner) (ScannerResult, error) {
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
	return scannerRunner.RunScanner(scanner, target, startedAt)
}

func resolveTarget(input string) (resolvedTarget, error) {
	if isURLTarget(input) {
		return resolvedTarget{kind: "url", input: input, resolvedPath: input}, nil
	}
	resolved, err := filepath.Abs(input)
	if err != nil {
		return resolvedTarget{}, err
	}
	return resolvedTarget{kind: "skill", input: input, resolvedPath: resolved}, nil
}

func isURLTarget(input string) bool {
	parsed, err := url.Parse(input)
	return err == nil && parsed.Scheme != "" && parsed.Host != "" && (parsed.Scheme == "http" || parsed.Scheme == "https")
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
	targetInfo, err := os.Stat(target)
	if err != nil {
		return "", err
	}
	if !targetInfo.IsDir() {
		paths = append(paths, target)
	} else {
		var skippedDirs []string
		if err := filepath.WalkDir(target, func(path string, entry os.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if entry.IsDir() {
				if shouldSkipTargetPath(target, path) {
					skippedDirs = append(skippedDirs, path)
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
		paths = append(paths, skippedDirs...)
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
		blocks = append(blocks, fmt.Sprintf("### %s\n%s%s\n%s\n%s", filepath.ToSlash(label), fence, languageForPath(path), text, fence))
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
	return fmt.Sprintf("### %s\n[omitted: %s]", filepath.ToSlash(rel), reason)
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
	outputPath       string
	outputUsed       bool
	promptSource     string
	promptPath       string
	promptSHA        string
	outputSchemaPath string
	outputSchemaSHA  string
	schemaSource     string
}

func RunJudge(opts JudgeOptions, artifact Artifact, commandRunner CommandRunner, timeout time.Duration, env map[string]string) (*JudgeResult, error) {
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
		workspace:  workspace,
		outputPath: filepath.Join(workspace, "judge-output.json"),
	}
	command, err := renderJudgeCommand(opts.Command, artifact, state)
	if err != nil {
		return nil, err
	}
	output, runErr := commandRunner.Run("/bin/sh", []string{"-c", command}, workspace, timeout)
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
			result.Result = raw
			return result, nil
		}
		result.Status = "failed"
		result.Error = fmt.Sprintf("Judge command produced invalid JSON: %v", err)
		result.Result = raw
		return result, nil
	}
	if _, ok := parsed.(map[string]any); !ok {
		result.Status = "failed"
		result.Error = fmt.Sprintf("Judge command produced %s; expected JSON object.", judgeJSONType(parsed))
		result.Result = parsed
		return result, nil
	}
	result.Result = parsed
	return result, nil
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

func renderJudgeCommand(command string, artifact Artifact, state *judgeCommandState) (string, error) {
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
			return shellQuote(state.workspace)
		case "output":
			if value != "" {
				renderErr = fmt.Errorf("{{ output }} does not accept a path")
				return match
			}
			state.outputUsed = true
			return shellQuote(state.outputPath)
		case "prompt":
			path, err := prepareJudgePrompt(value, artifact, state)
			if err != nil {
				renderErr = err
				return match
			}
			return shellQuote(path)
		case "output_schema":
			path, err := prepareJudgeOutputSchema(value, state)
			if err != nil {
				renderErr = err
				return match
			}
			return shellQuote(path)
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

func shellQuote(value string) string {
	if value == "" {
		return "''"
	}
	return "'" + strings.ReplaceAll(value, "'", "'\"'\"'") + "'"
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
	promptTemplate, err := os.ReadFile(source)
	if err != nil {
		return "", err
	}
	prompt, err := RenderPromptTemplate(string(promptTemplate), artifact)
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
	schema, err := os.ReadFile(source)
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

func prepareJudgeWorkspace(workspace string, artifact Artifact) error {
	if artifact.Target.Kind == "url" {
		return fmt.Errorf("judge workspace copying is unsupported for URL targets: %s", artifact.Target.Input)
	}
	manifest, err := copyTargetToWorkspace(artifact.Target.ResolvedPath, filepath.Join(workspace, "artifact"))
	if err != nil {
		return err
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
	info, err := os.Stat(source)
	if err != nil {
		return manifest, err
	}
	if !info.IsDir() {
		if err := os.MkdirAll(destRoot, 0o755); err != nil {
			return manifest, err
		}
		if !info.Mode().IsRegular() {
			manifest.addOmitted(filepath.Base(source), "not regular file", 0)
			return manifest, nil
		}
		if info.Size() > maxTargetFileBytes {
			manifest.addOmitted(filepath.Base(source), "file exceeds size limit", info.Size())
			return manifest, nil
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
	var totalBytes int64
	type workspaceFileCandidate struct {
		path string
		rel  string
		info os.FileInfo
	}
	var candidates []workspaceFileCandidate
	err = filepath.WalkDir(source, func(path string, entry os.DirEntry, err error) error {
		if err != nil {
			return manifest.recordWalkError(source, path, entry)
		}
		if shouldSkipTargetPath(source, path) {
			rel := relativeManifestPath(source, path)
			if entry.IsDir() {
				manifest.addOmitted(rel, "skipped path", 0)
				return filepath.SkipDir
			}
			manifest.addOmitted(rel, "skipped path", 0)
			return nil
		}
		if entry.IsDir() {
			return nil
		}
		info, err := entry.Info()
		if err != nil {
			return err
		}
		if !info.Mode().IsRegular() {
			return nil
		}
		rel, err := filepath.Rel(source, path)
		if err != nil {
			return err
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
	for _, candidate := range candidates {
		info := candidate.info
		rel := candidate.rel
		if info.Size() > maxTargetFileBytes {
			manifest.addOmitted(rel, "file exceeds size limit", info.Size())
			continue
		}
		if totalBytes+info.Size() > maxTargetFilesBytes {
			manifest.addOmitted(rel, "total file budget exceeded", info.Size())
			continue
		}
		if err := copyFile(candidate.path, filepath.Join(destRoot, rel)); err != nil {
			if isSourceReadError(err, candidate.path) {
				manifest.addOmitted(rel, "read failed", info.Size())
				continue
			}
			return manifest, err
		}
		totalBytes += info.Size()
		manifest.addCopied(rel, info.Size())
	}
	return manifest, nil
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

func (manifest *TargetWorkspaceManifest) addOmitted(path string, reason string, bytes int64) {
	manifest.TotalOmittedBytes += bytes
	if len(manifest.Omitted) >= maxOmittedTargetFileMarkers {
		manifest.SuppressedOmitted++
		return
	}
	manifest.Omitted = append(manifest.Omitted, TargetWorkspaceOmission{
		Path:   filepath.ToSlash(path),
		Reason: reason,
		Bytes:  bytes,
	})
}

func (manifest *TargetWorkspaceManifest) recordWalkError(root string, path string, entry os.DirEntry) error {
	rel := relativeManifestPath(root, path)
	manifest.addOmitted(rel, "read failed", 0)
	if entry != nil && entry.IsDir() {
		return filepath.SkipDir
	}
	return nil
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
	SkillSpectorCommand  []string
	VirusTotalHTTPClient VirusTotalHTTPClient
	GenDigitalHTTPClient GenDigitalHTTPClient
	Timeout              time.Duration
}

type OpenAIRequestOptions struct {
	Model     string
	Reasoning string
}

type openAIRequest struct {
	Model     string                 `json:"model"`
	Input     []openAIRequestMessage `json:"input"`
	Text      openAIRequestText      `json:"text"`
	Reasoning *openAIReasoning       `json:"reasoning,omitempty"`
}

type openAIRequestMessage struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

type openAIRequestText struct {
	Format openAIResponseFormat `json:"format"`
}

type openAIResponseFormat struct {
	Type   string `json:"type"`
	Name   string `json:"name"`
	Schema any    `json:"schema"`
	Strict bool   `json:"strict"`
}

type openAIReasoning struct {
	Effort string `json:"effort"`
}

func OpenAIRequestBody(opts OpenAIRequestOptions, systemPrompt string, prompt string, schema json.RawMessage) ([]byte, error) {
	if !strings.HasPrefix(opts.Model, "openai/") {
		return nil, fmt.Errorf("unsupported OpenAI request model provider: %s", opts.Model)
	}
	var schemaValue any
	if err := json.Unmarshal(schema, &schemaValue); err != nil {
		return nil, fmt.Errorf("parse output schema: %w", err)
	}
	input := []openAIRequestMessage{}
	if systemPrompt != "" {
		input = append(input, openAIRequestMessage{Role: "system", Content: systemPrompt})
	}
	input = append(input, openAIRequestMessage{Role: "user", Content: prompt})
	requestBody := openAIRequest{
		Model: strings.TrimPrefix(opts.Model, "openai/"),
		Input: input,
		Text: openAIRequestText{Format: openAIResponseFormat{
			Type:   "json_schema",
			Name:   "clawscan_output",
			Schema: schemaValue,
			Strict: true,
		}},
	}
	if opts.Reasoning != "" {
		requestBody.Reasoning = &openAIReasoning{Effort: opts.Reasoning}
	}
	return json.Marshal(requestBody)
}

func (runner ExternalScannerRunner) RunScanner(name string, target string, startedAt string) (ScannerResult, error) {
	switch name {
	case "agentverus":
		return runner.runAgentVerus(target, startedAt)
	case "skillspector":
		return runner.runSkillSpector(target, startedAt)
	case "static":
		return runner.runStatic(target, startedAt)
	case "snyk":
		return runner.runSnyk(target, startedAt)
	case "cisco":
		return runner.runCisco(target, startedAt)
	case "virustotal":
		return runner.runVirusTotal(target, startedAt)
	case "gendigital":
		return runner.runGenDigital(target, startedAt)
	default:
		return ScannerResult{
			Status:      "skipped",
			StartedAt:   startedAt,
			CompletedAt: time.Now().UTC().Format(time.RFC3339Nano),
			Command:     nil,
			Error:       "Scanner adapter not implemented in foundation slice.",
			Raw:         nil,
		}, nil
	}
}

func (runner ExternalScannerRunner) runAgentVerus(target string, startedAt string) (ScannerResult, error) {
	command := "npx"
	args := []string{"--yes", "agentverus-scanner", "scan", target, "--json"}
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
	commandParts := runner.SkillSpectorCommand
	if len(commandParts) == 0 {
		commandParts = discoverSkillSpectorCommand()
	}
	command := commandParts[0]
	args := append([]string{}, commandParts[1:]...)
	resultDir, err := os.MkdirTemp("", "clawscan-skillspector-*")
	if err != nil {
		return ScannerResult{}, err
	}
	defer os.RemoveAll(resultDir)
	resultPath := filepath.Join(resultDir, "skillspector-report.json")
	args = append(args, "scan", target, "--format", "json", "--output", resultPath)
	if !skillSpectorLLMEnabled(runner.Env) {
		args = append(args, "--no-llm")
	}
	fullCommand := append([]string{command}, args...)
	timeout := runner.Timeout
	if timeout == 0 {
		timeout = 20 * time.Minute
	}
	output, runErr := runner.CommandRunner.Run(command, args, "", timeout)
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
		Target: Target{
			Kind:         "skill",
			Input:        opts.Target,
			ResolvedPath: resolvedPath,
		},
		StartedAt:   startedAt,
		CompletedAt: completedAt,
		Env:         envPresence(opts, env),
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

func isSecretEnvKey(key string) bool {
	upper := strings.ToUpper(key)
	return strings.Contains(upper, "TOKEN") ||
		strings.Contains(upper, "SECRET") ||
		strings.Contains(upper, "PASSWORD") ||
		strings.HasSuffix(upper, "_KEY") ||
		strings.Contains(upper, "API_KEY")
}

func requirements(opts Options, env map[string]string) []requirement {
	var reqs []requirement
	for _, scanner := range opts.Scanners {
		if opts.ScannerResultPaths[scanner] != "" {
			continue
		}
		switch scanner {
		case "skillspector":
			if skillSpectorLLMEnabled(env) {
				reqs = append(reqs, requirement{"CLAWSCAN_SKILLSPECTOR_LLM", "scanner skillspector llm opt-in"})
				if envVar := skillSpectorProviderKeyEnv(env); envVar != "" {
					reqs = append(reqs, requirement{envVar, "scanner skillspector llm"})
				}
			}
		case "virustotal":
			reqs = append(reqs, requirement{"VIRUSTOTAL_API_KEY", "scanner virustotal"})
		case "snyk":
			reqs = append(reqs, requirement{"SNYK_TOKEN", "scanner snyk"})
		}
	}
	return dedupe(reqs)
}

func envPresence(opts Options, env map[string]string) map[string]string {
	out := map[string]string{}
	for _, req := range requirements(opts, env) {
		if strings.TrimSpace(env[req.envVar]) == "" {
			out[req.envVar] = "missing"
		} else {
			out[req.envVar] = "present"
		}
	}
	return out
}

func skillSpectorLLMEnabled(env map[string]string) bool {
	value := strings.TrimSpace(strings.ToLower(env["CLAWSCAN_SKILLSPECTOR_LLM"]))
	return value == "1" || value == "true" || value == "yes" || value == "on"
}

func skillSpectorProviderKeyEnv(env map[string]string) string {
	switch strings.TrimSpace(strings.ToLower(env["SKILLSPECTOR_PROVIDER"])) {
	case "", "openai":
		return "OPENAI_API_KEY"
	case "anthropic":
		return "ANTHROPIC_API_KEY"
	case "nv_inference", "nv_build", "nvidia":
		return "NVIDIA_INFERENCE_KEY"
	default:
		return ""
	}
}

func dedupe(reqs []requirement) []requirement {
	seen := map[string]bool{}
	var out []requirement
	for _, req := range reqs {
		key := req.envVar + ":" + req.reason
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

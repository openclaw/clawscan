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
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/openclaw/clawscan/internal/clawhubprompt"
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
	PromptPath string
	SchemaPath string
	Model      string
	Reasoning  string
	DryRun     bool
	ClawHub    *ClawHubPromptOptions
}

type ClawHubPromptOptions struct {
	SystemPromptPath string
	JobPath          string
	InjectionSignals []string
}

type RunContext struct {
	Env                 map[string]string
	Now                 func() time.Time
	CommandRunner       CommandRunner
	ScannerRunner       ScannerRunner
	JudgeRunner         JudgeRunner
	SkillSpectorCommand []string
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

type JudgeRunner interface {
	RunJudge(opts JudgeOptions, artifact Artifact, prompt string, schema json.RawMessage) (*JudgeResult, error)
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

type ScannerResult struct {
	Status      string          `json:"status"`
	StartedAt   string          `json:"startedAt"`
	CompletedAt string          `json:"completedAt"`
	Command     []string        `json:"command"`
	Error       string          `json:"error"`
	Raw         json.RawMessage `json:"raw"`
}

type JudgeResult struct {
	Status     string      `json:"status"`
	Model      string      `json:"model"`
	Reasoning  string      `json:"reasoning"`
	PromptPath string      `json:"promptPath"`
	SchemaPath string      `json:"schemaPath"`
	PromptSHA  string      `json:"promptSha256,omitempty"`
	Error      string      `json:"error"`
	Result     interface{} `json:"result"`
}

type requirement struct {
	envVar string
	reason string
}

var scannerSet = map[string]bool{
	"agentverus":     true,
	"skillspector":   true,
	"snyk":           true,
	"cisco":          true,
	"virustotal":     true,
	"gendigital":     true,
	"clawhub-static": true,
}

func ParseArgs(args []string) (Options, error) {
	if len(args) == 0 || strings.HasPrefix(args[0], "--") {
		return Options{}, errors.New("Missing scan target")
	}
	opts := Options{Target: args[0], ScannerResultPaths: map[string]string{}}
	var judgePrompt, judgeSchema, judgeModel, judgeReasoning string
	var judgeDryRun bool
	var clawHubSystemPrompt, clawHubJob string
	var clawHubInjectionSignals []string
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
		case "--judge-prompt":
			value, next, err := readValue(args, i, arg)
			if err != nil {
				return Options{}, err
			}
			judgePrompt = value
			i = next
		case "--judge-schema":
			value, next, err := readValue(args, i, arg)
			if err != nil {
				return Options{}, err
			}
			judgeSchema = value
			i = next
		case "--judge-model":
			value, next, err := readValue(args, i, arg)
			if err != nil {
				return Options{}, err
			}
			judgeModel = value
			i = next
		case "--judge-reasoning":
			value, next, err := readValue(args, i, arg)
			if err != nil {
				return Options{}, err
			}
			judgeReasoning = value
			i = next
		case "--judge-dry-run":
			judgeDryRun = true
		case "--clawhub-system-prompt":
			value, next, err := readValue(args, i, arg)
			if err != nil {
				return Options{}, err
			}
			clawHubSystemPrompt = value
			i = next
		case "--clawhub-job":
			value, next, err := readValue(args, i, arg)
			if err != nil {
				return Options{}, err
			}
			clawHubJob = value
			i = next
		case "--clawhub-injection-signal":
			value, next, err := readValue(args, i, arg)
			if err != nil {
				return Options{}, err
			}
			clawHubInjectionSignals = append(clawHubInjectionSignals, value)
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
	clawHubConfigured := clawHubSystemPrompt != "" || clawHubJob != "" || len(clawHubInjectionSignals) > 0
	if judgePrompt != "" || judgeSchema != "" || judgeModel != "" || judgeReasoning != "" || judgeDryRun || clawHubConfigured {
		if judgePrompt != "" && clawHubConfigured {
			return Options{}, errors.New("Use either --judge-prompt or --clawhub-system-prompt/--clawhub-job, not both")
		}
		if clawHubConfigured && !judgeDryRun {
			return Options{}, errors.New("ClawHub compatibility mode currently requires --judge-dry-run")
		}
		if judgePrompt == "" {
			if clawHubSystemPrompt == "" {
				return Options{}, errors.New("Missing required --clawhub-system-prompt")
			}
			if clawHubJob == "" {
				return Options{}, errors.New("Missing required --clawhub-job")
			}
		}
		if judgeSchema == "" && !judgeDryRun {
			return Options{}, errors.New("Missing required --judge-schema")
		}
		if judgeModel == "" {
			return Options{}, errors.New("Missing required --judge-model")
		}
		if !supportedJudgeModel(judgeModel) {
			return Options{}, fmt.Errorf("Unsupported judge model provider: %s", judgeModel)
		}
		opts.Judge = &JudgeOptions{PromptPath: judgePrompt, SchemaPath: judgeSchema, Model: judgeModel, Reasoning: judgeReasoning, DryRun: judgeDryRun}
		if clawHubConfigured {
			opts.Judge.ClawHub = &ClawHubPromptOptions{
				SystemPromptPath: clawHubSystemPrompt,
				JobPath:          clawHubJob,
				InjectionSignals: clawHubInjectionSignals,
			}
		}
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
	resolved, err := filepath.Abs(opts.Target)
	if err != nil {
		return Artifact{}, err
	}
	scannerRunner := ctx.ScannerRunner
	if scannerRunner == nil {
		commandRunner := ctx.CommandRunner
		if commandRunner == nil {
			commandRunner = defaultCommandRunner{}
		}
		scannerRunner = ExternalScannerRunner{
			CommandRunner:       commandRunner,
			Env:                 env,
			SkillSpectorCommand: ctx.SkillSpectorCommand,
			Timeout:             20 * time.Minute,
		}
	}
	artifact := NewArtifact(opts, resolved, startedAt, startedAt, env)
	for _, scanner := range opts.Scanners {
		scannerStartedAt := now().UTC().Format(time.RFC3339Nano)
		result, err := scannerResult(opts, scanner, resolved, scannerStartedAt, scannerRunner)
		if err != nil {
			return Artifact{}, err
		}
		artifact.Scanners[scanner] = result
	}
	if opts.Judge != nil {
		prompt, err := RenderPrompt(*opts.Judge, artifact)
		if err != nil {
			return Artifact{}, err
		}
		var judge *JudgeResult
		if opts.Judge.DryRun {
			judge = &JudgeResult{
				Status:     "dry_run",
				Model:      opts.Judge.Model,
				Reasoning:  opts.Judge.Reasoning,
				PromptPath: opts.Judge.PromptPath,
				SchemaPath: opts.Judge.SchemaPath,
				Error:      "",
				Result:     nil,
			}
		} else {
			schema, err := os.ReadFile(opts.Judge.SchemaPath)
			if err != nil {
				return Artifact{}, err
			}
			judgeRunner := ctx.JudgeRunner
			if judgeRunner == nil {
				judgeRunner = OpenAIJudgeRunner{Env: env}
			}
			judge, err = judgeRunner.RunJudge(*opts.Judge, artifact, prompt, json.RawMessage(schema))
			if err != nil {
				return Artifact{}, err
			}
		}
		if judge != nil {
			judge.PromptSHA = sha256Hex(prompt)
		}
		artifact.Judge = judge
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

func RenderPrompt(opts JudgeOptions, artifact Artifact) (string, error) {
	if opts.ClawHub != nil {
		return RenderClawHubPrompt(*opts.ClawHub, artifact)
	}
	promptTemplate, err := os.ReadFile(opts.PromptPath)
	if err != nil {
		return "", err
	}
	return RenderJudgePrompt(string(promptTemplate), artifact)
}

func RenderClawHubPrompt(opts ClawHubPromptOptions, artifact Artifact) (string, error) {
	systemPrompt, err := os.ReadFile(opts.SystemPromptPath)
	if err != nil {
		return "", err
	}
	job, err := loadClawHubJob(opts.JobPath)
	if err != nil {
		return "", err
	}
	applyScannerEvidenceToClawHubJob(&job, artifact)
	var skillSpector any
	if result, ok := artifact.Scanners["skillspector"]; ok && len(result.Raw) > 0 {
		skillSpector = clawhubprompt.RawJSON(result.Raw)
	}
	return clawhubprompt.Build(string(systemPrompt), job, opts.InjectionSignals, skillSpector)
}

type rawClawHubJob struct {
	Job    clawhubprompt.JobMetadata `json:"job"`
	Target rawClawHubTarget          `json:"target"`
}

type rawClawHubTarget struct {
	TrustedOpenClawPlugin bool               `json:"trustedOpenClawPlugin"`
	Version               *rawClawHubVersion `json:"version"`
	Release               *rawClawHubVersion `json:"release"`
}

type rawClawHubVersion struct {
	VTAnalysis           json.RawMessage `json:"vtAnalysis"`
	SkillSpectorAnalysis json.RawMessage `json:"skillSpectorAnalysis"`
}

func loadClawHubJob(path string) (clawhubprompt.Job, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return clawhubprompt.Job{}, err
	}
	var parsed rawClawHubJob
	if err := json.Unmarshal(raw, &parsed); err != nil {
		return clawhubprompt.Job{}, err
	}
	return clawhubprompt.Job{
		Job: parsed.Job,
		Target: clawhubprompt.Target{
			TrustedOpenClawPlugin: parsed.Target.TrustedOpenClawPlugin,
			Version:               convertClawHubVersion(parsed.Target.Version),
			Release:               convertClawHubVersion(parsed.Target.Release),
		},
	}, nil
}

func convertClawHubVersion(version *rawClawHubVersion) *clawhubprompt.Version {
	if version == nil {
		return nil
	}
	return &clawhubprompt.Version{
		VTAnalysis:           rawJSONValue(version.VTAnalysis),
		SkillSpectorAnalysis: rawJSONValue(version.SkillSpectorAnalysis),
	}
}

func rawJSONValue(raw json.RawMessage) any {
	if len(raw) == 0 {
		return nil
	}
	copied := append([]byte(nil), raw...)
	return clawhubprompt.RawJSON(copied)
}

func applyScannerEvidenceToClawHubJob(job *clawhubprompt.Job, artifact Artifact) {
	result, ok := artifact.Scanners["virustotal"]
	if !ok || len(result.Raw) == 0 {
		return
	}
	if job.Target.Version == nil && job.Target.Release == nil {
		job.Target.Version = &clawhubprompt.Version{}
	}
	if job.Target.Version != nil {
		job.Target.Version.VTAnalysis = clawhubprompt.RawJSON(result.Raw)
		return
	}
	job.Target.Release.VTAnalysis = clawhubprompt.RawJSON(result.Raw)
}

var scannerPlaceholderPattern = regexp.MustCompile(`\{\{\s*scanners\.([a-zA-Z0-9_-]+)\s*\}\}`)

const maxTargetFileBytes = 64 * 1024
const maxTargetFilesBytes = 256 * 1024
const maxOmittedTargetFileMarkers = 25

func RenderJudgePrompt(template string, artifact Artifact) (string, error) {
	rendered, err := renderTargetFilesPlaceholder(template, artifact)
	if err != nil {
		return "", err
	}
	var renderErr error
	rendered = scannerPlaceholderPattern.ReplaceAllStringFunc(rendered, func(match string) string {
		if renderErr != nil {
			return match
		}
		parts := scannerPlaceholderPattern.FindStringSubmatch(match)
		if len(parts) != 2 {
			return match
		}
		scanner := parts[1]
		result, ok := artifact.Scanners[scanner]
		if !ok {
			renderErr = fmt.Errorf("judge prompt references scanner %s, but it was not requested", scanner)
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

func renderTargetFilesPlaceholder(template string, artifact Artifact) (string, error) {
	if !strings.Contains(template, "{{ target.files }}") {
		return template, nil
	}
	files, err := renderTargetFiles(artifact.Target.ResolvedPath)
	if err != nil {
		return "", err
	}
	return strings.ReplaceAll(template, "{{ target.files }}", files), nil
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
		if err := filepath.WalkDir(target, func(path string, entry os.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if entry.IsDir() {
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
	sort.Strings(paths)
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
			return "", err
		}
		if bytes.IndexByte(content, 0) >= 0 {
			addOmission(path, "binary file")
			continue
		}
		totalBytes += len(content)
		label := path
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

func omittedTargetFileBlock(root string, path string, reason string) string {
	rel, err := filepath.Rel(root, path)
	if err != nil {
		rel = path
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

type ExternalScannerRunner struct {
	CommandRunner       CommandRunner
	Env                 map[string]string
	SkillSpectorCommand []string
	Timeout             time.Duration
}

type OpenAIJudgeRunner struct {
	Env        map[string]string
	HTTPClient *http.Client
	BaseURL    string
}

func (runner OpenAIJudgeRunner) RunJudge(opts JudgeOptions, artifact Artifact, prompt string, schema json.RawMessage) (*JudgeResult, error) {
	if !strings.HasPrefix(opts.Model, "openai/") {
		return &JudgeResult{
			Status:     "skipped",
			Model:      opts.Model,
			Reasoning:  opts.Reasoning,
			PromptPath: opts.PromptPath,
			SchemaPath: opts.SchemaPath,
			Error:      "Judge provider not implemented.",
			Result:     nil,
		}, nil
	}
	apiKey := strings.TrimSpace(runner.Env["OPENAI_API_KEY"])
	if apiKey == "" {
		return nil, errors.New("OPENAI_API_KEY is required by judge model " + opts.Model)
	}
	var schemaValue any
	if err := json.Unmarshal(schema, &schemaValue); err != nil {
		return nil, fmt.Errorf("parse judge schema: %w", err)
	}
	model := strings.TrimPrefix(opts.Model, "openai/")
	requestBody := map[string]any{
		"model": model,
		"input": prompt,
		"text": map[string]any{
			"format": map[string]any{
				"type":   "json_schema",
				"name":   "clawscan_judge",
				"schema": schemaValue,
				"strict": true,
			},
		},
	}
	if opts.Reasoning != "" {
		requestBody["reasoning"] = map[string]any{"effort": opts.Reasoning}
	}
	body, err := json.Marshal(requestBody)
	if err != nil {
		return nil, err
	}
	baseURL := runner.BaseURL
	if baseURL == "" {
		baseURL = "https://api.openai.com/v1"
	}
	client := runner.HTTPClient
	if client == nil {
		client = &http.Client{Timeout: 5 * time.Minute}
	}
	req, err := http.NewRequest(http.MethodPost, strings.TrimRight(baseURL, "/")+"/responses", bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+apiKey)
	req.Header.Set("Content-Type", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return &JudgeResult{
			Status:     "failed",
			Model:      opts.Model,
			Reasoning:  opts.Reasoning,
			PromptPath: opts.PromptPath,
			SchemaPath: opts.SchemaPath,
			Error:      fmt.Sprintf("OpenAI Responses API returned %s: %s", resp.Status, strings.TrimSpace(string(respBody))),
			Result:     nil,
		}, nil
	}
	outputText, err := responseOutputText(respBody)
	if err != nil {
		return nil, err
	}
	var result any
	if err := json.Unmarshal([]byte(outputText), &result); err != nil {
		return nil, fmt.Errorf("parse judge JSON output: %w", err)
	}
	return &JudgeResult{
		Status:     "completed",
		Model:      opts.Model,
		Reasoning:  opts.Reasoning,
		PromptPath: opts.PromptPath,
		SchemaPath: opts.SchemaPath,
		Error:      "",
		Result:     result,
	}, nil
}

func responseOutputText(body []byte) (string, error) {
	var payload struct {
		OutputText string `json:"output_text"`
		Output     []struct {
			Content []struct {
				Type string `json:"type"`
				Text string `json:"text"`
			} `json:"content"`
		} `json:"output"`
	}
	if err := json.Unmarshal(body, &payload); err != nil {
		return "", err
	}
	if payload.OutputText != "" {
		return payload.OutputText, nil
	}
	for _, item := range payload.Output {
		for _, content := range item.Content {
			if content.Type == "output_text" && content.Text != "" {
				return content.Text, nil
			}
		}
	}
	return "", errors.New("OpenAI response did not include output text")
}

func (runner ExternalScannerRunner) RunScanner(name string, target string, startedAt string) (ScannerResult, error) {
	switch name {
	case "agentverus":
		return runner.runAgentVerus(target, startedAt)
	case "skillspector":
		return runner.runSkillSpector(target, startedAt)
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
		message := runErr.Error()
		if strings.TrimSpace(output.Stderr) != "" {
			message += ": " + strings.TrimSpace(output.Stderr)
		}
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
		return ScannerResult{}, fmt.Errorf("AgentVerus scanner returned invalid JSON")
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
		message := runErr.Error()
		if strings.TrimSpace(output.Stderr) != "" {
			message += ": " + strings.TrimSpace(output.Stderr)
		}
		if readErr == nil {
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
		return ScannerResult{}, readErr
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

type defaultCommandRunner struct{}

func (defaultCommandRunner) Run(command string, args []string, cwd string, timeout time.Duration) (CommandOutput, error) {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, command, args...)
	cmd.Dir = cwd
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
	var judge *JudgeResult
	if opts.Judge != nil {
		judge = &JudgeResult{
			Status:     "skipped",
			Model:      opts.Judge.Model,
			Reasoning:  opts.Judge.Reasoning,
			PromptPath: opts.Judge.PromptPath,
			SchemaPath: opts.Judge.SchemaPath,
			Error:      "Judge execution not implemented in foundation slice.",
			Result:     nil,
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
		Judge:       judge,
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
	if opts.Judge != nil && !opts.Judge.DryRun {
		switch {
		case strings.HasPrefix(opts.Judge.Model, "openai/"):
			reqs = append(reqs, requirement{"OPENAI_API_KEY", "judge model " + opts.Judge.Model})
		case strings.HasPrefix(opts.Judge.Model, "anthropic/"):
			reqs = append(reqs, requirement{"ANTHROPIC_API_KEY", "judge model " + opts.Judge.Model})
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
	case "nvidia":
		return "NVIDIA_API_KEY"
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

func supportedJudgeModel(model string) bool {
	return strings.HasPrefix(model, "openai/") || strings.HasPrefix(model, "anthropic/")
}

func readValue(args []string, index int, flag string) (string, int, error) {
	next := index + 1
	if next >= len(args) || args[next] == "" || strings.HasPrefix(args[next], "--") {
		return "", index, fmt.Errorf("Missing value for %s", flag)
	}
	return args[next], next, nil
}

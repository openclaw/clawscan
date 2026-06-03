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
	"strings"
	"time"
)

type Options struct {
	Target     string
	Scanners   []string
	OutputPath string
	JSON       bool
	Judge      *JudgeOptions
}

type JudgeOptions struct {
	PromptPath string
	SchemaPath string
	Model      string
	Reasoning  string
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
	opts := Options{Target: args[0]}
	var judgePrompt, judgeSchema, judgeModel, judgeReasoning string
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
		default:
			return Options{}, fmt.Errorf("Unknown argument: %s", arg)
		}
	}
	if len(opts.Scanners) == 0 {
		return Options{}, errors.New("At least one --scanner is required")
	}
	if judgePrompt != "" || judgeSchema != "" || judgeModel != "" || judgeReasoning != "" {
		if judgePrompt == "" {
			return Options{}, errors.New("Missing required --judge-prompt")
		}
		if judgeSchema == "" {
			return Options{}, errors.New("Missing required --judge-schema")
		}
		if judgeModel == "" {
			return Options{}, errors.New("Missing required --judge-model")
		}
		if !supportedJudgeModel(judgeModel) {
			return Options{}, fmt.Errorf("Unsupported judge model provider: %s", judgeModel)
		}
		opts.Judge = &JudgeOptions{PromptPath: judgePrompt, SchemaPath: judgeSchema, Model: judgeModel, Reasoning: judgeReasoning}
	}
	return opts, nil
}

func ValidateRequirements(opts Options, env map[string]string) error {
	var missing []requirement
	for _, req := range requirements(opts) {
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
			SkillSpectorCommand: ctx.SkillSpectorCommand,
			Timeout:             20 * time.Minute,
		}
	}
	artifact := NewArtifact(opts, resolved, startedAt, startedAt, env)
	for _, scanner := range opts.Scanners {
		scannerStartedAt := now().UTC().Format(time.RFC3339Nano)
		result, err := scannerRunner.RunScanner(scanner, resolved, scannerStartedAt)
		if err != nil {
			return Artifact{}, err
		}
		artifact.Scanners[scanner] = result
	}
	if opts.Judge != nil {
		promptTemplate, err := os.ReadFile(opts.Judge.PromptPath)
		if err != nil {
			return Artifact{}, err
		}
		prompt, err := RenderJudgePrompt(string(promptTemplate), artifact)
		if err != nil {
			return Artifact{}, err
		}
		schema, err := os.ReadFile(opts.Judge.SchemaPath)
		if err != nil {
			return Artifact{}, err
		}
		judgeRunner := ctx.JudgeRunner
		if judgeRunner == nil {
			judgeRunner = OpenAIJudgeRunner{Env: env, HTTPClient: http.DefaultClient}
		}
		judge, err := judgeRunner.RunJudge(*opts.Judge, artifact, prompt, json.RawMessage(schema))
		if err != nil {
			return Artifact{}, err
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

var scannerPlaceholderPattern = regexp.MustCompile(`\{\{\s*scanners\.([a-zA-Z0-9_-]+)\s*\}\}`)

func RenderJudgePrompt(template string, artifact Artifact) (string, error) {
	var renderErr error
	rendered := scannerPlaceholderPattern.ReplaceAllStringFunc(template, func(match string) string {
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

func sha256Hex(value string) string {
	sum := sha256.Sum256([]byte(value))
	return hex.EncodeToString(sum[:])
}

type ExternalScannerRunner struct {
	CommandRunner       CommandRunner
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
		client = http.DefaultClient
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
				Status:      "failed",
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

func requirements(opts Options) []requirement {
	var reqs []requirement
	for _, scanner := range opts.Scanners {
		switch scanner {
		case "virustotal":
			reqs = append(reqs, requirement{"VIRUSTOTAL_API_KEY", "scanner virustotal"})
		case "snyk":
			reqs = append(reqs, requirement{"SNYK_TOKEN", "scanner snyk"})
		}
	}
	if opts.Judge != nil {
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
	for _, req := range requirements(opts) {
		if strings.TrimSpace(env[req.envVar]) == "" {
			out[req.envVar] = "missing"
		} else {
			out[req.envVar] = "present"
		}
	}
	return out
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

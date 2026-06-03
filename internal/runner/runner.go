package runner

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
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
	Env map[string]string
	Now func() time.Time
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
	completedAt := now().UTC().Format(time.RFC3339Nano)
	artifact := NewArtifact(opts, resolved, startedAt, completedAt, env)
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

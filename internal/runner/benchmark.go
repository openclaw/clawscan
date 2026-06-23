package runner

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

const (
	openClawBenchmarkID           = "OpenClaw/clawhub-security-signals"
	openClawBenchmarkConfig       = "default"
	openClawBenchmarkSource       = "huggingface"
	defaultOpenClawBenchmarkSplit = "eval_holdout"
	huggingFaceRowsEndpoint       = "https://datasets-server.huggingface.co/rows"
	huggingFaceRowsPageSize       = 100
)

var openClawBenchmarkSplits = map[string]bool{
	"train":        true,
	"validation":   true,
	"test":         true,
	"eval_holdout": true,
}

type BenchmarkClient interface {
	FetchOpenClawRows(dataset string, split string, offset int, limit int) ([]OpenClawBenchmarkRow, error)
}

type BenchmarkArtifact struct {
	SchemaVersion string            `json:"schemaVersion"`
	Benchmark     BenchmarkMetadata `json:"benchmark"`
	StartedAt     string            `json:"startedAt"`
	CompletedAt   string            `json:"completedAt"`
	Env           map[string]string `json:"env"`
	Cases         []BenchmarkCase   `json:"cases"`
	Summary       BenchmarkSummary  `json:"summary"`
}

type BenchmarkMetadata struct {
	ID     string `json:"id"`
	Source string `json:"source"`
	Config string `json:"config"`
	Split  string `json:"split"`
	Offset int    `json:"offset"`
	Limit  int    `json:"limit"`
	Rows   int    `json:"rows"`
}

type BenchmarkCase struct {
	ID           string            `json:"id"`
	SkillSlug    string            `json:"skillSlug"`
	SkillVersion string            `json:"skillVersion"`
	Expected     BenchmarkExpected `json:"expected"`
	Run          Artifact          `json:"run"`
}

type BenchmarkExpected struct {
	Verdict    string          `json:"verdict"`
	Confidence string          `json:"confidence"`
	Model      string          `json:"model"`
	Summary    string          `json:"summary"`
	Context    json.RawMessage `json:"context,omitempty"`
}

type BenchmarkSummary struct {
	CaseCount        int                       `json:"caseCount"`
	ExpectedVerdicts map[string]int            `json:"expectedVerdicts"`
	ScannerStatuses  map[string]map[string]int `json:"scannerStatuses"`
	JudgeStatuses    map[string]int            `json:"judgeStatuses,omitempty"`
}

type OpenClawBenchmarkRow struct {
	ID                 string               `json:"id"`
	SkillSlug          string               `json:"skill_slug"`
	SkillVersion       string               `json:"skill_version"`
	SkillMDContent     string               `json:"skill_md_content"`
	SkillBundleContent []OpenClawBundleFile `json:"skill_bundle_content"`
	ClawScanVerdict    string               `json:"clawscan_verdict"`
	ClawScanConfidence string               `json:"clawscan_confidence"`
	ClawScanModel      string               `json:"clawscan_model"`
	ClawScanSummary    string               `json:"clawscan_summary"`
	ClawScanContext    json.RawMessage      `json:"clawscan_context"`
	Split              string               `json:"split"`
}

type OpenClawBundleFile struct {
	Path      string `json:"path"`
	Content   string `json:"content"`
	SHA256    string `json:"sha256"`
	SizeBytes int64  `json:"sizeBytes"`
}

type HuggingFaceBenchmarkClient struct {
	HTTPClient *http.Client
	Endpoint   string
}

type huggingFaceRowsResponse struct {
	Rows  []huggingFaceRow `json:"rows"`
	Error string           `json:"error"`
}

type huggingFaceRow struct {
	Row OpenClawBenchmarkRow `json:"row"`
}

func RunBenchmark(opts Options, ctx RunContext) (BenchmarkArtifact, error) {
	if opts.Benchmark == nil {
		return BenchmarkArtifact{}, errors.New("missing benchmark options")
	}
	env := ctx.Env
	if env == nil {
		env = EnvMap(os.Environ())
	}
	if err := ValidateRequirements(opts, env); err != nil {
		return BenchmarkArtifact{}, err
	}
	now := ctx.Now
	if now == nil {
		now = time.Now
	}
	startedAt := now().UTC().Format(time.RFC3339Nano)
	client := ctx.BenchmarkClient
	if client == nil {
		client = HuggingFaceBenchmarkClient{}
	}
	rows, err := client.FetchOpenClawRows(opts.Benchmark.ID, opts.Benchmark.Split, opts.Benchmark.Offset, opts.Benchmark.Limit)
	if err != nil {
		return BenchmarkArtifact{}, err
	}
	artifact := BenchmarkArtifact{
		SchemaVersion: "clawscan-benchmark-v1",
		Benchmark: BenchmarkMetadata{
			ID:     opts.Benchmark.ID,
			Source: openClawBenchmarkSource,
			Config: openClawBenchmarkConfig,
			Split:  opts.Benchmark.Split,
			Offset: opts.Benchmark.Offset,
			Limit:  opts.Benchmark.Limit,
			Rows:   len(rows),
		},
		StartedAt: startedAt,
		Env:       envPresence(opts, env),
		Cases:     []BenchmarkCase{},
		Summary: BenchmarkSummary{
			ExpectedVerdicts: map[string]int{},
			ScannerStatuses:  map[string]map[string]int{},
			JudgeStatuses:    map[string]int{},
		},
	}
	for _, row := range rows {
		benchmarkCase, err := runOpenClawBenchmarkCase(opts, ctx, env, now, row)
		if err != nil {
			return BenchmarkArtifact{}, err
		}
		artifact.Cases = append(artifact.Cases, benchmarkCase)
		artifact.Summary.addCase(benchmarkCase)
	}
	artifact.CompletedAt = now().UTC().Format(time.RFC3339Nano)
	if opts.OutputPath != "" {
		if err := os.MkdirAll(filepath.Dir(opts.OutputPath), 0o755); err != nil {
			return BenchmarkArtifact{}, err
		}
		file, err := os.Create(opts.OutputPath)
		if err != nil {
			return BenchmarkArtifact{}, err
		}
		defer file.Close()
		if err := WriteJSON(file, artifact); err != nil {
			return BenchmarkArtifact{}, err
		}
	}
	return artifact, nil
}

func runOpenClawBenchmarkCase(opts Options, ctx RunContext, env map[string]string, now func() time.Time, row OpenClawBenchmarkRow) (BenchmarkCase, error) {
	dir, err := os.MkdirTemp("", "clawscan-benchmark-*")
	if err != nil {
		return BenchmarkCase{}, err
	}
	defer os.RemoveAll(dir)
	target, err := materializeOpenClawBenchmarkRow(dir, row)
	if err != nil {
		return BenchmarkCase{}, err
	}
	caseOpts := opts
	caseOpts.Target = target
	caseOpts.Benchmark = nil
	caseOpts.OutputPath = ""
	run, err := Run(caseOpts, RunContext{
		Env:                    env,
		Now:                    now,
		CommandRunner:          ctx.CommandRunner,
		ScannerRunner:          ctx.ScannerRunner,
		SkillSpectorCommand:    ctx.SkillSpectorCommand,
		AIInfraGuardHTTPClient: ctx.AIInfraGuardHTTPClient,
		VirusTotalHTTPClient:   ctx.VirusTotalHTTPClient,
		GenDigitalHTTPClient:   ctx.GenDigitalHTTPClient,
	})
	if err != nil {
		return BenchmarkCase{}, err
	}
	return BenchmarkCase{
		ID:           row.ID,
		SkillSlug:    row.SkillSlug,
		SkillVersion: row.SkillVersion,
		Expected: BenchmarkExpected{
			Verdict:    row.ClawScanVerdict,
			Confidence: row.ClawScanConfidence,
			Model:      row.ClawScanModel,
			Summary:    row.ClawScanSummary,
			Context:    normalizedRawMessage(row.ClawScanContext),
		},
		Run: run,
	}, nil
}

func materializeOpenClawBenchmarkRow(root string, row OpenClawBenchmarkRow) (string, error) {
	target := filepath.Join(root, "skill")
	if err := os.MkdirAll(target, 0o755); err != nil {
		return "", err
	}
	if err := os.WriteFile(filepath.Join(target, "SKILL.md"), []byte(row.SkillMDContent), 0o644); err != nil {
		return "", err
	}
	for _, file := range row.SkillBundleContent {
		rel, err := safeBenchmarkPath(file.Path)
		if err != nil {
			return "", err
		}
		if strings.EqualFold(filepath.ToSlash(rel), "SKILL.md") {
			continue
		}
		path := filepath.Join(target, rel)
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			return "", err
		}
		if err := os.WriteFile(path, []byte(file.Content), 0o644); err != nil {
			return "", err
		}
	}
	return target, nil
}

func safeBenchmarkPath(path string) (string, error) {
	clean := filepath.Clean(filepath.FromSlash(strings.ReplaceAll(path, "\\", "/")))
	if clean == "." || filepath.IsAbs(clean) || strings.HasPrefix(clean, ".."+string(filepath.Separator)) || clean == ".." {
		return "", fmt.Errorf("unsafe benchmark bundle path: %s", path)
	}
	return clean, nil
}

func (summary *BenchmarkSummary) addCase(benchmarkCase BenchmarkCase) {
	summary.CaseCount++
	if benchmarkCase.Expected.Verdict != "" {
		summary.ExpectedVerdicts[benchmarkCase.Expected.Verdict]++
	}
	for scanner, result := range benchmarkCase.Run.Scanners {
		if summary.ScannerStatuses[scanner] == nil {
			summary.ScannerStatuses[scanner] = map[string]int{}
		}
		summary.ScannerStatuses[scanner][result.Status]++
	}
	if benchmarkCase.Run.Judge != nil {
		summary.JudgeStatuses[benchmarkCase.Run.Judge.Status]++
	}
}

func canonicalBenchmarkID(id string) (string, error) {
	switch strings.ToLower(strings.TrimSpace(id)) {
	case strings.ToLower(openClawBenchmarkID):
		return openClawBenchmarkID, nil
	default:
		return "", fmt.Errorf("Unsupported benchmark: %s", id)
	}
}

func validateBenchmarkSplit(id string, split string) error {
	if id != openClawBenchmarkID {
		return nil
	}
	if openClawBenchmarkSplits[split] {
		return nil
	}
	valid := make([]string, 0, len(openClawBenchmarkSplits))
	for split := range openClawBenchmarkSplits {
		valid = append(valid, split)
	}
	sort.Strings(valid)
	return fmt.Errorf("Unsupported split for %s: %s (valid: %s)", id, split, strings.Join(valid, ", "))
}

func normalizedRawMessage(raw json.RawMessage) json.RawMessage {
	if len(raw) == 0 || string(raw) == "null" {
		return nil
	}
	return raw
}

func (client HuggingFaceBenchmarkClient) FetchOpenClawRows(dataset string, split string, offset int, limit int) ([]OpenClawBenchmarkRow, error) {
	httpClient := client.HTTPClient
	if httpClient == nil {
		httpClient = &http.Client{Timeout: 60 * time.Second}
	}
	endpoint := client.Endpoint
	if endpoint == "" {
		endpoint = huggingFaceRowsEndpoint
	}
	var rows []OpenClawBenchmarkRow
	nextOffset := offset
	for {
		length := huggingFaceRowsPageSize
		if limit > 0 {
			remaining := limit - len(rows)
			if remaining <= 0 {
				break
			}
			if remaining < length {
				length = remaining
			}
		}
		page, err := client.fetchOpenClawRowsPage(httpClient, endpoint, dataset, split, nextOffset, length)
		if err != nil {
			return nil, err
		}
		if len(page) == 0 {
			break
		}
		rows = append(rows, page...)
		nextOffset += len(page)
		if len(page) < length {
			break
		}
	}
	return rows, nil
}

func (client HuggingFaceBenchmarkClient) fetchOpenClawRowsPage(httpClient *http.Client, endpoint string, dataset string, split string, offset int, length int) ([]OpenClawBenchmarkRow, error) {
	values := url.Values{}
	values.Set("dataset", dataset)
	values.Set("config", openClawBenchmarkConfig)
	values.Set("split", split)
	values.Set("offset", fmt.Sprintf("%d", offset))
	values.Set("length", fmt.Sprintf("%d", length))
	requestURL := endpoint + "?" + values.Encode()
	response, err := httpClient.Get(requestURL)
	if err != nil {
		return nil, err
	}
	defer response.Body.Close()
	var parsed huggingFaceRowsResponse
	if err := json.NewDecoder(response.Body).Decode(&parsed); err != nil {
		return nil, err
	}
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		if parsed.Error != "" {
			return nil, fmt.Errorf("fetch benchmark rows: %s", parsed.Error)
		}
		return nil, fmt.Errorf("fetch benchmark rows: HTTP %d", response.StatusCode)
	}
	rows := make([]OpenClawBenchmarkRow, 0, len(parsed.Rows))
	for _, row := range parsed.Rows {
		rows = append(rows, row.Row)
	}
	return rows, nil
}

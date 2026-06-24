package runner

import (
	"archive/zip"
	"encoding/json"
	"errors"
	"fmt"
	"io"
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
	skillTrustBenchID             = "cuhk-zhuque/SkillTrustBench"
	skillTrustBenchAlias          = "SkillTrustBench"
	skillTrustBenchConfig         = "default"
	skillTrustBenchSource         = "huggingface"
	skillTrustBenchVersion        = "v1.0"
	defaultSkillTrustBenchSplit   = "benchmark"
	skillTrustBenchArchiveRoot    = "benchmark_full_v1.0"
	skillTrustBenchArchiveName    = "benchmark_full_v1.0.zip"
	skillTrustBenchArchiveURL     = "https://huggingface.co/datasets/cuhk-zhuque/SkillTrustBench/resolve/main/benchmark_full_v1.0.zip"
	huggingFaceRowsEndpoint       = "https://datasets-server.huggingface.co/rows"
	huggingFaceRowsPageSize       = 100
)

var openClawBenchmarkSplits = map[string]bool{
	"train":        true,
	"validation":   true,
	"test":         true,
	"eval_holdout": true,
}

var skillTrustBenchSplits = map[string]bool{
	"benchmark": true,
}

type BenchmarkClient interface {
	FetchOpenClawRows(dataset string, split string, offset int, limit int) ([]OpenClawBenchmarkRow, error)
	FetchSkillTrustBenchRows(dataset string, split string, offset int, limit int) ([]SkillTrustBenchRow, error)
	MaterializeSkillTrustBenchRow(root string, row SkillTrustBenchRow) (string, error)
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

type SkillTrustBenchRow struct {
	ID             string   `json:"id"`
	Judgment       string   `json:"judgment"`
	RiskLabels     []string `json:"risk_labels"`
	Source         string   `json:"source"`
	BaseCategory   string   `json:"base_category"`
	PrimaryPattern *string  `json:"primary_pattern"`
	AttackPattern  []string `json:"attack_pattern"`
	SkillPath      string   `json:"skill_path"`
}

type HuggingFaceBenchmarkClient struct {
	HTTPClient                 *http.Client
	Endpoint                   string
	SkillTrustBenchArchiveURL  string
	SkillTrustBenchArchivePath string
}

type huggingFaceRowsResponse struct {
	Rows  []huggingFaceRow `json:"rows"`
	Error string           `json:"error"`
}

type huggingFaceRow struct {
	Row OpenClawBenchmarkRow `json:"row"`
}

type skillTrustBenchRowsResponse struct {
	Rows  []skillTrustBenchHuggingFaceRow `json:"rows"`
	Error string                          `json:"error"`
}

type skillTrustBenchHuggingFaceRow struct {
	Row SkillTrustBenchRow `json:"row"`
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
	artifact := BenchmarkArtifact{
		SchemaVersion: "clawscan-benchmark-v1",
		Benchmark: BenchmarkMetadata{
			ID:     opts.Benchmark.ID,
			Source: benchmarkSource(opts.Benchmark.ID),
			Config: benchmarkConfig(opts.Benchmark.ID),
			Split:  opts.Benchmark.Split,
			Offset: opts.Benchmark.Offset,
			Limit:  opts.Benchmark.Limit,
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
	switch opts.Benchmark.ID {
	case openClawBenchmarkID:
		rows, err := client.FetchOpenClawRows(opts.Benchmark.ID, opts.Benchmark.Split, opts.Benchmark.Offset, opts.Benchmark.Limit)
		if err != nil {
			return BenchmarkArtifact{}, err
		}
		artifact.Benchmark.Rows = len(rows)
		for _, row := range rows {
			benchmarkCase, err := runOpenClawBenchmarkCase(opts, ctx, env, now, row)
			if err != nil {
				return BenchmarkArtifact{}, err
			}
			artifact.Cases = append(artifact.Cases, benchmarkCase)
			artifact.Summary.addCase(benchmarkCase)
		}
	case skillTrustBenchID:
		rows, err := client.FetchSkillTrustBenchRows(opts.Benchmark.ID, opts.Benchmark.Split, opts.Benchmark.Offset, opts.Benchmark.Limit)
		if err != nil {
			return BenchmarkArtifact{}, err
		}
		artifact.Benchmark.Rows = len(rows)
		for _, row := range rows {
			benchmarkCase, err := runSkillTrustBenchBenchmarkCase(opts, ctx, env, now, client, row)
			if err != nil {
				return BenchmarkArtifact{}, err
			}
			artifact.Cases = append(artifact.Cases, benchmarkCase)
			artifact.Summary.addCase(benchmarkCase)
		}
	default:
		return BenchmarkArtifact{}, fmt.Errorf("Unsupported benchmark: %s", opts.Benchmark.ID)
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
	run, err := runBenchmarkTarget(opts, ctx, env, now, target)
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

func runSkillTrustBenchBenchmarkCase(opts Options, ctx RunContext, env map[string]string, now func() time.Time, client BenchmarkClient, row SkillTrustBenchRow) (BenchmarkCase, error) {
	dir, err := os.MkdirTemp("", "clawscan-benchmark-*")
	if err != nil {
		return BenchmarkCase{}, err
	}
	defer os.RemoveAll(dir)
	target, err := client.MaterializeSkillTrustBenchRow(dir, row)
	if err != nil {
		return BenchmarkCase{}, err
	}
	run, err := runBenchmarkTarget(opts, ctx, env, now, target)
	if err != nil {
		return BenchmarkCase{}, err
	}
	expected, err := skillTrustBenchExpected(row)
	if err != nil {
		return BenchmarkCase{}, err
	}
	return BenchmarkCase{
		ID:           row.ID,
		SkillSlug:    row.ID,
		SkillVersion: skillTrustBenchVersion,
		Expected:     expected,
		Run:          run,
	}, nil
}

func runBenchmarkTarget(opts Options, ctx RunContext, env map[string]string, now func() time.Time, target string) (Artifact, error) {
	caseOpts := opts
	caseOpts.Target = target
	caseOpts.Benchmark = nil
	caseOpts.OutputPath = ""
	return Run(caseOpts, RunContext{
		Env:                    env,
		Now:                    now,
		CommandRunner:          ctx.CommandRunner,
		ScannerRunner:          ctx.ScannerRunner,
		SkillSpectorCommand:    ctx.SkillSpectorCommand,
		AIInfraGuardHTTPClient: ctx.AIInfraGuardHTTPClient,
		VirusTotalHTTPClient:   ctx.VirusTotalHTTPClient,
		GenDigitalHTTPClient:   ctx.GenDigitalHTTPClient,
	})
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

func skillTrustBenchExpected(row SkillTrustBenchRow) (BenchmarkExpected, error) {
	context, err := json.Marshal(struct {
		RiskLabels     []string `json:"risk_labels"`
		Source         string   `json:"source"`
		BaseCategory   string   `json:"base_category"`
		PrimaryPattern *string  `json:"primary_pattern"`
		AttackPattern  []string `json:"attack_pattern"`
		SkillPath      string   `json:"skill_path"`
	}{
		RiskLabels:     row.RiskLabels,
		Source:         row.Source,
		BaseCategory:   row.BaseCategory,
		PrimaryPattern: row.PrimaryPattern,
		AttackPattern:  row.AttackPattern,
		SkillPath:      row.SkillPath,
	})
	if err != nil {
		return BenchmarkExpected{}, err
	}
	return BenchmarkExpected{
		Verdict: row.Judgment,
		Summary: skillTrustBenchSummary(row),
		Context: json.RawMessage(context),
	}, nil
}

func skillTrustBenchSummary(row SkillTrustBenchRow) string {
	parts := []string{"SkillTrustBench judgment: " + row.Judgment}
	if row.BaseCategory != "" {
		parts = append(parts, "category: "+row.BaseCategory)
	}
	if row.PrimaryPattern != nil && *row.PrimaryPattern != "" {
		parts = append(parts, "primary pattern: "+*row.PrimaryPattern)
	}
	if row.Source != "" {
		parts = append(parts, "source: "+row.Source)
	}
	return strings.Join(parts, "; ")
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
	case strings.ToLower(skillTrustBenchID), strings.ToLower(skillTrustBenchAlias):
		return skillTrustBenchID, nil
	default:
		return "", fmt.Errorf("Unsupported benchmark: %s", id)
	}
}

func validateBenchmarkSplit(id string, split string) error {
	validSplits := benchmarkSplits(id)
	if validSplits[split] {
		return nil
	}
	valid := make([]string, 0, len(validSplits))
	for split := range validSplits {
		valid = append(valid, split)
	}
	sort.Strings(valid)
	return fmt.Errorf("Unsupported split for %s: %s (valid: %s)", id, split, strings.Join(valid, ", "))
}

func defaultBenchmarkID() string {
	return skillTrustBenchID
}

func defaultBenchmarkSplit(id string) string {
	switch id {
	case skillTrustBenchID:
		return defaultSkillTrustBenchSplit
	default:
		return defaultOpenClawBenchmarkSplit
	}
}

func benchmarkSplits(id string) map[string]bool {
	switch id {
	case skillTrustBenchID:
		return skillTrustBenchSplits
	default:
		return openClawBenchmarkSplits
	}
}

func benchmarkSource(id string) string {
	switch id {
	case skillTrustBenchID:
		return skillTrustBenchSource
	default:
		return openClawBenchmarkSource
	}
}

func benchmarkConfig(id string) string {
	switch id {
	case skillTrustBenchID:
		return skillTrustBenchConfig
	default:
		return openClawBenchmarkConfig
	}
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

func (client HuggingFaceBenchmarkClient) FetchSkillTrustBenchRows(dataset string, split string, offset int, limit int) ([]SkillTrustBenchRow, error) {
	httpClient := client.HTTPClient
	if httpClient == nil {
		httpClient = &http.Client{Timeout: 60 * time.Second}
	}
	endpoint := client.Endpoint
	if endpoint == "" {
		endpoint = huggingFaceRowsEndpoint
	}
	var rows []SkillTrustBenchRow
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
		page, err := client.fetchSkillTrustBenchRowsPage(httpClient, endpoint, dataset, split, nextOffset, length)
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

func (client HuggingFaceBenchmarkClient) fetchSkillTrustBenchRowsPage(httpClient *http.Client, endpoint string, dataset string, split string, offset int, length int) ([]SkillTrustBenchRow, error) {
	values := url.Values{}
	values.Set("dataset", dataset)
	values.Set("config", skillTrustBenchConfig)
	values.Set("split", split)
	values.Set("offset", fmt.Sprintf("%d", offset))
	values.Set("length", fmt.Sprintf("%d", length))
	requestURL := endpoint + "?" + values.Encode()
	response, err := httpClient.Get(requestURL)
	if err != nil {
		return nil, err
	}
	defer response.Body.Close()
	var parsed skillTrustBenchRowsResponse
	if err := json.NewDecoder(response.Body).Decode(&parsed); err != nil {
		return nil, err
	}
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		if parsed.Error != "" {
			return nil, fmt.Errorf("fetch benchmark rows: %s", parsed.Error)
		}
		return nil, fmt.Errorf("fetch benchmark rows: HTTP %d", response.StatusCode)
	}
	rows := make([]SkillTrustBenchRow, 0, len(parsed.Rows))
	for _, row := range parsed.Rows {
		rows = append(rows, row.Row)
	}
	return rows, nil
}

func (client HuggingFaceBenchmarkClient) MaterializeSkillTrustBenchRow(root string, row SkillTrustBenchRow) (string, error) {
	archivePath, err := client.skillTrustBenchArchivePath()
	if err != nil {
		return "", err
	}
	return materializeSkillTrustBenchArchiveRow(root, row, archivePath)
}

func (client HuggingFaceBenchmarkClient) skillTrustBenchArchivePath() (string, error) {
	if client.SkillTrustBenchArchivePath != "" {
		return client.SkillTrustBenchArchivePath, nil
	}
	cacheRoot, err := os.UserCacheDir()
	if err != nil || cacheRoot == "" {
		cacheRoot = os.TempDir()
	}
	cacheDir := filepath.Join(cacheRoot, "clawscan", "benchmarks", "skilltrustbench")
	archivePath := filepath.Join(cacheDir, skillTrustBenchArchiveName)
	if info, err := os.Stat(archivePath); err == nil && info.Size() > 0 {
		return archivePath, nil
	}
	if err := os.MkdirAll(cacheDir, 0o755); err != nil {
		return "", err
	}
	httpClient := client.HTTPClient
	if httpClient == nil {
		httpClient = &http.Client{Timeout: 10 * time.Minute}
	}
	archiveURL := client.SkillTrustBenchArchiveURL
	if archiveURL == "" {
		archiveURL = skillTrustBenchArchiveURL
	}
	response, err := httpClient.Get(archiveURL)
	if err != nil {
		return "", err
	}
	defer response.Body.Close()
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return "", fmt.Errorf("download SkillTrustBench archive: HTTP %d", response.StatusCode)
	}
	tmpPath := fmt.Sprintf("%s.%d.tmp", archivePath, os.Getpid())
	defer os.Remove(tmpPath)
	file, err := os.Create(tmpPath)
	if err != nil {
		return "", err
	}
	if _, err := io.Copy(file, response.Body); err != nil {
		file.Close()
		return "", err
	}
	if err := file.Close(); err != nil {
		return "", err
	}
	if err := os.Rename(tmpPath, archivePath); err != nil {
		return "", err
	}
	return archivePath, nil
}

func materializeSkillTrustBenchArchiveRow(root string, row SkillTrustBenchRow, archivePath string) (string, error) {
	skillPath, err := skillTrustBenchArchiveSkillPath(row)
	if err != nil {
		return "", err
	}
	reader, err := zip.OpenReader(archivePath)
	if err != nil {
		return "", err
	}
	defer reader.Close()
	target := filepath.Join(root, "skill")
	if err := os.MkdirAll(target, 0o755); err != nil {
		return "", err
	}
	prefix := skillPath + "/"
	foundAny := false
	foundSkill := false
	for _, file := range reader.File {
		name := strings.ReplaceAll(file.Name, "\\", "/")
		if !strings.HasPrefix(name, prefix) {
			continue
		}
		relName := strings.TrimPrefix(name, prefix)
		if relName == "" {
			continue
		}
		rel, err := safeBenchmarkPath(relName)
		if err != nil {
			return "", err
		}
		if file.FileInfo().Mode()&os.ModeSymlink != 0 {
			return "", fmt.Errorf("unsupported symlink in SkillTrustBench archive: %s", name)
		}
		if file.FileInfo().IsDir() {
			if err := os.MkdirAll(filepath.Join(target, rel), 0o755); err != nil {
				return "", err
			}
			continue
		}
		if err := extractSkillTrustBenchFile(file, filepath.Join(target, rel)); err != nil {
			return "", err
		}
		foundAny = true
		if strings.EqualFold(filepath.ToSlash(rel), "SKILL.md") {
			foundSkill = true
		}
	}
	if !foundAny {
		return "", fmt.Errorf("SkillTrustBench case not found in archive: %s", row.ID)
	}
	if !foundSkill {
		return "", fmt.Errorf("SkillTrustBench case missing SKILL.md: %s", row.ID)
	}
	return target, nil
}

func skillTrustBenchArchiveSkillPath(row SkillTrustBenchRow) (string, error) {
	if row.ID == "" || strings.Contains(row.ID, "/") || strings.Contains(row.ID, "\\") {
		return "", fmt.Errorf("invalid SkillTrustBench case id: %s", row.ID)
	}
	skillPath := row.SkillPath
	if strings.TrimSpace(skillPath) == "" {
		skillPath = skillTrustBenchArchiveRoot + "/" + row.ID
	}
	clean, err := safeBenchmarkPath(skillPath)
	if err != nil {
		return "", err
	}
	slash := filepath.ToSlash(clean)
	if !strings.HasPrefix(slash, skillTrustBenchArchiveRoot+"/") || !strings.HasSuffix(slash, "/"+row.ID) {
		return "", fmt.Errorf("unexpected SkillTrustBench skill path for %s: %s", row.ID, row.SkillPath)
	}
	return slash, nil
}

func extractSkillTrustBenchFile(file *zip.File, target string) error {
	if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
		return err
	}
	source, err := file.Open()
	if err != nil {
		return err
	}
	defer source.Close()
	destination, err := os.OpenFile(target, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o644)
	if err != nil {
		return err
	}
	if _, err := io.Copy(destination, source); err != nil {
		destination.Close()
		return err
	}
	return destination.Close()
}

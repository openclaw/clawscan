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
	"strconv"
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
	huggingFaceRowsMaxAttempts    = 6
)

var huggingFaceRowsRetryDelay = 2 * time.Second

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
	ID           string               `json:"id"`
	SkillSlug    string               `json:"skillSlug"`
	SkillVersion string               `json:"skillVersion"`
	Expected     BenchmarkExpected    `json:"expected"`
	Evaluation   *BenchmarkEvaluation `json:"evaluation,omitempty"`
	Run          Artifact             `json:"run"`
}

type BenchmarkExpected struct {
	Verdict    string          `json:"verdict"`
	Confidence string          `json:"confidence"`
	Model      string          `json:"model"`
	Summary    string          `json:"summary"`
	Context    json.RawMessage `json:"context,omitempty"`
}

type BenchmarkSummary struct {
	CaseCount        int                        `json:"caseCount"`
	ExpectedVerdicts map[string]int             `json:"expectedVerdicts"`
	ScannerStatuses  map[string]map[string]int  `json:"scannerStatuses"`
	JudgeStatuses    map[string]int             `json:"judgeStatuses,omitempty"`
	Evaluation       BenchmarkEvaluationSummary `json:"evaluation"`
}

type BenchmarkEvaluation struct {
	ExpectedVerdict  string `json:"expectedVerdict,omitempty"`
	PredictedVerdict string `json:"predictedVerdict,omitempty"`
	Status           string `json:"status"`
	Source           string `json:"source,omitempty"`
	Error            string `json:"error,omitempty"`
}

type BenchmarkEvaluationSummary struct {
	Scored     int     `json:"scored"`
	Correct    int     `json:"correct"`
	Incorrect  int     `json:"incorrect"`
	Abstained  int     `json:"abstained"`
	Unscorable int     `json:"unscorable"`
	Errors     int     `json:"errors"`
	Accuracy   float64 `json:"accuracy"`
}

type BenchmarkPrediction struct {
	ID         string `json:"id"`
	Prediction string `json:"prediction"`
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
	adapter, err := DefaultBenchmarkRegistry().Resolve(opts.Benchmark.ID)
	if err != nil {
		return BenchmarkArtifact{}, err
	}
	benchmarkOpts := *opts.Benchmark
	benchmarkOpts.ID = adapter.ID()
	opts.Benchmark = &benchmarkOpts
	if opts.Benchmark.PredictionsOutputPath != "" && !adapter.SupportsPredictionsOutput() {
		return BenchmarkArtifact{}, fmt.Errorf("predictions output is only supported for %s", openClawBenchmarkID)
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
			Source: adapter.Source(),
			Config: adapter.Config(),
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
	cases, err := adapter.RunCases(opts, ctx, env, now, client)
	if err != nil {
		return BenchmarkArtifact{}, err
	}
	artifact.Benchmark.Rows = len(cases)
	for _, benchmarkCase := range cases {
		evaluateBenchmarkCase(&benchmarkCase)
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
	if predictionsPath := BenchmarkPredictionsOutputPath(opts); predictionsPath != "" {
		if err := WriteBenchmarkPredictionsJSONL(predictionsPath, artifact); err != nil {
			return BenchmarkArtifact{}, err
		}
	}
	return artifact, nil
}

func BenchmarkPredictionsOutputPath(opts Options) string {
	if opts.Benchmark == nil || opts.Benchmark.ID != openClawBenchmarkID {
		return ""
	}
	if opts.Benchmark.PredictionsOutputPath != "" {
		return opts.Benchmark.PredictionsOutputPath
	}
	if opts.OutputPath == "" {
		return ""
	}
	return filepath.Join(filepath.Dir(opts.OutputPath), "predictions.jsonl")
}

func WriteBenchmarkPredictionsJSONL(path string, artifact BenchmarkArtifact) error {
	predictions, err := BenchmarkPredictions(artifact)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	file, err := os.Create(path)
	if err != nil {
		return err
	}
	defer file.Close()
	for _, prediction := range predictions {
		raw, err := json.Marshal(prediction)
		if err != nil {
			return err
		}
		if _, err := file.Write(append(raw, '\n')); err != nil {
			return err
		}
	}
	return nil
}

func BenchmarkPredictions(artifact BenchmarkArtifact) ([]BenchmarkPrediction, error) {
	if artifact.Benchmark.ID != openClawBenchmarkID {
		return nil, fmt.Errorf("predictions output is only supported for %s", openClawBenchmarkID)
	}
	predictions := make([]BenchmarkPrediction, 0, len(artifact.Cases))
	for _, benchmarkCase := range artifact.Cases {
		prediction, _, err := benchmarkCasePrediction(benchmarkCase)
		if err != nil {
			return nil, err
		}
		predictions = append(predictions, BenchmarkPrediction{
			ID:         benchmarkCase.ID,
			Prediction: prediction,
		})
	}
	return predictions, nil
}

func benchmarkCasePrediction(benchmarkCase BenchmarkCase) (string, string, error) {
	if benchmarkCase.Run.Judge != nil && benchmarkCase.Run.Judge.Status == "completed" {
		if prediction, ok := predictionFromObject(benchmarkCase.Run.Judge.Result); ok {
			return prediction, "judge", nil
		}
	}
	scannerPredictions := map[string][]string{}
	var staticResult *ScannerResult
	scanners := make([]string, 0, len(benchmarkCase.Run.Scanners))
	for scanner := range benchmarkCase.Run.Scanners {
		scanners = append(scanners, scanner)
	}
	sort.Strings(scanners)
	for _, scanner := range scanners {
		result := benchmarkCase.Run.Scanners[scanner]
		if scanner == "clawscan-static" {
			staticCopy := result
			staticResult = &staticCopy
		}
		if result.Status != "completed" || len(result.Raw) == 0 {
			continue
		}
		if prediction, ok := predictionFromObject(result.Raw); ok {
			scannerPredictions[prediction] = append(scannerPredictions[prediction], scanner)
		}
	}
	if len(scannerPredictions) == 1 {
		for prediction := range scannerPredictions {
			return prediction, "scanner:" + scannerPredictions[prediction][0], nil
		}
	}
	if len(scannerPredictions) > 1 {
		return "", "", fmt.Errorf("case %s has conflicting scanner predictions", benchmarkCase.ID)
	}
	if staticResult != nil && staticResult.Status == "completed" && len(staticResult.Raw) > 0 {
		if prediction, ok := staticPrediction(staticResult.Raw); ok {
			return prediction, "scanner:clawscan-static", nil
		}
	}
	return "", "", fmt.Errorf("case %s has no prediction verdict", benchmarkCase.ID)
}

func predictionFromObject(value interface{}) (string, bool) {
	switch typed := value.(type) {
	case json.RawMessage:
		var decoded map[string]interface{}
		if err := json.Unmarshal(typed, &decoded); err != nil {
			return "", false
		}
		return predictionFromObject(decoded)
	case []byte:
		var decoded map[string]interface{}
		if err := json.Unmarshal(typed, &decoded); err != nil {
			return "", false
		}
		return predictionFromObject(decoded)
	case map[string]interface{}:
		for _, key := range []string{"prediction", "verdict", "status"} {
			if prediction, ok := normalizePredictionLabel(typed[key]); ok {
				return prediction, true
			}
		}
	case map[string]string:
		for _, key := range []string{"prediction", "verdict", "status"} {
			if prediction, ok := normalizePredictionLabel(typed[key]); ok {
				return prediction, true
			}
		}
	}
	return "", false
}

func normalizePredictionLabel(value interface{}) (string, bool) {
	label, ok := value.(string)
	if !ok {
		return "", false
	}
	switch strings.ToLower(strings.TrimSpace(label)) {
	case "clean", "normal":
		return "clean", true
	case "suspicious", "malicious":
		return strings.ToLower(strings.TrimSpace(label)), true
	default:
		return "", false
	}
}

func staticPrediction(raw json.RawMessage) (string, bool) {
	var report staticScannerReport
	if err := json.Unmarshal(raw, &report); err != nil {
		return "", false
	}
	if report.SchemaVersion != staticScannerVersion {
		return "", false
	}
	prediction := "clean"
	for _, finding := range report.Findings {
		if strings.EqualFold(finding.Severity, "high") {
			return "malicious", true
		}
		prediction = "suspicious"
	}
	return prediction, true
}

func evaluateBenchmarkCase(benchmarkCase *BenchmarkCase) {
	expected, ok := canonicalVerdict(benchmarkCase.Expected.Verdict)
	if !ok {
		benchmarkCase.Evaluation = &BenchmarkEvaluation{
			ExpectedVerdict: benchmarkCase.Expected.Verdict,
			Status:          "unscorable",
			Error:           fmt.Sprintf("unsupported expected verdict: %s", benchmarkCase.Expected.Verdict),
		}
		return
	}
	predicted, source, err := benchmarkCasePrediction(*benchmarkCase)
	if err != nil {
		status := "abstained"
		if strings.Contains(err.Error(), "conflicting scanner predictions") {
			status = "error"
		}
		benchmarkCase.Evaluation = &BenchmarkEvaluation{
			ExpectedVerdict: expected,
			Status:          status,
			Error:           err.Error(),
		}
		return
	}
	status := "incorrect"
	if predicted == expected {
		status = "correct"
	}
	benchmarkCase.Evaluation = &BenchmarkEvaluation{
		ExpectedVerdict:  expected,
		PredictedVerdict: predicted,
		Status:           status,
		Source:           source,
	}
}

func canonicalVerdict(verdict string) (string, bool) {
	return normalizePredictionLabel(verdict)
}

func canonicalExpectedVerdict(verdict string) string {
	if canonical, ok := canonicalVerdict(verdict); ok {
		return canonical
	}
	return verdict
}

func runBenchmarkTarget(opts Options, ctx RunContext, env map[string]string, now func() time.Time, target string) (Artifact, error) {
	caseOpts := opts
	caseOpts.Target = target
	caseOpts.Benchmark = nil
	caseOpts.OutputPath = ""
	return Run(caseOpts, RunContext{
		Env:                  env,
		Now:                  now,
		CommandRunner:        ctx.CommandRunner,
		ScannerRunner:        ctx.ScannerRunner,
		SkillSpectorCommand:  ctx.SkillSpectorCommand,
		VirusTotalHTTPClient: ctx.VirusTotalHTTPClient,
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
	if benchmarkCase.Evaluation != nil {
		switch benchmarkCase.Evaluation.Status {
		case "correct":
			summary.Evaluation.Scored++
			summary.Evaluation.Correct++
		case "incorrect":
			summary.Evaluation.Scored++
			summary.Evaluation.Incorrect++
		case "abstained":
			summary.Evaluation.Abstained++
		case "unscorable":
			summary.Evaluation.Unscorable++
		case "error":
			summary.Evaluation.Errors++
		}
		if summary.Evaluation.Scored > 0 {
			summary.Evaluation.Accuracy = float64(summary.Evaluation.Correct) / float64(summary.Evaluation.Scored)
		}
	}
}

func canonicalBenchmarkID(id string) (string, error) {
	adapter, err := DefaultBenchmarkRegistry().Resolve(id)
	if err != nil {
		return "", err
	}
	return adapter.ID(), nil
}

func validateBenchmarkSplit(id string, split string) error {
	adapter, err := DefaultBenchmarkRegistry().Resolve(id)
	if err != nil {
		return err
	}
	validSplits := adapter.Splits()
	for _, validSplit := range validSplits {
		if split == validSplit {
			return nil
		}
	}
	return fmt.Errorf("Unsupported split for %s: %s (valid: %s)", adapter.ID(), split, strings.Join(validSplits, ", "))
}

func defaultBenchmarkID() string {
	return skillTrustBenchID
}

func defaultBenchmarkSplit(id string) string {
	adapter, err := DefaultBenchmarkRegistry().Resolve(id)
	if err != nil {
		return defaultOpenClawBenchmarkSplit
	}
	return adapter.DefaultSplit()
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
	raw, statusCode, err := fetchHuggingFaceRowsPage(httpClient, requestURL)
	if err != nil {
		return nil, err
	}
	var parsed huggingFaceRowsResponse
	if statusCode < 200 || statusCode >= 300 {
		_ = json.Unmarshal(raw, &parsed)
		if parsed.Error != "" {
			return nil, fmt.Errorf("fetch benchmark rows: %s", parsed.Error)
		}
		return nil, fmt.Errorf("fetch benchmark rows: HTTP %d", statusCode)
	}
	if err := json.Unmarshal(raw, &parsed); err != nil {
		return nil, err
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
	raw, statusCode, err := fetchHuggingFaceRowsPage(httpClient, requestURL)
	if err != nil {
		return nil, err
	}
	var parsed skillTrustBenchRowsResponse
	if statusCode < 200 || statusCode >= 300 {
		_ = json.Unmarshal(raw, &parsed)
		if parsed.Error != "" {
			return nil, fmt.Errorf("fetch benchmark rows: %s", parsed.Error)
		}
		return nil, fmt.Errorf("fetch benchmark rows: HTTP %d", statusCode)
	}
	if err := json.Unmarshal(raw, &parsed); err != nil {
		return nil, err
	}
	rows := make([]SkillTrustBenchRow, 0, len(parsed.Rows))
	for _, row := range parsed.Rows {
		rows = append(rows, row.Row)
	}
	return rows, nil
}

func fetchHuggingFaceRowsPage(httpClient *http.Client, requestURL string) ([]byte, int, error) {
	var lastErr error
	for attempt := 1; attempt <= huggingFaceRowsMaxAttempts; attempt++ {
		raw, statusCode, headers, err := fetchHuggingFaceRowsPageOnce(httpClient, requestURL)
		if err == nil && !isRetriableHuggingFaceRowsStatus(statusCode) {
			return raw, statusCode, nil
		}
		if err == nil && attempt == huggingFaceRowsMaxAttempts {
			return raw, statusCode, nil
		}
		if err != nil {
			lastErr = err
		} else {
			lastErr = fmt.Errorf("fetch benchmark rows: HTTP %d", statusCode)
		}
		if attempt == huggingFaceRowsMaxAttempts {
			break
		}
		time.Sleep(huggingFaceRowsBackoff(attempt, headers))
	}
	return nil, 0, lastErr
}

func fetchHuggingFaceRowsPageOnce(httpClient *http.Client, requestURL string) ([]byte, int, http.Header, error) {
	response, err := httpClient.Get(requestURL)
	if err != nil {
		return nil, 0, nil, err
	}
	defer response.Body.Close()
	raw, err := io.ReadAll(response.Body)
	if err != nil {
		return nil, response.StatusCode, response.Header, err
	}
	return raw, response.StatusCode, response.Header, nil
}

func isRetriableHuggingFaceRowsStatus(statusCode int) bool {
	return statusCode == http.StatusRequestTimeout ||
		statusCode == http.StatusTooManyRequests ||
		(statusCode >= http.StatusInternalServerError && statusCode <= 599)
}

func huggingFaceRowsBackoff(attempt int, headers http.Header) time.Duration {
	if retryAfter := headers.Get("Retry-After"); retryAfter != "" {
		if seconds, err := strconv.Atoi(retryAfter); err == nil && seconds >= 0 {
			return time.Duration(seconds) * time.Second
		}
		if retryAt, err := http.ParseTime(retryAfter); err == nil {
			if delay := time.Until(retryAt); delay > 0 {
				return delay
			}
		}
	}
	delay := time.Duration(attempt*attempt) * huggingFaceRowsRetryDelay
	if delay > 30*time.Second {
		return 30 * time.Second
	}
	return delay
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

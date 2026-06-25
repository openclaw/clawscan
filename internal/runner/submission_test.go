package runner

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestValidateSecuritySignalsSubmissionComputesLooseNonCleanMetrics(t *testing.T) {
	dir := writeSecuritySignalsSubmission(t, SecuritySignalsSubmissionMetadata{
		SchemaVersion: "clawscan-security-signals-submission-v1",
		Benchmark: SecuritySignalsSubmissionBenchmark{
			Dataset:  "OpenClaw/clawhub-security-signals",
			Split:    "eval_holdout",
			Revision: "fixture-sha",
		},
		System: SecuritySignalsSubmissionSystem{
			Name: "fixture-system",
			Role: "community",
		},
		VerificationStatus: "artifact-validated",
	}, []BenchmarkPrediction{
		{ID: "clean-correct", Prediction: "clean"},
		{ID: "clean-false-positive", Prediction: "suspicious"},
		{ID: "suspicious-true-positive", Prediction: "malicious"},
		{ID: "malicious-false-negative", Prediction: "clean"},
	})

	result, err := ValidateSecuritySignalsSubmission(dir, submissionBenchmarkClient{
		rows: []OpenClawBenchmarkRow{
			{ID: "clean-correct", ClawScanVerdict: "clean"},
			{ID: "clean-false-positive", ClawScanVerdict: "clean"},
			{ID: "suspicious-true-positive", ClawScanVerdict: "suspicious"},
			{ID: "malicious-false-negative", ClawScanVerdict: "malicious"},
		},
	})
	if err != nil {
		t.Fatal(err)
	}

	if result.SchemaVersion != "clawscan-security-signals-score-v1" {
		t.Fatalf("schema version = %q", result.SchemaVersion)
	}
	if result.Benchmark.Dataset != "OpenClaw/clawhub-security-signals" || result.Benchmark.Split != "eval_holdout" || result.Benchmark.Revision != "fixture-sha" {
		t.Fatalf("benchmark = %#v", result.Benchmark)
	}
	metrics := result.Metrics
	if metrics.CaseCount != 4 || metrics.TruePositive != 1 || metrics.FalsePositive != 1 || metrics.TrueNegative != 1 || metrics.FalseNegative != 1 {
		t.Fatalf("metrics counts = %#v", metrics)
	}
	if metrics.Precision != 0.5 || metrics.Recall != 0.5 || metrics.F1 != 0.5 || metrics.FalsePositiveRate != 0.5 {
		t.Fatalf("metric rates = %#v", metrics)
	}
}

func TestValidateSecuritySignalsSubmissionRejectsInvalidInputs(t *testing.T) {
	tests := []struct {
		name        string
		metadata    SecuritySignalsSubmissionMetadata
		predictions []BenchmarkPrediction
		wantErr     []string
	}{
		{
			name: "mismatched dataset",
			metadata: SecuritySignalsSubmissionMetadata{
				SchemaVersion: "clawscan-security-signals-submission-v1",
				Benchmark: SecuritySignalsSubmissionBenchmark{
					Dataset:  "other/dataset",
					Split:    "eval_holdout",
					Revision: "fixture-sha",
				},
			},
			predictions: []BenchmarkPrediction{{ID: "case-1", Prediction: "clean"}},
			wantErr:     []string{"metadata benchmark.dataset must be OpenClaw/clawhub-security-signals"},
		},
		{
			name: "mismatched split",
			metadata: SecuritySignalsSubmissionMetadata{
				SchemaVersion: "clawscan-security-signals-submission-v1",
				Benchmark: SecuritySignalsSubmissionBenchmark{
					Dataset:  "OpenClaw/clawhub-security-signals",
					Split:    "benchmark",
					Revision: "fixture-sha",
				},
			},
			predictions: []BenchmarkPrediction{{ID: "case-1", Prediction: "clean"}},
			wantErr:     []string{"Unsupported split for OpenClaw/clawhub-security-signals: benchmark"},
		},
		{
			name: "bad predictions",
			metadata: SecuritySignalsSubmissionMetadata{
				SchemaVersion: "clawscan-security-signals-submission-v1",
				Benchmark: SecuritySignalsSubmissionBenchmark{
					Dataset:  "OpenClaw/clawhub-security-signals",
					Split:    "eval_holdout",
					Revision: "fixture-sha",
				},
			},
			predictions: []BenchmarkPrediction{
				{ID: "case-1", Prediction: "clean"},
				{ID: "case-1", Prediction: "malicious"},
				{ID: "unknown-case", Prediction: "suspicious"},
				{ID: "case-2", Prediction: "normal"},
			},
			wantErr: []string{
				"duplicate prediction id: case-1",
				"unknown prediction id: unknown-case",
				"invalid prediction label for case-2: normal",
				"missing prediction id: case-3",
			},
		},
		{
			name: "missing revision",
			metadata: SecuritySignalsSubmissionMetadata{
				SchemaVersion: "clawscan-security-signals-submission-v1",
				Benchmark: SecuritySignalsSubmissionBenchmark{
					Dataset: "OpenClaw/clawhub-security-signals",
					Split:   "eval_holdout",
				},
			},
			predictions: []BenchmarkPrediction{{ID: "case-1", Prediction: "clean"}},
			wantErr:     []string{"metadata benchmark.revision is required"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := writeSecuritySignalsSubmission(t, tt.metadata, tt.predictions)
			_, err := ValidateSecuritySignalsSubmission(dir, submissionBenchmarkClient{
				rows: []OpenClawBenchmarkRow{
					{ID: "case-1", ClawScanVerdict: "clean"},
					{ID: "case-2", ClawScanVerdict: "suspicious"},
					{ID: "case-3", ClawScanVerdict: "malicious"},
				},
			})
			if err == nil {
				t.Fatal("expected error")
			}
			for _, want := range tt.wantErr {
				if !strings.Contains(err.Error(), want) {
					t.Fatalf("err missing %q:\n%v", want, err)
				}
			}
		})
	}
}

func TestHuggingFaceBenchmarkClientReportsNonJSONHTTPError(t *testing.T) {
	withHuggingFaceRowsRetryDelay(t, 0)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusBadGateway)
		_, _ = w.Write([]byte("<html>bad gateway</html>"))
	}))
	t.Cleanup(server.Close)

	client := HuggingFaceBenchmarkClient{Endpoint: server.URL}
	_, err := client.FetchOpenClawRows("OpenClaw/clawhub-security-signals", "eval_holdout", 0, 1)
	if err == nil || !strings.Contains(err.Error(), "fetch benchmark rows: HTTP 502") {
		t.Fatalf("err = %v", err)
	}
}

func TestHuggingFaceBenchmarkClientRetriesTransientHTTPError(t *testing.T) {
	withHuggingFaceRowsRetryDelay(t, 0)

	requests := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		requests++
		if requests == 1 {
			w.WriteHeader(http.StatusBadGateway)
			_, _ = w.Write([]byte("<html>bad gateway</html>"))
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"rows":[]}`))
	}))
	t.Cleanup(server.Close)

	client := HuggingFaceBenchmarkClient{Endpoint: server.URL}
	rows, err := client.FetchOpenClawRows("OpenClaw/clawhub-security-signals", "eval_holdout", 0, 1)
	if err != nil {
		t.Fatalf("FetchOpenClawRows err = %v", err)
	}
	if len(rows) != 0 {
		t.Fatalf("rows = %v, want empty rows", rows)
	}
	if requests != 2 {
		t.Fatalf("requests = %d, want 2", requests)
	}
}

func TestHuggingFaceBenchmarkClientRetriesRateLimitHTTPError(t *testing.T) {
	withHuggingFaceRowsRetryDelay(t, 0)

	requests := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		requests++
		if requests < 3 {
			w.Header().Set("Retry-After", "0")
			w.WriteHeader(http.StatusTooManyRequests)
			_, _ = w.Write([]byte(`{"error":"slow down"}`))
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"rows":[]}`))
	}))
	t.Cleanup(server.Close)

	client := HuggingFaceBenchmarkClient{Endpoint: server.URL}
	_, err := client.FetchOpenClawRows("OpenClaw/clawhub-security-signals", "eval_holdout", 0, 1)
	if err != nil {
		t.Fatalf("FetchOpenClawRows err = %v", err)
	}
	if requests != 3 {
		t.Fatalf("requests = %d, want 3", requests)
	}
}

func withHuggingFaceRowsRetryDelay(t *testing.T, delay time.Duration) {
	t.Helper()
	previous := huggingFaceRowsRetryDelay
	huggingFaceRowsRetryDelay = delay
	t.Cleanup(func() {
		huggingFaceRowsRetryDelay = previous
	})
}

func writeSecuritySignalsSubmission(t *testing.T, metadata SecuritySignalsSubmissionMetadata, predictions []BenchmarkPrediction) string {
	t.Helper()
	dir := t.TempDir()
	rawMetadata, err := json.MarshalIndent(metadata, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "metadata.json"), append(rawMetadata, '\n'), 0o644); err != nil {
		t.Fatal(err)
	}
	var lines []string
	for _, prediction := range predictions {
		raw, err := json.Marshal(prediction)
		if err != nil {
			t.Fatal(err)
		}
		lines = append(lines, string(raw))
	}
	if err := os.WriteFile(filepath.Join(dir, "predictions.jsonl"), []byte(strings.Join(lines, "\n")+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	return dir
}

type submissionBenchmarkClient struct {
	rows []OpenClawBenchmarkRow
}

func (client submissionBenchmarkClient) FetchOpenClawRows(_ string, _ string, _ int, _ int) ([]OpenClawBenchmarkRow, error) {
	return append([]OpenClawBenchmarkRow(nil), client.rows...), nil
}

func (client submissionBenchmarkClient) FetchSkillTrustBenchRows(_ string, _ string, _ int, _ int) ([]SkillTrustBenchRow, error) {
	return nil, nil
}

func (client submissionBenchmarkClient) MaterializeSkillTrustBenchRow(_ string, _ SkillTrustBenchRow) (string, error) {
	return "", nil
}

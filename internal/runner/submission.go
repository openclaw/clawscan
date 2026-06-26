package runner

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"strings"
)

const (
	securitySignalsSubmissionSchema = "clawscan-security-signals-submission-v1"
	securitySignalsScoreSchema      = "clawscan-security-signals-score-v1"
)

type SecuritySignalsSubmissionMetadata struct {
	SchemaVersion      string                             `json:"schemaVersion"`
	Benchmark          SecuritySignalsSubmissionBenchmark `json:"benchmark"`
	System             SecuritySignalsSubmissionSystem    `json:"system,omitempty"`
	VerificationStatus string                             `json:"verificationStatus,omitempty"`
}

type SecuritySignalsSubmissionBenchmark struct {
	Dataset  string `json:"dataset"`
	Split    string `json:"split"`
	Revision string `json:"revision"`
}

type SecuritySignalsSubmissionSystem struct {
	Name string `json:"name,omitempty"`
	Role string `json:"role,omitempty"`
}

type SecuritySignalsSubmissionResult struct {
	SchemaVersion      string                             `json:"schemaVersion"`
	Benchmark          SecuritySignalsSubmissionBenchmark `json:"benchmark"`
	System             SecuritySignalsSubmissionSystem    `json:"system,omitempty"`
	VerificationStatus string                             `json:"verificationStatus,omitempty"`
	Metrics            SecuritySignalsSubmissionMetrics   `json:"metrics"`
}

type SecuritySignalsSubmissionMetrics struct {
	CaseCount         int     `json:"caseCount"`
	TruePositive      int     `json:"truePositive"`
	FalsePositive     int     `json:"falsePositive"`
	TrueNegative      int     `json:"trueNegative"`
	FalseNegative     int     `json:"falseNegative"`
	Precision         float64 `json:"precision"`
	Recall            float64 `json:"recall"`
	F1                float64 `json:"f1"`
	FalsePositiveRate float64 `json:"falsePositiveRate"`
}

func ValidateSecuritySignalsSubmission(dir string, client BenchmarkClient) (SecuritySignalsSubmissionResult, error) {
	metadata, err := readSecuritySignalsSubmissionMetadata(filepath.Join(dir, "metadata.json"))
	if err != nil {
		return SecuritySignalsSubmissionResult{}, err
	}
	var validationErrors []string
	if metadata.SchemaVersion != securitySignalsSubmissionSchema {
		validationErrors = append(validationErrors, fmt.Sprintf("metadata schemaVersion must be %s", securitySignalsSubmissionSchema))
	}
	if metadata.Benchmark.Dataset != openClawBenchmarkID {
		validationErrors = append(validationErrors, fmt.Sprintf("metadata benchmark.dataset must be %s", openClawBenchmarkID))
	}
	if metadata.Benchmark.Revision == "" {
		validationErrors = append(validationErrors, "metadata benchmark.revision is required")
	}
	if metadata.Benchmark.Split == "" {
		validationErrors = append(validationErrors, "metadata benchmark.split is required")
	} else if err := validateBenchmarkSplit(openClawBenchmarkID, metadata.Benchmark.Split); err != nil {
		validationErrors = append(validationErrors, err.Error())
	}
	if len(validationErrors) > 0 {
		return SecuritySignalsSubmissionResult{}, errors.New(strings.Join(validationErrors, "\n"))
	}
	if client == nil {
		client = HuggingFaceBenchmarkClient{}
	}
	rows, err := client.FetchOpenClawRows(openClawBenchmarkDataset, metadata.Benchmark.Split, 0, 0)
	if err != nil {
		return SecuritySignalsSubmissionResult{}, err
	}
	predictions, err := readSecuritySignalsPredictions(filepath.Join(dir, "predictions.jsonl"))
	if err != nil {
		return SecuritySignalsSubmissionResult{}, err
	}
	expected := map[string]string{}
	for _, row := range rows {
		verdict, ok := canonicalVerdict(row.ClawScanVerdict)
		if !ok {
			validationErrors = append(validationErrors, fmt.Sprintf("unsupported expected verdict for %s: %s", row.ID, row.ClawScanVerdict))
			continue
		}
		expected[row.ID] = verdict
	}
	seen := map[string]bool{}
	for _, prediction := range predictions {
		if prediction.ID == "" {
			validationErrors = append(validationErrors, "prediction id is required")
			continue
		}
		if seen[prediction.ID] {
			validationErrors = append(validationErrors, fmt.Sprintf("duplicate prediction id: %s", prediction.ID))
		}
		seen[prediction.ID] = true
		if _, ok := expected[prediction.ID]; !ok {
			validationErrors = append(validationErrors, fmt.Sprintf("unknown prediction id: %s", prediction.ID))
		}
		if !isStrictSecuritySignalsPrediction(prediction.Prediction) {
			validationErrors = append(validationErrors, fmt.Sprintf("invalid prediction label for %s: %s", prediction.ID, prediction.Prediction))
		}
	}
	for id := range expected {
		if !seen[id] {
			validationErrors = append(validationErrors, fmt.Sprintf("missing prediction id: %s", id))
		}
	}
	if len(validationErrors) > 0 {
		return SecuritySignalsSubmissionResult{}, errors.New(strings.Join(validationErrors, "\n"))
	}
	return SecuritySignalsSubmissionResult{
		SchemaVersion:      securitySignalsScoreSchema,
		Benchmark:          metadata.Benchmark,
		System:             metadata.System,
		VerificationStatus: metadata.VerificationStatus,
		Metrics:            scoreLooseNonClean(expected, predictions),
	}, nil
}

func readSecuritySignalsSubmissionMetadata(path string) (SecuritySignalsSubmissionMetadata, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return SecuritySignalsSubmissionMetadata{}, err
	}
	var metadata SecuritySignalsSubmissionMetadata
	if err := json.Unmarshal(raw, &metadata); err != nil {
		return SecuritySignalsSubmissionMetadata{}, fmt.Errorf("read metadata.json: %w", err)
	}
	return metadata, nil
}

func readSecuritySignalsPredictions(path string) ([]BenchmarkPrediction, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	var predictions []BenchmarkPrediction
	scanner := bufio.NewScanner(file)
	line := 0
	for scanner.Scan() {
		line++
		text := strings.TrimSpace(scanner.Text())
		if text == "" {
			continue
		}
		var prediction BenchmarkPrediction
		if err := json.Unmarshal([]byte(text), &prediction); err != nil {
			return nil, fmt.Errorf("read predictions.jsonl line %d: %w", line, err)
		}
		predictions = append(predictions, prediction)
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	return predictions, nil
}

func isStrictSecuritySignalsPrediction(label string) bool {
	switch strings.TrimSpace(label) {
	case "clean", "suspicious", "malicious":
		return true
	default:
		return false
	}
}

func scoreLooseNonClean(expected map[string]string, predictions []BenchmarkPrediction) SecuritySignalsSubmissionMetrics {
	predicted := map[string]string{}
	for _, prediction := range predictions {
		predicted[prediction.ID] = prediction.Prediction
	}
	metrics := SecuritySignalsSubmissionMetrics{CaseCount: len(expected)}
	for id, expectedVerdict := range expected {
		expectedPositive := isLooseNonCleanPositive(expectedVerdict)
		predictedPositive := isLooseNonCleanPositive(predicted[id])
		switch {
		case expectedPositive && predictedPositive:
			metrics.TruePositive++
		case !expectedPositive && predictedPositive:
			metrics.FalsePositive++
		case !expectedPositive && !predictedPositive:
			metrics.TrueNegative++
		case expectedPositive && !predictedPositive:
			metrics.FalseNegative++
		}
	}
	metrics.Precision = safeDivide(metrics.TruePositive, metrics.TruePositive+metrics.FalsePositive)
	metrics.Recall = safeDivide(metrics.TruePositive, metrics.TruePositive+metrics.FalseNegative)
	metrics.F1 = safeDivideFloat(2*metrics.Precision*metrics.Recall, metrics.Precision+metrics.Recall)
	metrics.FalsePositiveRate = safeDivide(metrics.FalsePositive, metrics.FalsePositive+metrics.TrueNegative)
	return metrics
}

func isLooseNonCleanPositive(verdict string) bool {
	return verdict == "suspicious" || verdict == "malicious"
}

func safeDivide(numerator int, denominator int) float64 {
	if denominator == 0 {
		return 0
	}
	return roundMetric(float64(numerator) / float64(denominator))
}

func safeDivideFloat(numerator float64, denominator float64) float64 {
	if denominator == 0 {
		return 0
	}
	return roundMetric(numerator / denominator)
}

func roundMetric(value float64) float64 {
	return math.Round(value*10000) / 10000
}

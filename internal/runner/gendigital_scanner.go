package runner

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"
)

const genDigitalLookupEndpoint = "https://ai.gendigital.com/api/scan/lookup"

type GenDigitalHTTPClient interface {
	Do(request *http.Request) (*http.Response, error)
}

func (runner ExternalScannerRunner) runGenDigital(target string, startedAt string) (ScannerResult, error) {
	completedAt := func() string {
		return time.Now().UTC().Format(time.RFC3339Nano)
	}
	command := []string{"gendigital", "lookup", target}
	if !isURLTarget(target) {
		return ScannerResult{
			Status:      "skipped",
			StartedAt:   startedAt,
			CompletedAt: completedAt(),
			Command:     command,
			Error:       "Gen Digital v1 requires a ClawHub skill URL target; local path targets are unsupported.",
			Raw:         nil,
		}, nil
	}
	payload, err := json.Marshal(struct {
		SkillURL string `json:"skillUrl"`
	}{SkillURL: target})
	if err != nil {
		return ScannerResult{}, err
	}
	timeout := runner.Timeout
	if timeout == 0 {
		timeout = 20 * time.Minute
	}
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, genDigitalLookupEndpoint, bytes.NewReader(payload))
	if err != nil {
		return ScannerResult{}, err
	}
	request.Header.Set("content-type", "application/json")
	request.Header.Set("accept", "application/json")
	client := runner.GenDigitalHTTPClient
	if client == nil {
		client = http.DefaultClient
	}
	response, err := client.Do(request)
	if err != nil {
		return ScannerResult{
			Status:      "failed",
			StartedAt:   startedAt,
			CompletedAt: completedAt(),
			Command:     command,
			Error:       fmt.Sprintf("Gen Digital lookup request failed: %v", err),
			Raw:         nil,
		}, nil
	}
	defer response.Body.Close()
	body, err := io.ReadAll(response.Body)
	if err != nil {
		return ScannerResult{}, err
	}
	raw := json.RawMessage(nil)
	if json.Valid(body) {
		raw = json.RawMessage(body)
	}
	if response.StatusCode >= 200 && response.StatusCode <= 299 {
		if raw == nil {
			return ScannerResult{
				Status:      "failed",
				StartedAt:   startedAt,
				CompletedAt: completedAt(),
				Command:     command,
				Error:       "Gen Digital API returned non-JSON response.",
				Raw:         nil,
			}, nil
		}
		return ScannerResult{
			Status:      "completed",
			StartedAt:   startedAt,
			CompletedAt: completedAt(),
			Command:     command,
			Error:       "",
			Raw:         raw,
		}, nil
	}
	errorMessage := fmt.Sprintf("Gen Digital API returned HTTP %d.", response.StatusCode)
	if raw == nil {
		errorMessage = fmt.Sprintf("Gen Digital API returned HTTP %d with non-JSON response.", response.StatusCode)
	}
	return ScannerResult{
		Status:      "failed",
		StartedAt:   startedAt,
		CompletedAt: completedAt(),
		Command:     command,
		Error:       errorMessage,
		Raw:         raw,
	}, nil
}

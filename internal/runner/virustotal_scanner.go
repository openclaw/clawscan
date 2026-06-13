package runner

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"
)

const virusTotalFileReportEndpoint = "https://www.virustotal.com/api/v3/files/"

type VirusTotalHTTPClient interface {
	Do(request *http.Request) (*http.Response, error)
}

func (runner ExternalScannerRunner) runVirusTotal(target string, startedAt string) (ScannerResult, error) {
	completedAt := func() string {
		return time.Now().UTC().Format(time.RFC3339Nano)
	}
	command := []string{"virustotal", "file-report"}
	if isURLTarget(target) {
		return ScannerResult{
			Status:      "skipped",
			StartedAt:   startedAt,
			CompletedAt: completedAt(),
			Command:     command,
			Error:       "VirusTotal scanner supports single-file local targets in v1; URL targets are unsupported.",
			Raw:         nil,
		}, nil
	}
	info, err := os.Stat(target)
	if err != nil {
		return ScannerResult{
			Status:      "failed",
			StartedAt:   startedAt,
			CompletedAt: completedAt(),
			Command:     command,
			Error:       fmt.Sprintf("stat target: %v", err),
			Raw:         nil,
		}, nil
	}
	if info.IsDir() {
		return ScannerResult{
			Status:      "skipped",
			StartedAt:   startedAt,
			CompletedAt: completedAt(),
			Command:     command,
			Error:       "VirusTotal scanner supports single-file targets in v1; directory targets are unsupported.",
			Raw:         nil,
		}, nil
	}
	if !info.Mode().IsRegular() {
		return ScannerResult{
			Status:      "skipped",
			StartedAt:   startedAt,
			CompletedAt: completedAt(),
			Command:     command,
			Error:       "VirusTotal scanner supports single-file targets in v1; non-regular files are unsupported.",
			Raw:         nil,
		}, nil
	}
	digest, err := fileSHA256Hex(target)
	if err != nil {
		return ScannerResult{}, err
	}
	command = append(command, "sha256:"+digest)
	apiKey := strings.TrimSpace(runner.Env["VIRUSTOTAL_API_KEY"])
	timeout := runner.Timeout
	if timeout == 0 {
		timeout = 20 * time.Minute
	}
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, virusTotalFileReportEndpoint+digest, nil)
	if err != nil {
		return ScannerResult{}, err
	}
	request.Header.Set("x-apikey", apiKey)
	request.Header.Set("accept", "application/json")
	client := runner.VirusTotalHTTPClient
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
			Error:       fmt.Sprintf("VirusTotal file report request failed: %v", err),
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
	switch {
	case response.StatusCode >= 200 && response.StatusCode <= 299:
		if raw == nil {
			return ScannerResult{
				Status:      "failed",
				StartedAt:   startedAt,
				CompletedAt: completedAt(),
				Command:     command,
				Error:       "VirusTotal API returned non-JSON response.",
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
	case response.StatusCode == http.StatusNotFound:
		return ScannerResult{
			Status:      "skipped",
			StartedAt:   startedAt,
			CompletedAt: completedAt(),
			Command:     command,
			Error:       "VirusTotal has no file report for the target SHA-256 hash.",
			Raw:         raw,
		}, nil
	default:
		errorMessage := fmt.Sprintf("VirusTotal API returned HTTP %d.", response.StatusCode)
		if raw == nil {
			errorMessage = fmt.Sprintf("VirusTotal API returned HTTP %d with non-JSON response.", response.StatusCode)
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
}

func fileSHA256Hex(path string) (string, error) {
	file, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer file.Close()
	hash := sha256.New()
	if _, err := io.Copy(hash, file); err != nil {
		return "", err
	}
	return hex.EncodeToString(hash.Sum(nil)), nil
}

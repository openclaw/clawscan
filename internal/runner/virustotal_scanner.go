package runner

import (
	"archive/zip"
	"bytes"
	"compress/flate"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

const (
	virusTotalFilesEndpoint     = "https://www.virustotal.com/api/v3/files"
	virusTotalUploadURLEndpoint = "https://www.virustotal.com/api/v3/files/upload_url"
	virusTotalDirectUploadLimit = 32 * 1024 * 1024
)

var virusTotalFixedZipDate = time.Date(1980, 1, 1, 0, 0, 0, 0, time.Local)

type VirusTotalHTTPClient interface {
	Do(request *http.Request) (*http.Response, error)
}

type virusTotalScanArtifact struct {
	Bytes  []byte
	SHA256 string
	Kind   string
}

type virusTotalNormalizedAnalysis struct {
	Status      string                `json:"status"`
	Source      string                `json:"source,omitempty"`
	EngineStats *virusTotalStats      `json:"engineStats,omitempty"`
	CheckedAt   int64                 `json:"checkedAt"`
	Upload      *virusTotalUploadInfo `json:"upload,omitempty"`
}

type virusTotalUploadInfo struct {
	Status string          `json:"status"`
	Raw    json.RawMessage `json:"raw,omitempty"`
}

type virusTotalFileResponse struct {
	Data struct {
		Attributes struct {
			LastAnalysisStats *virusTotalStats `json:"last_analysis_stats"`
		} `json:"attributes"`
	} `json:"data"`
}

type virusTotalStats struct {
	Malicious  int `json:"malicious"`
	Suspicious int `json:"suspicious"`
	Undetected int `json:"undetected"`
	Harmless   int `json:"harmless"`
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
			Error:       "VirusTotal scanner supports local file or directory targets in v1; URL targets are unsupported.",
			Raw:         nil,
		}, nil
	}
	artifact, err := virusTotalArtifact(target)
	if err != nil {
		return ScannerResult{}, err
	}
	command = append(command, artifact.Kind, "sha256:"+artifact.SHA256)
	apiKey := strings.TrimSpace(runner.Env["VIRUSTOTAL_API_KEY"])
	timeout := runner.Timeout
	if timeout == 0 {
		timeout = 20 * time.Minute
	}
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	client := runner.VirusTotalHTTPClient
	if client == nil {
		client = http.DefaultClient
	}
	raw, statusCode, err := virusTotalFileReport(ctx, client, apiKey, artifact.SHA256)
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
	switch {
	case statusCode >= 200 && statusCode <= 299:
		analysis, err := normalizeVirusTotalFileReport(raw, time.Now)
		if err != nil {
			return ScannerResult{
				Status:      "failed",
				StartedAt:   startedAt,
				CompletedAt: completedAt(),
				Command:     command,
				Error:       err.Error(),
				Raw:         nil,
			}, nil
		}
		return ScannerResult{
			Status:      "completed",
			StartedAt:   startedAt,
			CompletedAt: completedAt(),
			Command:     command,
			Error:       "",
			Raw:         analysis,
		}, nil
	case statusCode == http.StatusNotFound:
		uploadRaw, uploadErr := uploadVirusTotalArtifact(ctx, client, apiKey, artifact)
		if uploadErr != nil {
			return ScannerResult{
				Status:      "failed",
				StartedAt:   startedAt,
				CompletedAt: completedAt(),
				Command:     append(command, "upload"),
				Error:       uploadErr.Error(),
				Raw:         raw,
			}, nil
		}
		var analysis json.RawMessage
		if runner.Profile != "clawhub" {
			encoded, err := json.Marshal(virusTotalNormalizedAnalysis{
				Status:    "pending",
				CheckedAt: time.Now().UnixMilli(),
				Upload: &virusTotalUploadInfo{
					Status: "submitted",
					Raw:    uploadRaw,
				},
			})
			if err != nil {
				return ScannerResult{}, err
			}
			analysis = json.RawMessage(encoded)
		}
		return ScannerResult{
			Status:      "completed",
			StartedAt:   startedAt,
			CompletedAt: completedAt(),
			Command:     append(command, "upload"),
			Error:       "",
			Raw:         analysis,
		}, nil
	default:
		errorMessage := fmt.Sprintf("VirusTotal API returned HTTP %d.", statusCode)
		if !json.Valid(raw) {
			errorMessage = fmt.Sprintf("VirusTotal API returned HTTP %d with non-JSON response.", statusCode)
			raw = nil
		}
		return ScannerResult{
			Status:      "failed",
			StartedAt:   startedAt,
			CompletedAt: completedAt(),
			Command:     command,
			Error:       errorMessage,
			Raw:         json.RawMessage(raw),
		}, nil
	}
}

func virusTotalArtifact(target string) (virusTotalScanArtifact, error) {
	info, err := os.Stat(target)
	if err != nil {
		return virusTotalScanArtifact{}, fmt.Errorf("stat target: %v", err)
	}
	if info.IsDir() {
		bytes, err := buildVirusTotalSkillZip(target)
		if err != nil {
			return virusTotalScanArtifact{}, err
		}
		return virusTotalScanArtifact{Bytes: bytes, SHA256: sha256BytesHex(bytes), Kind: "skill-zip"}, nil
	}
	if !info.Mode().IsRegular() {
		return virusTotalScanArtifact{}, fmt.Errorf("VirusTotal scanner supports local file or directory targets in v1; non-regular files are unsupported")
	}
	bytes, err := os.ReadFile(target)
	if err != nil {
		return virusTotalScanArtifact{}, err
	}
	return virusTotalScanArtifact{Bytes: bytes, SHA256: sha256BytesHex(bytes), Kind: "file"}, nil
}

func virusTotalFileReport(ctx context.Context, client VirusTotalHTTPClient, apiKey string, sha string) (json.RawMessage, int, error) {
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, virusTotalFilesEndpoint+"/"+sha, nil)
	if err != nil {
		return nil, 0, err
	}
	request.Header.Set("x-apikey", apiKey)
	request.Header.Set("accept", "application/json")
	response, err := client.Do(request)
	if err != nil {
		return nil, 0, err
	}
	defer response.Body.Close()
	body, err := io.ReadAll(response.Body)
	if err != nil {
		return nil, 0, err
	}
	raw := json.RawMessage(nil)
	if json.Valid(body) {
		raw = json.RawMessage(body)
	}
	return raw, response.StatusCode, nil
}

func normalizeVirusTotalFileReport(raw json.RawMessage, now func() time.Time) (json.RawMessage, error) {
	if !json.Valid(raw) {
		return nil, fmt.Errorf("VirusTotal API returned non-JSON response.")
	}
	var parsed virusTotalFileResponse
	if err := json.Unmarshal(raw, &parsed); err != nil {
		return nil, err
	}
	stats := parsed.Data.Attributes.LastAnalysisStats
	status := statusFromVirusTotalStats(stats)
	if status == "" {
		status = "pending"
	}
	out, err := json.Marshal(virusTotalNormalizedAnalysis{
		Status:      status,
		Source:      "engines",
		EngineStats: stats,
		CheckedAt:   now().UnixMilli(),
	})
	if err != nil {
		return nil, err
	}
	return json.RawMessage(out), nil
}

func statusFromVirusTotalStats(stats *virusTotalStats) string {
	if stats == nil {
		return ""
	}
	if stats.Malicious > 0 {
		return "malicious"
	}
	if stats.Suspicious > 0 {
		return "suspicious"
	}
	if stats.Harmless > 0 || stats.Undetected > 0 {
		return "clean"
	}
	return ""
}

func uploadVirusTotalArtifact(ctx context.Context, client VirusTotalHTTPClient, apiKey string, artifact virusTotalScanArtifact) (json.RawMessage, error) {
	uploadURL := virusTotalFilesEndpoint
	if len(artifact.Bytes) > virusTotalDirectUploadLimit {
		raw, statusCode, err := virusTotalUploadURL(ctx, client, apiKey)
		if err != nil {
			return nil, err
		}
		if statusCode < 200 || statusCode > 299 {
			return raw, fmt.Errorf("VirusTotal upload URL returned HTTP %d", statusCode)
		}
		var parsed struct {
			Data string `json:"data"`
		}
		if err := json.Unmarshal(raw, &parsed); err != nil {
			return raw, err
		}
		if strings.TrimSpace(parsed.Data) == "" {
			return raw, fmt.Errorf("VirusTotal upload URL response did not include a usable URL")
		}
		uploadURL = parsed.Data
	}
	body := &bytes.Buffer{}
	writer := multipart.NewWriter(body)
	part, err := writer.CreateFormFile("file", "skill.zip")
	if err != nil {
		return nil, err
	}
	if _, err := part.Write(artifact.Bytes); err != nil {
		return nil, err
	}
	if err := writer.Close(); err != nil {
		return nil, err
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, uploadURL, body)
	if err != nil {
		return nil, err
	}
	request.Header.Set("x-apikey", apiKey)
	request.Header.Set("accept", "application/json")
	request.Header.Set("content-type", writer.FormDataContentType())
	response, err := client.Do(request)
	if err != nil {
		return nil, fmt.Errorf("VirusTotal upload request failed: %w", err)
	}
	defer response.Body.Close()
	raw, err := io.ReadAll(response.Body)
	if err != nil {
		return nil, err
	}
	if response.StatusCode < 200 || response.StatusCode > 299 {
		return json.RawMessage(raw), fmt.Errorf("VirusTotal upload returned HTTP %d", response.StatusCode)
	}
	if !json.Valid(raw) {
		return nil, fmt.Errorf("VirusTotal upload returned non-JSON response")
	}
	return json.RawMessage(raw), nil
}

func virusTotalUploadURL(ctx context.Context, client VirusTotalHTTPClient, apiKey string) (json.RawMessage, int, error) {
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, virusTotalUploadURLEndpoint, nil)
	if err != nil {
		return nil, 0, err
	}
	request.Header.Set("x-apikey", apiKey)
	request.Header.Set("accept", "application/json")
	response, err := client.Do(request)
	if err != nil {
		return nil, 0, err
	}
	defer response.Body.Close()
	raw, err := io.ReadAll(response.Body)
	if err != nil {
		return nil, 0, err
	}
	return json.RawMessage(raw), response.StatusCode, nil
}

func buildVirusTotalSkillZip(root string) ([]byte, error) {
	var files []string
	if err := filepath.WalkDir(root, func(path string, entry os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if entry.IsDir() {
			switch entry.Name() {
			case ".git", "node_modules", "clawscan-results":
				if path != root {
					return filepath.SkipDir
				}
			}
			return nil
		}
		if entry.Type()&os.ModeType != 0 {
			return nil
		}
		rel, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		rel = filepath.ToSlash(rel)
		if rel == "" || strings.HasPrefix(rel, "../") || strings.Contains(rel, "/../") {
			return fmt.Errorf("unsafe target path for VirusTotal ZIP: %s", path)
		}
		files = append(files, rel)
		return nil
	}); err != nil {
		return nil, err
	}
	if len(files) == 0 {
		return nil, fmt.Errorf("VirusTotal scanner found no regular files to scan")
	}
	sort.Strings(files)
	buffer := &bytes.Buffer{}
	writer := zip.NewWriter(buffer)
	writer.RegisterCompressor(zip.Deflate, func(w io.Writer) (io.WriteCloser, error) {
		return newFlateWriter(w)
	})
	for _, rel := range files {
		fullPath := filepath.Join(root, filepath.FromSlash(rel))
		content, err := os.ReadFile(fullPath)
		if err != nil {
			return nil, err
		}
		if err := writeZipFile(writer, rel, content); err != nil {
			return nil, err
		}
	}
	meta, err := virusTotalSkillMeta(root)
	if err != nil {
		return nil, err
	}
	if err := writeZipFile(writer, "_meta.json", meta); err != nil {
		return nil, err
	}
	if err := writer.Close(); err != nil {
		return nil, err
	}
	return buffer.Bytes(), nil
}

func writeZipFile(writer *zip.Writer, name string, content []byte) error {
	header := &zip.FileHeader{Name: name, Method: zip.Deflate}
	header.SetModTime(virusTotalFixedZipDate)
	file, err := writer.CreateHeader(header)
	if err != nil {
		return err
	}
	_, err = file.Write(content)
	return err
}

func newFlateWriter(w io.Writer) (io.WriteCloser, error) {
	return flate.NewWriter(w, 6)
}

func virusTotalSkillMeta(root string) ([]byte, error) {
	meta := map[string]interface{}{
		"ownerId":     "clawscan",
		"slug":        filepath.Base(root),
		"version":     "0.0.0",
		"publishedAt": float64(0),
	}
	return json.MarshalIndent(meta, "", "  ")
}

func fileSHA256Hex(path string) (string, error) {
	bytes, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	return sha256BytesHex(bytes), nil
}

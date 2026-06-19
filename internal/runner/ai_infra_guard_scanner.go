package runner

import (
	"archive/zip"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

const (
	aiInfraGuardDefaultModelBaseURL = "https://api.openai.com/v1"
	aiInfraGuardDefaultLanguage     = "en"
	aiInfraGuardDefaultPrompt       = "Audit this AI tool / skill project"
	aiInfraGuardDefaultThreadCount  = 4
	aiInfraGuardDefaultUsername     = "openclaw"
	aiInfraGuardTaskType            = "mcp_scan"
)

type AIInfraGuardHTTPClient interface {
	Do(request *http.Request) (*http.Response, error)
}

type aiInfraGuardAPIEnvelope struct {
	Status  int             `json:"status"`
	Message string          `json:"message"`
	Data    json.RawMessage `json:"data"`
}

type aiInfraGuardUploadData struct {
	FileURL  string `json:"fileUrl"`
	Filename string `json:"filename"`
	Size     int64  `json:"size"`
}

type aiInfraGuardTaskData struct {
	SessionID string `json:"session_id"`
}

type aiInfraGuardStatusData struct {
	SessionID string `json:"session_id"`
	Status    string `json:"status"`
	Title     string `json:"title,omitempty"`
	Log       string `json:"log,omitempty"`
	CreatedAt int64  `json:"created_at,omitempty"`
	UpdatedAt int64  `json:"updated_at,omitempty"`
}

type aiInfraGuardRawEvidence struct {
	Scanner string                  `json:"scanner"`
	Upload  *aiInfraGuardUploadData `json:"upload,omitempty"`
	Task    aiInfraGuardTaskData    `json:"task"`
	Status  aiInfraGuardStatusData  `json:"status"`
	Result  json.RawMessage         `json:"result,omitempty"`
}

func (runner ExternalScannerRunner) runAIInfraGuard(target string, startedAt string) (ScannerResult, error) {
	completedAt := func() string {
		return time.Now().UTC().Format(time.RFC3339Nano)
	}
	command := []string{"ai-infra-guard", "taskapi", aiInfraGuardTaskType}
	timeout := runner.Timeout
	if timeout == 0 {
		timeout = 20 * time.Minute
	}
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	baseURL := strings.TrimRight(strings.TrimSpace(runner.Env["AIG_BASE_URL"]), "/")
	client := runner.AIInfraGuardHTTPClient
	if client == nil {
		client = http.DefaultClient
	}

	var upload *aiInfraGuardUploadData
	prompt := target
	if !isURLTarget(target) {
		archive, err := buildAIInfraGuardArchive(target)
		if err != nil {
			return ScannerResult{}, err
		}
		data, raw, message, err := runner.aiInfraGuardUpload(ctx, client, baseURL, archive, filepath.Base(target)+".zip")
		if err != nil {
			return ScannerResult{
				Status:      "failed",
				StartedAt:   startedAt,
				CompletedAt: completedAt(),
				Command:     command,
				Error:       message,
				Raw:         raw,
			}, nil
		}
		upload = &data
		prompt = aiInfraGuardScanPrompt(runner.Env)
	}

	task, raw, message, err := runner.aiInfraGuardCreateMCPTask(ctx, client, baseURL, prompt, upload)
	if err != nil {
		return ScannerResult{
			Status:      "failed",
			StartedAt:   startedAt,
			CompletedAt: completedAt(),
			Command:     command,
			Error:       message,
			Raw:         raw,
		}, nil
	}

	status, raw, message, err := runner.aiInfraGuardWaitForTask(ctx, client, baseURL, task.SessionID)
	if err != nil {
		return ScannerResult{
			Status:      "failed",
			StartedAt:   startedAt,
			CompletedAt: completedAt(),
			Command:     command,
			Error:       message,
			Raw:         raw,
		}, nil
	}
	if !aiInfraGuardStatusCompleted(status.Status) {
		raw, err := json.Marshal(aiInfraGuardRawEvidence{
			Scanner: "ai-infra-guard",
			Upload:  upload,
			Task:    task,
			Status:  status,
		})
		if err != nil {
			return ScannerResult{}, err
		}
		return ScannerResult{
			Status:      "failed",
			StartedAt:   startedAt,
			CompletedAt: completedAt(),
			Command:     command,
			Error:       fmt.Sprintf("AI-Infra-Guard task %s ended with status %q.", task.SessionID, status.Status),
			Raw:         json.RawMessage(raw),
		}, nil
	}

	result, raw, message, err := runner.aiInfraGuardTaskResult(ctx, client, baseURL, task.SessionID)
	if err != nil {
		return ScannerResult{
			Status:      "failed",
			StartedAt:   startedAt,
			CompletedAt: completedAt(),
			Command:     command,
			Error:       message,
			Raw:         raw,
		}, nil
	}
	evidence, err := json.Marshal(aiInfraGuardRawEvidence{
		Scanner: "ai-infra-guard",
		Upload:  upload,
		Task:    task,
		Status:  status,
		Result:  result,
	})
	if err != nil {
		return ScannerResult{}, err
	}
	return ScannerResult{
		Status:      "completed",
		StartedAt:   startedAt,
		CompletedAt: completedAt(),
		Command:     command,
		Error:       "",
		Raw:         json.RawMessage(evidence),
	}, nil
}

func (runner ExternalScannerRunner) aiInfraGuardUpload(ctx context.Context, client AIInfraGuardHTTPClient, baseURL string, archive []byte, filename string) (aiInfraGuardUploadData, json.RawMessage, string, error) {
	var body bytes.Buffer
	writer := multipart.NewWriter(&body)
	part, err := writer.CreateFormFile("file", filename)
	if err != nil {
		return aiInfraGuardUploadData{}, nil, "", err
	}
	if _, err := part.Write(archive); err != nil {
		return aiInfraGuardUploadData{}, nil, "", err
	}
	if err := writer.Close(); err != nil {
		return aiInfraGuardUploadData{}, nil, "", err
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, aiInfraGuardURL(baseURL, "/api/v1/app/taskapi/upload"), &body)
	if err != nil {
		return aiInfraGuardUploadData{}, nil, "", err
	}
	runner.setAIInfraGuardHeaders(request, writer.FormDataContentType())
	data, raw, message, err := runner.aiInfraGuardDo(request, client)
	if err != nil {
		return aiInfraGuardUploadData{}, raw, "AI-Infra-Guard upload failed: " + message, err
	}
	var upload aiInfraGuardUploadData
	if err := json.Unmarshal(data, &upload); err != nil {
		return aiInfraGuardUploadData{}, raw, "AI-Infra-Guard upload returned unexpected JSON.", err
	}
	if strings.TrimSpace(upload.FileURL) == "" {
		return aiInfraGuardUploadData{}, raw, "AI-Infra-Guard upload response did not include fileUrl.", fmt.Errorf("missing fileUrl")
	}
	return upload, raw, "", nil
}

func (runner ExternalScannerRunner) aiInfraGuardCreateMCPTask(ctx context.Context, client AIInfraGuardHTTPClient, baseURL string, prompt string, upload *aiInfraGuardUploadData) (aiInfraGuardTaskData, json.RawMessage, string, error) {
	content := map[string]any{
		"prompt":   prompt,
		"model":    runner.aiInfraGuardModel(),
		"thread":   aiInfraGuardThreadCount(runner.Env),
		"language": aiInfraGuardLanguage(runner.Env),
	}
	if upload != nil {
		content["attachments"] = upload.FileURL
	}
	payload := map[string]any{
		"type":    aiInfraGuardTaskType,
		"content": content,
	}
	body, err := json.Marshal(payload)
	if err != nil {
		return aiInfraGuardTaskData{}, nil, "", err
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, aiInfraGuardURL(baseURL, "/api/v1/app/taskapi/tasks"), bytes.NewReader(body))
	if err != nil {
		return aiInfraGuardTaskData{}, nil, "", err
	}
	runner.setAIInfraGuardHeaders(request, "application/json")
	data, raw, message, err := runner.aiInfraGuardDo(request, client)
	if err != nil {
		return aiInfraGuardTaskData{}, raw, "AI-Infra-Guard task creation failed: " + message, err
	}
	var task aiInfraGuardTaskData
	if err := json.Unmarshal(data, &task); err != nil {
		return aiInfraGuardTaskData{}, raw, "AI-Infra-Guard task creation returned unexpected JSON.", err
	}
	if strings.TrimSpace(task.SessionID) == "" {
		return aiInfraGuardTaskData{}, raw, "AI-Infra-Guard task creation response did not include session_id.", fmt.Errorf("missing session_id")
	}
	return task, raw, "", nil
}

func (runner ExternalScannerRunner) aiInfraGuardWaitForTask(ctx context.Context, client AIInfraGuardHTTPClient, baseURL string, sessionID string) (aiInfraGuardStatusData, json.RawMessage, string, error) {
	interval := aiInfraGuardPollInterval(runner.Env)
	attempts := aiInfraGuardPollMaxAttempts(runner.Env, runner.Timeout, interval)
	var lastRaw json.RawMessage
	var lastStatus aiInfraGuardStatusData
	for attempt := 0; attempt < attempts; attempt++ {
		status, raw, message, err := runner.aiInfraGuardTaskStatus(ctx, client, baseURL, sessionID)
		lastRaw = raw
		lastStatus = status
		if err != nil {
			return aiInfraGuardStatusData{}, raw, message, err
		}
		if aiInfraGuardStatusCompleted(status.Status) || aiInfraGuardStatusFailed(status.Status) {
			return status, raw, "", nil
		}
		if attempt < attempts-1 && interval > 0 {
			select {
			case <-ctx.Done():
				return lastStatus, lastRaw, "AI-Infra-Guard task polling timed out.", ctx.Err()
			case <-time.After(interval):
			}
		}
	}
	return lastStatus, lastRaw, fmt.Sprintf("AI-Infra-Guard task %s did not complete after %d poll attempt(s).", sessionID, attempts), fmt.Errorf("task incomplete")
}

func (runner ExternalScannerRunner) aiInfraGuardTaskStatus(ctx context.Context, client AIInfraGuardHTTPClient, baseURL string, sessionID string) (aiInfraGuardStatusData, json.RawMessage, string, error) {
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, aiInfraGuardURL(baseURL, "/api/v1/app/taskapi/status/"+url.PathEscape(sessionID)), nil)
	if err != nil {
		return aiInfraGuardStatusData{}, nil, "", err
	}
	runner.setAIInfraGuardHeaders(request, "")
	data, raw, message, err := runner.aiInfraGuardDo(request, client)
	if err != nil {
		return aiInfraGuardStatusData{}, raw, "AI-Infra-Guard task status failed: " + message, err
	}
	var status aiInfraGuardStatusData
	if err := json.Unmarshal(data, &status); err != nil {
		return aiInfraGuardStatusData{}, raw, "AI-Infra-Guard task status returned unexpected JSON.", err
	}
	return status, raw, "", nil
}

func (runner ExternalScannerRunner) aiInfraGuardTaskResult(ctx context.Context, client AIInfraGuardHTTPClient, baseURL string, sessionID string) (json.RawMessage, json.RawMessage, string, error) {
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, aiInfraGuardURL(baseURL, "/api/v1/app/taskapi/result/"+url.PathEscape(sessionID)), nil)
	if err != nil {
		return nil, nil, "", err
	}
	runner.setAIInfraGuardHeaders(request, "")
	data, raw, message, err := runner.aiInfraGuardDo(request, client)
	if err != nil {
		return nil, raw, "AI-Infra-Guard task result failed: " + message, err
	}
	return data, raw, "", nil
}

func (runner ExternalScannerRunner) aiInfraGuardDo(request *http.Request, client AIInfraGuardHTTPClient) (json.RawMessage, json.RawMessage, string, error) {
	response, err := client.Do(request)
	if err != nil {
		return nil, nil, redactEnvValues(err.Error(), runner.Env), err
	}
	defer response.Body.Close()
	body, err := io.ReadAll(response.Body)
	if err != nil {
		return nil, nil, "", err
	}
	raw := redactRawJSON(body, runner.Env)
	if !json.Valid(body) {
		return nil, nil, fmt.Sprintf("HTTP %d with non-JSON response.", response.StatusCode), fmt.Errorf("non-JSON response")
	}
	if response.StatusCode < 200 || response.StatusCode > 299 {
		return nil, raw, fmt.Sprintf("HTTP %d.", response.StatusCode), fmt.Errorf("http %d", response.StatusCode)
	}
	var envelope aiInfraGuardAPIEnvelope
	if err := json.Unmarshal(body, &envelope); err != nil {
		return nil, raw, "invalid API envelope.", err
	}
	if envelope.Status != 0 {
		message := strings.TrimSpace(envelope.Message)
		if message == "" {
			message = fmt.Sprintf("status %d", envelope.Status)
		}
		return nil, raw, redactEnvValues(message, runner.Env), fmt.Errorf("api status %d", envelope.Status)
	}
	return redactRawJSON(envelope.Data, runner.Env), raw, "", nil
}

func (runner ExternalScannerRunner) setAIInfraGuardHeaders(request *http.Request, contentType string) {
	if contentType != "" {
		request.Header.Set("content-type", contentType)
	}
	request.Header.Set("accept", "application/json")
	request.Header.Set("username", aiInfraGuardUsername(runner.Env))
	if apiKey := strings.TrimSpace(runner.Env["AIG_API_KEY"]); apiKey != "" {
		request.Header.Set("API-KEY", apiKey)
	}
}

func (runner ExternalScannerRunner) aiInfraGuardModel() map[string]string {
	baseURL := strings.TrimSpace(runner.Env["AIG_MODEL_BASE_URL"])
	if baseURL == "" {
		baseURL = aiInfraGuardDefaultModelBaseURL
	}
	return map[string]string{
		"model":    strings.TrimSpace(runner.Env["AIG_MODEL"]),
		"token":    strings.TrimSpace(runner.Env["AIG_MODEL_API_KEY"]),
		"base_url": baseURL,
	}
}

func buildAIInfraGuardArchive(target string) ([]byte, error) {
	info, err := os.Stat(target)
	if err != nil {
		return nil, err
	}
	var body bytes.Buffer
	writer := zip.NewWriter(&body)
	if info.IsDir() {
		err = filepath.WalkDir(target, func(path string, entry os.DirEntry, walkErr error) error {
			if walkErr != nil {
				return walkErr
			}
			if entry.IsDir() {
				return nil
			}
			fileInfo, err := entry.Info()
			if err != nil {
				return err
			}
			if !fileInfo.Mode().IsRegular() {
				return nil
			}
			relative, err := filepath.Rel(target, path)
			if err != nil {
				return err
			}
			return writeAIInfraGuardZipFile(writer, path, filepath.ToSlash(relative), fileInfo)
		})
	} else if info.Mode().IsRegular() {
		err = writeAIInfraGuardZipFile(writer, target, filepath.Base(target), info)
	} else {
		err = fmt.Errorf("AI-Infra-Guard scanner supports regular file or directory targets in v1")
	}
	if closeErr := writer.Close(); closeErr != nil && err == nil {
		err = closeErr
	}
	return body.Bytes(), err
}

func writeAIInfraGuardZipFile(writer *zip.Writer, source string, name string, info os.FileInfo) error {
	header, err := zip.FileInfoHeader(info)
	if err != nil {
		return err
	}
	header.Name = name
	header.Method = zip.Deflate
	header.Modified = time.Unix(0, 0).UTC()
	fileWriter, err := writer.CreateHeader(header)
	if err != nil {
		return err
	}
	file, err := os.Open(source)
	if err != nil {
		return err
	}
	defer file.Close()
	_, err = io.Copy(fileWriter, file)
	return err
}

func aiInfraGuardURL(baseURL string, path string) string {
	return strings.TrimRight(baseURL, "/") + path
}

func aiInfraGuardUsername(env map[string]string) string {
	username := strings.TrimSpace(env["AIG_USERNAME"])
	if username == "" {
		return aiInfraGuardDefaultUsername
	}
	return username
}

func aiInfraGuardLanguage(env map[string]string) string {
	language := strings.TrimSpace(env["AIG_SCAN_LANGUAGE"])
	if language == "" {
		return aiInfraGuardDefaultLanguage
	}
	return language
}

func aiInfraGuardScanPrompt(env map[string]string) string {
	prompt := strings.TrimSpace(env["AIG_SCAN_PROMPT"])
	if prompt == "" {
		return aiInfraGuardDefaultPrompt
	}
	return prompt
}

func aiInfraGuardThreadCount(env map[string]string) int {
	return positiveEnvInt(env, "AIG_SCAN_THREAD_COUNT", aiInfraGuardDefaultThreadCount)
}

func aiInfraGuardPollInterval(env map[string]string) time.Duration {
	ms := positiveEnvInt(env, "AIG_POLL_INTERVAL_MS", 3000)
	return time.Duration(ms) * time.Millisecond
}

func aiInfraGuardPollMaxAttempts(env map[string]string, timeout time.Duration, interval time.Duration) int {
	if value := positiveEnvInt(env, "AIG_POLL_MAX_ATTEMPTS", 0); value > 0 {
		return value
	}
	if timeout <= 0 {
		timeout = 20 * time.Minute
	}
	if interval <= 0 {
		return 1
	}
	return int(timeout/interval) + 1
}

func positiveEnvInt(env map[string]string, key string, fallback int) int {
	value, err := strconv.Atoi(strings.TrimSpace(env[key]))
	if err != nil || value < 0 {
		return fallback
	}
	return value
}

func aiInfraGuardStatusCompleted(status string) bool {
	switch strings.ToLower(strings.TrimSpace(status)) {
	case "completed", "done":
		return true
	default:
		return false
	}
}

func aiInfraGuardStatusFailed(status string) bool {
	switch strings.ToLower(strings.TrimSpace(status)) {
	case "failed", "error", "terminated":
		return true
	default:
		return false
	}
}

func redactRawJSON(raw []byte, env map[string]string) json.RawMessage {
	if len(raw) == 0 || !json.Valid(raw) {
		return nil
	}
	var value any
	if err := json.Unmarshal(raw, &value); err != nil {
		return json.RawMessage(raw)
	}
	redacted, err := json.Marshal(redactJudgeResult(value, env))
	if err != nil {
		return json.RawMessage(raw)
	}
	return json.RawMessage(redacted)
}

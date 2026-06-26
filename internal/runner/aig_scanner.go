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
	aigDefaultBaseURL     = "http://localhost:8088"
	aigDefaultLanguage    = "en"
	aigDefaultPrompt      = "Audit this AI tool / skill project"
	aigDefaultThreadCount = 4
	aigDefaultUsername    = "openclaw"
	aigTaskType           = "mcp_scan"
)

type AIInfraGuardHTTPClient interface {
	Do(request *http.Request) (*http.Response, error)
}

type aigAPIEnvelope struct {
	Status  int             `json:"status"`
	Message string          `json:"message"`
	Data    json.RawMessage `json:"data"`
}

type aigUploadData struct {
	FileURL  string `json:"fileUrl"`
	Filename string `json:"filename"`
	Size     int64  `json:"size"`
}

type aigTaskData struct {
	SessionID string `json:"session_id"`
}

type aigStatusData struct {
	SessionID string `json:"session_id"`
	Status    string `json:"status"`
	Title     string `json:"title,omitempty"`
	Log       string `json:"log,omitempty"`
	CreatedAt int64  `json:"created_at,omitempty"`
	UpdatedAt int64  `json:"updated_at,omitempty"`
}

type aigRawEvidence struct {
	Scanner string          `json:"scanner"`
	Upload  *aigUploadData  `json:"upload,omitempty"`
	Task    aigTaskData     `json:"task"`
	Status  aigStatusData   `json:"status"`
	Result  json.RawMessage `json:"result,omitempty"`
}

func (runner ExternalScannerRunner) runAIG(target string, startedAt string) (ScannerResult, error) {
	completedAt := func() string {
		return time.Now().UTC().Format(time.RFC3339Nano)
	}
	command := []string{"aig", "taskapi", aigTaskType}
	timeout := runner.Timeout
	if timeout == 0 {
		timeout = 20 * time.Minute
	}
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	client := runner.AIInfraGuardHTTPClient
	if client == nil {
		client = http.DefaultClient
	}

	var upload *aigUploadData
	prompt := target
	if !isURLTarget(target) {
		archive, err := buildAIGArchive(target)
		if err != nil {
			return ScannerResult{}, err
		}
		data, raw, message, err := runner.aigUpload(ctx, client, archive, filepath.Base(target)+".zip")
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
		prompt = aigScanPrompt(runner.Env)
	}

	task, raw, message, err := runner.aigCreateMCPTask(ctx, client, prompt, upload)
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

	status, raw, message, err := runner.aigWaitForTask(ctx, client, task.SessionID)
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
	if !aigStatusCompleted(status.Status) {
		raw, err := json.Marshal(aigRawEvidence{
			Scanner: "aig",
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

	result, raw, message, err := runner.aigTaskResult(ctx, client, task.SessionID)
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
	evidence, err := json.Marshal(aigRawEvidence{
		Scanner: "aig",
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

func (runner ExternalScannerRunner) aigUpload(ctx context.Context, client AIInfraGuardHTTPClient, archive []byte, filename string) (aigUploadData, json.RawMessage, string, error) {
	var body bytes.Buffer
	writer := multipart.NewWriter(&body)
	part, err := writer.CreateFormFile("file", filename)
	if err != nil {
		return aigUploadData{}, nil, "", err
	}
	if _, err := part.Write(archive); err != nil {
		return aigUploadData{}, nil, "", err
	}
	if err := writer.Close(); err != nil {
		return aigUploadData{}, nil, "", err
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, aigURL(runner.Env, "/api/v1/app/taskapi/upload"), &body)
	if err != nil {
		return aigUploadData{}, nil, "", err
	}
	runner.setAIGHeaders(request, writer.FormDataContentType())
	data, raw, message, err := runner.aigDo(request, client)
	if err != nil {
		return aigUploadData{}, raw, "AI-Infra-Guard upload failed: " + message, err
	}
	var upload aigUploadData
	if err := json.Unmarshal(data, &upload); err != nil {
		return aigUploadData{}, raw, "AI-Infra-Guard upload returned unexpected JSON.", err
	}
	if strings.TrimSpace(upload.FileURL) == "" {
		return aigUploadData{}, raw, "AI-Infra-Guard upload response did not include fileUrl.", fmt.Errorf("missing fileUrl")
	}
	return upload, raw, "", nil
}

func (runner ExternalScannerRunner) aigCreateMCPTask(ctx context.Context, client AIInfraGuardHTTPClient, prompt string, upload *aigUploadData) (aigTaskData, json.RawMessage, string, error) {
	content := map[string]any{
		"prompt":   prompt,
		"thread":   aigThreadCount(runner.Env),
		"language": aigLanguage(runner.Env),
	}
	if model := aigModel(runner.Env); len(model) > 0 {
		content["model"] = model
	}
	if upload != nil {
		content["attachments"] = upload.FileURL
	}
	payload := map[string]any{
		"type":    aigTaskType,
		"content": content,
	}
	body, err := json.Marshal(payload)
	if err != nil {
		return aigTaskData{}, nil, "", err
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, aigURL(runner.Env, "/api/v1/app/taskapi/tasks"), bytes.NewReader(body))
	if err != nil {
		return aigTaskData{}, nil, "", err
	}
	runner.setAIGHeaders(request, "application/json")
	data, raw, message, err := runner.aigDo(request, client)
	if err != nil {
		return aigTaskData{}, raw, "AI-Infra-Guard task creation failed: " + message, err
	}
	var task aigTaskData
	if err := json.Unmarshal(data, &task); err != nil {
		return aigTaskData{}, raw, "AI-Infra-Guard task creation returned unexpected JSON.", err
	}
	if strings.TrimSpace(task.SessionID) == "" {
		return aigTaskData{}, raw, "AI-Infra-Guard task creation response did not include session_id.", fmt.Errorf("missing session_id")
	}
	return task, raw, "", nil
}

func (runner ExternalScannerRunner) aigWaitForTask(ctx context.Context, client AIInfraGuardHTTPClient, sessionID string) (aigStatusData, json.RawMessage, string, error) {
	interval := aigPollInterval(runner.Env)
	attempts := aigPollMaxAttempts(runner.Env, runner.Timeout, interval)
	var lastRaw json.RawMessage
	var lastStatus aigStatusData
	for attempt := 0; attempt < attempts; attempt++ {
		status, raw, message, err := runner.aigTaskStatus(ctx, client, sessionID)
		lastRaw = raw
		lastStatus = status
		if err != nil {
			return aigStatusData{}, raw, message, err
		}
		if aigStatusCompleted(status.Status) || aigStatusFailed(status.Status) {
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

func (runner ExternalScannerRunner) aigTaskStatus(ctx context.Context, client AIInfraGuardHTTPClient, sessionID string) (aigStatusData, json.RawMessage, string, error) {
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, aigURL(runner.Env, "/api/v1/app/taskapi/status/"+url.PathEscape(sessionID)), nil)
	if err != nil {
		return aigStatusData{}, nil, "", err
	}
	runner.setAIGHeaders(request, "")
	data, raw, message, err := runner.aigDo(request, client)
	if err != nil {
		return aigStatusData{}, raw, "AI-Infra-Guard task status failed: " + message, err
	}
	var status aigStatusData
	if err := json.Unmarshal(data, &status); err != nil {
		return aigStatusData{}, raw, "AI-Infra-Guard task status returned unexpected JSON.", err
	}
	return status, raw, "", nil
}

func (runner ExternalScannerRunner) aigTaskResult(ctx context.Context, client AIInfraGuardHTTPClient, sessionID string) (json.RawMessage, json.RawMessage, string, error) {
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, aigURL(runner.Env, "/api/v1/app/taskapi/result/"+url.PathEscape(sessionID)), nil)
	if err != nil {
		return nil, nil, "", err
	}
	runner.setAIGHeaders(request, "")
	data, raw, message, err := runner.aigDo(request, client)
	if err != nil {
		return nil, raw, "AI-Infra-Guard task result failed: " + message, err
	}
	return data, raw, "", nil
}

func (runner ExternalScannerRunner) aigDo(request *http.Request, client AIInfraGuardHTTPClient) (json.RawMessage, json.RawMessage, string, error) {
	response, err := client.Do(request)
	if err != nil {
		return nil, nil, redactEnvValues(err.Error(), runner.Env), err
	}
	defer response.Body.Close()
	body, err := io.ReadAll(response.Body)
	if err != nil {
		return nil, nil, "", err
	}
	if !json.Valid(body) {
		return nil, nil, fmt.Sprintf("HTTP %d with non-JSON response.", response.StatusCode), fmt.Errorf("non-JSON response")
	}
	raw := redactAIGJSON(body, runner.Env)
	if response.StatusCode < 200 || response.StatusCode > 299 {
		return nil, raw, fmt.Sprintf("HTTP %d.", response.StatusCode), fmt.Errorf("http %d", response.StatusCode)
	}
	var envelope aigAPIEnvelope
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
	return redactAIGJSON(envelope.Data, runner.Env), raw, "", nil
}

func (runner ExternalScannerRunner) setAIGHeaders(request *http.Request, contentType string) {
	if contentType != "" {
		request.Header.Set("content-type", contentType)
	}
	request.Header.Set("accept", "application/json")
	request.Header.Set("username", aigUsername(runner.Env))
	if apiKey := strings.TrimSpace(runner.Env["AIG_API_KEY"]); apiKey != "" {
		request.Header.Set("API-KEY", apiKey)
	}
}

func buildAIGArchive(target string) ([]byte, error) {
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
			return writeAIGZipFile(writer, path, filepath.ToSlash(relative), fileInfo)
		})
	} else if info.Mode().IsRegular() {
		err = writeAIGZipFile(writer, target, filepath.Base(target), info)
	} else {
		err = fmt.Errorf("AI-Infra-Guard scanner supports regular file or directory targets")
	}
	if closeErr := writer.Close(); closeErr != nil && err == nil {
		err = closeErr
	}
	return body.Bytes(), err
}

func writeAIGZipFile(writer *zip.Writer, source string, name string, info os.FileInfo) error {
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

func aigBaseURL(env map[string]string) string {
	baseURL := strings.TrimSpace(env["AIG_BASE_URL"])
	if baseURL == "" {
		return aigDefaultBaseURL
	}
	return strings.TrimRight(baseURL, "/")
}

func aigURL(env map[string]string, path string) string {
	return aigBaseURL(env) + path
}

func aigUsername(env map[string]string) string {
	username := strings.TrimSpace(env["AIG_USERNAME"])
	if username == "" {
		return aigDefaultUsername
	}
	return username
}

func aigLanguage(env map[string]string) string {
	language := strings.TrimSpace(env["AIG_SCAN_LANGUAGE"])
	if language == "" {
		return aigDefaultLanguage
	}
	return language
}

func aigScanPrompt(env map[string]string) string {
	prompt := strings.TrimSpace(env["AIG_SCAN_PROMPT"])
	if prompt == "" {
		return aigDefaultPrompt
	}
	return prompt
}

func aigModel(env map[string]string) map[string]string {
	model := map[string]string{}
	if value := strings.TrimSpace(env["AIG_MODEL"]); value != "" {
		model["model"] = value
	}
	if value := strings.TrimSpace(env["AIG_MODEL_API_KEY"]); value != "" {
		model["token"] = value
	}
	if value := strings.TrimSpace(env["AIG_MODEL_BASE_URL"]); value != "" {
		model["base_url"] = value
	}
	return model
}

func aigThreadCount(env map[string]string) int {
	return positiveEnvInt(env, "AIG_SCAN_THREAD_COUNT", aigDefaultThreadCount)
}

func aigPollInterval(env map[string]string) time.Duration {
	ms := positiveEnvInt(env, "AIG_POLL_INTERVAL_MS", 3000)
	return time.Duration(ms) * time.Millisecond
}

func aigPollMaxAttempts(env map[string]string, timeout time.Duration, interval time.Duration) int {
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

func aigStatusCompleted(status string) bool {
	switch strings.ToLower(strings.TrimSpace(status)) {
	case "completed", "done":
		return true
	default:
		return false
	}
}

func aigStatusFailed(status string) bool {
	switch strings.ToLower(strings.TrimSpace(status)) {
	case "failed", "error", "terminated":
		return true
	default:
		return false
	}
}

func redactAIGJSON(raw []byte, env map[string]string) json.RawMessage {
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

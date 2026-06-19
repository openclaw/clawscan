package runner

import (
	"archive/zip"
	"bytes"
	"encoding/json"
	"io"
	"mime"
	"mime/multipart"
	"net/http"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func TestParseArgsAcceptsAIInfraGuardScanner(t *testing.T) {
	opts, err := ParseArgs([]string{"./my-skill", "--scanner", "ai-infra-guard"})
	if err != nil {
		t.Fatal(err)
	}
	if got := strings.Join(opts.Scanners, ","); got != "ai-infra-guard" {
		t.Fatalf("scanners = %q", got)
	}
}

func TestValidateRequirementsRequiresAIInfraGuardEnv(t *testing.T) {
	opts, err := ParseArgs([]string{"./my-skill", "--scanner", "ai-infra-guard"})
	if err != nil {
		t.Fatal(err)
	}
	err = ValidateRequirements(opts, map[string]string{
		"AIG_BASE_URL":      "http://127.0.0.1:8088",
		"AIG_MODEL_API_KEY": "secret-aig-model-key",
	})
	if err == nil {
		t.Fatal("expected missing env error")
	}
	for _, want := range []string{
		"AIG_MODEL required by scanner ai-infra-guard",
	} {
		if !strings.Contains(err.Error(), want) {
			t.Fatalf("err missing %q:\n%s", want, err)
		}
	}
	if strings.Contains(err.Error(), "secret-aig-model-key") {
		t.Fatalf("error leaked secret: %s", err)
	}
}

func TestValidateRequirementsSkipsAIInfraGuardFixtureCredentials(t *testing.T) {
	opts, err := ParseArgs([]string{
		"./my-skill",
		"--scanner", "ai-infra-guard",
		"--scanner-result", "ai-infra-guard=./aig.json",
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := ValidateRequirements(opts, map[string]string{}); err != nil {
		t.Fatalf("expected fixture-backed scanner to avoid live credentials, got %v", err)
	}
}

func TestAIInfraGuardScannerCompletesLocalArchiveFlow(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "skill")
	if err := os.Mkdir(target, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(target, "SKILL.md"), []byte("# Demo\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	client := &aiInfraGuardRecordingHTTPClient{
		responses: []*http.Response{
			jsonResponse(http.StatusOK, `{"status":0,"message":"ok","data":{"fileUrl":"/uploads/demo.zip","filename":"demo.zip","size":123}}`),
			jsonResponse(http.StatusOK, `{"status":0,"message":"task created successfully","data":{"session_id":"session-123"}}`),
			jsonResponse(http.StatusOK, `{"status":0,"message":"ok","data":{"session_id":"session-123","status":"completed","title":"MCP Scan Task","log":"done"}}`),
			jsonResponse(http.StatusOK, `{"status":0,"message":"ok","data":{"result":{"score":91,"results":[{"severity":"low","title":"demo"}]}}}`),
		},
	}
	opts, err := ParseArgs([]string{target, "--scanner", "ai-infra-guard"})
	if err != nil {
		t.Fatal(err)
	}
	artifact, err := Run(opts, RunContext{
		Env: map[string]string{
			"AIG_BASE_URL":          "http://aig.local",
			"AIG_API_KEY":           "secret-aig-api-key",
			"AIG_MODEL":             "gpt-4.1",
			"AIG_MODEL_API_KEY":     "secret-aig-model-key",
			"AIG_MODEL_BASE_URL":    "https://api.openai.com/v1",
			"AIG_USERNAME":          "openclaw-test",
			"AIG_POLL_INTERVAL_MS":  "0",
			"AIG_POLL_MAX_ATTEMPTS": "1",
			"AIG_SCAN_LANGUAGE":     "en",
			"AIG_SCAN_PROMPT":       "Audit this skill",
			"AIG_SCAN_THREAD_COUNT": "2",
		},
		AIInfraGuardHTTPClient: client,
	})
	if err != nil {
		t.Fatal(err)
	}
	result := artifact.Scanners["ai-infra-guard"]
	if result.Status != "completed" {
		t.Fatalf("status = %q error = %q", result.Status, result.Error)
	}
	if strings.Contains(result.Error, "foundation slice") {
		t.Fatalf("generic foundation skip leaked through: %q", result.Error)
	}
	if strings.Contains(string(result.Raw), "secret-aig-model-key") || strings.Contains(string(result.Raw), "secret-aig-api-key") {
		t.Fatalf("raw leaked secret: %s", result.Raw)
	}
	if len(client.requests) != 4 {
		t.Fatalf("requests = %d", len(client.requests))
	}
	upload := client.requests[0]
	if upload.Method != http.MethodPost || upload.URL.String() != "http://aig.local/api/v1/app/taskapi/upload" {
		t.Fatalf("upload request = %s %s", upload.Method, upload.URL.String())
	}
	if got := upload.Header.Get("API-KEY"); got != "secret-aig-api-key" {
		t.Fatalf("API-KEY header = %q", got)
	}
	if got := upload.Header.Get("username"); got != "openclaw-test" {
		t.Fatalf("username header = %q", got)
	}
	_, params, err := mime.ParseMediaType(upload.Header.Get("content-type"))
	if err != nil {
		t.Fatal(err)
	}
	reader := multipartReader(t, client.bodies[0], params["boundary"])
	file, err := reader.NextPart()
	if err != nil {
		t.Fatal(err)
	}
	archive, err := io.ReadAll(file)
	if err != nil {
		t.Fatal(err)
	}
	zipReader, err := zip.NewReader(bytes.NewReader(archive), int64(len(archive)))
	if err != nil {
		t.Fatal(err)
	}
	if !zipArchiveContains(zipReader, "SKILL.md") {
		t.Fatalf("zip did not contain SKILL.md")
	}

	create := client.requests[1]
	if create.Method != http.MethodPost || create.URL.String() != "http://aig.local/api/v1/app/taskapi/tasks" {
		t.Fatalf("create request = %s %s", create.Method, create.URL.String())
	}
	var task struct {
		Type    string `json:"type"`
		Content struct {
			Prompt      string `json:"prompt"`
			Attachments string `json:"attachments"`
			Thread      int    `json:"thread"`
			Language    string `json:"language"`
			Model       struct {
				Model   string `json:"model"`
				Token   string `json:"token"`
				BaseURL string `json:"base_url"`
			} `json:"model"`
		} `json:"content"`
	}
	if err := json.Unmarshal(client.bodies[1], &task); err != nil {
		t.Fatal(err)
	}
	if task.Type != "mcp_scan" {
		t.Fatalf("task type = %q", task.Type)
	}
	if task.Content.Attachments != "/uploads/demo.zip" {
		t.Fatalf("attachments = %q", task.Content.Attachments)
	}
	if task.Content.Prompt != "Audit this skill" || task.Content.Language != "en" || task.Content.Thread != 2 {
		t.Fatalf("task content = %#v", task.Content)
	}
	if task.Content.Model.Model != "gpt-4.1" || task.Content.Model.Token != "secret-aig-model-key" || task.Content.Model.BaseURL != "https://api.openai.com/v1" {
		t.Fatalf("model = %#v", task.Content.Model)
	}

	var raw struct {
		Task struct {
			SessionID string `json:"session_id"`
		} `json:"task"`
		Status struct {
			Status string `json:"status"`
		} `json:"status"`
		Result map[string]any `json:"result"`
	}
	if err := json.Unmarshal(result.Raw, &raw); err != nil {
		t.Fatal(err)
	}
	if raw.Task.SessionID != "session-123" || raw.Status.Status != "completed" {
		t.Fatalf("raw = %s", result.Raw)
	}
	if _, ok := raw.Result["result"]; !ok {
		t.Fatalf("raw result missing scan payload: %s", result.Raw)
	}
	if artifact.Env["AIG_BASE_URL"] != "present" || artifact.Env["AIG_MODEL"] != "present" || artifact.Env["AIG_MODEL_API_KEY"] != "present" {
		t.Fatalf("env presence = %#v", artifact.Env)
	}
}

func TestAIInfraGuardScannerCompletesURLFlowWithoutUpload(t *testing.T) {
	target := "https://github.com/example/skill-repo"
	client := &aiInfraGuardRecordingHTTPClient{
		responses: []*http.Response{
			jsonResponse(http.StatusOK, `{"status":0,"message":"task created successfully","data":{"session_id":"session-url"}}`),
			jsonResponse(http.StatusOK, `{"status":0,"message":"ok","data":{"session_id":"session-url","status":"completed"}}`),
			jsonResponse(http.StatusOK, `{"status":0,"message":"ok","data":{"result":{"score":100}}}`),
		},
	}
	opts, err := ParseArgs([]string{target, "--scanner", "ai-infra-guard"})
	if err != nil {
		t.Fatal(err)
	}
	artifact, err := Run(opts, RunContext{
		Env: map[string]string{
			"AIG_BASE_URL":          "http://aig.local/",
			"AIG_MODEL":             "gpt-4.1",
			"AIG_MODEL_API_KEY":     "secret-aig-model-key",
			"AIG_POLL_INTERVAL_MS":  "0",
			"AIG_POLL_MAX_ATTEMPTS": "1",
		},
		AIInfraGuardHTTPClient: client,
	})
	if err != nil {
		t.Fatal(err)
	}
	result := artifact.Scanners["ai-infra-guard"]
	if result.Status != "completed" {
		t.Fatalf("status = %q error = %q", result.Status, result.Error)
	}
	if len(client.requests) != 3 {
		t.Fatalf("requests = %d", len(client.requests))
	}
	var task struct {
		Type    string `json:"type"`
		Content struct {
			Prompt      string `json:"prompt"`
			Attachments string `json:"attachments,omitempty"`
		} `json:"content"`
	}
	if err := json.Unmarshal(client.bodies[0], &task); err != nil {
		t.Fatal(err)
	}
	if task.Type != "mcp_scan" || task.Content.Prompt != target || task.Content.Attachments != "" {
		t.Fatalf("task = %#v", task)
	}
}

func TestAIInfraGuardScannerFailsAPIErrorAndPreservesJSON(t *testing.T) {
	target := "https://github.com/example/skill-repo"
	const errorJSON = `{"status":1,"message":"invalid parameters: mcp_scan requires model.model and model.token","data":null}`
	client := &aiInfraGuardRecordingHTTPClient{
		responses: []*http.Response{jsonResponse(http.StatusOK, errorJSON)},
	}
	opts, err := ParseArgs([]string{target, "--scanner", "ai-infra-guard"})
	if err != nil {
		t.Fatal(err)
	}
	artifact, err := Run(opts, RunContext{
		Env: map[string]string{
			"AIG_BASE_URL":      "http://aig.local",
			"AIG_MODEL":         "gpt-4.1",
			"AIG_MODEL_API_KEY": "secret-aig-model-key",
		},
		AIInfraGuardHTTPClient: client,
	})
	if err != nil {
		t.Fatal(err)
	}
	result := artifact.Scanners["ai-infra-guard"]
	if result.Status != "failed" {
		t.Fatalf("status = %q error = %q", result.Status, result.Error)
	}
	if !strings.Contains(result.Error, "invalid parameters") {
		t.Fatalf("error = %q", result.Error)
	}
	if !jsonRawEqual(result.Raw, []byte(errorJSON)) {
		t.Fatalf("raw = %s", result.Raw)
	}
}

type aiInfraGuardRecordingHTTPClient struct {
	requests  []*http.Request
	bodies    [][]byte
	responses []*http.Response
	err       error
}

func (client *aiInfraGuardRecordingHTTPClient) Do(request *http.Request) (*http.Response, error) {
	client.requests = append(client.requests, request)
	var body []byte
	if request.Body != nil {
		var err error
		body, err = io.ReadAll(request.Body)
		if err != nil {
			return nil, err
		}
	}
	client.bodies = append(client.bodies, body)
	if client.err != nil {
		return nil, client.err
	}
	if len(client.responses) == 0 {
		return nil, errUnexpectedHTTPRequest
	}
	response := client.responses[0]
	client.responses = client.responses[1:]
	return response, nil
}

func jsonResponse(status int, body string) *http.Response {
	return &http.Response{
		StatusCode: status,
		Body:       io.NopCloser(strings.NewReader(body)),
	}
}

func multipartReader(t *testing.T, body []byte, boundary string) *multipart.Reader {
	t.Helper()
	if boundary == "" {
		t.Fatal("missing multipart boundary")
	}
	return multipart.NewReader(bytes.NewReader(body), boundary)
}

func zipArchiveContains(reader *zip.Reader, name string) bool {
	for _, file := range reader.File {
		if file.Name == name || strings.HasSuffix(file.Name, "/"+name) {
			return true
		}
	}
	return false
}

func jsonRawEqual(left []byte, right []byte) bool {
	var leftValue any
	var rightValue any
	if err := json.Unmarshal(left, &leftValue); err != nil {
		return false
	}
	if err := json.Unmarshal(right, &rightValue); err != nil {
		return false
	}
	return reflect.DeepEqual(leftValue, rightValue)
}

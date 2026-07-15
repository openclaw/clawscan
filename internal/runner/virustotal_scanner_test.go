package runner

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestRunExecutesVirusTotalScannerForSingleFile(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "SKILL.md")
	if err := os.WriteFile(target, []byte("# Demo\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	const apiKey = "test-vt-secret"
	expectedSHA, err := fileSHA256Hex(target)
	if err != nil {
		t.Fatal(err)
	}
	vtJSON := `{"data":{"id":"` + expectedSHA + `","type":"file","attributes":{"last_analysis_stats":{"malicious":0,"suspicious":0,"undetected":72}}}}`
	client := &recordingHTTPClient{
		response: &http.Response{
			StatusCode: http.StatusOK,
			Body:       io.NopCloser(strings.NewReader(vtJSON)),
		},
	}
	opts, err := ParseArgs([]string{target, "--scanner", "virustotal"})
	if err != nil {
		t.Fatal(err)
	}
	artifact, err := Run(opts, RunContext{
		Env:                  map[string]string{"VIRUSTOTAL_API_KEY": apiKey},
		VirusTotalHTTPClient: client,
	})
	if err != nil {
		t.Fatal(err)
	}
	result := artifact.Scanners["virustotal"]
	if result.Status != "completed" {
		t.Fatalf("status = %q error = %q", result.Status, result.Error)
	}
	var analysis virusTotalNormalizedAnalysis
	if err := json.Unmarshal(result.Raw, &analysis); err != nil {
		t.Fatal(err)
	}
	if analysis.Status != "clean" || analysis.EngineStats == nil || analysis.EngineStats.Undetected != 72 {
		t.Fatalf("analysis = %#v raw = %s", analysis, result.Raw)
	}
	if len(client.requests) != 1 {
		t.Fatalf("requests = %#v", client.requests)
	}
	request := client.requests[0]
	if got := request.Header.Get("x-apikey"); got != apiKey {
		t.Fatalf("x-apikey = %q", got)
	}
	if !strings.HasSuffix(request.URL.Path, "/api/v3/files/"+expectedSHA) {
		t.Fatalf("path = %s", request.URL.Path)
	}
	if !containsArg(result.Command, "sha256:"+expectedSHA) {
		t.Fatalf("command = %#v", result.Command)
	}
	if !containsArg(result.Command, "file") {
		t.Fatalf("command = %#v", result.Command)
	}
	rawArtifact, err := marshalVirusTotalTestArtifact(artifact)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(rawArtifact, []byte(apiKey)) {
		t.Fatalf("artifact leaked API key: %s", rawArtifact)
	}
}

func TestVirusTotalScannerScansDirectoryTargetsAsSkillZip(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "skill")
	if err := os.Mkdir(target, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(target, "SKILL.md"), []byte("# Demo\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(target, "scripts"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(target, "scripts", "check.sh"), []byte("echo ok\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	zipBytes, err := buildVirusTotalSkillZip(target)
	if err != nil {
		t.Fatal(err)
	}
	expectedSHA := sha256BytesHex(zipBytes)
	vtJSON := `{"data":{"id":"` + expectedSHA + `","type":"file","attributes":{"last_analysis_stats":{"malicious":1,"suspicious":0,"harmless":3,"undetected":70}}}}`
	client := &recordingHTTPClient{
		response: &http.Response{
			StatusCode: http.StatusOK,
			Body:       io.NopCloser(strings.NewReader(vtJSON)),
		},
	}
	opts, err := ParseArgs([]string{target, "--scanner", "virustotal"})
	if err != nil {
		t.Fatal(err)
	}
	artifact, err := Run(opts, RunContext{
		Env:                  map[string]string{"VIRUSTOTAL_API_KEY": "test-vt-secret"},
		VirusTotalHTTPClient: client,
	})
	if err != nil {
		t.Fatal(err)
	}
	result := artifact.Scanners["virustotal"]
	if result.Status != "completed" {
		t.Fatalf("status = %q error = %q", result.Status, result.Error)
	}
	var analysis virusTotalNormalizedAnalysis
	if err := json.Unmarshal(result.Raw, &analysis); err != nil {
		t.Fatal(err)
	}
	if analysis.Status != "malicious" || analysis.EngineStats == nil || analysis.EngineStats.Malicious != 1 {
		t.Fatalf("analysis = %#v raw = %s", analysis, result.Raw)
	}
	if len(client.requests) != 1 {
		t.Fatalf("requests = %#v", client.requests)
	}
	if !strings.HasSuffix(client.requests[0].URL.Path, "/api/v3/files/"+expectedSHA) {
		t.Fatalf("path = %s", client.requests[0].URL.Path)
	}
	if !containsArg(result.Command, "skill-zip") || !containsArg(result.Command, "sha256:"+expectedSHA) {
		t.Fatalf("command = %#v", result.Command)
	}
}

func TestVirusTotalScannerSkipsURLTargets(t *testing.T) {
	target := "https://clawhub.ai/author/skill"
	client := &recordingHTTPClient{err: errUnexpectedHTTPRequest}
	opts, err := ParseArgs([]string{target, "--scanner", "virustotal"})
	if err != nil {
		t.Fatal(err)
	}
	artifact, err := Run(opts, RunContext{
		Env:                  map[string]string{"VIRUSTOTAL_API_KEY": "test-vt-secret"},
		VirusTotalHTTPClient: client,
	})
	if err != nil {
		t.Fatal(err)
	}
	result := artifact.Scanners["virustotal"]
	if result.Status != "skipped" {
		t.Fatalf("status = %q error = %q", result.Status, result.Error)
	}
	if !strings.Contains(result.Error, "URL targets are unsupported") {
		t.Fatalf("error = %q", result.Error)
	}
	if len(client.requests) != 0 {
		t.Fatalf("unexpected HTTP requests: %#v", client.requests)
	}
}

func TestVirusTotalScannerUploadsMissingReports(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "SKILL.md")
	if err := os.WriteFile(target, []byte("# Demo\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	client := &recordingHTTPClient{
		responses: []*http.Response{
			{
				StatusCode: http.StatusNotFound,
				Body:       io.NopCloser(strings.NewReader(`{"error":{"code":"NotFoundError","message":"File not found"}}`)),
			},
			{
				StatusCode: http.StatusOK,
				Body:       io.NopCloser(strings.NewReader(`{"data":{"id":"analysis-id","type":"analysis"}}`)),
			},
		},
	}
	opts, err := ParseArgs([]string{target, "--scanner", "virustotal"})
	if err != nil {
		t.Fatal(err)
	}
	artifact, err := Run(opts, RunContext{
		Env:                  map[string]string{"VIRUSTOTAL_API_KEY": "test-vt-secret"},
		VirusTotalHTTPClient: client,
	})
	if err != nil {
		t.Fatal(err)
	}
	result := artifact.Scanners["virustotal"]
	if result.Status != "completed" {
		t.Fatalf("status = %q error = %q", result.Status, result.Error)
	}
	var analysis virusTotalNormalizedAnalysis
	if err := json.Unmarshal(result.Raw, &analysis); err != nil {
		t.Fatal(err)
	}
	if analysis.Status != "pending" || analysis.Upload == nil || analysis.Upload.Status != "submitted" {
		t.Fatalf("analysis = %#v raw = %s", analysis, result.Raw)
	}
	if len(client.requests) != 2 {
		t.Fatalf("requests = %#v", client.requests)
	}
	if client.requests[0].Method != http.MethodGet || client.requests[1].Method != http.MethodPost {
		t.Fatalf("methods = %s %s", client.requests[0].Method, client.requests[1].Method)
	}
	if client.requests[1].URL.String() != virusTotalFilesEndpoint {
		t.Fatalf("upload url = %s", client.requests[1].URL.String())
	}
	if !containsArg(result.Command, "upload") {
		t.Fatalf("command = %#v", result.Command)
	}
}

func TestClawHubVirusTotalUploadLeavesPromptEvidenceNullLikeProduction(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "SKILL.md")
	if err := os.WriteFile(target, []byte("# Demo\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	client := &recordingHTTPClient{
		responses: []*http.Response{
			{
				StatusCode: http.StatusNotFound,
				Body:       io.NopCloser(strings.NewReader(`{"error":{"code":"NotFoundError"}}`)),
			},
			{
				StatusCode: http.StatusOK,
				Body:       io.NopCloser(strings.NewReader(`{"data":{"id":"analysis-id","type":"analysis"}}`)),
			},
		},
	}
	artifact, err := Run(Options{
		Target:   target,
		Profile:  "clawhub",
		Scanners: []string{"virustotal"},
		Sandbox:  SandboxOptions{Mode: SandboxModeOff},
	}, RunContext{
		Env:                  map[string]string{"VIRUSTOTAL_API_KEY": "test-vt-secret"},
		VirusTotalHTTPClient: client,
	})
	if err != nil {
		t.Fatal(err)
	}
	result := artifact.Scanners["virustotal"]
	if result.Status != "completed" || len(result.Raw) != 0 {
		t.Fatalf("result = %#v", result)
	}
	if !containsArg(result.Command, "upload") {
		t.Fatalf("command = %#v", result.Command)
	}
}

func TestVirusTotalScannerFailsAPIErrorsAndPreservesJSON(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "SKILL.md")
	if err := os.WriteFile(target, []byte("# Demo\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	const vtJSON = `{"error":{"code":"QuotaExceededError","message":"quota exceeded"}}`
	client := &recordingHTTPClient{
		response: &http.Response{
			StatusCode: http.StatusTooManyRequests,
			Body:       io.NopCloser(strings.NewReader(vtJSON)),
		},
	}
	opts, err := ParseArgs([]string{target, "--scanner", "virustotal"})
	if err != nil {
		t.Fatal(err)
	}
	artifact, err := Run(opts, RunContext{
		Env:                  map[string]string{"VIRUSTOTAL_API_KEY": "test-vt-secret"},
		VirusTotalHTTPClient: client,
	})
	if err != nil {
		t.Fatal(err)
	}
	result := artifact.Scanners["virustotal"]
	if result.Status != "failed" {
		t.Fatalf("status = %q error = %q", result.Status, result.Error)
	}
	if !strings.Contains(result.Error, "HTTP 429") {
		t.Fatalf("error = %q", result.Error)
	}
	if !bytes.Equal(result.Raw, []byte(vtJSON)) {
		t.Fatalf("raw = %s", result.Raw)
	}
}

type recordingHTTPClient struct {
	requests  []*http.Request
	response  *http.Response
	responses []*http.Response
	err       error
}

func (client *recordingHTTPClient) Do(request *http.Request) (*http.Response, error) {
	index := len(client.requests)
	client.requests = append(client.requests, request)
	if client.err != nil {
		return nil, client.err
	}
	if len(client.responses) > 0 {
		if index >= len(client.responses) {
			return nil, errUnexpectedHTTPRequest
		}
		return client.responses[index], nil
	}
	if client.response == nil {
		return nil, errUnexpectedHTTPRequest
	}
	return client.response, nil
}

func marshalVirusTotalTestArtifact(artifact Artifact) ([]byte, error) {
	return json.Marshal(artifact)
}

var errUnexpectedHTTPRequest = &unexpectedHTTPRequestError{}

type unexpectedHTTPRequestError struct{}

func (*unexpectedHTTPRequestError) Error() string {
	return "unexpected HTTP request"
}

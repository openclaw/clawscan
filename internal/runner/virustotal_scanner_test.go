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
	if !bytes.Equal(result.Raw, []byte(vtJSON)) {
		t.Fatalf("raw = %s", result.Raw)
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
	rawArtifact, err := marshalVirusTotalTestArtifact(artifact)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(rawArtifact, []byte(apiKey)) {
		t.Fatalf("artifact leaked API key: %s", rawArtifact)
	}
}

func TestVirusTotalScannerSkipsDirectoryTargets(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "skill")
	if err := os.Mkdir(target, 0o755); err != nil {
		t.Fatal(err)
	}
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
	if !strings.Contains(result.Error, "single-file targets") {
		t.Fatalf("error = %q", result.Error)
	}
	if strings.Contains(result.Error, "foundation slice") {
		t.Fatalf("generic foundation skip leaked through: %q", result.Error)
	}
	if len(client.requests) != 0 {
		t.Fatalf("unexpected HTTP requests: %#v", client.requests)
	}
}

func TestVirusTotalScannerSkipsMissingReportsAndPreservesJSON(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "SKILL.md")
	if err := os.WriteFile(target, []byte("# Demo\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	const vtJSON = `{"error":{"code":"NotFoundError","message":"File not found"}}`
	client := &recordingHTTPClient{
		response: &http.Response{
			StatusCode: http.StatusNotFound,
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
	if result.Status != "skipped" {
		t.Fatalf("status = %q error = %q", result.Status, result.Error)
	}
	if !strings.Contains(result.Error, "no file report") {
		t.Fatalf("error = %q", result.Error)
	}
	if !bytes.Equal(result.Raw, []byte(vtJSON)) {
		t.Fatalf("raw = %s", result.Raw)
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
	requests []*http.Request
	response *http.Response
	err      error
}

func (client *recordingHTTPClient) Do(request *http.Request) (*http.Response, error) {
	client.requests = append(client.requests, request)
	if client.err != nil {
		return nil, client.err
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

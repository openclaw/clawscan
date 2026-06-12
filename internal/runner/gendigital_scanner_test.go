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

func TestGenDigitalScannerCompletesWithJSONResponse(t *testing.T) {
	target := "https://clawhub.ai/author/skill"
	const genJSON = `{"status":"error","message":"Skill not found on ClawHub or failed to fetch metadata","skillName":"skill","author":"author"}`
	client := &genDigitalRecordingHTTPClient{
		response: &http.Response{
			StatusCode: http.StatusOK,
			Body:       io.NopCloser(strings.NewReader(genJSON)),
		},
	}
	opts, err := ParseArgs([]string{target, "--scanner", "gendigital"})
	if err != nil {
		t.Fatal(err)
	}
	artifact, err := Run(opts, RunContext{
		Env:                  map[string]string{},
		GenDigitalHTTPClient: client,
	})
	if err != nil {
		t.Fatal(err)
	}
	result := artifact.Scanners["gendigital"]
	if result.Status != "completed" {
		t.Fatalf("status = %q error = %q", result.Status, result.Error)
	}
	if !bytes.Equal(result.Raw, []byte(genJSON)) {
		t.Fatalf("raw = %s", result.Raw)
	}
	if len(client.requests) != 1 {
		t.Fatalf("requests = %#v", client.requests)
	}
	request := client.requests[0]
	if request.Method != http.MethodPost {
		t.Fatalf("method = %q", request.Method)
	}
	if request.URL.String() != genDigitalLookupEndpoint {
		t.Fatalf("url = %s", request.URL.String())
	}
	if got := request.Header.Get("content-type"); got != "application/json" {
		t.Fatalf("content-type = %q", got)
	}
	var body struct {
		SkillURL string `json:"skillUrl"`
	}
	if err := json.Unmarshal(client.bodies[0], &body); err != nil {
		t.Fatal(err)
	}
	if body.SkillURL != target {
		t.Fatalf("skillUrl = %q", body.SkillURL)
	}
	if len(artifact.Env) != 0 {
		t.Fatalf("unexpected env requirements: %#v", artifact.Env)
	}
	if strings.Contains(result.Error, "foundation slice") {
		t.Fatalf("generic foundation skip leaked through: %q", result.Error)
	}
}

func TestGenDigitalScannerFailsHTTPErrorAndPreservesJSON(t *testing.T) {
	target := "https://clawhub.ai/author/skill"
	const genJSON = `{"status":"error","message":"rate limited"}`
	client := &genDigitalRecordingHTTPClient{
		response: &http.Response{
			StatusCode: http.StatusTooManyRequests,
			Body:       io.NopCloser(strings.NewReader(genJSON)),
		},
	}
	opts, err := ParseArgs([]string{target, "--scanner", "gendigital"})
	if err != nil {
		t.Fatal(err)
	}
	artifact, err := Run(opts, RunContext{
		Env:                  map[string]string{},
		GenDigitalHTTPClient: client,
	})
	if err != nil {
		t.Fatal(err)
	}
	result := artifact.Scanners["gendigital"]
	if result.Status != "failed" {
		t.Fatalf("status = %q error = %q", result.Status, result.Error)
	}
	if !strings.Contains(result.Error, "HTTP 429") {
		t.Fatalf("error = %q", result.Error)
	}
	if !bytes.Equal(result.Raw, []byte(genJSON)) {
		t.Fatalf("raw = %s", result.Raw)
	}
}

func TestGenDigitalScannerSkipsLocalPathTargets(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "skill")
	if err := os.Mkdir(target, 0o755); err != nil {
		t.Fatal(err)
	}
	client := &genDigitalRecordingHTTPClient{err: errUnexpectedHTTPRequest}
	opts, err := ParseArgs([]string{target, "--scanner", "gendigital"})
	if err != nil {
		t.Fatal(err)
	}
	artifact, err := Run(opts, RunContext{
		Env:                  map[string]string{},
		GenDigitalHTTPClient: client,
	})
	if err != nil {
		t.Fatal(err)
	}
	result := artifact.Scanners["gendigital"]
	if result.Status != "skipped" {
		t.Fatalf("status = %q error = %q", result.Status, result.Error)
	}
	if !strings.Contains(result.Error, "Gen Digital v1 requires a ClawHub skill URL target") {
		t.Fatalf("error = %q", result.Error)
	}
	if strings.Contains(result.Error, "foundation slice") {
		t.Fatalf("generic foundation skip leaked through: %q", result.Error)
	}
	if len(client.requests) != 0 {
		t.Fatalf("unexpected HTTP requests: %#v", client.requests)
	}
}

func TestGenDigitalScannerSkipsNonClawHubURLTargets(t *testing.T) {
	target := "https://example.invalid/private-skill"
	client := &genDigitalRecordingHTTPClient{err: errUnexpectedHTTPRequest}
	opts, err := ParseArgs([]string{target, "--scanner", "gendigital"})
	if err != nil {
		t.Fatal(err)
	}
	artifact, err := Run(opts, RunContext{
		Env:                  map[string]string{},
		GenDigitalHTTPClient: client,
	})
	if err != nil {
		t.Fatal(err)
	}
	result := artifact.Scanners["gendigital"]
	if result.Status != "skipped" {
		t.Fatalf("status = %q error = %q", result.Status, result.Error)
	}
	if !strings.Contains(result.Error, "non-ClawHub URL targets are unsupported") {
		t.Fatalf("error = %q", result.Error)
	}
	if len(client.requests) != 0 {
		t.Fatalf("unexpected HTTP requests: %#v", client.requests)
	}
}

func TestGenDigitalScannerFailsSuccessWithInvalidJSON(t *testing.T) {
	target := "https://clawhub.ai/author/skill"
	client := &genDigitalRecordingHTTPClient{
		response: &http.Response{
			StatusCode: http.StatusOK,
			Body:       io.NopCloser(strings.NewReader("not json")),
		},
	}
	opts, err := ParseArgs([]string{target, "--scanner", "gendigital"})
	if err != nil {
		t.Fatal(err)
	}
	artifact, err := Run(opts, RunContext{
		Env:                  map[string]string{},
		GenDigitalHTTPClient: client,
	})
	if err != nil {
		t.Fatal(err)
	}
	result := artifact.Scanners["gendigital"]
	if result.Status != "failed" {
		t.Fatalf("status = %q error = %q", result.Status, result.Error)
	}
	if !strings.Contains(result.Error, "non-JSON response") {
		t.Fatalf("error = %q", result.Error)
	}
	if result.Raw != nil {
		t.Fatalf("raw = %s", result.Raw)
	}
}

func TestRunRecordsURLTargetWithoutResolvingAsFilePath(t *testing.T) {
	target := "https://clawhub.ai/author/skill"
	opts, err := ParseArgs([]string{target, "--scanner", "gendigital"})
	if err != nil {
		t.Fatal(err)
	}
	recorder := &targetRecordingScannerRunner{}
	artifact, err := Run(opts, RunContext{
		Env:           map[string]string{},
		ScannerRunner: recorder,
	})
	if err != nil {
		t.Fatal(err)
	}
	if artifact.Target.Kind != "url" {
		t.Fatalf("kind = %q", artifact.Target.Kind)
	}
	if artifact.Target.Input != target || artifact.Target.ResolvedPath != target {
		t.Fatalf("target = %#v", artifact.Target)
	}
	if recorder.target != target {
		t.Fatalf("scanner target = %q", recorder.target)
	}
}

type genDigitalRecordingHTTPClient struct {
	requests []*http.Request
	bodies   [][]byte
	response *http.Response
	err      error
}

func (client *genDigitalRecordingHTTPClient) Do(request *http.Request) (*http.Response, error) {
	client.requests = append(client.requests, request)
	body, err := io.ReadAll(request.Body)
	if err != nil {
		return nil, err
	}
	client.bodies = append(client.bodies, body)
	if client.err != nil {
		return nil, client.err
	}
	return client.response, nil
}

type targetRecordingScannerRunner struct {
	target string
}

func (runner *targetRecordingScannerRunner) RunScanner(name string, target string, startedAt string) (ScannerResult, error) {
	runner.target = target
	return ScannerResult{
		Status:      "skipped",
		StartedAt:   startedAt,
		CompletedAt: startedAt,
		Error:       "recorded target",
	}, nil
}

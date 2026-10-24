package main

import (
	"archive/zip"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/openclaw/clawscan/internal/runner"
)

type inertBenchmarkTransport func(*http.Request) (*http.Response, error)

func (transport inertBenchmarkTransport) RoundTrip(request *http.Request) (*http.Response, error) {
	return transport(request)
}

func installGeneratedBenchmarkHTTP(t *testing.T) {
	t.Helper()
	var archive bytes.Buffer
	writer := zip.NewWriter(&archive)
	for _, id := range []string{"first", "second", "third"} {
		file, err := writer.Create("benchmark_full_v1.0/" + id + "/SKILL.md")
		if err != nil {
			t.Fatal(err)
		}
		if _, err := io.WriteString(file, id+"\n"); err != nil {
			t.Fatal(err)
		}
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	previous := http.DefaultTransport
	http.DefaultTransport = inertBenchmarkTransport(func(request *http.Request) (*http.Response, error) {
		var body []byte
		switch {
		case request.URL.Host == "datasets-server.huggingface.co":
			body = []byte(`{"rows":[{"row":{"id":"first","skill_md_content":"first","clawscan_verdict":"clean"}},{"row":{"id":"second","skill_md_content":"second","clawscan_verdict":"clean"}},{"row":{"id":"third","skill_md_content":"third","clawscan_verdict":"clean"}}]}`)
		case strings.HasSuffix(request.URL.Path, ".jsonl"):
			body = []byte("{\"id\":\"first\",\"judgment\":\"normal\"}\n{\"id\":\"second\",\"judgment\":\"normal\"}\n{\"id\":\"third\",\"judgment\":\"normal\"}\n")
		case strings.HasSuffix(request.URL.Path, ".zip"):
			body = archive.Bytes()
		default:
			return nil, errors.New("unrecognized generated benchmark request")
		}
		return &http.Response{StatusCode: 200, Header: http.Header{}, Body: io.NopCloser(bytes.NewReader(body)), Request: request}, nil
	})
	t.Cleanup(func() { http.DefaultTransport = previous })
}

func TestBenchmarkCLIEmitsCanceledPriorCaseEvidence(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX inert command")
	}
	for _, dataset := range []string{"clawhub-security-signals", "SkillTrustBench"} {
		t.Run(dataset, func(t *testing.T) {
			root := t.TempDir()
			t.Setenv("HOME", root)
			t.Setenv("XDG_CACHE_HOME", root)
			installGeneratedBenchmarkHTTP(t)
			config := filepath.Join(root, "config.yml")
			content := "version: 1\nprofiles:\n  inert:\n    sandbox:\n      mode: off\n    scanners:\n      - id: generated\n        targets: [skill]\n        command: >-\n          if grep -q second {{target}}/SKILL.md; then printf '{\"verdict\":\"clean\"}'; exec sleep 2; fi; printf '{\"verdict\":\"clean\"}'\n"
			writeFile(t, config, content)
			output := filepath.Join(root, "result.json")
			caller, cancel := context.WithTimeout(context.Background(), 150*time.Millisecond)
			defer cancel()
			var runErr error
			stdout := captureStdout(t, func() {
				runErr = runContext(caller, []string{"benchmark", dataset, "--config", config, "--profile", "inert", "--json", "--output", output}, []string{"PATH=" + os.Getenv("PATH")})
			})
			if !errors.Is(runErr, context.DeadlineExceeded) {
				t.Fatalf("CLI lost operational deadline: %v", runErr)
			}
			var artifact runner.BenchmarkArtifact
			if err := json.Unmarshal([]byte(stdout), &artifact); err != nil || len(artifact.Cases) != 3 {
				t.Fatalf("CLI lost partial JSON: %v cases=%d", err, len(artifact.Cases))
			}
			if !artifact.Cases[0].Run.Complete || artifact.Cases[1].Run.Complete || artifact.Cases[2].Run.Scanners["generated"].Status != "not_started" {
				t.Fatal("CLI changed completed/partial/unstarted evidence")
			}
			stored, err := os.ReadFile(output)
			if err != nil || !bytes.Equal(stored, []byte(stdout)) {
				t.Fatalf("stdout and disk partial artifacts differ: %v", err)
			}
		})
	}
}

func TestBenchmarkCLIRequiredJudgeFailureIsOperational(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX inert command")
	}
	for _, dataset := range []string{"clawhub-security-signals", "SkillTrustBench"} {
		t.Run(dataset, func(t *testing.T) {
			root := t.TempDir()
			t.Setenv("HOME", root)
			t.Setenv("XDG_CACHE_HOME", root)
			installGeneratedBenchmarkHTTP(t)
			var runErr error
			stdout := captureStdout(t, func() {
				runErr = run([]string{"benchmark", dataset, "--scanner", "clawscan-static", "--sandbox", "off", "--judge", `printf '{"verdict":"clean"}'; exit 1`, "--json"}, nil)
			})
			var artifact runner.BenchmarkArtifact
			if runErr == nil || json.Unmarshal([]byte(stdout), &artifact) != nil || len(artifact.Cases) != 3 || artifact.Summary.Evaluation.Scored != 0 {
				t.Fatalf("CLI accepted or hid required failure: err=%v cases=%d summary=%+v", runErr, len(artifact.Cases), artifact.Summary.Evaluation)
			}
		})
	}
}

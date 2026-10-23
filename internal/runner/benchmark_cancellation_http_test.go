package runner

import (
	"context"
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"
)

type benchmarkTransport func(*http.Request) (*http.Response, error)

func (transport benchmarkTransport) RoundTrip(request *http.Request) (*http.Response, error) {
	return transport(request)
}

type cancelingHTTPBody struct {
	request *http.Request
	cancel  context.CancelFunc
	closed  bool
}

func (body *cancelingHTTPBody) Read([]byte) (int, error) {
	body.cancel()
	select {
	case <-body.request.Context().Done():
		return 0, body.request.Context().Err()
	case <-time.After(100 * time.Millisecond):
		return 0, errors.New("response body outlived caller cancellation")
	}
}

func (body *cancelingHTTPBody) Close() error {
	body.closed = true
	return nil
}

func TestRunBenchmarkCancelsIDAndArchiveHTTP(t *testing.T) {
	for _, stage := range []string{"ids", "archive"} {
		for _, stall := range []string{"headers", "body"} {
			t.Run(stage+"/"+stall, func(t *testing.T) {
				root := t.TempDir()
				t.Setenv("HOME", root)
				t.Setenv("XDG_CACHE_HOME", root)
				caller, cancel := context.WithCancel(context.Background())
				defer cancel()
				var body *cancelingHTTPBody
				transport := benchmarkTransport(func(request *http.Request) (*http.Response, error) {
					if request.URL.Path == "/rows" {
						return &http.Response{StatusCode: 200, Header: http.Header{}, Body: io.NopCloser(strings.NewReader("{\"id\":\"generated\",\"judgment\":\"normal\"}\n")), Request: request}, nil
					}
					if stall == "headers" {
						cancel()
						select {
						case <-request.Context().Done():
							return nil, request.Context().Err()
						case <-time.After(100 * time.Millisecond):
							return nil, errors.New("headers outlived caller cancellation")
						}
					}
					body = &cancelingHTTPBody{request: request, cancel: cancel}
					return &http.Response{StatusCode: 200, Header: http.Header{}, Body: body, Request: request}, nil
				})
				oldTransport := http.DefaultTransport
				http.DefaultTransport = transport
				t.Cleanup(func() { http.DefaultTransport = oldTransport })
				opts := benchmarkTestOptions(t, skillTrustBenchID, "", 0, 0, "")
				if stage == "ids" {
					opts.Benchmark.IDsSource = "https://inert.invalid/ids"
				}
				started := time.Now()
				_, err := RunBenchmark(opts, RunContext{Context: caller, Env: map[string]string{}, BenchmarkClient: HuggingFaceBenchmarkClient{HTTPClient: &http.Client{Transport: transport}, SkillTrustBenchRowsURL: "https://inert.invalid/rows", SkillTrustBenchArchiveURL: "https://inert.invalid/archive"}})
				if !errors.Is(err, context.Canceled) || time.Since(started) >= 90*time.Millisecond {
					t.Fatalf("%s request did not obey caller cancellation: %v elapsed=%s", stage, err, time.Since(started))
				}
				if stall == "body" && (body == nil || !body.closed) {
					t.Fatal("canceled body not closed")
				}
			})
		}
	}
}

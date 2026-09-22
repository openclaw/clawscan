package runner

import (
	"context"
	"errors"
	"math"
	"net/http"
	"net/http/httptest"
	"strconv"
	"sync/atomic"
	"testing"
	"time"
)

func TestHuggingFaceRowsBackoffAvoidsDurationOverflow(t *testing.T) {
	for _, tc := range []struct {
		header string
		want   time.Duration
	}{
		{"0", 0},
		{"3600", time.Hour},
		{"9223372036", 9223372036 * time.Second},
		{"9223372037", time.Duration(math.MaxInt64)},
		{strconv.FormatUint(math.MaxUint64, 10), time.Duration(math.MaxInt64)},
		{"18446744073709551616", time.Duration(math.MaxInt64)},
		{"-1", huggingFaceRowsRetryDelay},
		{"invalid", huggingFaceRowsRetryDelay},
		{"18446744073709551616invalid", huggingFaceRowsRetryDelay},
	} {
		t.Run(tc.header, func(t *testing.T) {
			if got := huggingFaceRowsBackoff(1, http.Header{"Retry-After": {tc.header}}); got != tc.want {
				t.Fatalf("backoff = %s, want %s", got, tc.want)
			}
		})
	}
}

func TestHuggingFaceRowsLongCooldownWaitsForDeadline(t *testing.T) {
	for _, header := range []string{"3600", "9223372037", time.Now().Add(time.Hour).UTC().Format(http.TimeFormat)} {
		t.Run(header, func(t *testing.T) {
			var requests atomic.Int32
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				requests.Add(1)
				w.Header().Set("Retry-After", header)
				w.WriteHeader(http.StatusTooManyRequests)
			}))
			defer server.Close()
			ctx, cancel := context.WithTimeout(context.Background(), 250*time.Millisecond)
			defer cancel()
			client := HuggingFaceBenchmarkClient{Endpoint: server.URL, Context: ctx}
			_, err := client.FetchOpenClawRows("OpenClaw/clawhub-security-signals", "eval_holdout", 0, 1)
			if !errors.Is(err, context.DeadlineExceeded) {
				t.Fatalf("fetch error = %v, want deadline exceeded", err)
			}
			if got := requests.Load(); got != 1 {
				t.Fatalf("requests = %d, want one request before deadline", got)
			}
		})
	}
}

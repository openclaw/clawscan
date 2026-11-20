// Package testutil provides helpers for ClawScan subprocess tests.
package testutil

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// CancelOnReady cancels the context once a child creates the returned file.
// A missing marker expires the deadline instead, so callers can distinguish it.
func CancelOnReady(t *testing.T) (context.Context, string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "ready")
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	done := make(chan struct{})
	go func() {
		defer close(done)
		ticker := time.NewTicker(10 * time.Millisecond)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				if _, err := os.Stat(path); err == nil {
					cancel()
					return
				}
			}
		}
	}()
	t.Cleanup(func() { cancel(); <-done })
	return ctx, path
}

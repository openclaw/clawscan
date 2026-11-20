package main

import (
	"io"
	"os"
	"strings"
	"testing"
)

func TestCaptureOutputDrainsLargeWrites(t *testing.T) {
	payload := strings.Repeat("large fixture output\n", 16*1024)
	errPayload := strings.Repeat("large diagnostic\n", 16*1024)
	stdout, stderr := captureOutput(t, func() {
		if _, err := io.WriteString(os.Stdout, payload); err != nil {
			t.Fatal(err)
		}
		if _, err := io.WriteString(os.Stderr, errPayload); err != nil {
			t.Fatal(err)
		}
	})
	if stdout != payload || stderr != errPayload {
		t.Fatalf("captured %d stdout and %d stderr bytes, want %d and %d", len(stdout), len(stderr), len(payload), len(errPayload))
	}
}

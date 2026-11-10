package main

import (
	"io"
	"os"
	"strings"
	"testing"
)

func TestCaptureStdoutDrainsLargeWrites(t *testing.T) {
	payload := strings.Repeat("large fixture output\n", 16*1024)
	got := captureStdout(t, func() {
		if _, err := io.WriteString(os.Stdout, payload); err != nil {
			t.Fatal(err)
		}
	})
	if got != payload {
		t.Fatalf("captured %d bytes, want %d", len(got), len(payload))
	}
}

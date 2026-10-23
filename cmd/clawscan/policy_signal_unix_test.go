//go:build darwin || linux

package main

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
	"testing"
	"time"
)

func TestPolicyOpenStdinRetainsDefaultSignalEscape(t *testing.T) {
	binary := filepath.Join(t.TempDir(), "clawscan")
	build := exec.Command("go", "build", "-buildvcs=false", "-o", binary, ".")
	build.Env = append(os.Environ(), "GOPROXY=off")
	if output, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build public CLI: %v\n%s", err, output)
	}
	for _, signals := range [][2]syscall.Signal{{syscall.SIGTERM, syscall.SIGINT}, {syscall.SIGINT, syscall.SIGTERM}} {
		t.Run(signals[0].String(), func(t *testing.T) {
			command := exec.Command(binary, "openclaw-install-policy")
			command.Dir = t.TempDir()
			command.Env = []string{"PATH=" + os.Getenv("PATH")}
			command.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
			input, err := command.StdinPipe()
			if err != nil {
				t.Fatal(err)
			}
			defer input.Close()
			if err := command.Start(); err != nil {
				t.Fatal(err)
			}
			done := make(chan error, 1)
			go func() { done <- command.Wait() }()
			waited := false
			defer func() {
				if !waited {
					command.Process.Kill()
					<-done
				}
				if err := syscall.Kill(-command.Process.Pid, 0); err != syscall.ESRCH {
					t.Errorf("owned policy process group still present: %v", err)
				}
			}()
			if _, err := input.Write(bytes.Repeat([]byte(" "), 128*1024)); err != nil {
				t.Fatal(err)
			}
			time.Sleep(100 * time.Millisecond)
			if err := command.Process.Signal(signals[0]); err != nil {
				t.Fatal(err)
			}
			select {
			case err := <-done:
				waited = true
				if err == nil {
					t.Fatal("interrupted policy request claimed success")
				}
				return
			case <-time.After(300 * time.Millisecond):
			}
			if err := command.Process.Signal(signals[1]); err != nil {
				t.Fatal(err)
			}
			select {
			case err := <-done:
				waited = true
				if err == nil {
					t.Fatal("repeated interrupt claimed success")
				}
			case <-time.After(2 * time.Second):
				t.Fatal("CLI swallowed repeated signals while stdin remained open")
			}
		})
	}
}

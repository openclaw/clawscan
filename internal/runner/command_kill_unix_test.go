//go:build !windows

package runner

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"
)

func TestDefaultCommandRunnerNaturalExitRacingDeadlineKeepsExitCode(t *testing.T) {
	if _, err := os.Stat("/bin/sh"); err != nil {
		t.Skip("needs /bin/sh")
	}

	natural := exec.CommandContext(context.Background(), "/bin/sh", "-c", "exit 7")
	naturalKiller := configureCommandTreeKill(natural)
	if err := natural.Run(); err == nil {
		t.Fatal("natural command unexpectedly succeeded")
	}
	if naturalKiller.killConfirmed(natural) {
		t.Fatal("natural exit was misclassified as a configured kill")
	}
	naturalKiller.release()

	killed := exec.CommandContext(context.Background(), "/bin/sh", "-c", "sleep 30")
	killedKiller := configureCommandTreeKill(killed)
	if err := killed.Start(); err != nil {
		t.Fatal(err)
	}
	if err := killedKiller.started(killed); err != nil {
		t.Fatal(err)
	}
	if err := killed.Cancel(); err != nil {
		t.Fatal(err)
	}
	if err := killed.Wait(); err == nil {
		t.Fatal("killed command unexpectedly succeeded")
	}
	if !killedKiller.killConfirmed(killed) {
		t.Fatal("configured SIGKILL was not confirmed by the wait status")
	}
	killedKiller.release()
}

func TestDefaultCommandRunnerReapsDetachedDaemonAfterNormalCompletion(t *testing.T) {
	if _, err := os.Stat("/bin/sh"); err != nil {
		t.Skip("needs /bin/sh")
	}
	// A scanner that completes normally can still have detached a daemon
	// that holds no pipes (redirected to /dev/null) but inherited scanner
	// credentials. Run returns immediately with success — and the private
	// process group must still be reaped on the way out.
	pidFile := filepath.Join(t.TempDir(), "daemon.pid")
	output, err := defaultCommandRunner{}.Run(
		"/bin/sh", []string{"-c", `echo '{}'; sleep 30 </dev/null >/dev/null 2>&1 & echo $! > ` + pidFile}, "", time.Minute)
	if err != nil {
		t.Fatalf("err = %v", err)
	}
	if output.ExitCode == nil || *output.ExitCode != 0 {
		t.Fatalf("exit code = %v, want 0", output.ExitCode)
	}
	pid, readErr := os.ReadFile(pidFile)
	if readErr != nil {
		t.Fatal(readErr)
	}
	daemonPid, atoiErr := strconv.Atoi(strings.TrimSpace(string(pid)))
	if atoiErr != nil || daemonPid <= 0 {
		t.Fatalf("bad daemon pid %q: %v", pid, atoiErr)
	}
	deadline := time.Now().Add(5 * time.Second)
	for syscall.Kill(daemonPid, 0) == nil {
		if time.Now().After(deadline) {
			_ = syscall.Kill(daemonPid, syscall.SIGKILL)
			t.Fatalf("detached daemon %d outlived the completed run", daemonPid)
		}
		time.Sleep(50 * time.Millisecond)
	}
}

func TestDefaultCommandRunnerWaitDelayExpiryKillsDescendantsAndSuppressesExit(t *testing.T) {
	if _, err := os.Stat("/bin/sh"); err != nil {
		t.Skip("needs /bin/sh")
	}
	// The command exits zero but leaves a background child holding the
	// stdout pipe. No timeout fires, so only WaitDelay unblocks Run — and
	// on that path the descendant must be killed (it inherited scanner
	// credentials) and the zero exit must not be recorded: pipe output
	// from a force-closed run must not pass as a completed scan.
	pidFile := filepath.Join(t.TempDir(), "child.pid")
	output, err := defaultCommandRunner{WaitDelay: 200 * time.Millisecond}.Run(
		"/bin/sh", []string{"-c", `echo '{}'; sleep 30 & echo $! > ` + pidFile}, "", time.Minute)
	if err == nil || !strings.Contains(err.Error(), "background processes") {
		t.Fatalf("err = %v, want wait-delay refusal", err)
	}
	if output.ExitCode != nil {
		t.Fatalf("wait-delay run recorded exit code %d; partial output could pass as a completed scan", *output.ExitCode)
	}
	pid, readErr := os.ReadFile(pidFile)
	if readErr != nil {
		t.Fatal(readErr)
	}
	childPid, atoiErr := strconv.Atoi(strings.TrimSpace(string(pid)))
	if atoiErr != nil || childPid <= 0 {
		t.Fatalf("bad child pid %q: %v", pid, atoiErr)
	}
	deadline := time.Now().Add(5 * time.Second)
	for syscall.Kill(childPid, 0) == nil {
		if time.Now().After(deadline) {
			_ = syscall.Kill(childPid, syscall.SIGKILL)
			t.Fatalf("descendant %d survived wait-delay cleanup", childPid)
		}
		time.Sleep(50 * time.Millisecond)
	}
}

func TestDefaultCommandRunnerWaitDelayExpiryWithNonzeroExitSuppressesExit(t *testing.T) {
	if _, err := os.Stat("/bin/sh"); err != nil {
		t.Skip("needs /bin/sh")
	}
	pidFile := filepath.Join(t.TempDir(), "child.pid")
	output, err := defaultCommandRunner{WaitDelay: 200 * time.Millisecond}.Run(
		"/bin/sh", []string{"-c", `echo '{}'; sleep 30 & echo $! > ` + pidFile + `; exit 3`}, "", time.Minute)
	if err == nil || !strings.Contains(err.Error(), "background processes") {
		t.Fatalf("err = %v, want wait-delay refusal", err)
	}
	if output.ExitCode != nil {
		t.Fatalf("wait-delay run recorded exit code %d; partial output could pass as a completed scan", *output.ExitCode)
	}
	pid, readErr := os.ReadFile(pidFile)
	if readErr != nil {
		t.Fatal(readErr)
	}
	childPid, atoiErr := strconv.Atoi(strings.TrimSpace(string(pid)))
	if atoiErr != nil || childPid <= 0 {
		t.Fatalf("bad child pid %q: %v", pid, atoiErr)
	}
	deadline := time.Now().Add(5 * time.Second)
	for syscall.Kill(childPid, 0) == nil {
		if time.Now().After(deadline) {
			_ = syscall.Kill(childPid, syscall.SIGKILL)
			t.Fatalf("descendant %d survived wait-delay cleanup", childPid)
		}
		time.Sleep(50 * time.Millisecond)
	}
}

//go:build !windows

package runner

import (
	"os/exec"
	"sync/atomic"
	"syscall"
)

// processTreeKiller makes timeout cancellation reach the whole process
// tree, not just the direct child. exec.CommandContext only kills the
// process it started; a user-defined command like `sleep 1h & wait` run
// through /bin/sh leaves grandchildren holding the stdout/stderr pipes,
// and cmd.Run would block on them long past the deadline. Each command
// gets its own process group, and Cancel signals the group.
type processTreeKiller struct {
	fired atomic.Bool
}

func configureCommandTreeKill(cmd *exec.Cmd) *processTreeKiller {
	killer := &processTreeKiller{}
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	cmd.Cancel = func() error {
		killer.fired.Store(true)
		if cmd.Process == nil {
			return nil
		}
		// Negative PID addresses the process group. Fall back to the
		// direct process if the group signal fails (already reaped).
		if err := syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL); err != nil {
			return cmd.Process.Kill()
		}
		return nil
	}
	return killer
}

// started is a post-Start hook; group membership is inherited via Setpgid,
// so there is nothing to do on Unix.
func (killer *processTreeKiller) started(*exec.Cmd) {}

// reapStragglers kills descendants still holding the output pipes after
// the direct child exited (WaitDelay expiry). The group is private to this
// command, so the signal cannot reach unrelated processes.
func (killer *processTreeKiller) reapStragglers(cmd *exec.Cmd) {
	if cmd.Process != nil {
		_ = syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
	}
}

// release frees platform resources; none are held on Unix.
func (killer *processTreeKiller) release() {}

// cancelFired reports whether the kill path actually ran. The caller uses
// this instead of re-reading ctx.Err() after Wait returns: a command that
// finished just before the deadline must not be reclassified as timed out
// by a context timer that fired while the goroutine was descheduled.
func (killer *processTreeKiller) cancelFired() bool { return killer.fired.Load() }

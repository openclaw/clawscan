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
	cmd   *exec.Cmd
	fired atomic.Bool
}

func configureCommandTreeKill(cmd *exec.Cmd) *processTreeKiller {
	killer := &processTreeKiller{cmd: cmd}
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
func (killer *processTreeKiller) started(*exec.Cmd) error { return nil }

// reapStragglers kills descendants still holding the output pipes after
// the direct child exited (WaitDelay expiry). The group is private to this
// command, so the signal cannot reach unrelated processes.
func (killer *processTreeKiller) reapStragglers(cmd *exec.Cmd) {
	killer.cmd = cmd
	killer.release()
}

// release reaps the private process group unconditionally. A scanner that
// completed normally can still have detached a daemon (`sleep 300
// </dev/null >/dev/null &`) that holds no pipes but inherited scanner
// credentials; nothing may outlive the run. The group is private to this
// command, so the signal cannot reach unrelated processes, and a dead
// group is a harmless ESRCH.
func (killer *processTreeKiller) release() {
	if killer.cmd != nil && killer.cmd.Process != nil {
		_ = syscall.Kill(-killer.cmd.Process.Pid, syscall.SIGKILL)
	}
}

// cancelFired reports whether the kill path actually ran. The caller uses
// this instead of re-reading ctx.Err() after Wait returns: a command that
// finished just before the deadline must not be reclassified as timed out
// by a context timer that fired while the goroutine was descheduled.
func (killer *processTreeKiller) cancelFired() bool { return killer.fired.Load() }

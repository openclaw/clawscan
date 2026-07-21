//go:build !windows

package runner

import (
	"os/exec"
	"syscall"
)

// configureCommandTreeKill makes timeout cancellation reach the whole
// process tree, not just the direct child. exec.CommandContext only kills
// the process it started; a user-defined command like `sleep 1h & wait`
// run through /bin/sh leaves grandchildren holding the stdout/stderr pipes,
// and cmd.Run would block on them long past the deadline. Each command gets
// its own process group, and Cancel signals the group.
func configureCommandTreeKill(cmd *exec.Cmd) {
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	cmd.Cancel = func() error {
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
}

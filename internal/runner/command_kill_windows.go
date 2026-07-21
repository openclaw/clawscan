//go:build windows

package runner

import (
	"os/exec"
	"strconv"
)

// configureCommandTreeKill makes timeout cancellation reach the whole
// process tree on Windows, where TerminateProcess kills only the direct
// child and cmd.exe descendants keep the stdout/stderr handles open.
// taskkill /T terminates the tree rooted at the child's PID.
func configureCommandTreeKill(cmd *exec.Cmd) {
	cmd.Cancel = func() error {
		if cmd.Process == nil {
			return nil
		}
		kill := exec.Command("taskkill", "/T", "/F", "/PID", strconv.Itoa(cmd.Process.Pid))
		if err := kill.Run(); err != nil {
			return cmd.Process.Kill()
		}
		return nil
	}
}

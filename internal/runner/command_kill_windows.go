//go:build windows

package runner

import (
	"os/exec"
	"sync/atomic"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

// processTreeKiller makes timeout cancellation reach the whole process
// tree on Windows. TerminateProcess kills only the direct child, and
// taskkill /T resolves the tree by parent PID at kill time — useless once
// the parent has already exited (WaitDelay expiry) because the PID is
// gone while grandchildren keep the pipes open. A Job Object survives the
// parent: every descendant stays in the job, and terminating the job
// kills them all regardless of the parent's state.
type processTreeKiller struct {
	job   windows.Handle
	fired atomic.Bool
}

func configureCommandTreeKill(cmd *exec.Cmd) *processTreeKiller {
	killer := &processTreeKiller{}
	if job, err := windows.CreateJobObject(nil, nil); err == nil {
		// Descendants die with the job handle even if ClawScan itself is
		// killed before running cancellation.
		info := windows.JOBOBJECT_EXTENDED_LIMIT_INFORMATION{
			BasicLimitInformation: windows.JOBOBJECT_BASIC_LIMIT_INFORMATION{
				LimitFlags: windows.JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE,
			},
		}
		if _, err := windows.SetInformationJobObject(job, windows.JobObjectExtendedLimitInformation,
			uintptr(unsafe.Pointer(&info)), uint32(unsafe.Sizeof(info))); err == nil {
			killer.job = job
		} else {
			_ = windows.CloseHandle(job)
		}
	}
	// CREATE_SUSPENDED closes the assignment race: the child cannot spawn
	// grandchildren outside the job before AssignProcessToJobObject runs.
	if killer.job != 0 {
		if cmd.SysProcAttr == nil {
			cmd.SysProcAttr = &syscall.SysProcAttr{}
		}
		cmd.SysProcAttr.CreationFlags |= windows.CREATE_SUSPENDED
	}
	cmd.Cancel = func() error {
		killer.fired.Store(true)
		if killer.job != 0 {
			if err := windows.TerminateJobObject(killer.job, 1); err == nil {
				return nil
			}
		}
		if cmd.Process == nil {
			return nil
		}
		return cmd.Process.Kill()
	}
	return killer
}

// started assigns the suspended child to the job, then resumes it. On any
// failure the child is resumed anyway (a running scan beats a hung one)
// and the job degrades to direct-process kill.
func (killer *processTreeKiller) started(cmd *exec.Cmd) {
	if cmd.Process == nil {
		return
	}
	pid := uint32(cmd.Process.Pid)
	if killer.job != 0 {
		if handle, err := windows.OpenProcess(windows.PROCESS_SET_QUOTA|windows.PROCESS_TERMINATE, false, pid); err == nil {
			_ = windows.AssignProcessToJobObject(killer.job, handle)
			_ = windows.CloseHandle(handle)
		}
	}
	resumeMainThread(pid)
}

// resumeMainThread resumes the CREATE_SUSPENDED child's initial thread.
func resumeMainThread(pid uint32) {
	snapshot, err := windows.CreateToolhelp32Snapshot(windows.TH32CS_SNAPTHREAD, 0)
	if err != nil {
		return
	}
	defer windows.CloseHandle(snapshot)
	var entry windows.ThreadEntry32
	entry.Size = uint32(unsafe.Sizeof(entry))
	for err := windows.Thread32First(snapshot, &entry); err == nil; err = windows.Thread32Next(snapshot, &entry) {
		if entry.OwnerProcessID != pid {
			continue
		}
		if thread, err := windows.OpenThread(windows.THREAD_SUSPEND_RESUME, false, entry.ThreadID); err == nil {
			_, _ = windows.ResumeThread(thread)
			_ = windows.CloseHandle(thread)
		}
	}
}

// reapStragglers kills descendants still holding the output pipes after
// the direct child exited (WaitDelay expiry). The job outlives the parent
// PID, so this reaches grandchildren taskkill /T no longer could.
func (killer *processTreeKiller) reapStragglers(cmd *exec.Cmd) {
	if killer.job != 0 {
		_ = windows.TerminateJobObject(killer.job, 1)
		return
	}
	if cmd.Process != nil {
		_ = cmd.Process.Kill()
	}
}

// release closes the job handle. KILL_ON_JOB_CLOSE also terminates any
// remaining members, so this doubles as last-resort cleanup.
func (killer *processTreeKiller) release() {
	if killer.job != 0 {
		_ = windows.CloseHandle(killer.job)
		killer.job = 0
	}
}

// cancelFired reports whether the kill path actually ran. The caller uses
// this instead of re-reading ctx.Err() after Wait returns: a command that
// finished just before the deadline must not be reclassified as timed out
// by a context timer that fired while the goroutine was descheduled.
func (killer *processTreeKiller) cancelFired() bool { return killer.fired.Load() }

//go:build unix

package nexttrace

import (
	"os"
	"os/exec"
	"syscall"
)

// configureProcessGroup puts the child in its own process group so the whole
// group can be terminated on timeout or cancellation.
func configureProcessGroup(cmd *exec.Cmd) {
	if cmd.SysProcAttr == nil {
		cmd.SysProcAttr = &syscall.SysProcAttr{}
	}
	cmd.SysProcAttr.Setpgid = true
}

// killProcessGroup sends SIGKILL to the child's entire process group. It is
// best-effort: an already-exited process is not an error.
func killProcessGroup(process *os.Process) error {
	if process == nil {
		return nil
	}
	if err := syscall.Kill(-process.Pid, syscall.SIGKILL); err == nil || err == syscall.ESRCH {
		return nil
	}
	// Fall back to killing the parent if the group signal failed.
	return process.Kill()
}

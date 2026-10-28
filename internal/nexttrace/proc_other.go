//go:build !unix

package nexttrace

import (
	"os"
	"os/exec"
)

// configureProcessGroup is a no-op on platforms without POSIX process groups.
func configureProcessGroup(_ *exec.Cmd) {}

// killProcessGroup falls back to killing only the direct child.
func killProcessGroup(process *os.Process) error {
	if process == nil {
		return nil
	}
	return process.Kill()
}

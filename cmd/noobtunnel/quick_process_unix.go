//go:build !windows

package main

import (
	"context"
	"os"
	"os/exec"
	"syscall"
)

// Stop the installer pipeline and its child processes when the shared deadline
// expires, rather than leaving a download or installer running after Quick exits.
func quickInstallerCommand(ctx context.Context, name string, args ...string) *exec.Cmd {
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	cmd.Cancel = func() error {
		err := syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
		if err == syscall.ESRCH {
			return os.ErrProcessDone
		}
		return err
	}
	return cmd
}

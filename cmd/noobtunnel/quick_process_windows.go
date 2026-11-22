package main

import (
	"context"
	"os/exec"
)

func quickInstallerCommand(ctx context.Context, name string, args ...string) *exec.Cmd {
	return exec.CommandContext(ctx, name, args...)
}

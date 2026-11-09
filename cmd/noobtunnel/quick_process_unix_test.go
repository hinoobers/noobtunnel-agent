//go:build !windows

package main

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestQuickInstallerDeadlineStopsChildProcesses(t *testing.T) {
	marker := filepath.Join(t.TempDir(), "late-write")
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	cmd := quickInstallerCommand(ctx, "sh", "-c", `(sleep 0.3; printf late > "$NOOBTUNNEL_DEADLINE_MARKER") & wait`)
	cmd.Env = append(os.Environ(), "NOOBTUNNEL_DEADLINE_MARKER="+marker)
	if err := cmd.Run(); err == nil {
		t.Fatal("installer ignored deadline")
	}
	time.Sleep(350 * time.Millisecond)
	if _, err := os.Stat(marker); !os.IsNotExist(err) {
		t.Fatal("installer child continued after timeout")
	}
}

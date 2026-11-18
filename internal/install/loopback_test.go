package install

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestLinuxLoopbackInstallPolicy(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX filesystem fixture")
	}
	raw, err := Script()
	if err != nil {
		t.Fatal(err)
	}
	source := string(raw)
	start := strings.Index(source, "write_loopback_policy() {")
	if start < 0 {
		t.Fatal("policy helper missing")
	}
	end := strings.Index(source[start:], "\nstop_service()")
	if end < 0 {
		t.Fatal("policy helper boundary missing")
	}
	helper := source[start : start+end]
	dir := filepath.Join(t.TempDir(), "state")
	path := filepath.Join(dir, "forward-policy.json")
	for _, enabled := range []string{"0", "1", "0", "1"} {
		command := "set -eu\n" + helper + "\nLOOPBACK_ONLY=$1\nwrite_loopback_policy \"$2\""
		if out, err := exec.Command("sh", "-c", command, "fixture", enabled, dir).CombinedOutput(); err != nil {
			t.Fatalf("policy helper: %v %s", err, out)
		}
		data, err := os.ReadFile(path)
		if enabled == "0" && os.IsNotExist(err) {
			continue
		}
		if err != nil {
			t.Fatal(err)
		}
		var policy struct {
			LoopbackOnly bool `json:"loopbackOnly"`
		}
		if err := json.Unmarshal(data, &policy); err != nil || !policy.LoopbackOnly {
			t.Fatal("installer failed to preserve the local restriction", err)
		}
	}
}

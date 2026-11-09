package agent

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"
)

func TestHostsUpdatesAcrossProcesses(t *testing.T) {
	if path := os.Getenv("NOOBTUNNEL_HOSTS_TEST_PATH"); path != "" {
		id, err := strconv.Atoi(os.Getenv("NOOBTUNNEL_HOSTS_TEST_ID"))
		if err != nil {
			t.Fatal(err)
		}
		if err := writeMeshDNSHosts(path, uint32(id), []meshDNSRecord{{Name: fmt.Sprintf("peer-%d", id), Address: "10.77.1.2"}}); err != nil {
			t.Fatal(err)
		}
		return
	}
	path := filepath.Join(t.TempDir(), "hosts")
	original := []byte("127.0.0.1 localhost\n10.0.0.4 custom\n")
	if err := os.WriteFile(path, original, 0600); err != nil {
		t.Fatal(err)
	}
	before, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	var children []*exec.Cmd
	for i := 1; i <= 6; i++ {
		cmd := exec.Command(os.Args[0], "-test.run=^TestHostsUpdatesAcrossProcesses$")
		cmd.Env = append(os.Environ(), "NOOBTUNNEL_HOSTS_TEST_PATH="+path, fmt.Sprintf("NOOBTUNNEL_HOSTS_TEST_ID=%d", i))
		var output bytes.Buffer
		cmd.Stdout = &output
		cmd.Stderr = &output
		if err := cmd.Start(); err != nil {
			t.Fatal(err)
		}
		children = append(children, cmd)
	}
	for _, cmd := range children {
		if err := cmd.Wait(); err != nil {
			t.Fatalf("hosts writer failed: %v; %s", err, cmd.Stdout)
		}
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.HasPrefix(data, original) {
		t.Fatal("unrelated hosts entries changed")
	}
	for i := 1; i <= 6; i++ {
		if !strings.Contains(string(data), fmt.Sprintf("peer-%d.mesh peer-%d", i, i)) {
			t.Fatalf("lost process %d update", i)
		}
	}
	after, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if !os.SameFile(before, after) {
		t.Fatal("hosts inode replaced; bind mounts would become stale")
	}
	if runtime.GOOS != "windows" && after.Mode().Perm() != 0600 {
		t.Fatal("hosts permissions changed")
	}
}

func TestHostsRecoversEveryInterruptedWritePosition(t *testing.T) {
	before := []byte("127.0.0.1 localhost\n10.0.0.4 custom\n")
	after := []byte(meshDNSHostsContent(string(before), 1, []meshDNSRecord{{Name: "peer-one", Address: "10.77.1.2"}}))
	for _, pair := range [][2][]byte{{before, after}, {after, before}} {
		old, next := pair[0], pair[1]
		for n := 0; n <= len(next); n++ {
			t.Run(fmt.Sprintf("%d-%d-%d", len(old), len(next), n), func(t *testing.T) {
				dir := t.TempDir()
				path := filepath.Join(dir, "hosts")
				partial := append([]byte(nil), old...)
				if n > len(partial) {
					partial = append(partial, make([]byte, n-len(partial))...)
				}
				copy(partial, next[:n])
				if err := os.WriteFile(path, partial, 0600); err != nil {
					t.Fatal(err)
				}
				raw, _ := json.Marshal(hostsUpdate{Version: 1, Before: old, After: next})
				if err := os.WriteFile(path+".noobtunnel-journal", raw, 0600); err != nil {
					t.Fatal(err)
				}
				if err := writeMeshDNSHosts(path, 2, []meshDNSRecord{{Name: "peer-two", Address: "10.77.1.3"}}); err != nil {
					t.Fatal(err)
				}
				got, err := os.ReadFile(path)
				if err != nil {
					t.Fatal(err)
				}
				want := meshDNSHostsContent(string(next), 2, []meshDNSRecord{{Name: "peer-two", Address: "10.77.1.3"}})
				if string(got) != want {
					t.Fatal("interrupted update was not recovered before next edit")
				}
				journal, err := os.ReadFile(path + ".noobtunnel-journal")
				if err != nil || len(journal) != 0 {
					t.Fatal("completed journal not cleared", err)
				}
			})
		}
	}
}

func TestHostsRecoveryPreservesExternalEditsAndInvalidJournal(t *testing.T) {
	for _, invalid := range []bool{false, true} {
		path := filepath.Join(t.TempDir(), "hosts")
		current := []byte("127.0.0.1 localhost\n10.9.9.9 externally-added\n")
		os.WriteFile(path, current, 0600)
		raw, _ := json.Marshal(hostsUpdate{Version: 1, Before: []byte("original\n"), After: []byte("replacement\n")})
		if invalid {
			raw = []byte("incomplete journal")
		}
		os.WriteFile(path+".noobtunnel-journal", raw, 0600)
		if err := writeMeshDNSHosts(path, 1, nil); err == nil {
			t.Fatal("unsafe recovery accepted")
		}
		got, _ := os.ReadFile(path)
		journal, _ := os.ReadFile(path + ".noobtunnel-journal")
		if !bytes.Equal(got, current) || !bytes.Equal(journal, raw) {
			t.Fatal("external edits or recovery evidence overwritten")
		}
	}
}

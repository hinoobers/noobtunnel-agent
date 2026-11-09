package install

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestWindowsDownloadSurvivesSlowAndInterruptedTransfers(t *testing.T) {
	if _, err := exec.LookPath("powershell.exe"); err != nil {
		t.Skip("PowerShell unavailable")
	}
	source := string(WindowsScript())
	start := strings.Index(source, "function Fetch-Pinned(")
	end := strings.Index(source[start:], "\nWrite-Output") + start
	helper := source[start:end]
	payload := bytes.Repeat([]byte("verified-agent-bytes"), 65536)
	for _, mode := range []string{"interrupted", "slow", "wrong-pin"} {
		t.Run(mode, func(t *testing.T) {
			var requests, resumed atomic.Int32
			server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				n := requests.Add(1)
				if mode == "interrupted" && n == 1 {
					w.Header().Set("Content-Length", fmt.Sprint(len(payload)))
					w.Write(payload[:len(payload)/2])
					w.(http.Flusher).Flush()
					conn, _, _ := w.(http.Hijacker).Hijack()
					conn.Close()
					return
				}
				if mode == "slow" {
					w.Header().Set("Content-Length", fmt.Sprint(len(payload)))
					for i := 0; i < 31; i++ {
						w.Write(payload[i*4096 : (i+1)*4096])
						w.(http.Flusher).Flush()
						time.Sleep(time.Second)
					}
					w.Write(payload[31*4096:])
					return
				}
				if r.Header.Get("Range") != "" {
					resumed.Add(1)
				}
				http.ServeContent(w, r, "agent.exe", time.Now(), bytes.NewReader(payload))
			}))
			defer server.Close()
			digest := sha256.Sum256(server.Certificate().RawSubjectPublicKeyInfo)
			if mode == "wrong-pin" {
				digest = sha256.Sum256([]byte("wrong"))
			}
			pin := base64.StdEncoding.EncodeToString(digest[:])
			target := filepath.Join(t.TempDir(), "agent.exe")
			script := "$ErrorActionPreference='Stop'; $Pin='" + pin + "'; function Get-RemainingSetupSeconds { return 600 }; " + helper + "\nFetch-Pinned '" + server.URL + "' '" + strings.ReplaceAll(target, "'", "''") + "' -Resume"
			out, err := exec.Command("powershell.exe", "-NoProfile", "-NonInteractive", "-Command", script).CombinedOutput()
			if mode == "wrong-pin" {
				if err == nil || requests.Load() != 0 {
					t.Fatalf("pin not enforced: %v %s", err, out)
				}
				return
			}
			if err != nil {
				t.Fatalf("download: %v %s", err, out)
			}
			got, err := os.ReadFile(target)
			if err != nil || !bytes.Equal(got, payload) {
				t.Fatalf("download bytes changed: %v", err)
			}
			if mode == "interrupted" && (requests.Load() != 2 || resumed.Load() != 1) {
				t.Fatalf("partial transfer did not resume: requests=%d resumes=%d", requests.Load(), resumed.Load())
			}
		})
	}
}

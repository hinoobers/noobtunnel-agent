package install

import (
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
)

func TestWindowsUninstallDiscovery(t *testing.T) {
	ps, err := exec.LookPath("powershell.exe")
	if err != nil {
		t.Skip("Windows PowerShell unavailable")
	}
	for _, mode := range []string{"legacy", "saved", "explicit", "legacy-removed", "saved-removed", "explicit-removed", "wrong-certificate", "remote-failure", "unauthorized", "local-only", "missing-id"} {
		t.Run(mode, func(t *testing.T) {
			var requests atomic.Int32
			server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				requests.Add(1)
				if r.Method != "POST" || r.URL.Path != "/api/agent-uninstall/42" || r.Header.Get("Authorization") != "Bearer fixture-token" {
					t.Error("unexpected uninstall request")
					w.WriteHeader(403)
					return
				}
				if mode == "remote-failure" {
					w.WriteHeader(500)
				}
				if mode == "unauthorized" {
					w.WriteHeader(401)
				}
				if strings.HasSuffix(mode, "-removed") {
					fmt.Fprint(w, `{"ok":true,"alreadyRemoved":true}`)
				}
			}))
			defer server.Close()
			endpoint := strings.TrimPrefix(server.URL, "https://")
			fingerprint := fmt.Sprintf("%x", sha256.Sum256(server.Certificate().Raw))
			if mode == "wrong-certificate" {
				fingerprint = strings.Repeat("0", 64)
			}
			pin := sha256.Sum256(server.Certificate().RawSubjectPublicKeyInfo)
			dir := t.TempDir()
			programs, data := filepath.Join(dir, "programs"), filepath.Join(dir, "data")
			state, program := filepath.Join(data, "noobtunnel"), filepath.Join(programs, "noobtunnel")
			for _, path := range []string{state, program} {
				if err := os.MkdirAll(path, 0700); err != nil {
					t.Fatal(err)
				}
			}
			write := func(name, content string) {
				t.Helper()
				if err := os.WriteFile(filepath.Join(state, name), []byte(content), 0600); err != nil {
					t.Fatal(err)
				}
			}
			write("token", "fixture-token")
			if mode != "missing-id" {
				write("runtime.json", `{"agentId":42}`)
			}
			if strings.HasPrefix(mode, "saved") {
				write("uninstall.json", fmt.Sprintf(`{"server":%q,"pin":%q}`, endpoint, base64.StdEncoding.EncodeToString(pin[:])))
			}
			// Only the elevation block is bypassed. All actual destructive operations
			// target the isolated fixture; native service/firewall calls are mocked.
			source := string(WindowsScript())
			start := strings.Index(source, "$identity = [Security.Principal.WindowsIdentity]")
			end := strings.Index(source[start:], "[void](Get-RemainingSetupSeconds)") + start
			source = source[:start] + source[end:]
			source = strings.Replace(source, "  exit 0", "  return", 1)
			scriptPath := filepath.Join(dir, "installer.ps1")
			if err := os.WriteFile(scriptPath, []byte(source), 0600); err != nil {
				t.Fatal(err)
			}
			quote := func(s string) string { return "'" + strings.ReplaceAll(s, "'", "''") + "'" }
			command := fmt.Sprintf(`$ErrorActionPreference='Stop'
$env:ProgramFiles=%s
$env:ProgramData=%s
function Get-CimInstance { param($ClassName,$Filter,$ErrorAction); [pscustomobject]@{PathName='"agent.exe" "agent" "--server" "%s" "--fingerprint" "%s"'} }
function Get-Service { param($Name,$ErrorAction); return $null }
function Get-NetFirewallRule { param($Name,$ErrorAction); return @() }
function Remove-NetFirewallRule { process {} }
& %s -Uninstall`, quote(programs), quote(data), endpoint, fingerprint, quote(scriptPath))
			if mode == "local-only" {
				command += " -LocalOnly"
			}
			if strings.HasPrefix(mode, "explicit") {
				command = strings.Replace(command, endpoint+`" "--fingerprint"`, `wrong.invalid:1" "--fingerprint"`, 1)
				command += " -Server " + quote(endpoint) + " -Pin " + quote(base64.StdEncoding.EncodeToString(pin[:])) + " -AgentId 42"
			}
			command += "; if ($LASTEXITCODE) { exit $LASTEXITCODE }"
			harness := filepath.Join(dir, "test.ps1")
			if err := os.WriteFile(harness, []byte(command), 0600); err != nil {
				t.Fatal(err)
			}
			out, runErr := exec.Command(ps, "-NoProfile", "-ExecutionPolicy", "Bypass", "-File", harness).CombinedOutput()
			fails := mode == "wrong-certificate" || mode == "remote-failure" || mode == "unauthorized" || mode == "missing-id"
			if (runErr != nil) != fails {
				t.Fatalf("unexpected result: %v\n%s", runErr, out)
			}
			for _, path := range []string{state, program} {
				_, err := os.Stat(path)
				if fails && err != nil {
					t.Fatal("failed uninstall deleted local files")
				}
				if !fails && !os.IsNotExist(err) {
					t.Fatal("uninstall left local files")
				}
			}
			want := int32(1)
			if mode == "wrong-certificate" || mode == "local-only" || mode == "missing-id" {
				want = 0
			}
			if requests.Load() != want {
				t.Fatalf("received %d requests, want %d", requests.Load(), want)
			}
		})
	}
}

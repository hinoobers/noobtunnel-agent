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
	"testing"
)

// Real pinned downloads and installer state changes, with Windows service and
// ACL operations mocked so the test never changes the host installation.
func TestWindowsReinstallOverDeadAgent(t *testing.T) {
	ps, err := exec.LookPath("powershell.exe")
	if err != nil {
		t.Skip("Windows PowerShell unavailable")
	}
	for _, mode := range []string{"running", "stopped", "changed-controller"} {
		t.Run(mode, func(t *testing.T) {
			artifact := []byte("replacement agent fixture")
			digest := fmt.Sprintf("%x", sha256.Sum256(artifact))
			server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				switch r.URL.Path {
				case "/download/manifest.json":
					fmt.Fprintf(w, `{"binaries":[{"name":"noobtunnel_windows_amd64.exe","sha256":%q}]}`, digest)
				case "/download/noobtunnel_windows_amd64.exe":
					w.Write(artifact)
				default:
					http.NotFound(w, r)
				}
			}))
			defer server.Close()
			endpoint := strings.TrimPrefix(server.URL, "https://")
			pin := sha256.Sum256(server.Certificate().RawSubjectPublicKeyInfo)
			fingerprint := fmt.Sprintf("%x", sha256.Sum256(server.Certificate().Raw))
			dir := t.TempDir()
			programs, data := filepath.Join(dir, "programs"), filepath.Join(dir, "data")
			program, state := filepath.Join(programs, "noobtunnel"), filepath.Join(data, "noobtunnel")
			for _, p := range []string{program, state} {
				if err := os.MkdirAll(p, 0700); err != nil {
					t.Fatal(err)
				}
			}
			write := func(p, s string) {
				t.Helper()
				if err := os.WriteFile(p, []byte(s), 0600); err != nil {
					t.Fatal(err)
				}
			}
			write(filepath.Join(state, "token"), "dead-token")
			write(filepath.Join(state, "runtime.json"), `{"agentId":7,"connected":false,"lastError":"agent revoked"}`)
			write(filepath.Join(state, "identity.json"), "existing identity fixture")
			write(filepath.Join(program, "noobtunnel.exe"), "old binary")
			write(filepath.Join(program, "wintun.dll"), "existing driver fixture")
			source := string(WindowsScript())
			start := strings.Index(source, "$identity = [Security.Principal.WindowsIdentity]")
			end := strings.Index(source[start:], "[void](Get-RemainingSetupSeconds)") + start
			source = source[:start] + source[end:]
			source = strings.ReplaceAll(source, "  exit 0", "  return")
			installer := filepath.Join(dir, "installer.ps1")
			write(installer, source)
			q := func(s string) string { return "'" + strings.ReplaceAll(s, "'", "''") + "'" }
			oldEndpoint := endpoint
			if mode == "changed-controller" {
				oldEndpoint = "old.invalid:8443"
			}
			oldCommand := fmt.Sprintf(`"%s" "agent" "--server" "%s" "--token-file" "%s" "--fingerprint" "%s" "--name" "dead-agent" "--state-dir" "%s"`, filepath.Join(program, "noobtunnel.exe"), oldEndpoint, filepath.Join(state, "token"), fingerprint, state)
			status := "Running"
			if mode == "stopped" {
				status = "Stopped"
			}
			harness := fmt.Sprintf(`$ErrorActionPreference='Stop'
$env:ProgramFiles=%s; $env:ProgramData=%s; $env:TEMP=%s
$env:NOOBTUNNEL_QUICK_SETUP=''
$global:fixtureService=[pscustomobject]@{Status=%s}
$global:fixtureService | Add-Member ScriptMethod WaitForStatus { param($status,$timeout); if ($this.Status -ne 'Stopped') {throw 'service did not stop'} }
$global:fixtureStopped=$false; $global:fixtureChanged=$false; $global:fixtureStarted=$false
function Get-Service { param($Name,$ErrorAction); return $global:fixtureService }
function Stop-Service { param($Name,[switch]$Force); $global:fixtureService.Status='Stopped'; $global:fixtureStopped=$true }
function Get-CimInstance { param($ClassName,$Filter); return [pscustomobject]@{PathName=%s} }
function Invoke-CimMethod { param($InputObject,$MethodName,$Arguments); if ($Arguments.PathName -notlike '*"%s"*') {throw 'wrong controller in service update'}; $global:fixtureChanged=$true; return [pscustomobject]@{ReturnValue=0} }
function New-Service { throw 'created duplicate service' }
function icacls.exe { $global:LASTEXITCODE=0 }
function Start-Service {
 param($Name)
 $state=Join-Path $env:ProgramData 'noobtunnel'
 if ((Get-Content -Raw -LiteralPath (Join-Path $state 'token')) -ne 'fresh-token') {throw 'stale token retained'}
 if (Test-Path -LiteralPath (Join-Path $state 'runtime.json')) {throw 'stale runtime retained'}
 if ((Get-FileHash (Join-Path $env:ProgramFiles 'noobtunnel/noobtunnel.exe')).Hash -ne '%s') {throw 'binary not replaced'}
 if ((Get-Content -Raw (Join-Path $state 'uninstall.json') | ConvertFrom-Json).server -ne '%s') {throw 'uninstall settings stale'}
 '{"agentId":42,"connected":true,"address":"100.64.1.2"}' | Set-Content -LiteralPath (Join-Path $state 'runtime.json')
 $global:fixtureStarted=$true
}
& %s -Server %s -Token 'fresh-token' -Name 'replacement' -Fingerprint %s -Pin %s
if (-not $global:fixtureStarted) {throw 'service never restarted'}
if ($global:fixtureStopped -ne $%s) {throw 'wrong stop behavior'}
if ($global:fixtureChanged -ne $%s) {throw 'wrong service update behavior'}
`, q(programs), q(data), q(dir), q(status), q(oldCommand), endpoint, digest, endpoint, q(installer), q(endpoint), q(fingerprint), q(base64.StdEncoding.EncodeToString(pin[:])), fmt.Sprint(mode != "stopped"), fmt.Sprint(mode == "changed-controller"))
			path := filepath.Join(dir, "test.ps1")
			write(path, harness)
			out, err := exec.Command(ps, "-NoProfile", "-ExecutionPolicy", "Bypass", "-File", path).CombinedOutput()
			if err != nil {
				t.Fatalf("reinstall failed: %v\n%s", err, out)
			}
			identity, err := os.ReadFile(filepath.Join(state, "identity.json"))
			if err != nil || string(identity) != "existing identity fixture" {
				t.Fatal("existing identity lost")
			}
		})
	}
}

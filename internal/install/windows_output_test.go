package install

import (
	"encoding/base64"
	"encoding/binary"
	"os/exec"
	"strings"
	"testing"
	"unicode/utf16"
)

func TestWindowsInstallerProgressPrintedOnce(t *testing.T) {
	if _, err := exec.LookPath("powershell.exe"); err != nil {
		t.Skip("Windows PowerShell unavailable")
	}
	// Quick launches this encoded installer as a native child. Write-Host emits
	// both console text and a CLIXML information record in that configuration.
	// Execute only the actual progress statements, never installation operations.
	script := "$ProgressPreference = 'SilentlyContinue'; $runtime = [pscustomobject]@{ address = '10.77.1.2' }\n"
	for _, line := range strings.Split(string(WindowsScript()), "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "Write-Host ") || strings.HasPrefix(line, "Write-Output ") {
			script += line + "\n"
		}
	}
	units := utf16.Encode([]rune(script))
	raw := make([]byte, 2*len(units))
	for i, unit := range units {
		binary.LittleEndian.PutUint16(raw[2*i:], unit)
	}
	out, err := exec.Command("powershell.exe", "-NoProfile", "-EncodedCommand", base64.StdEncoding.EncodeToString(raw)).CombinedOutput()
	if err != nil {
		t.Fatalf("progress statements failed: %v\n%s", err, out)
	}
	for _, message := range []string{"Downloading noobtunnel agent...", "Waiting for agent to connect...", "Agent connected. Mesh address: 10.77.1.2"} {
		if count := strings.Count(string(out), message); count != 1 {
			t.Fatalf("message printed %d times: %q\n%s", count, message, out)
		}
	}
	if strings.Contains(string(out), "CLIXML") {
		t.Fatalf("plain progress leaked information records: %s", out)
	}
}

func TestWindowsQuickInstallerReturnsBeforeLocalReadinessWait(t *testing.T) {
	if _, err := exec.LookPath("powershell.exe"); err != nil {
		t.Skip("Windows PowerShell unavailable")
	}
	source := string(WindowsScript())
	start := strings.Index(source, "Start-Service -Name 'noobtunnel-agent'")
	if start < 0 {
		t.Fatal("missing service startup")
	}
	end := strings.Index(source[start:], "Write-Output 'Waiting for agent to connect...'") + start
	if start < 0 || end < start {
		t.Fatal("missing service startup or local readiness wait")
	}
	script := `function Start-Service { param($Name) }; $env:NOOBTUNNEL_QUICK_SETUP='1'; ` + source[start:end] + "; throw 'Quick waited for local readiness'"
	if out, err := exec.Command("powershell.exe", "-NoProfile", "-NonInteractive", "-Command", script).CombinedOutput(); err != nil {
		t.Fatalf("Quick installer failed to return after service startup: %v\n%s", err, out)
	}
}

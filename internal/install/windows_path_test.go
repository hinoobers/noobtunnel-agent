package install

import (
	"os/exec"
	"strings"
	"testing"
)

func TestWindowsCommandPath(t *testing.T) {
	ps, err := exec.LookPath("powershell.exe")
	if err != nil {
		t.Skip("PowerShell is unavailable")
	}
	source := string(WindowsScript())
	start := strings.Index(source, "function Set-NoobtunnelCommandPath(")
	if start < 0 {
		t.Fatal("command path helper missing")
	}
	end := strings.Index(source[start:], "\nif ($Uninstall)")
	if end < 0 {
		t.Fatal("command path helper boundary missing")
	}
	helper := source[start : start+end]
	helper = strings.ReplaceAll(helper, "[Environment]::GetEnvironmentVariable('Path', 'Machine')", "$script:FixturePath")
	helper = strings.ReplaceAll(helper, "[Environment]::SetEnvironmentVariable('Path', $updated, 'Machine')", "$script:FixturePath = $updated; $script:Writes++")
	if strings.Contains(helper, "[Environment]") {
		t.Fatal("fixture must not access the real environment")
	}
	script := helper + `
$ErrorActionPreference='Stop'
$root='C:\Program Files\noobtunnel'
$script:FixturePath='C:\Windows;;C:\Tools'
$script:Writes=0
Set-NoobtunnelCommandPath $false
if ($script:Writes -ne 0) { throw 'Uninstall modified an unrelated PATH' }
Set-NoobtunnelCommandPath $true
if ($script:FixturePath -cne ('C:\Windows;;C:\Tools;'+$root)) { throw 'Install did not preserve PATH entries' }
Set-NoobtunnelCommandPath $true
if ($script:Writes -ne 1) { throw 'Repeated install changed PATH' }
Set-NoobtunnelCommandPath $false
if ($script:FixturePath -cne 'C:\Windows;;C:\Tools') { throw 'Uninstall did not preserve other entries' }
$script:FixturePath='C:\Windows;C:\PROGRAM FILES\NOOBTUNNEL\;C:\Tools'
Set-NoobtunnelCommandPath $false
if ($script:FixturePath -cne 'C:\Windows;C:\Tools') { throw 'Uninstall did not match existing directory' }
`
	if out, err := exec.Command(ps, "-NoProfile", "-NonInteractive", "-Command", script).CombinedOutput(); err != nil {
		t.Fatalf("PATH checks failed: %v\n%s", err, out)
	}
}

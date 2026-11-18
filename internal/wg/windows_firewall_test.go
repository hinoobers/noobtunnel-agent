//go:build windows

package wg

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

func TestWindowsFirewallReconciliation(t *testing.T) {
	ps, err := exec.LookPath("powershell.exe")
	if err != nil {
		t.Skip("PowerShell unavailable")
	}
	for _, mode := range []string{"correct", "missing", "stale", "disabled", "blocked", "stale-handle", "recovery-fails"} {
		t.Run(mode, func(t *testing.T) {
			script := fmt.Sprintf(`$ErrorActionPreference='Stop'
$global:mode='%s'; $global:changed=0; $global:created=0; $global:removed=0
function Get-NetFirewallRule {
 param($Name,$ErrorAction)
 if ($Name -ne 'noobtunnel-mesh') {throw 'unexpected rule'}
 if ($global:mode -eq 'missing') {return}
 $enabled='True'; $action='Allow'
 if ($global:mode -eq 'disabled') {$enabled='False'}
 if ($global:mode -eq 'blocked') {$action='Block'}
 [pscustomobject]@{Enabled=$enabled;Direction='Inbound';Action=$action;Profile='Any'}
}
function Get-NetFirewallInterfaceFilter {
 param([Parameter(ValueFromPipeline=$true)]$InputObject)
 process {
  if ($global:mode -like 'stale*' -or $global:mode -eq 'recovery-fails') {[pscustomobject]@{InterfaceAlias='{old-adapter}'}}
  else {[pscustomobject]@{InterfaceAlias='noobtun'}}
 }
}
function Set-NetFirewallRule {
 param($Name,$InterfaceAlias,$Enabled,$Direction,$Action,$Profile,$ErrorAction)
 if ($Name -ne 'noobtunnel-mesh' -or $InterfaceAlias -ne 'noobtun' -or $Action -ne 'Allow' -or $Direction -ne 'Inbound') {throw 'unsafe update'}
 $global:changed++
 if ($global:mode -in @('stale-handle','recovery-fails')) {throw 'The handle is invalid'}
 if ($global:mode -eq 'correct') {throw 'rewrote valid rule'}
}
function Remove-NetFirewallRule {
 param($Name,$ErrorAction)
 if ($Name -ne 'noobtunnel-mesh') {throw 'removed unrelated rule'}
 $global:removed++
}
function New-NetFirewallRule {
 param($Name,$DisplayName,$Direction,$Action,$Profile,$InterfaceAlias,$ErrorAction)
 if ($Name -ne 'noobtunnel-mesh' -or $InterfaceAlias -ne 'noobtun' -or $Action -ne 'Allow' -or $Direction -ne 'Inbound') {throw 'unsafe replacement'}
 $global:created++
 if ($global:mode -eq 'recovery-fails') {throw 'Cannot create rule'}
}
$failed=$false
try {
%s
} catch {$failed=$true}
if ($failed -ne ($global:mode -eq 'recovery-fails')) {throw 'wrong failure behavior'}
$wantChanged=1; $wantCreated=0; $wantRemoved=0
if ($global:mode -eq 'correct') {$wantChanged=0}
if ($global:mode -eq 'missing') {$wantChanged=0;$wantCreated=1}
if ($global:mode -in @('stale-handle','recovery-fails')) {$wantCreated=1;$wantRemoved=1}
if ($global:changed -ne $wantChanged -or $global:created -ne $wantCreated -or $global:removed -ne $wantRemoved) {throw 'wrong firewall operations'}
`, mode, windowsFirewallScript("noobtun"))
			path := filepath.Join(t.TempDir(), "firewall.ps1")
			if err := os.WriteFile(path, []byte(script), 0600); err != nil {
				t.Fatal(err)
			}
			if out, err := exec.Command(ps, "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-File", path).CombinedOutput(); err != nil {
				t.Fatalf("%v\n%s", err, out)
			}
		})
	}
}

param(
  [string]$Server,
  [string]$Token,
  [string]$Fingerprint,
  [string]$Pin,
  [string]$Name,
  [switch]$Uninstall,
  [switch]$LocalOnly,
  [uint32]$AgentId,
  [long]$Deadline
)

$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
if ($Deadline -le 0) { $Deadline = [DateTimeOffset]::UtcNow.ToUnixTimeSeconds() + 600 }
function Get-RemainingSetupSeconds {
  $remaining = $Deadline - [DateTimeOffset]::UtcNow.ToUnixTimeSeconds()
  if ($remaining -le 0) { throw 'Setup timed out after 10 minutes. Check your connection and retry.' }
  return $remaining
}

$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = New-Object Security.Principal.WindowsPrincipal($identity)
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
  function PSQuote([string]$Value) { return "'" + $Value.Replace("'", "''") + "'" }
  if ($Uninstall) {
    $reentry = '& ' + (PSQuote $PSCommandPath) + ' -Uninstall -Server ' + (PSQuote $Server) +
      ' -Pin ' + (PSQuote $Pin) + ' -AgentId ' + $AgentId
    if ($LocalOnly) { $reentry += ' -LocalOnly' }
  } else {
    $reentry = '& ' + (PSQuote $PSCommandPath) + ' -Server ' + (PSQuote $Server) +
      ' -Token ' + (PSQuote $Token) + ' -Fingerprint ' + (PSQuote $Fingerprint) +
      ' -Pin ' + (PSQuote $Pin) + ' -Name ' + (PSQuote $Name)
  }
  $reentry += ' -Deadline ' + $Deadline
  # Preserve the result in the administrator window and report the real status.
  $reentry = '$ErrorActionPreference=''Stop''; try { ' + $reentry + '; $setupExitCode=$LASTEXITCODE; if (-not [Console]::IsInputRedirected) { [void](Read-Host ''Press Enter to close'') }; exit $setupExitCode } catch { Write-Host (''noobtunnel: '' + $_.Exception.Message) -ForegroundColor Red; if (-not [Console]::IsInputRedirected) { [void](Read-Host ''Press Enter to close'') }; exit 1 }'
  $encoded = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($reentry))
  Write-Output 'Requesting administrator access to manage the tunnel service...'
  $process = Start-Process -FilePath powershell.exe -Verb RunAs -PassThru -Wait -ArgumentList @('-NoProfile', '-ExecutionPolicy', 'Bypass', '-EncodedCommand', $encoded)
  exit $process.ExitCode
}
if ($Server -notmatch '^[A-Za-z0-9.\-]+:\d+$') { throw 'Invalid control server address.' }
[void](Get-RemainingSetupSeconds)
if ($Pin -notmatch '^[A-Za-z0-9+/]{43}=$') { throw 'Invalid certificate pin.' }
$root = Join-Path $env:ProgramFiles 'noobtunnel'
$state = Join-Path $env:ProgramData 'noobtunnel'
$binary = Join-Path $root 'noobtunnel.exe'
$dll = Join-Path $root 'wintun.dll'
$tokenFile = Join-Path $state 'token'

if ($Uninstall) {
  if (-not $LocalOnly -and $AgentId -eq 0) { throw 'Invalid agent ID.' }
  if (-not (Test-Path -LiteralPath $tokenFile)) { throw 'No local agent token found. Use control node only removal.' }
  $localToken = (Get-Content -LiteralPath $tokenFile -Raw).Trim()
  if (-not $localToken) { throw 'The local agent token is empty.' }
  if (-not $LocalOnly) {
    ('header = "Authorization: Bearer ' + $localToken + '"') | & curl.exe --fail --silent --show-error `
    --insecure --connect-timeout 5 --max-time (Get-RemainingSetupSeconds) --pinnedpubkey "sha256//$Pin" --config - --request POST `
    "https://$Server/api/agent-uninstall/$AgentId" --output NUL
    if ($LASTEXITCODE -ne 0) { throw 'Control node removal failed. The local agent was kept so you can retry.' }
  }
  $service = Get-Service -Name 'noobtunnel-agent' -ErrorAction SilentlyContinue
  if ($service) {
    if ($service.Status -ne 'Stopped') {
      Stop-Service -Name 'noobtunnel-agent' -Force
      (Get-Service -Name 'noobtunnel-agent').WaitForStatus('Stopped', [TimeSpan]::FromSeconds((Get-RemainingSetupSeconds)))
    }
    & sc.exe delete noobtunnel-agent | Out-Null
    if ($LASTEXITCODE -ne 0) { throw 'Could not remove the Windows service.' }
  }
  Get-NetFirewallRule -Name 'noobtunnel-mesh' -ErrorAction SilentlyContinue | Remove-NetFirewallRule
  foreach ($target in @($root, $state)) {
    $resolved = [IO.Path]::GetFullPath($target)
    if ([IO.Path]::GetFileName($resolved) -ne 'noobtunnel' -or (Get-Item -LiteralPath $resolved -ErrorAction SilentlyContinue).Attributes -band [IO.FileAttributes]::ReparsePoint) { throw 'Unsafe uninstall directory.' }
    if (Test-Path -LiteralPath $resolved) { Remove-Item -LiteralPath $resolved -Recurse -Force }
  }
  if ($LocalOnly) { Write-Output 'Orphaned agent removed from this machine.' }
  else { Write-Output 'Agent removed from the control node and this machine.' }
  exit 0
}

if (-not [Environment]::Is64BitOperatingSystem) { throw 'This installer currently supports 64-bit Windows only.' }
if (-not $Token -or -not $Name) { throw 'Token and name are required.' }
# The control node formats SHA-256 fingerprints as colon-separated hex.
if ($Fingerprint -notmatch '^(?:[a-fA-F0-9]{2}:){31}[a-fA-F0-9]{2}$' -and
    $Fingerprint -notmatch '^[a-fA-F0-9]{64}$') { throw 'Invalid certificate fingerprint.' }

New-Item -ItemType Directory -Force -Path $root, $state | Out-Null

function Fetch-Pinned([string]$Url, [string]$Target, [switch]$Resume) {
  # Start with this release's bytes. Resume only this invocation's partial file.
  if (Test-Path -LiteralPath $Target) { Remove-Item -LiteralPath $Target -Force }
  for ($attempt = 1; $attempt -le 3; $attempt++) {
    $budget = [Math]::Min(180, (Get-RemainingSetupSeconds))
    $resumeArgs = @()
    if ($Resume -and (Test-Path -LiteralPath $Target)) { $resumeArgs = @('--continue-at', '-') }
    & curl.exe --fail --silent --show-error --location --insecure --connect-timeout 15 --max-time $budget --speed-limit 1024 --speed-time 30 --pinnedpubkey "sha256//$Pin" @resumeArgs $Url --output $Target
    $downloadCode = $LASTEXITCODE
    if ($downloadCode -eq 0) { return }
    # Never retry a certificate pin failure or accept an unverified download.
    if ($downloadCode -eq 90) { throw "Download certificate pin mismatch: $Url" }
    if ($attempt -eq 3) { throw "Download failed after 3 attempts: $Url (curl $downloadCode)" }
    # Servers without Range support must restart instead of appending bad bytes.
    if ($downloadCode -eq 33 -or $downloadCode -eq 22) {
      if (Test-Path -LiteralPath $Target) { Remove-Item -LiteralPath $Target -Force }
    }
    Write-Output "Download interrupted; retrying ($($attempt + 1)/3)..."
    Start-Sleep -Seconds 1
  }
}

Write-Output 'Downloading noobtunnel agent...'
$downloadId = [Guid]::NewGuid().ToString('N')
$manifestFile = Join-Path $env:TEMP ('noobtunnel-manifest-' + $downloadId + '.json')
Fetch-Pinned "https://$Server/download/manifest.json" $manifestFile
$manifest = Get-Content -LiteralPath $manifestFile -Raw | ConvertFrom-Json
$artifact = @($manifest.binaries | Where-Object { $_.name -eq 'noobtunnel_windows_amd64.exe' }) | Select-Object -First 1
if (-not $artifact) { throw 'The control node has no Windows agent binary. Ask the operator to publish it.' }
$download = Join-Path $env:TEMP ('noobtunnel-agent-' + $downloadId + '.exe')
Fetch-Pinned "https://$Server/download/noobtunnel_windows_amd64.exe" $download -Resume
$actual = (Get-FileHash -LiteralPath $download -Algorithm SHA256).Hash.ToLowerInvariant()
if ($actual -ne $artifact.sha256.ToLowerInvariant()) { throw 'Agent binary checksum mismatch.' }

if (-not (Test-Path -LiteralPath $dll)) {
  Write-Output 'Downloading signed Wintun driver...'
  $zip = Join-Path $env:TEMP 'noobtunnel-wintun.zip'
  Invoke-WebRequest -Uri 'https://www.wintun.net/builds/wintun-0.14.1.zip' -OutFile $zip -UseBasicParsing -TimeoutSec (Get-RemainingSetupSeconds)
  $expected = '07c256185d6ee3652e09fa55c0b673e2624b565e02c4b9091c79ca7d2f24ef51'
  if ((Get-FileHash -LiteralPath $zip -Algorithm SHA256).Hash.ToLowerInvariant() -ne $expected) {
    throw 'Wintun driver checksum mismatch.'
  }
  $expanded = Join-Path $env:TEMP 'noobtunnel-wintun'
  Expand-Archive -LiteralPath $zip -DestinationPath $expanded -Force
  $source = Get-ChildItem -LiteralPath $expanded -Recurse -Filter wintun.dll | Where-Object { $_.FullName -match 'amd64' } | Select-Object -First 1
  if (-not $source) { throw 'Wintun archive has no 64-bit DLL.' }
  Copy-Item -LiteralPath $source.FullName -Destination $dll -Force
}

$service = Get-Service -Name 'noobtunnel-agent' -ErrorAction SilentlyContinue
if ($service -and $service.Status -ne 'Stopped') {
  Stop-Service -Name 'noobtunnel-agent' -Force
  (Get-Service -Name 'noobtunnel-agent').WaitForStatus('Stopped', [TimeSpan]::FromSeconds((Get-RemainingSetupSeconds)))
}
$runtimePath = Join-Path $state 'runtime.json'
if (Test-Path -LiteralPath $runtimePath) { Remove-Item -LiteralPath $runtimePath -Force }
[void](Get-RemainingSetupSeconds)
Copy-Item -LiteralPath $download -Destination $binary -Force
& icacls.exe $state /inheritance:r /grant:r 'SYSTEM:(OI)(CI)F' 'Administrators:(OI)(CI)F' | Out-Null
if ($LASTEXITCODE -ne 0) { throw 'Could not secure the agent state directory.' }
Set-Content -LiteralPath $tokenFile -Value $Token -NoNewline -Encoding Ascii
& icacls.exe $tokenFile /inheritance:r /grant:r 'SYSTEM:F' 'Administrators:F' | Out-Null
if ($LASTEXITCODE -ne 0) { throw 'Could not secure the enrollment token.' }
& icacls.exe $root /inheritance:r /grant:r 'SYSTEM:(OI)(CI)F' 'Administrators:(OI)(CI)F' | Out-Null
if ($LASTEXITCODE -ne 0) { throw 'Could not secure the agent program directory.' }

$agentArgs = @('agent', '--server', $Server, '--token-file', $tokenFile, '--fingerprint', $Fingerprint, '--name', $Name, '--state-dir', $state)
$quoted = @($agentArgs | ForEach-Object { '"' + $_.Replace('"','\"') + '"' }) -join ' '
$command = '"' + $binary + '" ' + $quoted
if ($service) {
  $existing = Get-CimInstance Win32_Service -Filter "Name='noobtunnel-agent'"
  $compatible = $existing.PathName.Contains('"' + $binary + '"') -and
    $existing.PathName.Contains('"' + $Server + '"') -and
    $existing.PathName.Contains('"' + $tokenFile + '"') -and
    $existing.PathName.Contains('"' + $Fingerprint + '"') -and
    $existing.PathName.Contains('"' + $state + '"')
  if (-not $compatible) {
    $change = Invoke-CimMethod -InputObject $existing -MethodName Change -Arguments @{PathName=$command;StartMode='Automatic'}
    if ($change.ReturnValue -ne 0) { throw "Could not update the Windows service (Windows error $($change.ReturnValue))." }
  }
} else {
  New-Service -Name 'noobtunnel-agent' -BinaryPathName $command -DisplayName 'noobtunnel agent' -StartupType Automatic | Out-Null
}
Start-Service -Name 'noobtunnel-agent'
if ($env:NOOBTUNNEL_QUICK_SETUP -eq '1') {
  Write-Output 'Agent service started. Verifying enrollment with the control node...'
  exit 0
}
Write-Output 'Waiting for agent to connect...'
$failureSeen = 0
$lastFailure = ''
while ((Get-RemainingSetupSeconds) -gt 0) {
  Start-Sleep -Milliseconds 500
  if (Test-Path -LiteralPath $runtimePath) {
    $runtime = $null
    try { $runtime = Get-Content -LiteralPath $runtimePath -Raw | ConvertFrom-Json } catch { }
    if ($runtime) {
      if ($runtime.connected -and $runtime.address -and -not $runtime.lastError) {
        Write-Output "Agent connected. Mesh address: $($runtime.address)"
        exit 0
      }
      if ($runtime.lastError) {
        if ($runtime.lastError -ne $lastFailure) { Write-Warning "Agent setup: $($runtime.lastError)" }
        $lastFailure = $runtime.lastError
        $failureSeen++
        if ($failureSeen -ge 10) { throw "Agent could not connect: $lastFailure" }
      }
    }
  }
  if ((Get-Service -Name 'noobtunnel-agent').Status -eq 'Stopped') {
    if ($lastFailure) { throw "Agent service stopped: $lastFailure" }
    throw 'Agent service stopped before writing runtime status.'
  }
}
throw 'Setup timed out. Run "C:\Program Files\noobtunnel\noobtunnel.exe" status for details.'

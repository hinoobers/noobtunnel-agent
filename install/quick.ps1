param([string]$Server, [string]$Pin, [string]$Ticket, [long]$Deadline)
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
if ($Deadline -le 0) { $Deadline = [DateTimeOffset]::UtcNow.ToUnixTimeSeconds() + 600 }
function Get-RemainingSetupSeconds {
  $remaining = $Deadline - [DateTimeOffset]::UtcNow.ToUnixTimeSeconds()
  if ($remaining -le 0) { throw 'Quick setup deadline expired. Generate a new command and retry.' }
  return $remaining
}
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

$principal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
  function PSQuote([string]$Value) { return "'" + $Value.Replace("'", "''") + "'" }
  $reentry = '& ' + (PSQuote $PSCommandPath) + ' -Server ' + (PSQuote $Server) + ' -Pin ' + (PSQuote $Pin) + ' -Ticket ' + (PSQuote $Ticket) + ' -Deadline ' + $Deadline
  $reentry = '$ErrorActionPreference=''Stop''; try { ' + $reentry + '; $setupExitCode=$LASTEXITCODE; if (-not [Console]::IsInputRedirected) { [void](Read-Host ''Press Enter to close'') }; exit $setupExitCode } catch { Write-Host (''noobtunnel: '' + $_.Exception.Message) -ForegroundColor Red; if (-not [Console]::IsInputRedirected) { [void](Read-Host ''Press Enter to close'') }; exit 1 }'
  $encoded = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($reentry))
  $process = Start-Process powershell.exe -Verb RunAs -PassThru -Wait -ArgumentList @('-NoProfile', '-ExecutionPolicy', 'Bypass', '-EncodedCommand', $encoded)
  exit $process.ExitCode
}
if ($Server -notmatch '^[A-Za-z0-9.\-]+:\d+$' -or $Pin -notmatch '^[A-Za-z0-9+/]{43}=$') { throw 'Invalid control endpoint or pin' }
$taskDir = Join-Path $env:TEMP ('noobtunnel-quick-' + [Guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $taskDir | Out-Null
try {
  $binary = Join-Path $taskDir 'noobtunnel.exe'
  Fetch-Pinned "https://$Server/download/noobtunnel_windows_amd64.exe" $binary -Resume
  # Keep Quick attached to the console so interactive prompts remain visible.
  $quickProcess = Start-Process -FilePath $binary -NoNewWindow -Wait -PassThru -ArgumentList @('quick', '--server', $Server, '--pin', $Pin, '--ticket', $Ticket, '--deadline', [string]$Deadline)
  $global:LASTEXITCODE = $quickProcess.ExitCode
  if ($LASTEXITCODE -ne 0) { throw 'Quick setup failed; see the message above' }
} finally {
  $resolved = [IO.Path]::GetFullPath($taskDir)
  $tempRoot = [IO.Path]::GetFullPath($env:TEMP).TrimEnd('\') + '\'
  if ($resolved.StartsWith($tempRoot, [StringComparison]::OrdinalIgnoreCase)) { Remove-Item -LiteralPath $resolved -Recurse -Force }
}

# noobtunnel agent

The agent connects your machine to [noobtunnel](https://tunnel.byenoob.com), joins your private mesh, and forwards traffic for services you publish.

## Information sent to the controller

- Agent name, machine hostname, operating system, architecture, and agent version.
- Enrollment token for authentication and the agent's WireGuard public key.
- Advertised routes, local IPv4 subnet ranges, and network interface names.
- Uptime, WireGuard interface settings, and connection errors.
- Traffic byte counts, peer public keys and endpoints, handshake times, and whether connections are direct or relayed.
- When diagnostics are requested: connectivity test results, source addresses, routing details, and available firewall rules and packet counters.

The controller also sees the IP address you connect from. Your WireGuard private key is generated and stored locally.

## Uninstall

On Linux:

```sh
curl -fsSL https://tunnel.byenoob.com/install.sh | sudo sh -s -- --uninstall
```

This removes the local agent but keeps its saved identity. Add `--purge` to remove that identity too. The agent's panel entry is removed separately.

On Windows, run in PowerShell:

```powershell
$script = Join-Path $env:TEMP ("noobtunnel-uninstall-" + [guid]::NewGuid() + ".ps1")
try {
    Invoke-WebRequest https://tunnel.byenoob.com/install.ps1 -UseBasicParsing -OutFile $script -ErrorAction Stop
    powershell.exe -NoProfile -ExecutionPolicy Bypass -File $script -Uninstall
} finally {
    Remove-Item -LiteralPath $script -Force -ErrorAction SilentlyContinue
}
```

This finds the installed agent automatically and removes it from both the PC and the panel, along with its published resources and saved identity. Approve the administrator prompt. Run it on the PC where the agent is installed; any folder works. If the panel entry was already deleted, add `-LocalOnly` after `-Uninstall` to remove only the local installation.

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

On Windows, use the agent's uninstall action in the [panel](https://tunnel.byenoob.com) to get its machine-specific uninstall command.

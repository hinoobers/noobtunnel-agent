//go:build windows

package wg

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/tun"
)

// WindowsBackend runs WireGuard in this process over the signed Wintun driver.
// It needs only wintun.dll beside noobtunnel.exe, not the WireGuard desktop app.
type WindowsBackend struct {
	Runner    Runner
	mu        sync.Mutex
	dev       *device.Device
	iface     string
	addresses []string
	routes    []string
	mtu       int
}

func (b *WindowsBackend) Name() string { return "windows" }

func (b *WindowsBackend) runner() Runner {
	if b.Runner != nil {
		return b.Runner
	}
	return ExecRunner{}
}

func (b *WindowsBackend) Sync(ctx context.Context, iface string, cfg Config) error {
	if err := ValidateInterfaceName(iface); err != nil {
		return err
	}
	// WireGuard's Windows bind uses AI_NUMERICHOST when parsing endpoints.
	// Resolve hostnames before creating the adapter so DNS still uses the
	// machine's ordinary network route.
	cfg.Peers = append([]PeerConfig(nil), cfg.Peers...)
	for i := range cfg.Peers {
		if cfg.Peers[i].Endpoint == "" {
			continue
		}
		endpoint, err := resolveWindowsEndpoint(ctx, cfg.Peers[i].Endpoint)
		if err != nil {
			return fmt.Errorf("resolve WireGuard endpoint %s: %w", cfg.Peers[i].Endpoint, err)
		}
		cfg.Peers[i].Endpoint = endpoint
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.dev == nil {
		mtu := cfg.Interface.MTU
		if mtu == 0 {
			mtu = DefaultMTU
		}
		adapter, err := tun.CreateTUN(iface, mtu)
		if err != nil {
			return fmt.Errorf("create Wintun adapter: %w (is wintun.dll beside noobtunnel.exe, and is this process elevated?)", err)
		}
		b.dev = device.NewDevice(adapter, conn.NewDefaultBind(), device.NewLogger(device.LogLevelError, "noobtunnel: "))
		b.iface = iface
		b.mtu = mtu
	}
	if b.iface != iface {
		return fmt.Errorf("windows backend already uses %s", b.iface)
	}
	ipc, err := windowsIPC(cfg)
	if err != nil {
		return err
	}
	if err := b.dev.IpcSet(ipc); err != nil {
		return fmt.Errorf("configure WireGuard: %w", err)
	}
	if err := b.dev.Up(); err != nil {
		return fmt.Errorf("start WireGuard: %w", err)
	}
	if err := b.syncNetwork(ctx, iface, cfg.Interface.Addresses, cfg.Routes); err != nil {
		return err
	}
	return nil
}

func resolveWindowsEndpoint(ctx context.Context, endpoint string) (string, error) {
	host, port, err := net.SplitHostPort(endpoint)
	if err != nil {
		return "", err
	}
	if ip, err := netip.ParseAddr(host); err == nil {
		return net.JoinHostPort(ip.String(), port), nil
	}
	lookupCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	addresses, err := net.DefaultResolver.LookupNetIP(lookupCtx, "ip", host)
	if err != nil {
		return "", err
	}
	for _, address := range addresses {
		if address.Is4() {
			return net.JoinHostPort(address.String(), port), nil
		}
	}
	if len(addresses) == 0 {
		return "", fmt.Errorf("no IP address for %s", host)
	}
	return net.JoinHostPort(addresses[0].String(), port), nil
}

func windowsFirewallScript(iface string) string {
	return fmt.Sprintf(`$meshRule=Get-NetFirewallRule -Name 'noobtunnel-mesh' -ErrorAction SilentlyContinue;
$meshBindings=@();
if ($meshRule) {
  try { $meshBindings=@($meshRule | Get-NetFirewallInterfaceFilter -ErrorAction Stop | ForEach-Object { $_.InterfaceAlias }) } catch { $meshBindings=@() }
}
$newMeshRule={ New-NetFirewallRule -Name 'noobtunnel-mesh' -DisplayName 'noobtunnel mesh' -Direction Inbound -Action Allow -Profile Any -InterfaceAlias '%s' -ErrorAction Stop | Out-Null };
if (-not $meshRule) {
  & $newMeshRule
} elseif (@($meshRule).Count -ne 1 -or [string]$meshRule.Enabled -ne 'True' -or [string]$meshRule.Direction -ne 'Inbound' -or [string]$meshRule.Action -ne 'Allow' -or [string]$meshRule.Profile -ne 'Any' -or $meshBindings.Count -ne 1 -or $meshBindings[0] -ne '%s') {
  try {
    Set-NetFirewallRule -Name 'noobtunnel-mesh' -InterfaceAlias '%s' -Enabled True -Direction Inbound -Action Allow -Profile Any -ErrorAction Stop | Out-Null
  } catch {
    Remove-NetFirewallRule -Name 'noobtunnel-mesh' -ErrorAction Stop;
    & $newMeshRule
  }
}`, iface, iface, iface)
}

func windowsIPC(cfg Config) (string, error) {
	key, err := keyHex(cfg.Interface.PrivateKey)
	if err != nil {
		return "", fmt.Errorf("private key: %w", err)
	}
	var out strings.Builder
	fmt.Fprintf(&out, "private_key=%s\nlisten_port=%d\nreplace_peers=true\n", key, cfg.Interface.ListenPort)
	for _, peer := range cfg.Peers {
		key, err := keyHex(peer.PublicKey)
		if err != nil {
			return "", fmt.Errorf("peer public key: %w", err)
		}
		fmt.Fprintf(&out, "public_key=%s\nreplace_allowed_ips=true\n", key)
		if peer.PresharedKey != "" {
			psk, err := keyHex(peer.PresharedKey)
			if err != nil {
				return "", fmt.Errorf("peer preshared key: %w", err)
			}
			fmt.Fprintf(&out, "preshared_key=%s\n", psk)
		}
		if peer.Endpoint != "" {
			fmt.Fprintf(&out, "endpoint=%s\n", peer.Endpoint)
		}
		for _, ip := range peer.AllowedIPs {
			if _, err := netip.ParsePrefix(ip); err != nil {
				return "", err
			}
			fmt.Fprintf(&out, "allowed_ip=%s\n", ip)
		}
		fmt.Fprintf(&out, "persistent_keepalive_interval=%d\n", peer.PersistentKeepalive)
	}
	return out.String(), nil
}

func keyHex(key string) (string, error) {
	raw, err := base64.StdEncoding.DecodeString(key)
	if err != nil || len(raw) != 32 {
		return "", fmt.Errorf("invalid WireGuard key")
	}
	return hex.EncodeToString(raw), nil
}

func hexKey(key string) string {
	raw, err := hex.DecodeString(key)
	if err != nil || len(raw) != 32 {
		return ""
	}
	return base64.StdEncoding.EncodeToString(raw)
}

func (b *WindowsBackend) ps(ctx context.Context, script string) error {
	_, err := b.runner().Run(ctx, "powershell.exe", "-NoProfile", "-NonInteractive", "-Command", "$ErrorActionPreference='Stop'; "+script)
	return err
}

// Configure the interface in one PowerShell process. Starting PowerShell and
// loading NetTCPIP separately for every prefix dominates Windows enrollment.
// Commit the cache only after every operation succeeds so failures are retried.
func (b *WindowsBackend) syncNetwork(ctx context.Context, iface string, addresses, routes []string) error {
	if err := ValidateInterfaceName(iface); err != nil {
		return err
	}
	var script strings.Builder
	fmt.Fprintf(&script, "$i=Get-NetAdapter -Name '%s' -ErrorAction Stop;\n", iface)
	want := make(map[string]bool, len(addresses))
	for _, addr := range addresses {
		prefix, err := netip.ParsePrefix(addr)
		if err != nil || !prefix.Addr().Is4() {
			return fmt.Errorf("invalid Windows tunnel address %q", addr)
		}
		want[addr] = true
		if !contains(b.addresses, addr) {
			fmt.Fprintf(&script, "if (-not (Get-NetIPAddress -InterfaceIndex $i.ifIndex -IPAddress '%s' -ErrorAction SilentlyContinue)) { New-NetIPAddress -InterfaceIndex $i.ifIndex -IPAddress '%s' -PrefixLength %d -PolicyStore ActiveStore | Out-Null };\n", prefix.Addr(), prefix.Addr(), prefix.Bits())
		}
	}
	for _, old := range b.addresses {
		if want[old] {
			continue
		}
		prefix, _ := netip.ParsePrefix(old)
		fmt.Fprintf(&script, "Get-NetIPAddress -InterfaceIndex $i.ifIndex -IPAddress '%s' -ErrorAction SilentlyContinue | Remove-NetIPAddress -Confirm:$false;\n", prefix.Addr())
	}
	want = make(map[string]bool, len(routes))
	for _, route := range routes {
		prefix, err := netip.ParsePrefix(route)
		if err != nil || !prefix.Addr().Is4() {
			return fmt.Errorf("invalid Windows mesh route %q", route)
		}
		want[route] = true
		if contains(b.routes, route) {
			continue
		}
		script.WriteString(windowsRouteScript(route))
	}
	for _, old := range b.routes {
		if want[old] {
			continue
		}
		fmt.Fprintf(&script, "Get-NetRoute -DestinationPrefix '%s' -InterfaceIndex $i.ifIndex -NextHop '0.0.0.0' -ErrorAction SilentlyContinue | Remove-NetRoute -Confirm:$false;\n", old)
	}
	script.WriteString(windowsFirewallScript(iface))
	if err := b.ps(ctx, script.String()); err != nil {
		return fmt.Errorf("configure Windows tunnel networking: %w", err)
	}
	b.addresses = append([]string(nil), addresses...)
	b.routes = append([]string(nil), routes...)
	return nil
}

func windowsRouteScript(route string) string {
	return fmt.Sprintf("if (-not (Get-NetRoute -DestinationPrefix '%s' -InterfaceIndex $i.ifIndex -ErrorAction SilentlyContinue)) { New-NetRoute -DestinationPrefix '%s' -InterfaceIndex $i.ifIndex -NextHop '0.0.0.0' -RouteMetric 1000 -PolicyStore ActiveStore | Out-Null };\n", route, route)
}

func contains(items []string, value string) bool {
	for _, item := range items {
		if item == value {
			return true
		}
	}
	return false
}

func (b *WindowsBackend) EnsureRoutes(ctx context.Context, iface string, routes []string) error {
	if err := ValidateInterfaceName(iface); err != nil {
		return err
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	// A Windows route can disappear when the network stack reconfigures. Read it
	// back and recreate it without interrupting the tunnel.
	if len(routes) == 0 {
		return nil
	}
	var script strings.Builder
	fmt.Fprintf(&script, "$i=Get-NetAdapter -Name '%s' -ErrorAction Stop;\n", iface)
	for _, route := range routes {
		if _, err := netip.ParsePrefix(route); err != nil {
			return err
		}
		script.WriteString(windowsRouteScript(route))
	}
	return b.ps(ctx, script.String())
}

func (b *WindowsBackend) Status(_ context.Context, iface string) (InterfaceStatus, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.dev == nil || b.iface != iface {
		return InterfaceStatus{}, ErrNoInterface
	}
	raw, err := b.dev.IpcGet()
	if err != nil {
		return InterfaceStatus{}, err
	}
	status := InterfaceStatus{Name: iface, Exists: true, Addresses: append([]string(nil), b.addresses...), MTU: b.mtu}
	var peer *PeerStatus
	flush := func() {
		if peer != nil {
			status.Peers = append(status.Peers, *peer)
		}
	}
	for _, line := range strings.Split(raw, "\n") {
		key, value, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		switch key {
		case "private_key":
			if priv := hexKey(value); priv != "" {
				status.PublicKey, _ = PublicFromPrivate(priv)
			}
		case "listen_port":
			status.ListenPort, _ = strconv.Atoi(value)
		case "public_key":
			flush()
			peer = &PeerStatus{PublicKey: hexKey(value)}
		case "endpoint":
			if peer != nil {
				peer.Endpoint = value
			}
		case "allowed_ip":
			if peer != nil {
				peer.AllowedIPs = append(peer.AllowedIPs, value)
			}
		case "last_handshake_time_sec":
			if peer != nil {
				sec, _ := strconv.ParseInt(value, 10, 64)
				if sec > 0 {
					peer.LatestHandshake = time.Unix(sec, 0)
				}
			}
		case "rx_bytes":
			if peer != nil {
				peer.RxBytes, _ = strconv.ParseUint(value, 10, 64)
			}
		case "tx_bytes":
			if peer != nil {
				peer.TxBytes, _ = strconv.ParseUint(value, 10, 64)
			}
		case "persistent_keepalive_interval":
			if peer != nil {
				peer.PersistentKeepalive, _ = strconv.Atoi(value)
			}
		case "preshared_key":
			if peer != nil {
				peer.HasPresharedKey = value != strings.Repeat("0", 64)
			}
		}
	}
	flush()
	return status, nil
}

func (b *WindowsBackend) Down(_ context.Context, iface string) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.dev != nil && b.iface == iface {
		b.dev.Close()
		b.dev = nil
		b.iface = ""
		b.addresses = nil
		b.routes = nil
	}
	return nil
}

//go:build windows

package wg

import (
	"context"
	"errors"
	"strings"
	"testing"
)

type windowsNetworkRunner struct {
	scripts []string
	err     error
}

func (r *windowsNetworkRunner) Run(_ context.Context, _ string, args ...string) (string, error) {
	r.scripts = append(r.scripts, args[len(args)-1])
	return "", r.err
}

func TestWindowsNetworkBatchesRoutesAndRetriesFailedConfiguration(t *testing.T) {
	runner := &windowsNetworkRunner{err: errors.New("fixture failure")}
	b := &WindowsBackend{Runner: runner, addresses: []string{"10.77.0.8/32"}, routes: []string{"10.77.0.9/32"}}
	routes := []string{"10.77.0.1/32", "10.77.0.2/32", "10.77.0.3/32", "10.77.0.4/32", "10.77.0.5/32", "10.78.78.1/32", "10.78.78.2/32"}
	addresses := []string{"10.77.0.6/32"}
	if err := b.syncNetwork(context.Background(), "noobtun", addresses, routes); err == nil {
		t.Fatal("configuration failure was ignored")
	}
	if b.addresses[0] != "10.77.0.8/32" || b.routes[0] != "10.77.0.9/32" {
		t.Fatal("failed configuration was cached as successful")
	}
	runner.err = nil
	if err := b.syncNetwork(context.Background(), "noobtun", addresses, routes); err != nil {
		t.Fatal(err)
	}
	if len(runner.scripts) != 2 || runner.scripts[0] != runner.scripts[1] {
		t.Fatal("each attempt must use one process and retry every unfinished operation")
	}
	script := runner.scripts[1]
	if strings.Count(script, "Get-NetAdapter") != 1 || strings.Count(script, "New-NetRoute") != len(routes) {
		t.Fatal("network operations were not batched around a single adapter lookup")
	}
	for _, want := range []string{"New-NetIPAddress", "Remove-NetIPAddress", "Remove-NetRoute", "Set-NetFirewallRule", "New-NetFirewallRule"} {
		if !strings.Contains(script, want) {
			t.Fatalf("missing operation %s", want)
		}
	}
	if len(b.routes) != len(routes) || b.addresses[0] != addresses[0] {
		t.Fatal("successful configuration was not cached")
	}
	runner.scripts = nil
	if err := b.EnsureRoutes(context.Background(), "noobtun", routes); err != nil {
		t.Fatal(err)
	}
	if len(runner.scripts) != 1 || strings.Count(runner.scripts[0], "New-NetRoute") != len(routes) {
		t.Fatal("route repair must recheck every route in one process")
	}
	runner.scripts = nil
	if err := b.EnsureRoutes(context.Background(), "noobtun", []string{"10.77.0.1/32", "invalid'prefix"}); err == nil || len(runner.scripts) != 0 {
		t.Fatal("invalid routes must fail before executing any commands")
	}
}

func TestWindowsIPCUsesUAPIKeysAndRoutes(t *testing.T) {
	self, _ := GenerateKeyPair()
	peer, _ := GenerateKeyPair()
	cfg := Config{Interface: InterfaceConfig{PrivateKey: self.Private, Addresses: []string{"10.77.0.2/32"}, ListenPort: 51820}, Peers: []PeerConfig{{PublicKey: peer.Public, AllowedIPs: []string{"10.77.0.1/32"}, Endpoint: "example.com:51820", PersistentKeepalive: 25}}}
	ipc, err := windowsIPC(cfg)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"private_key=", "listen_port=51820", "replace_peers=true", "public_key=", "allowed_ip=10.77.0.1/32", "endpoint=example.com:51820", "persistent_keepalive_interval=25"} {
		if !strings.Contains(ipc, want) {
			t.Fatalf("missing %q in UAPI config", want)
		}
	}
	if strings.Contains(ipc, "10.77.0.2/32") {
		t.Fatal("interface address must be configured through Windows networking, not WireGuard UAPI")
	}
}

func TestResolveWindowsEndpointToNumericAddress(t *testing.T) {
	got, err := resolveWindowsEndpoint(context.Background(), "localhost:51820")
	if err != nil {
		t.Fatal(err)
	}
	if got != "127.0.0.1:51820" {
		t.Fatalf("got %q, want IPv4 endpoint", got)
	}
	got, err = resolveWindowsEndpoint(context.Background(), "203.0.113.10:51820")
	if err != nil || got != "203.0.113.10:51820" {
		t.Fatalf("numeric endpoint changed: %q, %v", got, err)
	}
}

package agent

import (
	"context"
	"errors"
	"fmt"
	"github.com/hinoobers/noobtunnel-agent/internal/proto"
	"github.com/hinoobers/noobtunnel-agent/internal/wg"
	"io"
	"log/slog"
	"syscall"
	"testing"
)

type portTestBackend struct {
	wg.Backend
	ports    []int
	occupied map[int]bool
	failure  error
}

func (b *portTestBackend) Name() string { return "port-test" }
func (b *portTestBackend) Sync(ctx context.Context, iface string, cfg wg.Config) error {
	b.ports = append(b.ports, cfg.Interface.ListenPort)
	if b.failure != nil {
		return b.failure
	}
	if b.occupied[cfg.Interface.ListenPort] {
		return fmt.Errorf("bind: %w", syscall.EADDRINUSE)
	}
	return nil
}
func (b *portTestBackend) Status(context.Context, string) (wg.InterfaceStatus, error) {
	return wg.InterfaceStatus{}, wg.ErrNoInterface
}
func portTestAgent(t *testing.T, b wg.Backend) *Agent {
	t.Helper()
	kp, err := wg.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	hub, err := wg.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	return &Agent{opts: Options{Interface: "ntport"}, identity: &Identity{PrivateKey: kp.Private}, backend: b, log: slog.New(slog.NewTextHandler(io.Discard, nil)), direct: map[uint32]bool{}, session: &sessionState{welcome: proto.Welcome{AgentID: 4, Address: "10.77.0.4", MeshCIDR: "10.77.0.0/24", Hub: proto.Hub{Address: "10.77.0.1", PublicKey: hub.Public}}}}
}
func TestListenPortFallbackAndStickyFirewallPort(t *testing.T) {
	b := &portTestBackend{occupied: map[int]bool{51824: true, 51825: true}}
	a := portTestAgent(t, b)
	a.opts.SetupSystem = true
	a.hostRunner = &fakeHost{iptables: true}
	if err := a.applyDevice(context.Background(), false); err != nil {
		t.Fatal(err)
	}
	if len(b.ports) != 3 || a.firewallListenPort() != 51826 {
		t.Fatal(b.ports, a.firewallListenPort())
	}
	a.setupHost(context.Background())
	host := a.hostRunner.(*fakeHost)
	if !host.ran("iptables", "-I", "INPUT", "-p", "udp", "--dport", "51826", "-m", "comment", "--comment", "noobtunnel-wireguard", "-j", "ACCEPT") {
		t.Fatal("firewall did not follow selected port")
	}
	if err := a.applyDevice(context.Background(), false); err != nil {
		t.Fatal(err)
	}
	if len(b.ports) != 3 {
		t.Fatal("unchanged config rebound")
	}
	if err := a.applyDevice(context.Background(), true); err != nil {
		t.Fatal(err)
	}
	if b.ports[len(b.ports)-1] != 51826 {
		t.Fatal("lost selected port on resync")
	}
}
func TestListenPortUnrelatedFailureRemainsRetryable(t *testing.T) {
	b := &portTestBackend{failure: errors.New("permission denied")}
	a := portTestAgent(t, b)
	if a.applyDevice(context.Background(), false) == nil || len(b.ports) != 1 {
		t.Fatal("wrong retry")
	}
	b.failure = nil
	if err := a.applyDevice(context.Background(), false); err != nil || len(b.ports) != 2 {
		t.Fatal("failed config was cached", err)
	}
}
func TestListenPortFallbackWrapBoundAndCancel(t *testing.T) {
	b := &portTestBackend{occupied: map[int]bool{65535: true}}
	a := portTestAgent(t, b)
	a.opts.WGListenPort = 65535
	if err := a.applyDevice(context.Background(), false); err != nil || a.firewallListenPort() != 49152 {
		t.Fatal(err, b.ports)
	}
	b = &portTestBackend{failure: syscall.EADDRINUSE}
	a = portTestAgent(t, b)
	if a.applyDevice(context.Background(), false) == nil || len(b.ports) != maxListenPortAttempts {
		t.Fatal("unbounded collision retries")
	}
	b = &portTestBackend{}
	a = portTestAgent(t, b)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if !errors.Is(a.applyDevice(ctx, false), context.Canceled) || len(b.ports) != 0 {
		t.Fatal("ignored cancellation")
	}
}

package agent

import (
	"context"
	"github.com/hinoobers/noobtunnel-agent/internal/wg"
	"net"
	"os"
	"testing"
	"time"
)

// The release verifier runs this only inside a disposable network namespace.
func TestListenPortKernelCollision(t *testing.T) {
	if os.Getenv("NOOBTUNNEL_PORT_KERNEL_TEST") != "1" {
		t.Skip("requires disposable network namespace")
	}
	socket, err := net.ListenPacket("udp4", "0.0.0.0:51824")
	if err != nil {
		t.Fatal(err)
	}
	defer socket.Close()
	backend := &wg.ExecBackend{}
	a := portTestAgent(t, backend)
	a.opts.SetupSystem = true
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	defer backend.Down(context.Background(), a.opts.Interface)
	if err := a.applyDevice(ctx, false); err != nil {
		t.Fatal(err)
	}
	live, err := backend.Status(ctx, a.opts.Interface)
	if err != nil {
		t.Fatal(err)
	}
	if live.ListenPort == 51824 || live.ListenPort != a.firewallListenPort() {
		t.Fatal("did not bind fallback port", live.ListenPort)
	}
	t.Logf("Occupied UDP 51824 preserved; WireGuard bound %d", live.ListenPort)
}

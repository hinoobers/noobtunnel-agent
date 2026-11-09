package agent

import (
	"context"
	"encoding/json"
	"github.com/hinoobers/noobtunnel-agent/internal/netutil"
	"github.com/hinoobers/noobtunnel-agent/internal/wg"
	"net"
	"os"
	"os/exec"
	"testing"
	"time"
)

// Runs only in a disposable namespace prepared by the release verifier.
func TestMeshEndpointKernelFailover(t *testing.T) {
	if os.Getenv("NOOBTUNNEL_MESH_KERNEL_TEST") == "" {
		t.Skip("requires disposable namespaces")
	}
	var config struct{ PrivateKey, HubKey string }
	if err := json.Unmarshal([]byte(os.Getenv("NOOBTUNNEL_MESH_KERNEL_TEST")), &config); err != nil {
		t.Fatal(err)
	}
	backend := &wg.ExecBackend{}
	a := portTestAgent(t, backend)
	a.opts.Interface = "mesh"
	a.opts.StateDir = t.TempDir()
	a.identity.PrivateKey = config.PrivateKey
	a.session.welcome.Hub.PublicKey = config.HubKey
	a.session.welcome.Hub.Endpoints = []string{"192.0.2.99:51820", "192.0.2.1:51820", "192.0.2.3:51820"}
	a.session.welcome.Hub.ProbeAddress = net.JoinHostPort("10.77.0.1", netutil.MeshProbePort)
	a.session.welcome.KeepaliveSec = 1
	ctx, cancel := context.WithTimeout(context.Background(), 55*time.Second)
	defer cancel()
	defer backend.Down(context.Background(), a.opts.Interface)
	if err := a.applyDevice(ctx, true); err != nil {
		t.Fatal(err)
	}
	done := make(chan struct{})
	go func() { defer close(done); a.watchMeshEndpoint(ctx) }()
	defer func() { cancel(); <-done }()
	wait := func(want string) {
		t.Helper()
		for ctx.Err() == nil {
			status, err := backend.Status(ctx, a.opts.Interface)
			if err == nil {
				if peer, ok := status.PeerByKey(config.HubKey); ok && peer.Endpoint == want && netutil.ProbeMesh(ctx, "10.77.0.4", a.session.welcome.Hub.ProbeAddress) {
					t.Log("encrypted path available at", want)
					return
				}
			}
			time.Sleep(250 * time.Millisecond)
		}
		t.Fatal("fallback failed", want)
	}
	wait("192.0.2.1:51820")
	// Only this namespace is affected. Kill the selected public UDP path.
	for _, args := range [][]string{
		{"-I", "OUTPUT", "-d", "192.0.2.1", "-p", "udp", "--dport", "51820", "-j", "DROP"},
		{"-I", "INPUT", "-s", "192.0.2.1", "-p", "udp", "--sport", "51820", "-j", "DROP"},
	} {
		if output, err := exec.Command("iptables", args...).CombinedOutput(); err != nil {
			t.Fatal(err, string(output))
		}
	}
	wait("192.0.2.3:51820")
}

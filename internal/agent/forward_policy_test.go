package agent

import (
	"context"
	"io"
	"log/slog"
	"net"
	"os"
	"testing"

	"github.com/hinoobers/noobtunnel-agent/internal/proto"
)

func TestLoopbackTargets(t *testing.T) {
	for _, target := range []string{"127.0.0.1:25565", "127.0.0.2:80", "[::1]:443", "[::ffff:127.0.0.1]:80", "localhost:25565", "LOCALHOST:80"} {
		resolved, err := resolveLoopbackTarget(target)
		if err != nil {
			t.Fatalf("%s: %v", target, err)
		}
		host, _, _ := net.SplitHostPort(resolved)
		if ip := net.ParseIP(host); ip == nil || !ip.IsLoopback() {
			t.Fatalf("target was not pinned to loopback: %s", resolved)
		}
	}
	for _, target := range []string{"192.168.1.1:80", "10.0.0.1:80", "169.254.169.254:80", "0.0.0.0:80", "[::]:80", "[::ffff:192.168.1.1]:80", "[::1%eth0]:80", "example.com:80", "localhost.example.com:80", "pterodactyl:25565", "127.0.0.1:http", "127.0.0.1:0", "127.0.0.1:65536", "127.0.0.1"} {
		if _, err := resolveLoopbackTarget(target); err == nil {
			t.Errorf("accepted %s", target)
		}
	}
}

func TestLocalForwardPolicy(t *testing.T) {
	dir := t.TempDir()
	a := &Agent{opts: Options{StateDir: dir}}
	if enabled, err := a.loopbackOnly(); enabled || err != nil {
		t.Fatalf("default: %v %v", enabled, err)
	}
	for _, enabled := range []bool{true, false, true} {
		if err := SaveForwardPolicy(dir, ForwardPolicy{LoopbackOnly: enabled}); err != nil {
			t.Fatal(err)
		}
		if got, err := a.loopbackOnly(); got != enabled || err != nil {
			t.Fatalf("round trip: %v %v", got, err)
		}
	}
	a.opts.LoopbackOnly = true
	if err := SaveForwardPolicy(dir, ForwardPolicy{}); err != nil {
		t.Fatal(err)
	}
	if enabled, err := a.loopbackOnly(); !enabled || err != nil {
		t.Fatalf("startup flag must enforce restriction: %v %v", enabled, err)
	}
	a.opts.LoopbackOnly = false
	for _, raw := range []string{`{`, `{}`, `null`, `{"loopbackOnly":null}`, `{"loopbackOnly":"false"}`} {
		if err := os.WriteFile(ForwardPolicyPath(dir), []byte(raw), 0o644); err != nil {
			t.Fatal(err)
		}
		if enabled, err := a.loopbackOnly(); !enabled || err == nil {
			t.Fatalf("invalid policy must restrict forwarding: %s: %v %v", raw, enabled, err)
		}
	}
}

func TestPolicyReloadStopsNonLoopbackForwards(t *testing.T) {
	for _, protocol := range []string{"tcp", "udp"} {
		t.Run(protocol, func(t *testing.T) {
			dir := t.TempDir()
			a := &Agent{
				opts:    Options{StateDir: dir},
				log:     slog.New(slog.NewTextHandler(io.Discard, nil)),
				session: &sessionState{welcome: proto.Welcome{Address: "127.0.0.1"}},
			}
			port := freeTCPPort(t)
			if protocol == "udp" {
				socket, err := net.ListenPacket("udp", "127.0.0.1:0")
				if err != nil {
					t.Fatal(err)
				}
				port = socket.LocalAddr().(*net.UDPAddr).Port
				socket.Close()
			}
			key := forwardKey{network: protocol, port: port}
			a.setForwards([]proto.Forward{{Protocol: protocol, Port: port, Target: "192.0.2.1:25565"}})
			a.syncForwards(context.Background())
			previous := a.forwards[key]
			if previous == nil {
				t.Fatalf("unrestricted listener did not start: %s", a.forwardErrors[key])
			}
			t.Cleanup(func() { a.setForwards(nil); a.syncForwards(context.Background()) })
			if err := SaveForwardPolicy(dir, ForwardPolicy{LoopbackOnly: true}); err != nil {
				t.Fatal(err)
			}
			a.syncForwards(context.Background())
			if a.forwards[key] != nil || a.forwardErrors[key] == "" {
				t.Fatal("controller target bypassed local policy")
			}
			select {
			case <-previous.done:
			default:
				t.Fatal("old forward was not stopped")
			}
			a.setForwards([]proto.Forward{{Protocol: protocol, Port: port, Target: "localhost:25565"}})
			a.syncForwards(context.Background())
			if f := a.forwards[key]; f == nil || f.resolvedTarget != "127.0.0.1:25565" {
				t.Fatal("loopback forward did not start with a pinned destination")
			}
			previous = a.forwards[key]
			if err := SaveForwardPolicy(dir, ForwardPolicy{}); err != nil {
				t.Fatal(err)
			}
			a.syncForwards(context.Background())
			if err := SaveForwardPolicy(dir, ForwardPolicy{LoopbackOnly: true}); err != nil {
				t.Fatal(err)
			}
			a.syncForwards(context.Background())
			if a.forwards[key] != previous {
				t.Fatal("policy change restarted a pinned loopback forward")
			}
		})
	}
}

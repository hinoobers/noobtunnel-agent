package agent

import (
	"context"
	"crypto/sha256"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/hinoobers/noobtunnel-agent/internal/proto"
)

func TestReconnectUsesAuthenticatedBackupDespiteStaleDNS(t *testing.T) {
	a := &Agent{opts: Options{ControlEndpoint: "control.example.com:8443", DialTimeout: time.Second, StateDir: t.TempDir()}}
	a.rememberControls([]string{"8.8.8.8", "1.1.1.1", "127.0.0.1", "invalid", "1.1.1.1"})
	a.lookupControl = func(context.Context, string) ([]net.IPAddr, error) {
		return []net.IPAddr{{IP: net.ParseIP("8.8.8.8")}}, nil
	}
	var cancelled atomic.Bool
	peer, healthy := net.Pipe()
	defer healthy.Close()
	a.dialControl = func(ctx context.Context, target, host string) (net.Conn, error) {
		if host != "control.example.com" {
			t.Errorf("lost logical TLS hostname")
		}
		if strings.HasPrefix(target, "8.8.8.8:") {
			<-ctx.Done()
			cancelled.Store(true)
			return nil, ctx.Err()
		}
		return peer, nil
	}
	start := time.Now()
	conn, err := a.dial(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if time.Since(start) > 700*time.Millisecond {
		t.Fatal("waited for stalled DNS-preferred backend")
	}
	deadline := time.Now().Add(time.Second)
	for !cancelled.Load() && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if !cancelled.Load() {
		t.Fatal("losing attempt not cancelled")
	}
	b := &Agent{opts: a.opts}
	b.loadControls()
	if len(b.controlAddresses) != 2 {
		t.Fatal("untrusted/private peers were persisted", b.controlAddresses)
	}
	b.opts.ControlEndpoint = "another.example.com:8443"
	b.controlAddresses = nil
	b.loadControls()
	if len(b.controlAddresses) != 0 {
		t.Fatal("cache reused for another control hostname")
	}
}

func TestReconnectBoundsDNSFailureAndSkipsFailedPreferredAddress(t *testing.T) {
	a := &Agent{opts: Options{ControlEndpoint: "control.example.com:8443"}, controlAddresses: []string{"8.8.8.8", "1.1.1.1"}}
	a.lookupControl = func(ctx context.Context, _ string) ([]net.IPAddr, error) { <-ctx.Done(); return nil, ctx.Err() }
	start := time.Now()
	targets, err := a.controlTargets(context.Background(), "control.example.com", "8443")
	if err != nil || len(targets) != 2 || time.Since(start) > time.Second {
		t.Fatal("DNS outage prevented known backup", targets, err)
	}
	a.lookupControl = func(context.Context, string) ([]net.IPAddr, error) {
		return []net.IPAddr{{IP: net.ParseIP("8.8.8.8")}}, nil
	}
	a.failedControl("8.8.8.8:8443")
	targets, err = a.controlTargets(context.Background(), "control.example.com", "8443")
	if err != nil || targets[0] != "1.1.1.1:8443" {
		t.Fatal("just-failed POP preferred over backup", targets)
	}
}

func TestReconnectRetainsTLSPinSNIAndUpgradeHost(t *testing.T) {
	observed := make(chan string, 1)
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		observed <- r.TLS.ServerName + "/" + r.Host
		conn, _, err := w.(http.Hijacker).Hijack()
		if err != nil {
			return
		}
		defer conn.Close()
		fmt.Fprint(conn, "HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: noobtunnel\r\n\r\n")
	}))
	defer server.Close()
	sum := sha256.Sum256(server.Certificate().Raw)
	a := &Agent{opts: Options{ControlEndpoint: "control.example.com:8443", Fingerprint: fmt.Sprintf("%x", sum)}}
	conn, err := a.dialControlEndpoint(context.Background(), server.Listener.Addr().String(), "control.example.com")
	if err != nil {
		t.Fatal(err)
	}
	conn.Close()
	if got := <-observed; got != "control.example.com/control.example.com:8443" {
		t.Fatal(got)
	}
	a.opts.Fingerprint = strings.Repeat("0", 64)
	if conn, err := a.dialControlEndpoint(context.Background(), server.Listener.Addr().String(), "control.example.com"); err == nil {
		conn.Close()
		t.Fatal("backup bypassed certificate pin")
	}
	// A cancelled attempt must not wait through a TCP/TLS timeout.
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := a.dialControlEndpoint(ctx, server.Listener.Addr().String(), "control.example.com"); err == nil {
		t.Fatal("ignored cancellation")
	}
}

func TestHeartbeatDetectsSilentConnectionAndKeepsHealthySessionAlive(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	stop := startControlHeartbeat(ctx, client, &connWriter{conn: client}, 20*time.Millisecond)
	defer stop()
	msgs := make(chan rawMessage, 10)
	errs := make(chan error, 1)
	var enabled atomic.Bool
	enabled.Store(true)
	client.SetReadDeadline(time.Now().Add(100 * time.Millisecond))
	go readLoop(client, msgs, errs, &enabled)
	var respond atomic.Bool
	respond.Store(true)
	go func() {
		for {
			typ, raw, err := proto.ReadRaw(server)
			if err != nil {
				return
			}
			if typ == proto.TPing && respond.Load() {
				proto.WriteJSON(server, proto.Pong{T: proto.TPong})
				_ = raw
			}
		}
	}()
	select {
	case <-msgs:
	case err := <-errs:
		t.Fatal(err)
	case <-time.After(time.Second):
		t.Fatal("heartbeat was not answered")
	}
	// Incoming answers extended the read deadline. Outbound-only traffic must
	// not do so when a POP silently stops responding.
	respond.Store(false)
	client.SetReadDeadline(time.Now().Add(100 * time.Millisecond))
	select {
	case err := <-errs:
		if err == nil {
			t.Fatal("missing timeout")
		}
	case <-time.After(time.Second):
		t.Fatal("blackhole remained connected")
	}
}

func TestControlUpgradeHasDeadline(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		io.Copy(io.Discard, conn)
	}()
	a := &Agent{opts: Options{ControlEndpoint: "control.example.com:8443", Insecure: true}, log: slog.Default()}
	start := time.Now()
	_, err = a.dialControlEndpoint(ctx, listener.Addr().String(), "control.example.com")
	if err == nil || time.Since(start) > time.Second {
		t.Fatal("stalled handshake ignored cancellation", err)
	}
}

package agent

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"log/slog"
	"net"
	"os"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"time"
)

func TestUDPReplyPreservesQueuedLargeAndEmptyDatagrams(t *testing.T) {
	backend, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer backend.Close()
	payloads := [][]byte{bytes.Repeat([]byte("z"), 60000), {}, []byte("last")}
	go func() {
		buffer := make([]byte, 8)
		_, peer, err := backend.ReadFrom(buffer)
		if err != nil {
			return
		}
		for _, payload := range payloads {
			if _, err := backend.WriteTo(payload, peer); err != nil {
				return
			}
		}
	}()
	listener, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	defer listener.Close()
	a := &Agent{log: slog.New(slog.NewTextHandler(io.Discard, nil))}
	f := &forwarder{resolvedTarget: backend.LocalAddr().String(), done: make(chan struct{}), agent: a}
	go f.servePackets(ctx, listener)
	client := udpLimitClient(t, listener.LocalAddr().String())
	if _, err := client.Write([]byte("reply")); err != nil {
		t.Fatal(err)
	}
	client.SetDeadline(time.Now().Add(3 * time.Second))
	buffer := make([]byte, udpReplyBufferSize)
	for _, want := range payloads {
		n, err := client.Read(buffer)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(buffer[:n], want) {
			t.Fatalf("datagram changed: bytes=%d want=%d", n, len(want))
		}
	}
	cancel()
	listener.Close()
	waitUDPSlots(t, a, 0)
}

func TestUDPConfiguredTotalSharedAcrossServices(t *testing.T) {
	a := &Agent{opts: Options{UDPMaxSessions: 2, UDPMaxTotalSessions: 2}, log: slog.New(slog.NewTextHandler(io.Discard, nil))}
	left, leftStop := udpLimitFixtureForAgent(t, 2, a)
	right, rightStop := udpLimitFixtureForAgent(t, 2, a)
	first, second, third := udpLimitClient(t, left), udpLimitClient(t, right), udpLimitClient(t, right)
	if err := udpLimitExchange(first, time.Second); err != nil {
		t.Fatal(err)
	}
	if err := udpLimitExchange(second, time.Second); err != nil {
		t.Fatal(err)
	}
	if err := udpLimitExchange(third, 100*time.Millisecond); err == nil {
		t.Fatal("agent-wide budget was not shared between services")
	}
	leftStop()
	waitUDPSlots(t, a, 1)
	if err := udpLimitExchange(third, time.Second); err != nil {
		t.Fatal("released service capacity was not reusable", err)
	}
	rightStop()
	waitUDPSlots(t, a, 0)
}

func TestUDPBudgetConfiguration(t *testing.T) {
	for _, opts := range []Options{{UDPMaxSessions: -1}, {UDPMaxTotalSessions: -1}, {UDPMaxSessions: 3, UDPMaxTotalSessions: 2}} {
		opts.ControlEndpoint = "control.example.com:8443"
		opts.StateDir = t.TempDir()
		if _, err := New(opts); err == nil || !strings.Contains(err.Error(), "UDP") {
			t.Fatal("invalid UDP limits accepted")
		}
	}
	a := &Agent{}
	if cap(a.udpSessionSlots()) != DefaultUDPMaxTotalSessions {
		t.Fatal("default UDP budget changed")
	}
	a = &Agent{opts: Options{UDPMaxTotalSessions: 17000}}
	if cap(a.udpSessionSlots()) != 17000 {
		t.Fatal("configured UDP budget ignored")
	}
}

// Opt-in socket stress test: all traffic stays on loopback, and kernel limits
// can be raised in the test process without altering any installed service.
func TestUDPCapacityHeadroom(t *testing.T) {
	raw := os.Getenv("NOOBTUNNEL_UDP_CAPACITY_TEST")
	if raw == "" {
		t.Skip("set NOOBTUNNEL_UDP_CAPACITY_TEST to a session count")
	}
	n, err := strconv.Atoi(raw)
	if err != nil || n < 1 || n > DefaultUDPMaxTotalSessions {
		t.Fatal("invalid capacity-test session count")
	}
	runtime.GC()
	var before, after runtime.MemStats
	runtime.ReadMemStats(&before)
	a := &Agent{log: slog.New(slog.NewTextHandler(io.Discard, nil))}
	var addresses []string
	var stops []func()
	for i := 0; i < (n+DefaultUDPMaxSessions-1)/DefaultUDPMaxSessions; i++ {
		address, stop := udpLimitFixtureForAgent(t, DefaultUDPMaxSessions, a)
		addresses = append(addresses, address)
		stops = append(stops, stop)
	}
	clients := make([]net.Conn, 0, n)
	defer func() {
		for _, client := range clients {
			client.Close()
		}
	}()
	started := time.Now()
	for i := 0; i < n; i++ {
		client, err := net.Dial("udp", addresses[i/DefaultUDPMaxSessions])
		if err != nil {
			t.Fatalf("client %d: %v", i, err)
		}
		clients = append(clients, client)
		if err := udpLimitExchange(client, 3*time.Second); err != nil {
			t.Fatalf("session %d: %v", i, err)
		}
	}
	if len(a.udpSessionSlots()) != n {
		t.Fatal("sessions above the previous cap were lost")
	}
	runtime.GC()
	runtime.ReadMemStats(&after)
	used := int64(after.HeapAlloc) - int64(before.HeapAlloc)
	t.Logf("%d active UDP sessions; Go heap delta %.1f MiB; setup %s", n, float64(used)/(1<<20), time.Since(started).Round(time.Millisecond))
	if used > int64(n)*16*1024+(16<<20) {
		t.Fatal("idle sessions retain excessive packet-buffer memory")
	}
	for i, client := range clients {
		if err := udpLimitExchange(client, 3*time.Second); err != nil {
			t.Fatal(fmt.Sprintf("session %d failed reuse: %v", i, err))
		}
	}
	for _, stop := range stops {
		stop()
	}
	waitUDPSlots(t, a, 0)
}

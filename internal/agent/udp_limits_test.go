package agent

import (
	"context"
	"io"
	"log/slog"
	"net"
	"testing"
	"time"
)

func udpLimitFixture(t *testing.T, limit int) (string, func(), *Agent) {
	a := &Agent{log: slog.New(slog.NewTextHandler(io.Discard, nil))}
	address, stop := udpLimitFixtureForAgent(t, limit, a)
	return address, stop, a
}

func udpLimitFixtureForAgent(t *testing.T, limit int, agent *Agent) (string, func()) {
	t.Helper()
	backend, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { backend.Close() })
	go func() {
		buffer := make([]byte, 64)
		for {
			n, peer, err := backend.ReadFrom(buffer)
			if err != nil {
				return
			}
			backend.WriteTo(buffer[:n], peer)
		}
	}()
	listener, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	f := &forwarder{resolvedTarget: backend.LocalAddr().String(), done: make(chan struct{}), agent: agent}
	done := make(chan struct{})
	go func() { defer close(done); f.servePacketsWithLimit(ctx, listener, limit) }()
	stop := func() {
		cancel()
		listener.Close()
		select {
		case <-done:
		case <-time.After(time.Second):
			t.Error("UDP forward did not stop")
		}
	}
	t.Cleanup(stop)
	return listener.LocalAddr().String(), stop
}

func udpLimitClient(t *testing.T, address string) net.Conn {
	t.Helper()
	conn, err := net.Dial("udp", address)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { conn.Close() })
	return conn
}

func udpLimitExchange(conn net.Conn, timeout time.Duration) error {
	if err := conn.SetDeadline(time.Now().Add(timeout)); err != nil {
		return err
	}
	if _, err := conn.Write([]byte("ping")); err != nil {
		return err
	}
	buffer := make([]byte, 8)
	_, err := conn.Read(buffer)
	return err
}

func waitUDPSlots(t *testing.T, agent *Agent, want int) {
	t.Helper()
	slots := agent.udpSessionSlots()
	deadline := time.Now().Add(3 * time.Second)
	for len(slots) != want && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if len(slots) != want {
		t.Fatalf("UDP session slots=%d want=%d", len(slots), want)
	}
}

func TestUDPForwardSessionLimitPreservesExistingClients(t *testing.T) {
	address, stop, agent := udpLimitFixture(t, 2)
	first, second, third := udpLimitClient(t, address), udpLimitClient(t, address), udpLimitClient(t, address)
	for _, client := range []net.Conn{first, second} {
		if err := udpLimitExchange(client, time.Second); err != nil {
			t.Fatal(err)
		}
	}
	if err := udpLimitExchange(third, 100*time.Millisecond); err == nil {
		t.Fatal("session limit did not reject new client")
	}
	if err := udpLimitExchange(first, time.Second); err != nil {
		t.Fatal("existing session stopped working at capacity", err)
	}
	waitUDPSlots(t, agent, 2)
	stop()
	waitUDPSlots(t, agent, 0)
}

func TestUDPForwardGlobalBudgetAndRelease(t *testing.T) {
	address, stop, agent := udpLimitFixture(t, 2)
	slots := agent.udpSessionSlots()
	for i := 0; i < cap(slots); i++ {
		slots <- struct{}{}
	}
	reserved := cap(slots)
	defer func() {
		for i := 0; i < reserved; i++ {
			<-slots
		}
	}()
	client := udpLimitClient(t, address)
	if err := udpLimitExchange(client, 100*time.Millisecond); err == nil {
		t.Fatal("global budget did not reject new session")
	}
	<-slots
	reserved--
	if err := udpLimitExchange(client, time.Second); err != nil {
		t.Fatal("released capacity was not reusable", err)
	}
	stop()
	waitUDPSlots(t, agent, reserved)
}

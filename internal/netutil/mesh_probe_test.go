package netutil

import (
	"context"
	"net"
	"testing"
	"time"
)

func TestEndpointChoiceOrderedFallback(t *testing.T) {
	var e EndpointChoice
	candidates := []string{"first", "second", "third"}
	if e.Current(candidates) != "first" {
		t.Fatal("not first")
	}
	if e.Result(candidates, "first", false) {
		t.Fatal("single failure switched")
	}
	e.Result(candidates, "first", true)
	if e.Result(candidates, "first", false) || !e.Result(candidates, "first", false) || e.Current(candidates) != "second" {
		t.Fatal("did not select second")
	}
	if e.Result(candidates, "first", false) {
		t.Fatal("stale check changed selection")
	}
	e.Result(candidates, "second", false)
	e.Result(candidates, "second", false)
	if e.Current(candidates) != "third" {
		t.Fatal("did not select third")
	}
	e.Result(candidates, "third", false)
	e.Result(candidates, "third", false)
	if e.Current(candidates) != "first" {
		t.Fatal("did not retry exhausted list")
	}
	if e.Current([]string{"replacement"}) != "replacement" {
		t.Fatal("removed address retained")
	}
	if e.Current(nil) != "" {
		t.Fatal("empty candidates retained address")
	}
}

func TestMeshProbeRoundTripAndRejectWrongReply(t *testing.T) {
	socket, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	address := socket.LocalAddr().String()
	socket.Close()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { defer close(done); _ = ServeMeshProbe(ctx, address) }()
	defer func() { cancel(); <-done }()
	deadline := time.Now().Add(3 * time.Second)
	for {
		// The first datagram can precede the listener. A full production timeout
		// would consume the entire readiness window before a second attempt.
		attempt, stop := context.WithTimeout(ctx, 100*time.Millisecond)
		healthy := ProbeMesh(attempt, "127.0.0.1", address)
		stop()
		if healthy {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("echo failed")
		}
		time.Sleep(time.Millisecond * 10)
	}
	bad, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer bad.Close()
	go func() {
		buffer := make([]byte, 24)
		_, remote, err := bad.ReadFrom(buffer)
		if err == nil {
			_, _ = bad.WriteTo(make([]byte, 24), remote)
		}
	}()
	if ProbeMesh(ctx, "127.0.0.1", bad.LocalAddr().String()) {
		t.Fatal("accepted wrong nonce")
	}
}

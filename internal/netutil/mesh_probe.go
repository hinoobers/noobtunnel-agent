package netutil

import (
	"bytes"
	"context"
	"crypto/rand"
	"net"
	"sync"
	"time"
)

// MeshProbePort is reachable only on the controller's encrypted mesh address.
const MeshProbePort = "51999"

// ProbeMesh verifies a round trip through WireGuard, not just public TCP reachability.
func ProbeMesh(ctx context.Context, source, target string) bool {
	d := net.Dialer{LocalAddr: &net.UDPAddr{IP: net.ParseIP(source)}}
	ctx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	c, err := d.DialContext(ctx, "udp4", target)
	if err != nil {
		return false
	}
	defer c.Close()
	deadline, _ := ctx.Deadline()
	_ = c.SetDeadline(deadline)
	packet := make([]byte, 24)
	copy(packet, "NTMESH01")
	if _, err := rand.Read(packet[8:]); err != nil {
		return false
	}
	if _, err := c.Write(packet); err != nil {
		return false
	}
	reply := make([]byte, 25)
	n, err := c.Read(reply)
	return err == nil && bytes.Equal(reply[:n], packet)
}

// ServeMeshProbe echoes fixed size challenges. Bind to a mesh IP, never a wildcard.
func ServeMeshProbe(ctx context.Context, address string) error {
	c, err := net.ListenPacket("udp4", address)
	if err != nil {
		return err
	}
	defer c.Close()
	done := make(chan struct{})
	defer close(done)
	go func() {
		select {
		case <-ctx.Done():
			c.Close()
		case <-done:
		}
	}()
	buffer := make([]byte, 25)
	for {
		n, remote, err := c.ReadFrom(buffer)
		if err != nil {
			return err
		}
		if n == 24 && bytes.Equal(buffer[:8], []byte("NTMESH01")) {
			_, _ = c.WriteTo(buffer[:n], remote)
		}
	}
}

// EndpointChoice retains a working candidate until its path fails. Candidates
// are tried in supplied order; exhausting them starts a fresh pass.
type EndpointChoice struct {
	mu       sync.Mutex
	current  string
	failures int
}

func (e *EndpointChoice) Current(candidates []string) string {
	e.mu.Lock()
	defer e.mu.Unlock()
	for _, value := range candidates {
		if value == e.current {
			return value
		}
	}
	e.current = ""
	e.failures = 0
	if len(candidates) > 0 {
		e.current = candidates[0]
	}
	return e.current
}
func (e *EndpointChoice) Result(candidates []string, checked string, healthy bool) bool {
	e.mu.Lock()
	defer e.mu.Unlock()
	if checked != e.current {
		return false
	}
	if healthy {
		e.failures = 0
		return false
	}
	e.failures++
	if e.failures < 2 || len(candidates) < 2 {
		return false
	}
	e.failures = 0
	for i, value := range candidates {
		if value == checked {
			e.current = candidates[(i+1)%len(candidates)]
			return e.current != checked
		}
	}
	return false
}

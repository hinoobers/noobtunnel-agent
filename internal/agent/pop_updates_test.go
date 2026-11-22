package agent

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/hinoobers/noobtunnel-agent/internal/proto"
)

func TestPOPPullPinnedAuthenticatedAndUpdatesRoutes(t *testing.T) {
	list := proto.POPLocations{POPs: []proto.POPLocation{{ID: "one", PublicAddress: "8.8.8.8", MeshAddress: "10.77.0.1"}, {ID: "two", PublicAddress: "1.1.1.1", MeshAddress: "10.79.0.1"}}}
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/agent/pops" || r.Header.Get("Authorization") != "Bearer test-token" {
			t.Error("incorrect POP request")
			w.WriteHeader(401)
			return
		}
		json.NewEncoder(w).Encode(list)
	}))
	defer server.Close()
	backend := &portTestBackend{}
	a := portTestAgent(t, backend)
	a.opts.ControlEndpoint = "controller.invalid:443"
	a.opts.Token = "test-token"
	pin := sha256.Sum256(server.Certificate().Raw)
	a.opts.Fingerprint = hex.EncodeToString(pin[:])
	original := a.session
	target := server.Listener.Addr().String()
	if err := a.refreshPOPs(context.Background(), target); err != nil {
		t.Fatal(err)
	}
	if a.session != original || !slices.Equal(a.controlAddresses, []string{"8.8.8.8", "1.1.1.1"}) {
		t.Fatal("session replaced or missing controllers")
	}
	cfg, err := a.desiredConfig()
	if err != nil || !slices.Contains(cfg.Routes, "10.79.0.1/32") {
		t.Fatal("new POP route missing", err)
	}
	a.opts.Fingerprint = strings.Repeat("0", 64)
	if _, err := a.fetchPOPs(context.Background(), target); err == nil {
		t.Fatal("incorrect certificate pin accepted")
	}
	a.opts.Fingerprint = hex.EncodeToString(pin[:])
	list.POPs[1].PublicAddress = "127.0.0.1"
	if err := a.refreshPOPs(context.Background(), target); err == nil {
		t.Fatal("invalid controller accepted")
	}
	if !slices.Equal(a.controlAddresses, []string{"8.8.8.8", "1.1.1.1"}) {
		t.Fatal("invalid response replaced cached controllers")
	}
}

func TestPOPPullDoesNotFollowRedirects(t *testing.T) {
	destinationHits := 0
	destination := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { destinationHits++ }))
	defer destination.Close()
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { http.Redirect(w, r, destination.URL, 302) }))
	defer server.Close()
	a := &Agent{opts: Options{ControlEndpoint: strings.TrimPrefix(server.URL, "https://"), Insecure: true, Token: "secret"}}
	if _, err := a.fetchPOPs(context.Background(), server.Listener.Addr().String()); err == nil || destinationHits != 0 {
		t.Fatal("followed redirect")
	}
}

func TestPOPNotificationsCoalesce(t *testing.T) {
	a := &Agent{}
	writer := &connWriter{popUpdates: make(chan struct{}, 1)}
	for i := 0; i < 100; i++ {
		if err := a.handleMessage(rawMessage{typ: proto.TPOPsChanged}, writer); err != nil {
			t.Fatal(err)
		}
	}
	if len(writer.popUpdates) != 1 {
		t.Fatal("notifications did not coalesce")
	}
}

func TestPOPUpdateRetriesOnExistingControlConnection(t *testing.T) {
	t.Setenv("NOOBTUNNEL_HOSTS_FILE", t.TempDir()+"/hosts")
	backend := &portTestBackend{}
	a := portTestAgent(t, backend)
	welcome := a.session.welcome
	welcome.T = proto.TWelcome
	welcome.Prefix = 32
	var connections, pulls atomic.Int32
	ready := make(chan struct{})
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/agent/pops" {
			if pulls.Add(1) == 1 {
				w.WriteHeader(503)
				return
			}
			json.NewEncoder(w).Encode(proto.POPLocations{POPs: []proto.POPLocation{{ID: "one", PublicAddress: "8.8.8.8", MeshAddress: "10.77.0.1"}, {ID: "two", PublicAddress: "1.1.1.1", MeshAddress: "10.79.0.1"}}})
			return
		}
		connections.Add(1)
		conn, rw, err := w.(http.Hijacker).Hijack()
		if err != nil {
			return
		}
		defer conn.Close()
		fmt.Fprint(rw, "HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: "+proto.UpgradeToken+"\r\n\r\n")
		rw.Flush()
		magic := make([]byte, len(proto.Magic))
		if _, err = io.ReadFull(conn, magic); err != nil {
			return
		}
		_, raw, err := proto.ReadRaw(conn)
		if err != nil {
			return
		}
		var hello proto.Hello
		if json.Unmarshal(raw, &hello) != nil || !hello.POPPull {
			t.Error("POP pull capability missing")
			return
		}
		if err = proto.WriteJSON(conn, welcome); err != nil {
			return
		}
		if err = proto.WriteJSON(conn, proto.POPsChanged{T: proto.TPOPsChanged}); err != nil {
			return
		}
		close(ready)
		io.Copy(io.Discard, conn)
	}))
	defer server.Close()
	a.opts.ControlEndpoint = strings.TrimPrefix(server.URL, "https://")
	a.opts.Insecure = true
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- a.controlSession(ctx) }()
	defer func() { cancel(); <-done }()
	select {
	case <-ready:
	case <-time.After(3 * time.Second):
		t.Fatal("control handshake failed")
	}
	deadline := time.Now().Add(8 * time.Second)
	for time.Now().Before(deadline) {
		a.mu.Lock()
		updated := slices.Contains(a.controlAddresses, "1.1.1.1")
		a.mu.Unlock()
		if updated {
			if connections.Load() != 1 || pulls.Load() != 2 || !a.Connected() {
				t.Fatal("refresh replaced or disconnected control session")
			}
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("POP refresh did not retry")
}

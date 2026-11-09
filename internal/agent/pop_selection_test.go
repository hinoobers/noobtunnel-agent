package agent

import (
	"context"
	"crypto/sha256"
	"errors"
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

func measurement(best, worst int) controlMeasurement {
	return controlMeasurement{best: time.Duration(best) * time.Millisecond, worst: time.Duration(worst) * time.Millisecond}
}

func TestPOPSelectionRequiresSustainedFasterMeasurements(t *testing.T) {
	cases := []struct {
		name               string
		current, candidate controlMeasurement
		want               bool
	}{
		{"clear improvement", measurement(60, 65), measurement(20, 25), true},
		{"less than old absolute threshold", measurement(30, 32), measurement(18, 20), true},
		{"less than old relative threshold", measurement(100, 101), measurement(79, 80), true},
		{"one millisecond faster", measurement(10, 12), measurement(8, 9), true},
		{"equal latency", measurement(10, 12), measurement(8, 10), false},
		{"one lucky alternative ping", measurement(60, 65), measurement(10, 62), false},
		{"one slow incumbent ping", measurement(20, 120), measurement(21, 22), false},
		{"alternative probe failed", measurement(60, 65), controlMeasurement{err: errors.New("timeout")}, false},
		{"incumbent probe failed", controlMeasurement{err: errors.New("timeout")}, measurement(20, 22), false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			p := controlSelection{}
			for i := 1; i <= controlBetterRounds; i++ {
				got := p.observe("current", map[string]controlMeasurement{"current": tc.current, "candidate": tc.candidate})
				if (got != "") != (tc.want && i == controlBetterRounds) {
					t.Fatalf("round %d: got %q", i, got)
				}
			}
		})
	}
}

func TestPOPSelectionResetsOnLossRegressionAndChangingWinner(t *testing.T) {
	for _, interruption := range []map[string]controlMeasurement{
		{"current": measurement(60, 65), "candidate": {err: errors.New("lost response")}},
		{"current": measurement(60, 65), "candidate": measurement(55, 60)},
		{"current": measurement(60, 65), "other": measurement(20, 25)},
		{"candidate": measurement(20, 25)},
	} {
		p := controlSelection{}
		good := map[string]controlMeasurement{"current": measurement(60, 65), "candidate": measurement(20, 25)}
		for i := 0; i < controlBetterRounds-1; i++ {
			if p.observe("current", good) != "" {
				t.Fatal("moved early")
			}
		}
		if p.observe("current", interruption) != "" {
			t.Fatal("moved despite interruption")
		}
		for i := 0; i < controlBetterRounds-1; i++ {
			if p.observe("current", good) != "" {
				t.Fatal("old confidence survived interruption")
			}
		}
		if p.observe("current", good) != "candidate" {
			t.Fatal("never recovered confidence")
		}
	}
}

func TestPOPSelectionChoosesFastestOfAllAlternatives(t *testing.T) {
	p := controlSelection{}
	results := map[string]controlMeasurement{"current": measurement(30, 32), "close": measurement(26, 28), "fastest": measurement(24, 25)}
	for i := 1; i <= controlBetterRounds; i++ {
		got := p.observe("current", results)
		if i < controlBetterRounds && got != "" {
			t.Fatal("moved after too few rounds", got)
		}
		if i == controlBetterRounds && got != "fastest" {
			t.Fatal("did not choose fastest POP", got)
		}
	}
}

func TestPOPMoveCooldownAndPreferenceSurviveRestartAndFailure(t *testing.T) {
	now := time.Now()
	if controlMoveAllowed(now, now.Add(-time.Minute), time.Time{}) {
		t.Fatal("minimum dwell ignored")
	}
	if controlMoveAllowed(now, now.Add(-time.Hour), now.Add(-9*time.Minute)) {
		t.Fatal("cooldown ignored")
	}
	if !controlMoveAllowed(now, now.Add(-time.Hour), now.Add(-11*time.Minute)) {
		t.Fatal("cooldown never expired")
	}
	a := &Agent{opts: Options{ControlEndpoint: "control.example.com:8443", StateDir: t.TempDir()}, log: slog.New(slog.NewTextHandler(io.Discard, nil))}
	a.rememberControls([]string{"8.8.8.8", "1.1.1.1"})
	client, server := net.Pipe()
	defer server.Close()
	a.acceptControlMove(controlMove{conn: client, target: "1.1.1.1:8443"})
	conn, _, err := a.nextControl(context.Background())
	if err != nil || conn != client {
		t.Fatal("prepared connection was discarded")
	}
	conn.Close()
	b := &Agent{opts: a.opts}
	b.loadControls()
	if b.preferredControl != "1.1.1.1" || b.lastControlMove.IsZero() {
		t.Fatal("move state lost on restart")
	}
	b.lookupControl = func(context.Context, string) ([]net.IPAddr, error) {
		return []net.IPAddr{{IP: net.ParseIP("8.8.8.8")}}, nil
	}
	targets, err := b.controlTargets(context.Background(), "control.example.com", "8443")
	if err != nil || targets[0] != "1.1.1.1:8443" {
		t.Fatal("stale DNS overrode measured preference", targets, err)
	}
	b.failedControl("1.1.1.1:8443")
	b.clearControlPreference("1.1.1.1:8443")
	targets, err = b.controlTargets(context.Background(), "control.example.com", "8443")
	if err != nil || targets[0] != "8.8.8.8:8443" {
		t.Fatal("failed migration did not fall back", targets, err)
	}
	c := &Agent{opts: a.opts}
	c.loadControls()
	if c.preferredControl != "" || c.lastControlMove.IsZero() {
		t.Fatal("failure preference/cooldown not persisted")
	}
}

func TestPOPProbeUsesPinnedTLSAndLocalResponsesWithoutEnrollment(t *testing.T) {
	var requests atomic.Int32
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "HEAD" || r.URL.Path != "/api/public/latency" || r.Host != "control.example.com:8443" || r.TLS.ServerName != "control.example.com" {
			t.Error("incorrect latency request", r.Method, r.URL.Path, r.Host, r.TLS.ServerName)
		}
		if r.Header.Get("Authorization") != "" || r.Header.Get("Cookie") != "" {
			t.Error("probe exposed credentials")
		}
		requests.Add(1)
		w.Header().Set("X-Noobtunnel-POP", "test")
		w.WriteHeader(204)
	}))
	defer server.Close()
	sum := sha256.Sum256(server.Certificate().Raw)
	a := &Agent{opts: Options{ControlEndpoint: "control.example.com:8443", Fingerprint: fmt.Sprintf("%x", sum)}}
	m := a.measureControlPOP(context.Background(), server.Listener.Addr().String(), "control.example.com")
	if m.err != nil || m.best <= 0 || m.worst < m.best || requests.Load() != 3 {
		t.Fatal("probe failed", m, requests.Load())
	}
	a.opts.Fingerprint = strings.Repeat("0", 64)
	if a.measureControlPOP(context.Background(), server.Listener.Addr().String(), "control.example.com").err == nil {
		t.Fatal("probe bypassed TLS pin")
	}
}

func TestPOPProbeRejectsUnavailableOrNonLocalEndpoint(t *testing.T) {
	for _, status := range []int{204, 503} {
		server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(status) }))
		a := &Agent{opts: Options{ControlEndpoint: "control.example.com:8443", Insecure: true}}
		if a.measureControlPOP(context.Background(), server.Listener.Addr().String(), "control.example.com").err == nil {
			t.Fatal("unhealthy or unidentified endpoint accepted")
		}
		server.Close()
	}
}

func TestPOPProbeCancellationAndExplicitIPOptOut(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { <-r.Context().Done() }))
	defer server.Close()
	a := &Agent{opts: Options{ControlEndpoint: "control.example.com:8443", Insecure: true}}
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	start := time.Now()
	if a.measureControlPOP(ctx, server.Listener.Addr().String(), "control.example.com").err == nil || time.Since(start) > time.Second {
		t.Fatal("probe ignored cancellation")
	}
	a.opts.ControlEndpoint = "8.8.8.8:8443"
	done := make(chan struct{})
	go func() { a.watchControlPOPs(context.Background(), "8.8.8.8:8443", make(chan controlMove)); close(done) }()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("IP-pinned agent started migration monitor")
	}
}

func TestRejectedPOPMigrationReturnsToIncumbent(t *testing.T) {
	client, server := net.Pipe()
	defer server.Close()
	a := &Agent{opts: Options{ControlEndpoint: "control.example.com:8443", StateDir: t.TempDir()},
		identity: &Identity{}, log: slog.New(slog.NewTextHandler(io.Discard, nil))}
	a.rememberControls([]string{"8.8.8.8", "1.1.1.1"})
	a.acceptControlMove(controlMove{conn: client, target: "1.1.1.1:8443", from: "8.8.8.8:8443"})
	go func() {
		magic := make([]byte, len(proto.Magic))
		if _, err := io.ReadFull(server, magic); err != nil {
			return
		}
		var hello proto.Hello
		if proto.ReadJSON(server, &hello) != nil {
			return
		}
		_ = proto.WriteJSON(server, proto.Error{T: proto.TError, Code: "token", Message: "not replicated yet"})
	}()
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	err := a.controlSession(ctx)
	if err == nil || errors.Is(err, errTokenRejected) {
		t.Fatal("migration rejection would stop agent", err)
	}
	if a.preferredControl != "8.8.8.8" || a.lastControlMove.IsZero() {
		t.Fatal("incumbent/cooldown lost", a.preferredControl)
	}
}

func TestMeasuredPreferenceResistsRestartRacingAndStillFailsOver(t *testing.T) {
	for _, unavailable := range []bool{false, true} {
		a := &Agent{opts: Options{ControlEndpoint: "control.example.com:8443", DialTimeout: 2 * time.Second},
			controlAddresses: []string{"1.1.1.1", "8.8.8.8"}, preferredControl: "1.1.1.1"}
		a.lookupControl = func(context.Context, string) ([]net.IPAddr, error) {
			return []net.IPAddr{{IP: net.ParseIP("8.8.8.8")}}, nil
		}
		client, server := net.Pipe()
		defer server.Close()
		var fallback atomic.Bool
		a.dialControl = func(ctx context.Context, target, host string) (net.Conn, error) {
			if target == "1.1.1.1:8443" {
				if unavailable {
					<-ctx.Done()
					return nil, ctx.Err()
				}
				select {
				case <-time.After(250 * time.Millisecond):
					return client, nil
				case <-ctx.Done():
					return nil, ctx.Err()
				}
			}
			fallback.Store(true)
			return client, nil
		}
		start := time.Now()
		conn, err := a.dial(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		conn.Close()
		if fallback.Load() != unavailable {
			t.Fatal("restart race ignored preference or prevented failover")
		}
		if unavailable && time.Since(start) > 1900*time.Millisecond {
			t.Fatal("preferred POP delayed fallback too long")
		}
	}
}

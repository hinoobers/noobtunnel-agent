package agent

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"math/rand/v2"
	"net"
	"net/http"
	"net/netip"
	"slices"
	"sync"
	"time"
)

const (
	controlProbeInterval = 30 * time.Second
	controlProbeTimeout  = 3 * time.Second
	controlMoveCooldown  = 10 * time.Minute
	controlMinimumDwell  = 2 * time.Minute
	controlBetterRounds  = 5
)

type controlMeasurement struct {
	best, worst time.Duration
	err         error
}

// Every round compares the alternative's worst RTT with the incumbent's best.
// A single lucky probe or a slow incumbent sample cannot trigger migration.
type controlSelection struct {
	challenger string
	rounds     int
}

func (p *controlSelection) observe(current string, measurements map[string]controlMeasurement) string {
	baseline, ok := measurements[current]
	if !ok || baseline.err != nil || baseline.best <= 0 {
		*p = controlSelection{}
		return ""
	}
	best := ""
	var latency time.Duration
	for target, m := range measurements {
		if target == current || m.err != nil || m.worst <= 0 || m.worst >= baseline.best {
			continue
		}
		if best == "" || m.worst < latency || (m.worst == latency && target < best) {
			best, latency = target, m.worst
		}
	}
	if best == "" {
		*p = controlSelection{}
		return ""
	}
	if p.challenger != best {
		p.challenger, p.rounds = best, 0
	}
	p.rounds++
	if p.rounds >= controlBetterRounds {
		return best
	}
	return ""
}

type controlMove struct {
	conn                     net.Conn
	target                   string
	from                     string
	currentRTT, candidateRTT time.Duration
}

func (a *Agent) nextControl(ctx context.Context) (net.Conn, string, error) {
	a.mu.Lock()
	conn := a.nextControlConn
	from := a.nextControlFrom
	a.nextControlConn = nil
	a.nextControlFrom = ""
	a.mu.Unlock()
	if conn != nil {
		return conn, from, nil
	}
	conn, err := a.dial(ctx)
	return conn, "", err
}

func (a *Agent) closeNextControl() {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.nextControlConn != nil {
		_ = a.nextControlConn.Close()
		a.nextControlConn = nil
	}
}

func (a *Agent) acceptControlMove(move controlMove) {
	host, _, _ := net.SplitHostPort(move.target)
	a.mu.Lock()
	a.preferredControl, a.lastControlMove = host, time.Now()
	a.nextControlConn = move.conn
	a.nextControlFrom = move.from
	a.mu.Unlock()
	a.saveControls()
	a.log.Info("moving to consistently faster POP", "controller", move.target,
		"currentRTT", move.currentRTT.Round(time.Millisecond), "candidateRTT", move.candidateRTT.Round(time.Millisecond),
		"consecutiveChecks", controlBetterRounds, "cooldown", controlMoveCooldown)
}

func (a *Agent) restoreControlAfterMove(from string) {
	host, _, _ := net.SplitHostPort(from)
	a.mu.Lock()
	a.preferredControl = host
	a.mu.Unlock()
	a.saveControls()
}

func (a *Agent) clearControlPreference(target string) {
	host, _, _ := net.SplitHostPort(target)
	a.mu.Lock()
	changed := a.preferredControl == host
	if changed {
		a.preferredControl = ""
	}
	a.mu.Unlock()
	if changed {
		a.saveControls()
	}
}

func controlMoveAllowed(now, connectedAt, lastMove time.Time) bool {
	return now.Sub(connectedAt) >= controlMinimumDwell && (lastMove.IsZero() || now.Sub(lastMove) >= controlMoveCooldown)
}

// Probing never sends an enrollment token or claims a controller session.
// IP-pinned installations deliberately retain the operator's explicit choice.
func (a *Agent) watchControlPOPs(ctx context.Context, current string, moves chan<- controlMove) {
	host, port, err := net.SplitHostPort(a.opts.ControlEndpoint)
	if err != nil {
		return
	}
	if _, err := netip.ParseAddr(host); err == nil {
		return
	}
	connectedAt := time.Now()
	policy := controlSelection{}
	timer := time.NewTimer(controlProbeInterval + time.Duration(rand.Int64N(int64(5*time.Second))))
	defer timer.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-timer.C:
		}
		a.mu.Lock()
		addresses := append([]string(nil), a.controlAddresses...)
		lastMove := a.lastControlMove
		a.mu.Unlock()
		if !lastMove.IsZero() && time.Since(lastMove) < controlMoveCooldown {
			policy = controlSelection{}
			timer.Reset(controlProbeInterval)
			continue
		}
		targets := []string{current}
		for _, ip := range publicControls(addresses) {
			target := net.JoinHostPort(ip, port)
			if !slices.Contains(targets, target) {
				targets = append(targets, target)
			}
		}
		if len(targets) < 2 {
			timer.Reset(controlProbeInterval)
			continue
		}
		measurements := a.measureControlPOPs(ctx, targets, host)
		candidate := policy.observe(current, measurements)
		if candidate != "" && controlMoveAllowed(time.Now(), connectedAt, lastMove) {
			// Warm the actual pinned control upgrade before closing the incumbent.
			// Hello is sent only after transfer, avoiding competing live leases.
			probeCtx, cancel := context.WithTimeout(ctx, controlProbeTimeout)
			conn, err := a.dialControlEndpoint(probeCtx, candidate, host)
			cancel()
			if err == nil {
				move := controlMove{conn: conn, target: candidate, from: current, currentRTT: measurements[current].best, candidateRTT: measurements[candidate].worst}
				select {
				case moves <- move:
					return
				case <-ctx.Done():
					_ = conn.Close()
					return
				}
			}
			policy = controlSelection{}
		}
		timer.Reset(controlProbeInterval + time.Duration(rand.Int64N(int64(5*time.Second))))
	}
}

func (a *Agent) measureControlPOPs(ctx context.Context, targets []string, host string) map[string]controlMeasurement {
	results := make(map[string]controlMeasurement, len(targets))
	var mu sync.Mutex
	var wg sync.WaitGroup
	for _, target := range targets {
		wg.Go(func() {
			probeCtx, cancel := context.WithTimeout(ctx, controlProbeTimeout)
			defer cancel()
			m := a.measureControlPOP(probeCtx, target, host)
			mu.Lock()
			results[target] = m
			mu.Unlock()
		})
	}
	wg.Wait()
	return results
}

func (a *Agent) measureControlPOP(ctx context.Context, target, host string) (m controlMeasurement) {
	conn, err := a.dialControlTLS(ctx, target, host)
	if err != nil {
		m.err = err
		return
	}
	defer conn.Close()
	stop := context.AfterFunc(ctx, func() { _ = conn.Close() })
	defer stop()
	reader := bufio.NewReader(conn)
	for i := 0; i < 3; i++ {
		if err := ctx.Err(); err != nil {
			m.err = err
			return
		}
		_ = conn.SetDeadline(time.Now().Add(controlProbeTimeout))
		request := &http.Request{Method: http.MethodHead}
		start := time.Now()
		_, err := fmt.Fprintf(conn, "HEAD /api/public/latency HTTP/1.1\r\nHost: %s\r\nCache-Control: no-cache\r\n\r\n", a.opts.ControlEndpoint)
		if err != nil {
			m.err = err
			return
		}
		response, err := http.ReadResponse(reader, request)
		if err != nil {
			m.err = err
			return
		}
		elapsed := time.Since(start)
		if elapsed <= 0 {
			elapsed = time.Nanosecond
		}
		_ = response.Body.Close()
		if response.StatusCode != http.StatusNoContent || response.Header.Get("X-Noobtunnel-POP") == "" {
			m.err = errors.New("agent: POP did not answer its local latency probe")
			return
		}
		if m.best == 0 || elapsed < m.best {
			m.best = elapsed
		}
		if elapsed > m.worst {
			m.worst = elapsed
		}
	}
	return
}

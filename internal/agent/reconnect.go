package agent

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math/rand/v2"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"sort"
	"time"

	"github.com/hinoobers/noobtunnel-agent/internal/netutil"
	"github.com/hinoobers/noobtunnel-agent/internal/proto"
)

const (
	controlHeartbeatInterval  = 3 * time.Second
	controlIdleTimeout        = 10 * time.Second
	controlRaceDelay          = 150 * time.Millisecond
	controlPreferredRaceDelay = 1500 * time.Millisecond
	maxControlAddresses       = 8
)

func reconnectDelay(backoff time.Duration) time.Duration {
	// Keep the first retry prompt, with bounded jitter to spread a POP outage.
	return backoff*3/4 + time.Duration(rand.Int64N(int64(backoff/2)+1))
}

type controlCache struct {
	Endpoint  string    `json:"endpoint"`
	Addresses []string  `json:"addresses"`
	Preferred string    `json:"preferred,omitempty"`
	LastMove  time.Time `json:"lastMove,omitempty"`
}

func publicControls(addresses []string) []string {
	result := []string{}
	seen := map[string]bool{}
	for _, raw := range addresses {
		ip, err := netip.ParseAddr(raw)
		if err != nil || !netutil.PublicProbeAddress(ip) {
			continue
		}
		address := ip.Unmap().String()
		if seen[address] {
			continue
		}
		seen[address] = true
		result = append(result, address)
		if len(result) == maxControlAddresses {
			break
		}
	}
	return result
}

func (a *Agent) loadControls() {
	raw, err := os.ReadFile(filepath.Join(a.opts.StateDir, "control-peers.json"))
	if err != nil {
		return
	}
	var saved controlCache
	if json.Unmarshal(raw, &saved) == nil && saved.Endpoint == a.opts.ControlEndpoint {
		a.controlAddresses = publicControls(saved.Addresses)
		for _, ip := range a.controlAddresses {
			if ip == saved.Preferred {
				a.preferredControl = ip
			}
		}
		if saved.LastMove.Before(time.Now()) {
			a.lastControlMove = saved.LastMove
		}
	}
}

func (a *Agent) rememberControls(addresses []string) {
	addresses = publicControls(addresses)
	a.mu.Lock()
	a.controlAddresses = addresses
	a.mu.Unlock()
	a.saveControls()
}

func (a *Agent) saveControls() {
	if a.opts.StateDir == "" {
		return
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	raw, _ := json.Marshal(controlCache{Endpoint: a.opts.ControlEndpoint, Addresses: a.controlAddresses, Preferred: a.preferredControl, LastMove: a.lastControlMove})
	path := filepath.Join(a.opts.StateDir, "control-peers.json")
	if err := os.WriteFile(path+".tmp", raw, 0600); err != nil {
		return
	}
	_ = os.Rename(path+".tmp", path)
}

func (a *Agent) failedControl(address string) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.failedControls == nil {
		a.failedControls = map[string]time.Time{}
	}
	for candidate, at := range a.failedControls {
		if time.Since(at) > 10*time.Second {
			delete(a.failedControls, candidate)
		}
	}
	a.failedControls[address] = time.Now()
}

func (a *Agent) controlTargets(ctx context.Context, host, port string) ([]string, error) {
	if ip, err := netip.ParseAddr(host); err == nil {
		return []string{net.JoinHostPort(ip.String(), port)}, nil
	}
	a.mu.Lock()
	known := append([]string(nil), a.controlAddresses...)
	a.mu.Unlock()
	lookup := a.lookupControl
	if lookup == nil {
		lookup = net.DefaultResolver.LookupIPAddr
	}
	budget := time.Second
	if len(known) > 0 {
		budget = 250 * time.Millisecond
	}
	lookupCtx, cancel := context.WithTimeout(ctx, budget)
	ips, lookupErr := lookup(lookupCtx, host)
	cancel()
	targets := []string{}
	seen := map[string]bool{}
	add := func(ip string) {
		target := net.JoinHostPort(ip, port)
		if !seen[target] && len(targets) < maxControlAddresses {
			seen[target] = true
			targets = append(targets, target)
		}
	}
	for _, ip := range ips {
		add(ip.IP.String())
	}
	for _, ip := range known {
		add(ip)
	}
	if len(targets) == 0 {
		if lookupErr != nil {
			return nil, lookupErr
		}
		return nil, errors.New("agent: control hostname has no addresses")
	}
	a.mu.Lock()
	sort.SliceStable(targets, func(i, j int) bool {
		failedI, failedJ := a.failedControls[targets[i]], a.failedControls[targets[j]]
		badI, badJ := !failedI.IsZero() && time.Since(failedI) <= 10*time.Second, !failedJ.IsZero() && time.Since(failedJ) <= 10*time.Second
		if badI != badJ {
			return !badI
		}
		return targets[i] == net.JoinHostPort(a.preferredControl, port) && targets[j] != net.JoinHostPort(a.preferredControl, port)
	})
	a.mu.Unlock()
	return targets, nil
}

func (a *Agent) dial(ctx context.Context) (net.Conn, error) {
	host, port, err := net.SplitHostPort(a.opts.ControlEndpoint)
	if err != nil {
		return nil, fmt.Errorf("agent: invalid control endpoint: %w", err)
	}
	budget := a.opts.DialTimeout
	if budget <= 0 {
		budget = defaultDialTimeout
	}
	ctx, cancel := context.WithTimeout(ctx, budget)
	defer cancel()
	targets, err := a.controlTargets(ctx, host, port)
	if err != nil {
		return nil, err
	}
	dial := a.dialControl
	if dial == nil {
		dial = a.dialControlEndpoint
	}
	type result struct {
		conn net.Conn
		err  error
	}
	results := make(chan result)
	a.mu.Lock()
	preferFirst := a.preferredControl != "" && targets[0] == net.JoinHostPort(a.preferredControl, port)
	failedAt := a.failedControls[targets[0]]
	preferFirst = preferFirst && (failedAt.IsZero() || time.Since(failedAt) > 10*time.Second)
	a.mu.Unlock()
	for index, target := range targets {
		go func(index int, target string) {
			if index > 0 {
				delay := time.Duration(index) * controlRaceDelay
				if preferFirst {
					delay += controlPreferredRaceDelay - controlRaceDelay
				}
				timer := time.NewTimer(delay)
				defer timer.Stop()
				select {
				case <-ctx.Done():
					return
				case <-timer.C:
				}
			}
			conn, err := dial(ctx, target, host)
			if err != nil && ctx.Err() == nil {
				a.failedControl(target)
			}
			select {
			case results <- result{conn, err}:
			case <-ctx.Done():
				if conn != nil {
					_ = conn.Close()
				}
			}
		}(index, target)
	}
	var lastErr error
	for range targets {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case result := <-results:
			if result.err == nil && result.conn != nil {
				return result.conn, nil
			}
			lastErr = result.err
		}
	}
	return nil, lastErr
}

func startControlHeartbeat(ctx context.Context, conn net.Conn, writer *connWriter, interval time.Duration) context.CancelFunc {
	ctx, cancel := context.WithCancel(ctx)
	go func() {
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		var seq uint64
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				seq++
				if err := writer.send(proto.Ping{T: proto.TPing, Seq: seq}); err != nil {
					_ = conn.Close()
					return
				}
			}
		}
	}()
	return cancel
}

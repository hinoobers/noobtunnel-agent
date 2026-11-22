package agent

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"time"

	"github.com/hinoobers/noobtunnel-agent/internal/netutil"
	"github.com/hinoobers/noobtunnel-agent/internal/proto"
)

func (a *Agent) fetchPOPs(ctx context.Context, controller string) (proto.POPLocations, error) {
	var locations proto.POPLocations
	host, _, err := net.SplitHostPort(a.opts.ControlEndpoint)
	if err != nil {
		return locations, err
	}
	transport := &http.Transport{DisableKeepAlives: true, DialTLSContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
		return a.dialControlTLS(ctx, controller, host)
	}}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, Timeout: 5 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://"+a.opts.ControlEndpoint+"/agent/pops", nil)
	if err != nil {
		return locations, err
	}
	req.Header.Set("Authorization", "Bearer "+a.opts.Token)
	response, err := client.Do(req)
	if err != nil {
		return locations, err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return locations, fmt.Errorf("POP list returned HTTP %d", response.StatusCode)
	}
	const limit = 64 << 10
	raw, err := io.ReadAll(io.LimitReader(response.Body, limit+1))
	if err != nil {
		return locations, err
	}
	if len(raw) > limit {
		return locations, fmt.Errorf("POP list exceeds size limit")
	}
	if err = json.Unmarshal(raw, &locations); err != nil {
		return locations, err
	}
	if err = validatePOPs(locations); err != nil {
		return locations, err
	}
	return locations, nil
}

func validatePOPs(locations proto.POPLocations) error {
	if len(locations.POPs) == 0 || len(locations.POPs) > maxControlAddresses {
		return fmt.Errorf("invalid POP count")
	}
	ids, public, mesh := map[string]bool{}, map[string]bool{}, map[string]bool{}
	for _, pop := range locations.POPs {
		p, err := netip.ParseAddr(pop.PublicAddress)
		if err != nil || !netutil.PublicProbeAddress(p) {
			return fmt.Errorf("invalid POP public address")
		}
		m, err := netip.ParseAddr(pop.MeshAddress)
		if err != nil || !m.Is4() || !m.IsPrivate() {
			return fmt.Errorf("invalid POP mesh address")
		}
		if pop.ID == "" || ids[pop.ID] || public[p.Unmap().String()] || mesh[m.String()] {
			return fmt.Errorf("duplicate POP identity or address")
		}
		ids[pop.ID], public[p.Unmap().String()], mesh[m.String()] = true, true, true
	}
	return nil
}

func (a *Agent) refreshPOPs(ctx context.Context, controller string) error {
	locations, err := a.fetchPOPs(ctx, controller)
	if err != nil {
		return err
	}
	public, mesh := []string{}, []string{}
	for _, pop := range locations.POPs {
		public = append(public, pop.PublicAddress)
		mesh = append(mesh, pop.MeshAddress)
	}
	a.mu.Lock()
	if a.session == nil {
		a.mu.Unlock()
		return errNoSession
	}
	a.session.welcome.ControlAddresses = public
	a.session.welcome.Hub.ControllerAddresses = mesh
	a.mu.Unlock()
	if err = a.applyDevice(ctx, false); err != nil {
		return err
	}
	a.rememberControls(public)
	a.log.Info("updated POP locations", "count", len(public))
	return nil
}

func (a *Agent) watchPOPUpdates(ctx context.Context, controller string, updates <-chan struct{}) {
	for {
		select {
		case <-ctx.Done():
			return
		case <-updates:
		}
		delay := 5 * time.Second
		for {
			if err := a.refreshPOPs(ctx, controller); err == nil {
				break
			} else if ctx.Err() != nil {
				return
			} else {
				a.log.Warn("could not refresh POP locations", "error", err)
			}
			timer := time.NewTimer(delay)
			select {
			case <-ctx.Done():
				timer.Stop()
				return
			case <-timer.C:
			}
			if delay < 30*time.Second {
				delay *= 2
				if delay > 30*time.Second {
					delay = 30 * time.Second
				}
			}
		}
	}
}

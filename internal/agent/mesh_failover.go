package agent

import (
	"context"
	"github.com/hinoobers/noobtunnel-agent/internal/netutil"
	"time"
)

func (a *Agent) watchMeshEndpoint(ctx context.Context) {
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
		welcome, _, _, _, ok := a.snapshot()
		if !ok || len(welcome.Hub.Endpoints) < 2 || welcome.Hub.ProbeAddress == "" {
			continue
		}
		healthy := netutil.ProbeMesh(ctx, welcome.Address, welcome.Hub.ProbeAddress)
		if ctx.Err() != nil {
			return
		}
		if a.meshEndpoint.Result(welcome.Hub.Endpoints, welcome.Hub.Endpoint, healthy) {
			a.log.Warn("mesh address unavailable; trying next address on this POP")
			if err := a.applyDevice(ctx, true); err != nil {
				a.setLastError(err.Error())
			}
		}
	}
}

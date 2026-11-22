package agent

import (
	"context"
	"errors"
	"fmt"
	"github.com/hinoobers/noobtunnel-agent/internal/wg"
	"strings"
	"syscall"
)

const maxListenPortAttempts = 32

// Let WireGuard perform the binding: a separate availability check would race
// other agents. Retry only address-in-use errors, never unrelated setup errors.
func (a *Agent) syncDeviceWithPortFallback(ctx context.Context, cfg *wg.Config) error {
	original := cfg.Interface.ListenPort
	for attempt := 0; attempt < maxListenPortAttempts; attempt++ {
		if err := ctx.Err(); err != nil {
			return err
		}
		err := a.backend.Sync(ctx, a.opts.Interface, *cfg)
		if err == nil {
			a.mu.Lock()
			a.selectedListenPort = cfg.Interface.ListenPort
			a.mu.Unlock()
			if cfg.Interface.ListenPort != original {
				a.log.Info("WireGuard UDP port occupied, using another port", "requestedPort", original, "listenPort", cfg.Interface.ListenPort)
			}
			return nil
		}
		if !listenPortInUse(err) {
			return err
		}
		if attempt == maxListenPortAttempts-1 {
			return fmt.Errorf("no available WireGuard UDP port after %d attempts: %w", maxListenPortAttempts, err)
		}
		cfg.Interface.ListenPort++
		if cfg.Interface.ListenPort > 65535 {
			cfg.Interface.ListenPort = 49152
		}
	}
	panic("unreachable")
}

func listenPortInUse(err error) bool {
	if errors.Is(err, syscall.EADDRINUSE) {
		return true
	}
	// wg(8) and Windows' userspace backend wrap bind errors as command text.
	msg := strings.ToLower(err.Error())
	return strings.Contains(msg, "address already in use") || strings.Contains(msg, "only one usage of each socket address")
}

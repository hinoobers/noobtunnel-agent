package agent

import (
	"errors"
	"fmt"
	"path/filepath"

	"github.com/hinoobers/noobtunnel-agent/internal/wg"
)

// A pinned, authenticated controller can identify a fresh registration trying
// to reuse an old installation's reserved key. Never release that old claim.
func (a *Agent) renewEnrollmentIdentity() error {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.session != nil || a.enrollmentIdentityRotated {
		return errors.New("agent: device identity conflict requires operator review")
	}
	pair, err := wg.GenerateKeyPair()
	if err != nil {
		return fmt.Errorf("agent: generate enrollment identity: %w", err)
	}
	next := *a.identity
	next.PrivateKey, next.PublicKey = pair.Private, pair.Public
	if err := writeIdentity(filepath.Join(a.opts.StateDir, "identity.json"), &next); err != nil {
		return fmt.Errorf("agent: save fresh enrollment identity: %w", err)
	}
	a.identity = &next
	a.enrollmentIdentityRotated = true
	return nil
}

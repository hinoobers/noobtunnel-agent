package agent

import (
	"encoding/json"
	"fmt"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

type ForwardPolicy struct {
	LoopbackOnly bool `json:"loopbackOnly"`
}

func ForwardPolicyPath(stateDir string) string {
	return filepath.Join(stateDir, "forward-policy.json")
}

func LoadForwardPolicy(stateDir string) (ForwardPolicy, error) {
	var policy ForwardPolicy
	if stateDir == "" {
		return policy, nil
	}
	raw, err := os.ReadFile(ForwardPolicyPath(stateDir))
	if os.IsNotExist(err) {
		return policy, nil
	}
	if err != nil {
		return policy, fmt.Errorf("read forwarding policy: %w", err)
	}
	var stored struct {
		LoopbackOnly *bool `json:"loopbackOnly"`
	}
	if err := json.Unmarshal(raw, &stored); err != nil {
		return policy, fmt.Errorf("parse forwarding policy: %w", err)
	}
	if stored.LoopbackOnly == nil {
		return policy, fmt.Errorf("forwarding policy must contain a boolean loopbackOnly setting")
	}
	policy.LoopbackOnly = *stored.LoopbackOnly
	return policy, nil
}

func SaveForwardPolicy(stateDir string, policy ForwardPolicy) error {
	if stateDir == "" {
		return fmt.Errorf("agent state directory is required")
	}
	if err := os.MkdirAll(stateDir, 0o755); err != nil {
		return err
	}
	if err := allowPublicRead(stateDir, true); err != nil {
		return err
	}
	raw, err := json.MarshalIndent(policy, "", "  ")
	if err != nil {
		return err
	}
	file, err := os.CreateTemp(stateDir, ".forward-policy-*")
	if err != nil {
		return fmt.Errorf("write forwarding policy (administrator access may be required): %w", err)
	}
	defer os.Remove(file.Name())
	if _, err = file.Write(raw); err == nil {
		err = file.Sync()
	}
	closeErr := file.Close()
	if err != nil {
		return err
	}
	if closeErr != nil {
		return closeErr
	}
	if err := os.Chmod(file.Name(), 0o644); err != nil {
		return err
	}
	if err := allowPublicRead(file.Name(), false); err != nil {
		return err
	}
	return os.Rename(file.Name(), ForwardPolicyPath(stateDir))
}

func (a *Agent) loopbackOnly() (bool, error) {
	policy, err := LoadForwardPolicy(a.opts.StateDir)
	return a.opts.LoopbackOnly || policy.LoopbackOnly || err != nil, err
}

func resolveLoopbackTarget(target string) (string, error) {
	host, port, err := net.SplitHostPort(target)
	if err != nil {
		return "", err
	}
	n, err := strconv.Atoi(port)
	if err != nil || n < 1 || n > 65535 {
		return "", fmt.Errorf("invalid forwarding port %q", port)
	}
	// Pin localhost without DNS so later resolution cannot select a LAN address.
	if strings.EqualFold(host, "localhost") {
		host = "127.0.0.1"
	}
	ip, err := netip.ParseAddr(host)
	if err != nil || ip.Zone() != "" || !ip.Unmap().IsLoopback() {
		return "", fmt.Errorf("local loopback-only policy blocks target %q; use 127.0.0.1 or ::1", target)
	}
	return net.JoinHostPort(ip.Unmap().String(), strconv.Itoa(n)), nil
}

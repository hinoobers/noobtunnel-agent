package agent

import (
	"context"
	"fmt"
	"net/netip"
	"os/exec"
	"strconv"
	"strings"
)

// hostRunner abstracts host commands for testing.
type hostRunner interface {
	LookPath(name string) (string, error)
	Run(ctx context.Context, name string, args ...string) (string, error)
}

type execHostRunner struct{}

// host returns the runner the agent uses for host commands.
func (a *Agent) host() hostRunner {
	if a.hostRunner != nil {
		return a.hostRunner
	}
	return execHostRunner{}
}

func (execHostRunner) LookPath(name string) (string, error) { return exec.LookPath(name) }

func (execHostRunner) Run(ctx context.Context, name string, args ...string) (string, error) {
	out, err := exec.CommandContext(ctx, name, args...).CombinedOutput()
	if err != nil {
		return string(out), fmt.Errorf("%s %s: %w: %s", name, strings.Join(args, " "), err, strings.TrimSpace(string(out)))
	}
	return string(out), nil
}

// setupHost applies the host-side setup unless the operator turned it off.
func (a *Agent) setupHost(ctx context.Context) {
	if !a.opts.SetupSystem {
		return
	}
	a.allowMeshTraffic(ctx)
}

// meshRawExempt bypasses raw-table container isolation for routed mesh targets.
func (a *Agent) meshRawExempt(ctx context.Context, iface string, prefixes []string) {
	if !a.opts.SetupSystem || len(prefixes) == 0 {
		return
	}
	host := a.host()
	iptables, err := host.LookPath("iptables")
	if err != nil {
		return
	}
	var problems []string
	for _, prefix := range prefixes {
		// The table comes before the operation, so the chain follows `-D`/`-I`
		// where iptables expects it.
		rule := []string{"PREROUTING", "-i", iface, "-d", prefix, "-j", "ACCEPT"}
		for attempts := 0; attempts < 4; attempts++ {
			if _, err := host.Run(ctx, iptables, append([]string{"-t", "raw", "-D"}, rule...)...); err != nil {
				break
			}
		}
		if _, err := host.Run(ctx, iptables, append([]string{"-t", "raw", "-I"}, rule...)...); err != nil {
			problems = append(problems, fmt.Sprintf("iptables -t raw -I PREROUTING -i %s -d %s -j ACCEPT: %v", iface, prefix, err))
		}
	}
	if len(problems) > 0 {
		message := "host firewall: " + strings.Join(problems, "; ")
		a.setLastError(message)
		a.log.Warn("could not exempt mesh traffic in the host's raw table", "problems", message)
		return
	}
	a.log.Debug("mesh traffic is exempt from the host's raw table", "networks", strings.Join(prefixes, ", "))
}

// meshNATExempt preserves source addresses on replies to the mesh.
// Reinsert the exemption ahead of Docker's masquerade rules.
func (a *Agent) meshNATExempt(ctx context.Context, meshCIDR string) {
	if !a.opts.SetupSystem {
		return
	}
	prefix, err := netip.ParsePrefix(strings.TrimSpace(meshCIDR))
	if err != nil || !prefix.Addr().Is4() {
		return
	}
	host := a.host()
	iptables, err := host.LookPath("iptables")
	if err != nil {
		return // No iptables: nothing to order, nft setups are left alone.
	}
	rule := []string{"-t", "nat", "POSTROUTING", "-d", prefix.Masked().String(), "-j", "RETURN"}
	// Delete first so the insert lands at the head of the chain, ahead of
	// anything that would masquerade the packet.
	remove := append([]string{"-t", "nat", "-D"}, rule[2:]...)
	insert := append([]string{"-t", "nat", "-I"}, rule[2:]...)
	_, _ = host.Run(ctx, iptables, remove...)
	if _, err := host.Run(ctx, iptables, insert...); err != nil {
		message := "host NAT: could not keep mesh traffic out of Docker's masquerade rules, " +
			"so services inside containers may answer from the wrong address: " + err.Error()
		a.setLastError(message)
		a.log.Warn("could not exclude the mesh from host NAT", "error", err)
		return
	}
	a.log.Debug("mesh traffic is excluded from host NAT", "mesh", prefix.Masked().String())
}

// allowMeshTraffic permits mesh traffic and enables IPv4 forwarding.
func (a *Agent) allowMeshTraffic(ctx context.Context) {
	if !a.opts.SetupSystem {
		return
	}
	iface := a.opts.Interface
	if iface == "" {
		iface = "noobtun"
	}
	// The controller can add forwarding targets after enrollment.
	advertises := a.advertises()
	var problems []string

	switch {
	case a.ufwActive(ctx):
		if port := a.firewallListenPort(); port > 0 {
			if err := a.ufw("allow", "in", "proto", "udp", "to", "any", "port", strconv.Itoa(port), "comment", "noobtunnel-wireguard"); err != nil {
				problems = append(problems, "ufw WireGuard UDP: "+err.Error())
			}
		}
		// ufw keeps its own chains, so its default deny has to be opened for the
		// mesh interface as well.
		if err := a.ufw("allow", "in", "on", iface); err != nil {
			problems = append(problems, "ufw allow in on "+iface+": "+err.Error())
		}
		// ufw route rules are the FORWARD chain: traffic relayed between the mesh
		// and the networks behind this machine.
		if err := a.ufw("route", "allow", "in", "on", iface); err != nil {
			problems = append(problems, "ufw route allow in on "+iface+": "+err.Error())
		}
		if err := a.ufw("route", "allow", "out", "on", iface); err != nil {
			problems = append(problems, "ufw route allow out on "+iface+": "+err.Error())
		}
	default:
		problems = append(problems, a.iptablesAllow(ctx, iface, true)...)
	}

	if err := a.enableForwarding(ctx); err != nil {
		problems = append(problems, err.Error())
	}
	if len(problems) > 0 {
		// Report setup failures without stopping the control connection.
		a.setLastError("host firewall: " + strings.Join(problems, "; "))
		a.log.Warn("could not open the host firewall for the mesh", "problems", strings.Join(problems, "; "))
		return
	}
	a.log.Info("host firewall allows mesh traffic", "interface", iface, "forwarding", advertises)
}

// ufwActive reports whether ufw is managing this host's firewall.
func (a *Agent) ufwActive(ctx context.Context) bool {
	host := a.host()
	if _, err := host.LookPath("ufw"); err != nil {
		return false
	}
	out, err := host.Run(ctx, "ufw", "status")
	return err == nil && strings.Contains(out, "Status: active")
}

func (a *Agent) ufw(args ...string) error {
	out, err := a.host().Run(context.Background(), "ufw", args...)
	if err == nil {
		return nil
	}
	// Repeating a rule ufw already has is not an error for us.
	if strings.Contains(out, "Skipping") {
		return nil
	}
	return err
}

// iptablesAllow inserts the accept rules a host firewall needs, once.
func (a *Agent) iptablesAllow(ctx context.Context, iface string, advertises bool) []string {
	host := a.host()
	iptables, err := host.LookPath("iptables")
	if err != nil {
		return nil // No iptables: nothing to open, and nft setups are left alone.
	}
	var problems []string
	ensure := func(args ...string) {
		// Remove duplicates and insert ahead of Docker rules that may drop mesh traffic.
		for attempts := 0; attempts < 4; attempts++ {
			if _, err := host.Run(ctx, iptables, append([]string{"-D"}, args...)...); err != nil {
				break
			}
		}
		insert := append([]string{"-I"}, args...)
		if _, err := host.Run(ctx, iptables, insert...); err != nil {
			problems = append(problems, fmt.Sprintf("iptables %s: %v", strings.Join(args, " "), err))
		}
	}
	if port := a.firewallListenPort(); port > 0 {
		ensure("INPUT", "-p", "udp", "--dport", strconv.Itoa(port), "-m", "comment", "--comment", "noobtunnel-wireguard", "-j", "ACCEPT")
	}
	ensure("INPUT", "-i", iface, "-j", "ACCEPT")
	// Oracle images reject OUTPUT to link-local addresses, including controller
	// mesh addresses. Permit mesh replies before that instance-services chain;
	// metadata traffic on the host's ordinary interface remains subject to it.
	ensure("OUTPUT", "-o", iface, "-m", "comment", "--comment", "noobtunnel-mesh-output", "-j", "ACCEPT")
	if advertises {
		ensure("FORWARD", "-i", iface, "-j", "ACCEPT")
		ensure("FORWARD", "-o", iface, "-j", "ACCEPT")
		// Clamp TCP segments to the path MTU for forwarded traffic.
		clamp := []string{"FORWARD", "-p", "tcp", "--tcp-flags", "SYN,RST", "SYN",
			"-j", "TCPMSS", "--clamp-mss-to-pmtu"}
		check := append([]string{"-t", "mangle", "-C"}, clamp...)
		if _, err := host.Run(ctx, iptables, check...); err != nil {
			appendRule := append([]string{"-t", "mangle", "-A"}, clamp...)
			if _, err := host.Run(ctx, iptables, appendRule...); err != nil {
				problems = append(problems, fmt.Sprintf("iptables mangle TCPMSS clamping: %v", err))
			}
		}
	}
	return problems
}

// enableForwarding turns on IPv4 forwarding, which relaying between the mesh and
// an advertised network needs.
func (a *Agent) enableForwarding(ctx context.Context) error {
	host := a.host()
	// Avoid writing read-only container sysctls when forwarding is already enabled.
	if out, err := host.Run(ctx, "sysctl", "-n", "net.ipv4.ip_forward"); err == nil {
		if strings.TrimSpace(out) == "1" {
			return nil
		}
	}
	if _, err := host.Run(ctx, "sysctl", "-w", "net.ipv4.ip_forward=1"); err != nil {
		if out, readErr := host.Run(ctx, "sysctl", "-n", "net.ipv4.ip_forward"); readErr == nil && strings.TrimSpace(out) == "1" {
			return nil
		}
		return fmt.Errorf("ipv4 forwarding: %w", err)
	}
	return nil
}

// firewallListenPort exposes only the port successfully bound by our device.
// Never open the preferred port while it may belong to another program.
func (a *Agent) firewallListenPort() int {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.selectedListenPort
}

func (a *Agent) desiredListenPort() int {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.selectedListenPort > 0 {
		return a.selectedListenPort
	}
	if a.opts.WGListenPort > 0 {
		return a.opts.WGListenPort
	}
	if a.session == nil {
		return 0
	}
	return defaultAgentListenPort(a.session.welcome.AgentID)
}

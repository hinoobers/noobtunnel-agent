package main

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"time"

	"github.com/hinoobers/noobtunnel-agent/internal/agent"
)

func runInfo(args []string) error {
	fs := newFlagSet("info")
	stateDir := fs.String("state-dir", env("NOOBTUNNEL_STATE_DIR", defaultStateDir()), "agent state directory")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 0 {
		return fmt.Errorf("usage: noobtunnel info [--state-dir DIR]")
	}
	printVersion()
	fmt.Printf("state directory %s\n\n", *stateDir)
	if _, err := os.Stat(agent.RuntimePath(*stateDir)); os.IsNotExist(err) {
		fmt.Println("No local agent status yet.")
	} else {
		state, err := agent.LoadRuntime(*stateDir)
		if err != nil {
			return err
		}
		fmt.Print(state.Describe())
		if time.Since(state.UpdatedAt) > time.Minute {
			fmt.Println("Status is over a minute old; the agent may have stopped.")
		}
	}
	policy, err := agent.LoadForwardPolicy(*stateDir)
	if err != nil {
		return err
	}
	fmt.Printf("\nloopback-only  %s (local setting)\n", policyLabel(policy.LoopbackOnly))
	fmt.Println("\nCommands: status, info, version, loopback-only [on|off|status], help")
	return nil
}

func runLoopbackOnly(args []string) error {
	fs := newFlagSet("loopback-only")
	stateDir := fs.String("state-dir", env("NOOBTUNNEL_STATE_DIR", defaultStateDir()), "agent state directory")
	action := "status"
	actionProvided := false
	if len(args) > 0 && (args[0] == "on" || args[0] == "off" || args[0] == "status") {
		action, args = args[0], args[1:]
		actionProvided = true
	}
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() > 1 || (actionProvided && fs.NArg() != 0) {
		return fmt.Errorf("usage: noobtunnel loopback-only [on|off|status] [--state-dir DIR]")
	}
	if fs.NArg() == 1 {
		action = fs.Arg(0)
	}
	if action != "on" && action != "off" && action != "status" {
		return fmt.Errorf("expected on, off or status")
	}
	policy, err := agent.LoadForwardPolicy(*stateDir)
	if err != nil && action == "status" {
		return err
	}
	if action != "status" {
		if _, err := os.Stat(filepath.Join(*stateDir, "identity.json")); err != nil {
			return fmt.Errorf("no installed agent identity in %s; select its directory with --state-dir", *stateDir)
		}
		policy.LoopbackOnly = action == "on"
		if err := agent.SaveForwardPolicy(*stateDir, policy); err != nil {
			if runtime.GOOS == "windows" && errors.Is(err, os.ErrPermission) {
				return fmt.Errorf("access denied, are we running as Admin?")
			}
			return err
		}
	}
	fmt.Printf("Loopback-only: %s\n", policyLabel(policy.LoopbackOnly))
	if state, err := agent.LoadRuntime(*stateDir); err == nil {
		fmt.Printf("Agent last reported: %s\n", policyLabel(state.LoopbackOnly))
	}
	if action != "status" {
		fmt.Println("Saved locally. Updated agents apply changes within 30 seconds while connected.")
	}
	fmt.Println("Applies to service forwarding. Mesh access and advertised routes are separate.")
	fmt.Println("An agent started with --loopback-only keeps the restriction enabled.")
	return nil
}

func policyLabel(enabled bool) string {
	if enabled {
		return "on"
	}
	return "off"
}

//go:build !windows

package main

import "github.com/hinoobers/noobtunnel-agent/internal/agent"

func runAgentAsWindowsService(_ *agent.Agent) (bool, error) { return false, nil }

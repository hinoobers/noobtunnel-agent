package main

import (
	"strings"
	"testing"
)

func TestAgentRejectsInvalidUDPLimitsBeforeStarting(t *testing.T) {
	for _, args := range [][]string{
		{"--udp-max-sessions", "0"},
		{"--udp-max-total-sessions", "-1"},
		{"--udp-max-sessions", "10", "--udp-max-total-sessions", "9"},
	} {
		if err := runAgent(args); err == nil || !strings.Contains(err.Error(), "UDP session limits") {
			t.Fatalf("invalid limits accepted: %v", err)
		}
	}
	t.Setenv("NOOBTUNNEL_SERVER", "")
	t.Setenv("NOOBTUNNEL_UDP_MAX_SESSIONS", "20000")
	t.Setenv("NOOBTUNNEL_UDP_MAX_TOTAL_SESSIONS", "10000")
	if err := runAgent(nil); err == nil || !strings.Contains(err.Error(), "UDP session limits") {
		t.Fatal("environment limits not validated", err)
	}
	if err := runAgent([]string{"--udp-max-sessions", "3000", "--udp-max-total-sessions", "6000"}); err == nil || !strings.Contains(err.Error(), "--server is required") {
		t.Fatal("flags did not override environment", err)
	}
}

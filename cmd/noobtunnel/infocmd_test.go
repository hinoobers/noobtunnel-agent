package main

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/hinoobers/noobtunnel-agent/internal/agent"
)

func TestLoopbackCommand(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("NOOBTUNNEL_STATE_DIR", dir)
	if err := runLoopbackOnly([]string{"on"}); err == nil {
		t.Fatal("must not create settings for an unidentified agent")
	}
	if err := os.WriteFile(filepath.Join(dir, "identity.json"), []byte(`{}`), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, args := range [][]string{{"on"}, {"off"}, {"--state-dir", dir, "on"}} {
		if err := runLoopbackOnly(args); err != nil {
			t.Fatal(err)
		}
		policy, err := agent.LoadForwardPolicy(dir)
		want := args[len(args)-1] == "on"
		if err != nil || policy.LoopbackOnly != want {
			t.Fatalf("policy after %v: %+v %v", args, policy, err)
		}
	}
	if err := runLoopbackOnly(nil); err != nil {
		t.Fatal(err)
	}
	if policy, _ := agent.LoadForwardPolicy(dir); !policy.LoopbackOnly {
		t.Fatal("status must not modify the local policy")
	}
	if err := runLoopbackOnly([]string{"invalid"}); err == nil {
		t.Fatal("invalid action accepted")
	}
	if err := runLoopbackOnly([]string{"on", "off"}); err == nil {
		t.Fatal("conflicting actions accepted")
	}
}

func TestInfoWithoutInstalledAgent(t *testing.T) {
	t.Setenv("NOOBTUNNEL_STATE_DIR", t.TempDir())
	if err := runInfo(nil); err != nil {
		t.Fatal(err)
	}
}

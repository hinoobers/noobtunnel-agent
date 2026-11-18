package agent

import (
	"slices"
	"testing"

	"github.com/hinoobers/noobtunnel-agent/internal/proto"
)

func TestControllerOriginsPreserveCrossPOPServiceSources(t *testing.T) {
	a := &Agent{identity: &Identity{}, session: &sessionState{welcome: proto.Welcome{
		AgentID: 9, Address: "10.77.0.2", MeshCIDR: "10.77.0.0/24",
		Hub: proto.Hub{Address: "10.78.77.2", PublicKey: "hub", ControllerAddresses: []string{"10.77.0.1", "10.78.77.2", "192.0.2.1", "invalid"}},
	}}}
	cfg, err := a.desiredConfig()
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Contains(cfg.Routes, "10.77.0.1/32") {
		t.Fatal("remote controller reply route missing")
	}
	for _, peer := range cfg.Peers {
		if peer.PublicKey != "hub" {
			continue
		}
		if !slices.Contains(peer.AllowedIPs, "10.77.0.1/32") {
			t.Fatal("remote controller source rejected by hub peer")
		}
		if slices.Contains(peer.AllowedIPs, "192.0.2.1/32") {
			t.Fatal("public address authorized as controller source")
		}
		return
	}
	t.Fatal("hub peer missing")
}

package agent

import (
	"encoding/json"
	"errors"
	"github.com/hinoobers/noobtunnel-agent/internal/proto"
	"github.com/hinoobers/noobtunnel-agent/internal/wg"
	"testing"
)

func TestMeshEndpointSelectionUpdatesDesiredConfig(t *testing.T) {
	a := portTestAgent(t, &portTestBackend{})
	a.session.welcome.Hub.Endpoints = []string{"192.0.2.1:51820", "192.0.2.2:51820"}
	cfg, err := a.desiredConfig()
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Peers[0].Endpoint != "192.0.2.1:51820" {
		t.Fatal(cfg.Peers)
	}
	a.meshEndpoint.Result(a.session.welcome.Hub.Endpoints, "192.0.2.1:51820", false)
	a.meshEndpoint.Result(a.session.welcome.Hub.Endpoints, "192.0.2.1:51820", false)
	cfg, err = a.desiredConfig()
	if err != nil || cfg.Peers[0].Endpoint != "192.0.2.2:51820" {
		t.Fatal(err, cfg.Peers)
	}
	// A normal membership snapshot must not reset a healthy fallback to primary.
	raw, _ := json.Marshal(proto.Peers{T: proto.TPeers, HubEndpoints: a.session.welcome.Hub.Endpoints})
	if err := a.handleMessage(rawMessage{typ: proto.TPeers, raw: raw}, nil); err != nil && !errors.Is(err, wg.ErrNoInterface) {
		t.Fatal(err)
	}
	welcome, _, _, _, _ := a.snapshot()
	if welcome.Hub.Endpoint != "192.0.2.2:51820" {
		t.Fatal("snapshot reset selected fallback")
	}
}

package topology

import (
	"net/netip"
	"testing"

	"github.com/hinoobers/noobtunnel-agent/internal/wg"
)

func mustAddr(t *testing.T, s string) netip.Addr {
	t.Helper()
	addr, err := netip.ParseAddr(s)
	if err != nil {
		t.Fatal(err)
	}
	return addr
}

func mustPrefix(t *testing.T, s string) netip.Prefix {
	t.Helper()
	prefix, err := netip.ParsePrefix(s)
	if err != nil {
		t.Fatal(err)
	}
	return prefix
}

func testMesh() Mesh {
	return Mesh{
		CIDR:          netip.MustParsePrefix("10.77.0.0/16"),
		MTU:           1420,
		KeepaliveSec:  25,
		DirectEnabled: true,
	}
}

func stubAgent(id uint32, name, addr string, advertise ...string) Member {
	member := Member{
		ID:      id,
		Name:    name,
		Address: netip.MustParseAddr(addr),
		Enabled: true,
		Online:  true,
	}
	for _, raw := range advertise {
		member.Advertise = append(member.Advertise, netip.MustParsePrefix(raw))
	}
	return member
}

func hubPeer(cfg wg.Config, key string) (wg.PeerConfig, bool) {
	for _, peer := range cfg.Peers {
		if peer.PublicKey == key {
			return peer, true
		}
	}
	return wg.PeerConfig{}, false
}

func TestRelayedPeerIsOwnedByHub(t *testing.T) {
	self := stubAgent(1, "self", "10.77.0.2")
	hub := HubMember{
		Address:      mustAddr(t, "10.77.0.1"),
		PublicKey:    "HUBKEY",
		Endpoint:     "203.0.113.1:51820",
		PresharedKey: "HUBPSK",
	}
	peer := stubAgent(2, "peer", "10.77.0.3", "192.168.5.0/24")
	peer.PublicKey = "PEERKEY"
	// No endpoint: the peer is not directly reachable, so everything goes
	// through the hub.
	cfg, _ := BuildAgentConfig(AgentInput{
		Mesh:       testMesh(),
		Self:       self,
		Hub:        hub,
		WGPort:     51821,
		Peers:      []Member{peer},
		PrivateKey: "SELFPRIV",
		PairKeys:   map[uint32]string{2: "PAIRPSK"},
		Direct:     map[uint32]bool{},
	})
	if cfg.Interface.ListenPort != 51821 {
		t.Fatalf("agent listen port = %d, want stable port 51821", cfg.Interface.ListenPort)
	}

	hubEntry, ok := hubPeer(cfg, "HUBKEY")
	if !ok {
		t.Fatal("hub peer missing")
	}
	if !contains(hubEntry.AllowedIPs, "10.77.0.3/32") {
		t.Fatalf("hub should own the unreachable peer's address, got %v", hubEntry.AllowedIPs)
	}
	if !contains(hubEntry.AllowedIPs, "192.168.5.0/24") || !contains(cfg.Routes, "192.168.5.0/24") {
		t.Fatalf("hub should carry the shared network while the peer is relayed: %v, routes %v", hubEntry.AllowedIPs, cfg.Routes)
	}
	if !contains(hubEntry.AllowedIPs, "10.77.0.1/32") {
		t.Fatalf("hub should own its own address, got %v", hubEntry.AllowedIPs)
	}
	if _, exists := hubPeer(cfg, "PEERKEY"); exists {
		t.Fatal("a peer without an endpoint must not be configured directly")
	}
	if !contains(cfg.Routes, "10.77.0.0/16") {
		t.Fatalf("mesh route missing from %v", cfg.Routes)
	}
}

func TestDirectPeerOwnsItsPrefixes(t *testing.T) {
	self := stubAgent(1, "self", "10.77.0.2")
	hub := HubMember{Address: mustAddr(t, "10.77.0.1"), PublicKey: "HUBKEY", Endpoint: "203.0.113.1:51820"}
	peer := stubAgent(2, "peer", "10.77.0.3", "192.168.5.0/24")
	peer.PublicKey = "PEERKEY"
	peer.Endpoint = "198.51.100.9:51820"

	cfg, _ := BuildAgentConfig(AgentInput{
		Mesh:       testMesh(),
		Self:       self,
		Hub:        hub,
		Peers:      []Member{peer},
		PrivateKey: "SELFPRIV",
		PairKeys:   map[uint32]string{2: "PAIRPSK"},
		Direct:     map[uint32]bool{2: true},
	})

	direct, ok := hubPeer(cfg, "PEERKEY")
	if !ok {
		t.Fatal("direct peer missing")
	}
	if direct.PresharedKey != "PAIRPSK" {
		t.Fatalf("direct peer should use the pairwise key, got %q", direct.PresharedKey)
	}
	if direct.Endpoint != "198.51.100.9:51820" {
		t.Fatalf("direct peer endpoint = %q", direct.Endpoint)
	}
	if !contains(direct.AllowedIPs, "10.77.0.3/32") {
		t.Fatalf("a direct peer should own its mesh address, got %v", direct.AllowedIPs)
	}
	if !contains(direct.AllowedIPs, "192.168.5.0/24") {
		t.Fatalf("direct peer should carry its shared network, got %v", direct.AllowedIPs)
	}
	hubEntry, _ := hubPeer(cfg, "HUBKEY")
	if contains(hubEntry.AllowedIPs, "10.77.0.3/32") {
		t.Fatalf("ownership must move off the hub, hub still has %v", hubEntry.AllowedIPs)
	}
	if contains(hubEntry.AllowedIPs, "192.168.5.0/24") {
		t.Fatalf("advertised prefix must move off the hub, hub still has %v", hubEntry.AllowedIPs)
	}
	if !contains(cfg.Routes, "192.168.5.0/24") {
		t.Fatalf("shared network needs a kernel route: %v", cfg.Routes)
	}
}

func TestProbePeerHasNoAllowedIPs(t *testing.T) {
	self := stubAgent(1, "self", "10.77.0.2")
	hub := HubMember{Address: mustAddr(t, "10.77.0.1"), PublicKey: "HUBKEY", Endpoint: "203.0.113.1:51820"}
	peer := stubAgent(2, "peer", "10.77.0.3")
	peer.PublicKey = "PEERKEY"
	peer.Endpoint = "198.51.100.9:51820"

	cfg, _ := BuildAgentConfig(AgentInput{
		Mesh: testMesh(), Self: self, Hub: hub, Peers: []Member{peer},
		PrivateKey: "SELFPRIV", Direct: map[uint32]bool{},
	})
	probe, ok := hubPeer(cfg, "PEERKEY")
	if !ok {
		t.Fatal("a peer with an endpoint should still be probed")
	}
	if len(probe.AllowedIPs) != 0 {
		t.Fatalf("a probe must not claim prefixes until the path is proven, got %v", probe.AllowedIPs)
	}
	if probe.PersistentKeepalive == 0 {
		t.Fatal("a probe needs keepalives to trigger handshakes")
	}
	hubEntry, _ := hubPeer(cfg, "HUBKEY")
	if !contains(hubEntry.AllowedIPs, "10.77.0.3/32") {
		t.Fatalf("traffic must keep flowing through the hub while probing: %v", hubEntry.AllowedIPs)
	}
}

func TestDirectDisabledRelaysEverything(t *testing.T) {
	mesh := testMesh()
	mesh.DirectEnabled = false
	self := stubAgent(1, "self", "10.77.0.2")
	hub := HubMember{Address: mustAddr(t, "10.77.0.1"), PublicKey: "HUBKEY", Endpoint: "203.0.113.1:51820"}
	peer := stubAgent(2, "peer", "10.77.0.3")
	peer.PublicKey = "PEERKEY"
	peer.Endpoint = "198.51.100.9:51820"

	cfg, _ := BuildAgentConfig(AgentInput{
		Mesh: mesh, Self: self, Hub: hub, Peers: []Member{peer},
		PrivateKey: "SELFPRIV", Direct: map[uint32]bool{2: true},
	})
	if _, exists := hubPeer(cfg, "PEERKEY"); exists {
		t.Fatal("direct paths are disabled, no direct peer entry should exist")
	}
	hubEntry, _ := hubPeer(cfg, "HUBKEY")
	if !contains(hubEntry.AllowedIPs, "10.77.0.3/32") {
		t.Fatalf("hub must carry the peer: %v", hubEntry.AllowedIPs)
	}
}

func TestAdvertiseSanitisation(t *testing.T) {
	mesh := testMesh()
	self := stubAgent(1, "self", "10.77.0.2", "192.168.1.0/24")
	ok, rejected := mesh.Sanitise([]netip.Prefix{
		mustPrefix(t, "192.168.1.0/24"), // our own advertised range
		mustPrefix(t, "10.77.0.0/16"),   // the mesh itself
		mustPrefix(t, "0.0.0.0/0"),      // the whole internet
		mustPrefix(t, "127.0.0.0/8"),    // loopback
		mustPrefix(t, "10.77.0.2/32"),   // our own address
		mustPrefix(t, "172.20.0.0/16"),  // fine
	}, self, []netip.Prefix{mustPrefix(t, "192.168.1.0/24")})

	if len(ok) != 1 || ok[0].String() != "172.20.0.0/16" {
		t.Fatalf("accepted = %v, want only 172.20.0.0/16", ok)
	}
	if len(rejected) != 5 {
		t.Fatalf("rejected = %d entries, want 5: %v", len(rejected), rejected)
	}
}

func TestAdvertiseConflictsResolvedDeterministically(t *testing.T) {
	mesh := testMesh()
	members := []Member{
		stubAgent(3, "third", "10.77.0.4", "192.168.50.0/24"),
		stubAgent(2, "second", "10.77.0.3", "192.168.50.0/24"),
	}
	owners, rejected := mesh.ResolveAdvertise(members)
	if len(owners[2]) != 1 {
		t.Fatalf("the lower member id should win the conflict, got %v", owners[2])
	}
	if len(owners[3]) != 0 {
		t.Fatalf("the losing member should advertise nothing, got %v", owners[3])
	}
	if len(rejected) != 1 || rejected[0].MemberID != 3 {
		t.Fatalf("expected one rejection for member 3, got %+v", rejected)
	}
}

func contains(list []string, want string) bool {
	for _, item := range list {
		if item == want {
			return true
		}
	}
	return false
}

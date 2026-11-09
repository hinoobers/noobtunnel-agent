package agent

import (
	"encoding/json"
	"errors"
	"testing"

	"github.com/hinoobers/noobtunnel-agent/internal/proto"
)

func TestFreshEnrollmentReplacesReservedIdentity(t *testing.T) {
	dir := t.TempDir()
	old, err := LoadIdentity(dir)
	if err != nil {
		t.Fatal(err)
	}
	a := &Agent{opts: Options{StateDir: dir}, identity: old}
	raw, _ := json.Marshal(proto.Error{T: proto.TError, Code: "enrollment_identity_conflict"})
	msg := rawMessage{typ: proto.TError, raw: raw}
	if err := a.handleFirstMessage(msg); !errors.Is(err, errReconnectRequest) {
		t.Fatal("did not retry fresh enrollment", err)
	}
	saved, err := LoadIdentity(dir)
	if err != nil {
		t.Fatal(err)
	}
	if saved.PublicKey == old.PublicKey || saved.PrivateKey == old.PrivateKey || saved.NodeID != old.NodeID || saved.PublicKey != a.identity.PublicKey {
		t.Fatal("identity was not durably replaced")
	}
	if err := a.handleFirstMessage(msg); err == nil || errors.Is(err, errReconnectRequest) {
		t.Fatal("repeated reset was not bounded", err)
	}
	if a.identity.PublicKey != saved.PublicKey {
		t.Fatal("repeated rejection rotated again")
	}
}

func TestEnrollmentConflictDoesNotRotateEstablishedOrUnrelatedErrors(t *testing.T) {
	for _, established := range []bool{false, true} {
		for _, code := range []string{"enrollment_identity_conflict", "key_conflict", "error", "token"} {
			if !established && code == "enrollment_identity_conflict" {
				continue
			}
			dir := t.TempDir()
			id, err := LoadIdentity(dir)
			if err != nil {
				t.Fatal(err)
			}
			a := &Agent{opts: Options{StateDir: dir}, identity: id}
			if established {
				a.session = &sessionState{}
			}
			raw, _ := json.Marshal(proto.Error{T: proto.TError, Code: code, Message: "fixture"})
			if err := a.handleFirstMessage(rawMessage{typ: proto.TError, raw: raw}); err == nil || errors.Is(err, errReconnectRequest) {
				t.Fatal("unexpected retry", code, err)
			}
			saved, _ := LoadIdentity(dir)
			if saved.PublicKey != id.PublicKey {
				t.Fatal("rotated existing or unrelated identity", code)
			}
		}
	}
}

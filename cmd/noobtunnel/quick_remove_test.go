package main

import (
	"bytes"
	"strings"
	"testing"
)

func TestQuickOrphanRemovalDefaultsToNo(t *testing.T) {
	for _, answer := range []string{"\n", "n\n", "N\n", "yes please\n", "", "y"} {
		var output bytes.Buffer
		if confirmQuickRemoval(strings.NewReader(answer), &output) {
			t.Fatalf("confirmed removal for %q", answer)
		}
		if !strings.Contains(output.String(), "[y/N]") {
			t.Fatal("default No not visible")
		}
	}
	for _, answer := range []string{"y\n", "Y\r\n", " y \n"} {
		if !confirmQuickRemoval(strings.NewReader(answer), &bytes.Buffer{}) {
			t.Fatalf("did not confirm for %q", answer)
		}
	}
}

func TestQuickRemovalConfigurationMustMatch(t *testing.T) {
	token := "nt_123456789abc_" + strings.Repeat("a", 64)
	raw := "NOOBTUNNEL_TOKEN=" + token + "\nNOOBTUNNEL_SERVER=example.com:8443"
	if !quickConfigMatches(raw, token, "example.com:8443") {
		t.Fatal("matching installation rejected")
	}
	if quickConfigMatches(raw, token+"bad", "example.com:8443") || quickConfigMatches(raw, token, "other.com:8443") {
		t.Fatal("unrelated installation accepted")
	}
}

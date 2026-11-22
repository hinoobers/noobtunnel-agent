package main

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestQuickNativeAgentDoesNotRequireDocker(t *testing.T) {
	called := false
	got, err := quickDockerCandidates(true, false, func() ([]quickCandidate, error) {
		called = true
		return nil, errors.New("Docker is stopped")
	})
	if called || err != nil || len(got) != 0 {
		t.Fatal("a verified native agent was blocked by Docker inventory")
	}
}

func TestQuickWindowsAllowsStoppedDocker(t *testing.T) {
	for _, failure := range []error{errors.New("daemon unavailable"), errors.New("container inventory unavailable")} {
		called := false
		got, err := quickDockerCandidates(false, true, func() ([]quickCandidate, error) { called = true; return nil, failure })
		if !called || err != nil || len(got) != 0 {
			t.Fatal("unavailable Docker inventory blocked Windows setup")
		}
		if _, err := quickDockerCandidates(false, false, func() ([]quickCandidate, error) { return nil, failure }); !errors.Is(err, failure) {
			t.Fatal("Docker setup ignored an unavailable inventory")
		}
	}
}

func TestQuickWindowsStillDiscoversAvailableDockerAgent(t *testing.T) {
	want := []quickCandidate{{Token: "fixture", Start: []string{"docker", "start", "fixture-container"}}}
	got, err := quickDockerCandidates(false, true, func() ([]quickCandidate, error) { return want, nil })
	if err != nil || len(got) != 1 || got[0].Token != want[0].Token || len(got[0].Start) != 3 {
		t.Fatal("available Docker agent was not retained for reuse")
	}
}

func TestQuickDiscoveryCustomTokenFileAndStateDirectory(t *testing.T) {
	root := t.TempDir()
	dir := filepath.Join(root, "custom install")
	if err := os.Mkdir(dir, 0700); err != nil {
		t.Fatal(err)
	}
	token := "nt_123456789abc_" + strings.Repeat("a", 64)
	path := filepath.Join(dir, "token")
	if err := os.WriteFile(path, []byte(token), 0600); err != nil {
		t.Fatal(err)
	}
	for _, raw := range []string{`agent --token-file "` + path + `"`, `agent --state-dir "` + dir + `"`, `"agent" "--token-file" "` + path + `"`, `"agent" "--state-dir" "` + dir + `"`, `NOOBTUNNEL_STATE_DIR="` + dir + `"`, `NOOBTUNNEL_TOKEN=` + token} {
		candidates := appendQuickConfig(nil, raw, root, []string{"service", "start"})
		if len(candidates) != 1 || candidates[0].Token != token {
			t.Fatalf("custom configuration was not discovered: %s", raw)
		}
	}
}

func TestQuickConfigFilesOnlyReadExplicitLocations(t *testing.T) {
	root := t.TempDir()
	dir := filepath.Join(root, "saved installation")
	if err := os.Mkdir(dir, 0700); err != nil {
		t.Fatal(err)
	}
	token := "nt_123456789abc_" + strings.Repeat("a", 64)
	if err := os.WriteFile(filepath.Join(dir, "token"), []byte(token), 0600); err != nil {
		t.Fatal(err)
	}
	if got := quickConfigFiles([]string{root}); len(got) != 0 {
		t.Fatal("discovery recursively searched a directory")
	}
	if got := quickConfigFiles([]string{dir, dir}); len(got) != 1 || got[0].Token != token {
		t.Fatal("saved installation location was not read directly")
	}
}

func TestQuickCandidateDeduplicationKeepsRestart(t *testing.T) {
	candidates := uniqueQuickCandidates([]quickCandidate{{Token: "same"}, {Token: "same", Start: []string{"docker", "start", "agent"}}, {Token: "other"}})
	if len(candidates) != 2 || len(candidates[0].Start) == 0 {
		t.Fatal("lost matching service restart information")
	}
}

package main

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"
	"unicode/utf16"
)

// Exercise actual Windows inventory and Quick's pinned HTTP client. All state
// and enrollment responses belong to this fixture; no real agent is started.
func TestQuickWindowsReusesNativeWithDockerUnavailable(t *testing.T) {
	quickWindowsReuseFixture(t, "native")
}

func TestQuickWindowsReusesExistingDockerAgent(t *testing.T) {
	quickWindowsReuseFixture(t, "docker")
}

func TestQuickWindowsFreshSetupDoesNotScanDrives(t *testing.T) {
	quickWindowsReuseFixture(t, "new")
}

func quickWindowsReuseFixture(t *testing.T, mode string) {
	t.Helper()
	root := t.TempDir()
	state := filepath.Join(root, "noobtunnel")
	if err := os.Mkdir(state, 0700); err != nil {
		t.Fatal(err)
	}
	token := "nt_123456789abc_" + strings.Repeat("a", 64)
	if mode == "native" {
		if err := os.WriteFile(filepath.Join(state, "token"), []byte(token), 0600); err != nil {
			t.Fatal(err)
		}
	}
	marker := filepath.Join(root, "docker-called")
	stub := "@echo off\r\necho called>\"" + marker + "\"\r\nexit /b 1\r\n"
	if err := os.WriteFile(filepath.Join(root, "docker.cmd"), []byte(stub), 0600); err != nil {
		t.Fatal(err)
	}
	if mode == "docker" {
		// This executable simulates an existing container; it never accesses Docker.
		fixture := `package main
import("encoding/json";"os")
func main(){switch os.Args[1]{
case "ps":os.Stdout.WriteString("fixture-container\n")
case "inspect":json.NewEncoder(os.Stdout).Encode([]any{map[string]any{"ID":"fixture-container","Config":map[string]any{"Env":[]string{"NOOBTUNNEL_TOKEN="+os.Getenv("NOOBTUNNEL_DOCKER_TEST_TOKEN")}}}})
case "start":os.WriteFile(os.Getenv("NOOBTUNNEL_DOCKER_TEST_MARKER"),[]byte("started"),0600)
default:os.Exit(1)}}`
		source := filepath.Join(root, "docker-fixture.go")
		if err := os.WriteFile(source, []byte(fixture), 0600); err != nil {
			t.Fatal(err)
		}
		if out, err := exec.Command("go", "build", "-o", filepath.Join(root, "docker.exe"), source).CombinedOutput(); err != nil {
			t.Fatalf("build Docker fixture: %v %s", err, out)
		}
		t.Setenv("NOOBTUNNEL_DOCKER_TEST_TOKEN", token)
		t.Setenv("NOOBTUNNEL_DOCKER_TEST_MARKER", marker)
	}
	t.Setenv("ProgramData", root)
	t.Setenv("PATH", root+string(os.PathListSeparator)+os.Getenv("PATH"))
	var completed atomic.Bool
	installMarker := filepath.Join(root, "installed")
	installScript := `if ($env:NOOBTUNNEL_QUICK_SETUP -ne '1') { exit 7 }; [IO.File]::WriteAllText($env:NOOBTUNNEL_QUICK_INSTALL_MARKER,'installed'); exit 0`
	units := utf16.Encode([]rune(installScript))
	encoded := make([]byte, len(units)*2)
	for i, unit := range units {
		binary.LittleEndian.PutUint16(encoded[i*2:], unit)
	}
	installCommand := "powershell.exe -NoProfile -ExecutionPolicy Bypass -EncodedCommand " + base64.StdEncoding.EncodeToString(encoded)
	t.Setenv("NOOBTUNNEL_QUICK_INSTALL_MARKER", installMarker)
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var request struct {
			Action, AgentToken string
			Tokens             []string
		}
		if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
			http.Error(w, "bad fixture request", 400)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		switch request.Action {
		case "status":
			count := 1
			method := "windows"
			if mode == "new" {
				count = 0
			}
			if mode == "docker" {
				method = "docker"
			}
			json.NewEncoder(w).Encode(map[string]any{"agentCount": count, "installMethods": []string{method}})
		case "discover":
			if mode == "new" {
				http.Error(w, "fresh account must skip discovery", 400)
				return
			}
			for i, candidate := range request.Tokens {
				if candidate == token {
					fmt.Fprintf(w, `{"found":true,"tokenIndex":%d}`, i)
					return
				}
			}
			w.Write([]byte(`{"found":false}`))
		case "complete":
			if request.AgentToken != token {
				http.Error(w, "unexpected agent", 403)
				return
			}
			completed.Store(true)
			w.Write([]byte(`{"resource":{"id":123,"name":"Windows fixture","public":"127.0.0.1:25565"}}`))
		case "install":
			if mode != "new" {
				http.Error(w, "existing agent must be reused", 400)
				return
			}
			json.NewEncoder(w).Encode(map[string]any{"agent": map[string]any{"id": 123, "token": token, "installMethod": "windows"}, "installCommand": installCommand})
		default:
			http.Error(w, "fixture must reuse the native agent", 400)
		}
	}))
	defer server.Close()
	hash := sha256.Sum256(server.Certificate().RawSubjectPublicKeyInfo)
	args := []string{"--server", strings.TrimPrefix(server.URL, "https://"), "--pin", base64.StdEncoding.EncodeToString(hash[:]), "--ticket", "fixture.ticket"}
	if binary := os.Getenv("NOOBTUNNEL_QUICK_TEST_BINARY"); binary != "" {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		out, err := exec.CommandContext(ctx, binary, append([]string{"quick"}, args...)...).CombinedOutput()
		if err != nil {
			t.Fatalf("Windows Quick executable: %v\n%s", err, out)
		}
	} else if err := runQuick(args); err != nil {
		t.Fatal(err)
	}
	if !completed.Load() {
		t.Fatal("native Windows agent was not reused")
	}
	_, markerErr := os.Stat(marker)
	if mode == "docker" && markerErr != nil {
		t.Fatal("existing Docker agent was not reused")
	}
	if mode == "native" && !os.IsNotExist(markerErr) {
		t.Fatal("native agent reuse invoked Docker")
	}
	if mode == "new" {
		if _, err := os.Stat(installMarker); err != nil {
			t.Fatal("fresh Windows setup did not run its installer")
		}
	}
}

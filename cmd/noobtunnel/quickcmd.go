package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"
)

type quickCandidate struct {
	Token string
	Start []string
}
type quickClient struct {
	ctx              context.Context
	endpoint, ticket string
	http             *http.Client
}

func (c quickClient) request(action string, values map[string]any, out any) error {
	values["ticket"], values["action"] = c.ticket, action
	raw, _ := json.Marshal(values)
	ctx := c.ctx
	if ctx == nil {
		ctx = context.Background()
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.endpoint+"/api/quick-resource", bytes.NewReader(raw))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	res, err := c.http.Do(req)
	if err != nil {
		return errors.New("could not reach the control node")
	}
	defer res.Body.Close()
	raw, err = io.ReadAll(io.LimitReader(res.Body, 2<<20))
	if err != nil {
		return err
	}
	if res.StatusCode != 200 {
		var failure struct {
			Error string `json:"error"`
		}
		json.Unmarshal(raw, &failure)
		if failure.Error == "" {
			failure.Error = "Quick setup request rejected"
		}
		return errors.New(failure.Error)
	}
	return json.Unmarshal(raw, out)
}

func finishQuickSetup(ctx context.Context, cancel context.CancelFunc, resultErr *error) {
	// Inspect the work result before cleanup cancels the context. A completed
	// resource remains successful even if the deadline expires as we return.
	if *resultErr != nil && errors.Is(ctx.Err(), context.DeadlineExceeded) {
		*resultErr = errors.New("Quick setup deadline expired; rerun to continue")
	}
	cancel()
}

func runQuick(args []string) (resultErr error) {
	fs := newFlagSet("quick")
	server := fs.String("server", "", "control host:port")
	pin := fs.String("pin", "", "TLS public key pin")
	ticket := fs.String("ticket", "", "scoped setup ticket")
	setupDeadline := fs.Int64("deadline", 0, "shared setup deadline (Unix seconds)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	deadline := time.Now().Add(10 * time.Minute)
	if *setupDeadline > 0 && time.Unix(*setupDeadline, 0).Before(deadline) {
		deadline = time.Unix(*setupDeadline, 0)
	}
	ctx, cancel := context.WithDeadline(context.Background(), deadline)
	defer func() {
		finishQuickSetup(ctx, cancel, &resultErr)
	}()
	expected, err := base64.StdEncoding.DecodeString(*pin)
	if err != nil || len(expected) != 32 || *server == "" || *ticket == "" {
		return errors.New("server, valid pin and setup ticket are required")
	}
	client := quickClient{ctx: ctx, endpoint: "https://" + *server, ticket: *ticket, http: &http.Client{Timeout: 30 * time.Second, Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true, MinVersion: tls.VersionTLS12, VerifyConnection: func(cs tls.ConnectionState) error {
		if len(cs.PeerCertificates) == 0 {
			return errors.New("missing control certificate")
		}
		hash := sha256.Sum256(cs.PeerCertificates[0].RawSubjectPublicKeyInfo)
		if !bytes.Equal(hash[:], expected) {
			return errors.New("control certificate pin mismatch")
		}
		return nil
	}}}}}
	fmt.Println("Checking your account for existing agents...")
	var account struct {
		AgentCount     *int     `json:"agentCount"`
		InstallMethods []string `json:"installMethods"`
	}
	if err := client.request("status", map[string]any{}, &account); err != nil && err.Error() != "unsupported Quick action" {
		return err
	}
	var candidates []quickCandidate
	var selected *quickCandidate
	search := func(list []quickCandidate) error {
		for offset := 0; offset < len(list); offset += 128 {
			end := offset + 128
			if end > len(list) {
				end = len(list)
			}
			tokens := make([]string, 0, end-offset)
			for _, entry := range list[offset:end] {
				tokens = append(tokens, entry.Token)
			}
			var result struct {
				Found      bool `json:"found"`
				TokenIndex int  `json:"tokenIndex"`
			}
			if err := client.request("discover", map[string]any{"tokens": tokens}, &result); err != nil {
				return err
			}
			if result.Found {
				if result.TokenIndex < 0 || result.TokenIndex >= len(tokens) {
					return errors.New("invalid discovery response")
				}
				candidate := list[offset+result.TokenIndex]
				selected = &candidate
				return nil
			}
		}
		return nil
	}
	if account.AgentCount == nil || *account.AgentCount > 0 {
		checkedDocker := false
		if len(account.InstallMethods) == 1 && account.InstallMethods[0] == "docker" {
			fmt.Println("Checking the account's Docker installation...")
			dockerCandidates, discoveryErr := quickDockerCandidates(false, runtime.GOOS == "windows", func() ([]quickCandidate, error) { return discoverQuickDockerAgents(ctx) })
			if discoveryErr != nil {
				return discoveryErr
			}
			candidates = append(candidates, dockerCandidates...)
			if err = search(dockerCandidates); err != nil {
				return err
			}
			checkedDocker = true
		}
		if selected == nil {
			fmt.Println("Checking installed services and known configuration paths...")
			nativeCandidates, discoveryErr := discoverQuickNativeAgents(ctx)
			if discoveryErr != nil {
				return discoveryErr
			}
			candidates = append(candidates, nativeCandidates...)
			if err = search(nativeCandidates); err != nil {
				return err
			}
		}
		if !checkedDocker {
			dockerCandidates, err := quickDockerCandidates(selected != nil, runtime.GOOS == "windows", func() ([]quickCandidate, error) { return discoverQuickDockerAgents(ctx) })
			if err != nil {
				return err
			}
			if err = search(dockerCandidates); err != nil {
				return err
			}
			candidates = uniqueQuickCandidates(append(candidates, dockerCandidates...))
		}
		if selected == nil {
			fmt.Println("Checking saved installation paths...")
			configCandidates := discoverQuickConfigFiles()
			candidates = uniqueQuickCandidates(append(candidates, configCandidates...))
			if err = search(configCandidates); err != nil {
				return err
			}
		}
	} else {
		// Do not replace a local agent registered elsewhere. This reads exact known
		// files only; no service inventory, Docker query or directory walk is needed.
		for _, path := range []string{filepath.Join(defaultStateDir(), "token"), "/etc/noobtunnel/token", "/etc/noobtunnel/agent.env"} {
			candidates = appendQuickConfig(candidates, readQuickFile(path), filepath.Dir(path), nil)
		}
		fmt.Println("No agents are registered to this account; skipping discovery.")
	}
	if selected == nil && len(candidates) > 0 {
		candidates = uniqueQuickCandidates(candidates)
		if len(candidates) != 1 {
			return errors.New("multiple unmatched local agents were found; remove the intended installation manually before retrying")
		}
		// Human response time is not charged against the setup work deadline.
		if err := ctx.Err(); err != nil {
			return err
		}
		remaining := time.Until(deadline)
		cancel()
		confirmed := promptQuickOrphanRemoval()
		deadline = time.Now().Add(remaining)
		ctx, cancel = context.WithDeadline(context.Background(), deadline)
		client.ctx = ctx
		if !confirmed {
			return errors.New("existing agent preserved; Quick setup cancelled")
		}
		if err := removeQuickOrphan(ctx, client, candidates[0], *server, *pin, deadline); err != nil {
			return err
		}
	}
	token := ""
	if selected != nil {
		token = selected.Token
		fmt.Println("Reusing the existing agent registered to your account.")
		if len(selected.Start) > 0 {
			cmd := exec.CommandContext(ctx, selected.Start[0], selected.Start[1:]...)
			out, startErr := cmd.CombinedOutput()
			if startErr != nil && !(runtime.GOOS == "windows" && strings.Contains(string(out), "1056")) {
				return errors.New("could not start the existing agent; check its service or Docker status")
			}
		}
	} else {
		fmt.Println("No matching local agent found. Installing an agent...")
		var result struct {
			Agent struct {
				ID            uint32 `json:"id"`
				InstallMethod string `json:"installMethod"`
				Token         string `json:"token"`
			} `json:"agent"`
			InstallCommand string `json:"installCommand"`
		}
		if err = client.request("install", map[string]any{}, &result); err != nil {
			return err
		}
		if result.Agent.Token == "" || result.InstallCommand == "" {
			return errors.New("invalid install response")
		}
		token = result.Agent.Token
		var cmd *exec.Cmd
		if runtime.GOOS == "windows" {
			parts := strings.Fields(result.InstallCommand)
			if len(parts) != 6 || parts[0] != "powershell.exe" || parts[4] != "-EncodedCommand" {
				return errors.New("unsupported Windows installer command")
			}
			cmd = quickInstallerCommand(ctx, parts[0], parts[1:]...)
		} else {
			command := result.InstallCommand
			// Quick's ticket already selected the method. Do not ask again from
			// the installer's isolated process group (which cannot read the tty).
			if result.Agent.InstallMethod == "service" {
				command += " --service"
			}
			cmd = quickInstallerCommand(ctx, "sh", "-c", command)
		}
		cmd.Env = append(os.Environ(), fmt.Sprintf("NOOBTUNNEL_SETUP_DEADLINE=%d", deadline.Unix()))
		if runtime.GOOS == "windows" {
			// Quick completes against the controller's enrollment record. Do not
			// spend its remaining budget waiting for local interface setup too.
			cmd.Env = append(cmd.Env, "NOOBTUNNEL_QUICK_SETUP=1")
		}
		cmd.Stdout, cmd.Stderr, cmd.Stdin = os.Stdout, os.Stderr, os.Stdin
		if result.Agent.InstallMethod == "docker" && runtime.GOOS != "windows" {
			dir := filepath.Join("/opt/noobtunnel-agents", fmt.Sprintf("agent-%d", result.Agent.ID))
			if err := os.MkdirAll(dir, 0755); err != nil {
				return errors.New("could not prepare the Docker agent directory")
			}
			cmd.Dir = dir
		}
		if err = cmd.Run(); err != nil {
			return errors.New("agent installation failed; fix the reported error and rerun this command")
		}
	}
	fmt.Println("Waiting for enrollment and creating the resource...")
	var result struct {
		Resource struct {
			ID            uint32 `json:"id"`
			Name          string `json:"name"`
			URL           string `json:"url"`
			PublicAddress string `json:"public"`
		} `json:"resource"`
	}
	for {
		err = client.request("complete", map[string]any{"agentToken": token}, &result)
		if err == nil {
			break
		}
		if !strings.Contains(err.Error(), "waiting for agent enrollment") || ctx.Err() != nil {
			return err
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(time.Second):
		}
	}
	fmt.Printf("Resource %q created (ID %d).\n", result.Resource.Name, result.Resource.ID)
	if result.Resource.PublicAddress != "" {
		fmt.Println("Public address:", result.Resource.PublicAddress)
	}
	fmt.Println("Open Resources in your dashboard to see the address and connection status.")
	return nil
}

func readQuickFile(path string) string {
	info, err := os.Stat(path)
	if err != nil || !info.Mode().IsRegular() {
		return ""
	}
	file, err := os.Open(path)
	if err != nil {
		return ""
	}
	defer file.Close()
	raw, err := io.ReadAll(io.LimitReader(file, 1<<20))
	if err != nil {
		return ""
	}
	return string(raw)
}

// Only read known configuration files. Service commands and Docker metadata
// already supply custom paths, so discovery never walks directories or drives.
func discoverQuickConfigFiles() []quickCandidate {
	dirs := []string{defaultStateDir(), "/etc/noobtunnel", "/var/lib/noobtunnel"}
	if cwd, err := os.Getwd(); err == nil {
		dirs = append(dirs, cwd, filepath.Join(cwd, "noobtunnel"), filepath.Join(cwd, "state"))
	}
	if home, err := os.UserHomeDir(); err == nil {
		dirs = append(dirs, filepath.Join(home, ".noobtunnel"), filepath.Join(home, "noobtunnel"))
	}
	for _, key := range []string{"ProgramData", "ProgramFiles", "LOCALAPPDATA", "APPDATA"} {
		if root := os.Getenv(key); root != "" {
			dirs = append(dirs, filepath.Join(root, "noobtunnel"))
		}
	}
	dirs = append(dirs, quickPlatformConfigDirs()...)
	result := quickConfigFiles(dirs)
	if dir := strings.TrimSpace(readQuickFile("/etc/noobtunnel/docker-compose-dir")); dir != "" {
		for _, candidate := range quickConfigFiles([]string{dir}) {
			candidate.Start = []string{"docker", "compose", "--project-directory", dir, "up", "-d"}
			result = append(result, candidate)
		}
	}
	return uniqueQuickCandidates(result)
}

func quickConfigFiles(dirs []string) []quickCandidate {
	var result []quickCandidate
	seen := map[string]bool{}
	for _, dir := range dirs {
		dir = filepath.Clean(dir)
		if seen[dir] {
			continue
		}
		seen[dir] = true
		for _, name := range []string{"token", "agent.env", ".env"} {
			result = appendQuickConfig(result, readQuickFile(filepath.Join(dir, name)), dir, nil)
		}
	}
	return uniqueQuickCandidates(result)
}

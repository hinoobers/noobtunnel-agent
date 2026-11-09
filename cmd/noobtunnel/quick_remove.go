package main

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"time"

	"github.com/hinoobers/noobtunnel-agent/internal/install"
)

func confirmQuickRemoval(input io.Reader, output io.Writer) bool {
	fmt.Fprint(output, "Remove the orphaned local agent and install a new one? [y/N] ")
	line, err := bufio.NewReader(input).ReadString('\n')
	if err != nil {
		return false
	}
	return strings.EqualFold(strings.TrimSpace(line), "y")
}

func promptQuickOrphanRemoval() bool {
	fmt.Println("A local agent configuration was found, but no reusable agent was verified.")
	input := os.Stdin
	// curl | sudo sh consumes stdin for the script. Read the operator's terminal.
	if runtime.GOOS != "windows" {
		terminal, err := os.Open("/dev/tty")
		if err != nil {
			fmt.Println("No interactive terminal; keeping the existing agent.")
			return false
		}
		defer terminal.Close()
		input = terminal
	}
	return confirmQuickRemoval(input, os.Stdout)
}

type quickRemovalPlan struct {
	script []byte
	args   []string
	dir    string
}

func quickConfigMatches(raw, token, server string) bool {
	return quickTokenPattern.FindString(raw) == token && quickServerMatches(raw, server)
}

func quickServerMatches(raw, server string) bool {
	return regexp.MustCompile(`(?:^|[\s"'=])(?:https://)?` + regexp.QuoteMeta(server) + `(?:$|[\s"'])`).MatchString(raw)
}

func planQuickOrphanRemoval(ctx context.Context, candidate quickCandidate, server, pin string, deadline time.Time) (quickRemovalPlan, error) {
	unsafe := errors.New("could not verify a standard local installation for this server; the agent was preserved. Remove custom installations manually")
	if len(candidate.Start) > 0 && candidate.Start[0] == "docker" {
		if runtime.GOOS == "windows" || len(candidate.Start) != 3 || candidate.Start[1] != "start" {
			return quickRemovalPlan{}, unsafe
		}
		raw, err := quickOutput(ctx, "docker", "inspect", candidate.Start[2])
		if err != nil {
			return quickRemovalPlan{}, unsafe
		}
		var containers []struct {
			Name   string
			Config struct{ Labels map[string]string }
		}
		if json.Unmarshal(raw, &containers) != nil || len(containers) != 1 || containers[0].Name != "/noobtunnel-agent" {
			return quickRemovalPlan{}, unsafe
		}
		dir := filepath.Clean(containers[0].Config.Labels["com.docker.compose.project.working_dir"])
		if !filepath.IsAbs(dir) || dir == string(filepath.Separator) || !quickConfigMatches(readQuickFile(filepath.Join(dir, ".env")), candidate.Token, server) || !strings.Contains(readQuickFile(filepath.Join(dir, "docker-compose.yml")), "container_name: noobtunnel-agent") {
			return quickRemovalPlan{}, unsafe
		}
		script, _ := install.Script()
		return quickRemovalPlan{script: script, args: []string{"--uninstall", "--purge", "--docker"}, dir: dir}, nil
	}
	if len(candidate.Start) > 0 && candidate.Start[len(candidate.Start)-1] != "noobtunnel-agent" && candidate.Start[len(candidate.Start)-1] != "noobtunnel-agent.service" {
		return quickRemovalPlan{}, unsafe
	}
	if runtime.GOOS == "windows" {
		if strings.TrimSpace(readQuickFile(filepath.Join(defaultStateDir(), "token"))) != candidate.Token {
			return quickRemovalPlan{}, unsafe
		}
		raw, err := quickOutput(ctx, "powershell.exe", "-NoProfile", "-NonInteractive", "-Command", `(Get-CimInstance Win32_Service -Filter "Name='noobtunnel-agent'").PathName`)
		root := filepath.Join(os.Getenv("ProgramFiles"), "noobtunnel", "noobtunnel.exe")
		if err != nil || !quickServerMatches(string(raw), server) || !strings.HasPrefix(strings.ToLower(strings.TrimSpace(string(raw))), strings.ToLower(`"`+root+`" "agent"`)) {
			return quickRemovalPlan{}, unsafe
		}
		return quickRemovalPlan{script: install.WindowsScript(), args: []string{"-Uninstall", "-LocalOnly", "-Server", server, "-Pin", pin, "-Deadline", fmt.Sprint(deadline.Unix())}}, nil
	}
	if !quickConfigMatches(readQuickFile("/etc/noobtunnel/agent.env"), candidate.Token, server) {
		return quickRemovalPlan{}, unsafe
	}
	script, _ := install.Script()
	return quickRemovalPlan{script: script, args: []string{"--uninstall", "--purge", "--service"}}, nil
}

func removeQuickOrphan(ctx context.Context, client quickClient, candidate quickCandidate, server, pin string, deadline time.Time) error {
	plan, err := planQuickOrphanRemoval(ctx, candidate, server, pin, deadline)
	if err != nil {
		return err
	}
	// The ticket is scoped to the current account. A registration on this server,
	// even under another account or disabled, blocks orphan cleanup.
	if err = client.request("check-orphan", map[string]any{"agentToken": candidate.Token}, &struct{}{}); err != nil {
		return err
	}
	dir, err := os.MkdirTemp("", "noobtunnel-orphan-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(dir)
	name := "remove.sh"
	if runtime.GOOS == "windows" {
		name = "remove.ps1"
	}
	path := filepath.Join(dir, name)
	if err = os.WriteFile(path, plan.script, 0600); err != nil {
		return err
	}
	var cmd *exec.Cmd
	if runtime.GOOS == "windows" {
		cmd = quickInstallerCommand(ctx, "powershell.exe", append([]string{"-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-File", path}, plan.args...)...)
	} else {
		cmd = quickInstallerCommand(ctx, "sh", append([]string{path}, plan.args...)...)
	}
	cmd.Dir = plan.dir
	cmd.Stdin, cmd.Stdout, cmd.Stderr = os.Stdin, os.Stdout, os.Stderr
	fmt.Println("Removing the orphaned local agent...")
	if err = cmd.Run(); err != nil {
		return errors.New("orphan removal failed; fix the reported error before retrying")
	}
	return nil
}

package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"time"
)

var quickTokenPattern = regexp.MustCompile(`\bnt_[0-9a-f]+_[0-9a-f]{64}\b`)
var quickPathPattern = regexp.MustCompile(`(?:"?--(?:token-file|state-dir|env-file)"?|NOOBTUNNEL_(?:STATE_DIR|TOKEN_FILE))\s*(?:=|\s)\s*(?:"([^"]+)"|'([^']+)'|([^\s;]+))`)
var quickSystemdEscape = regexp.MustCompile(`\\x[0-9a-fA-F]{2}`)

func quickOutput(parent context.Context, name string, args ...string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(parent, 5*time.Second)
	defer cancel()
	return exec.CommandContext(ctx, name, args...).Output()
}

func appendQuickConfig(result []quickCandidate, raw, dir string, start []string) []quickCandidate {
	raw = quickSystemdEscape.ReplaceAllStringFunc(raw, func(value string) string { n, _ := strconv.ParseUint(value[2:], 16, 8); return string(rune(n)) })
	for _, token := range quickTokenPattern.FindAllString(raw, -1) {
		result = append(result, quickCandidate{Token: token, Start: start})
	}
	for _, match := range quickPathPattern.FindAllStringSubmatch(raw, -1) {
		path := ""
		for _, part := range match[1:] {
			if part != "" {
				path = part
				break
			}
		}
		if !filepath.IsAbs(path) {
			path = filepath.Join(dir, path)
		}
		for _, file := range []string{path, filepath.Join(path, "token"), filepath.Join(path, "agent.env")} {
			for _, token := range quickTokenPattern.FindAllString(readQuickFile(file), -1) {
				result = append(result, quickCandidate{Token: token, Start: start})
			}
		}
	}
	return result
}

func uniqueQuickCandidates(entries []quickCandidate) []quickCandidate {
	out := make([]quickCandidate, 0)
	index := map[string]int{}
	for _, entry := range entries {
		if i, ok := index[entry.Token]; ok {
			if len(out[i].Start) == 0 && len(entry.Start) > 0 {
				out[i].Start = entry.Start
			}
			continue
		}
		index[entry.Token] = len(out)
		out = append(out, entry)
	}
	return out
}

func discoverQuickNativeAgents(ctx context.Context) ([]quickCandidate, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	var result []quickCandidate
	defaults := []string{"/etc/noobtunnel/agent.env", "/etc/noobtunnel/token", filepath.Join(defaultStateDir(), "token")}
	for _, path := range defaults {
		result = appendQuickConfig(result, readQuickFile(path), filepath.Dir(path), nil)
	}
	if runtime.GOOS == "windows" {
		// Enumerate every process and service, including custom executable paths and
		// names. Only extract noobtunnel token/config fields; never print raw output.
		script := `[Console]::OutputEncoding=[Text.UTF8Encoding]::new($false); $rows=@(); Get-CimInstance Win32_Process | ForEach-Object { if ($_.CommandLine) { $rows+=@{raw=$_.CommandLine;dir=(Split-Path $_.ExecutablePath);service=''} } }; Get-CimInstance Win32_Service | ForEach-Object { $svc=$_; $envs=(Get-ItemProperty -LiteralPath ('HKLM:\SYSTEM\CurrentControlSet\Services\'+$svc.Name) -Name Environment -ErrorAction SilentlyContinue).Environment; $rows+=@{raw=($svc.PathName+' '+($envs -join ' '));dir='';service=$svc.Name} }; ConvertTo-Json -InputObject $rows -Compress`
		raw, err := quickOutput(ctx, "powershell.exe", "-NoProfile", "-NonInteractive", "-Command", script)
		if err != nil {
			return nil, fmt.Errorf("could not inspect Windows processes and services; refusing to install a duplicate agent")
		}
		var rows []struct {
			Raw     string `json:"raw"`
			Dir     string `json:"dir"`
			Service string `json:"service"`
		}
		if err = json.Unmarshal(raw, &rows); err != nil {
			return nil, fmt.Errorf("could not parse local service inventory")
		}
		for _, row := range rows {
			var start []string
			if row.Service != "" {
				start = []string{"sc.exe", "start", row.Service}
			}
			result = appendQuickConfig(result, row.Raw, row.Dir, start)
		}
	} else {
		entries, err := os.ReadDir("/proc")
		if err != nil {
			return nil, fmt.Errorf("cannot inspect local processes; refusing to install a duplicate agent")
		}
		for _, entry := range entries {
			if err := ctx.Err(); err != nil {
				return nil, err
			}
			if !entry.IsDir() || entry.Name() == "self" || entry.Name() == "thread-self" {
				continue
			}
			raw := readQuickFile(filepath.Join("/proc", entry.Name(), "cmdline"))
			if !strings.Contains(raw, "agent") && !strings.Contains(raw, "noobtunnel") {
				continue
			}
			cwd, _ := os.Readlink(filepath.Join("/proc", entry.Name(), "cwd"))
			// Quote argv paths with spaces before parsing token-file/state-dir flags.
			var argv []string
			for _, arg := range strings.Split(strings.TrimRight(raw, "\x00"), "\x00") {
				for _, flag := range []string{"--token-file=", "--state-dir="} {
					if strings.HasPrefix(arg, flag) {
						arg = strings.TrimSuffix(flag, "=") + ` "` + strings.TrimPrefix(arg, flag) + `"`
						break
					}
				}
				if strings.Contains(arg, " ") && !strings.Contains(arg, ` "`) {
					arg = `"` + arg + `"`
				}
				argv = append(argv, arg)
			}
			result = appendQuickConfig(result, strings.Join(argv, " ")+" "+strings.ReplaceAll(readQuickFile(filepath.Join("/proc", entry.Name(), "environ")), "\x00", " "), cwd, nil)
		}
		if _, err := exec.LookPath("systemctl"); err == nil {
			units, err := quickOutput(ctx, "systemctl", "list-unit-files", "--type=service", "--no-legend", "--no-pager")
			if err != nil {
				return nil, fmt.Errorf("cannot inspect systemd service inventory; refusing to install a duplicate agent")
			}
			args := []string{"show", "--no-pager", "--property=Id,ExecStart,Environment,EnvironmentFiles,WorkingDirectory"}
			for _, line := range strings.Split(string(units), "\n") {
				fields := strings.Fields(line)
				if len(fields) > 0 {
					args = append(args, fields[0])
				}
			}
			if len(args) > 3 {
				inventory, err := quickOutput(ctx, "systemctl", args...)
				if err != nil {
					return nil, fmt.Errorf("cannot inspect service configuration; refusing to install a duplicate agent")
				}
				for _, block := range strings.Split(string(inventory), "\n\n") {
					id, dir := "", "/"
					for _, line := range strings.Split(block, "\n") {
						if strings.HasPrefix(line, "Id=") {
							id = strings.TrimPrefix(line, "Id=")
						}
						if strings.HasPrefix(line, "WorkingDirectory=") && len(line) > 17 {
							dir = strings.TrimPrefix(line, "WorkingDirectory=")
						}
					}
					start := []string{"systemctl", "start", id}
					result = appendQuickConfig(result, block, dir, start)
					for _, line := range strings.Split(block, "\n") {
						if strings.HasPrefix(line, "EnvironmentFiles=") {
							// systemd show renders each file as PATH (ignore_errors=BOOL).
							for _, part := range strings.Split(strings.TrimPrefix(line, "EnvironmentFiles="), ")") {
								path := strings.TrimSpace(strings.SplitN(part, " (", 2)[0])
								if path != "" {
									result = appendQuickConfig(result, readQuickFile(path), filepath.Dir(path), start)
								}
							}
						}
					}
				}
			}
		}
	}
	return uniqueQuickCandidates(result), nil
}

// A verified native agent needs no Docker inventory. Otherwise, available
// Docker agents can be reused, but a stopped daemon must not block Windows setup.
func quickDockerCandidates(foundNative, optional bool, discover func() ([]quickCandidate, error)) ([]quickCandidate, error) {
	if foundNative {
		return nil, nil
	}
	candidates, err := discover()
	if err != nil && optional {
		return nil, nil
	}
	return candidates, err
}

func discoverQuickDockerAgents(ctx context.Context) ([]quickCandidate, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	var result []quickCandidate
	if _, err := exec.LookPath("docker"); err == nil {
		ids, err := quickOutput(ctx, "docker", "ps", "-aq")
		if err == nil && strings.TrimSpace(string(ids)) != "" {
			args := append([]string{"inspect"}, strings.Fields(string(ids))...)
			raw, err := quickOutput(ctx, "docker", args...)
			if err != nil {
				return nil, fmt.Errorf("cannot inspect Docker agents; refusing to install a duplicate agent")
			}
			var containers []struct {
				ID     string
				Config struct {
					Env        []string
					Cmd        []string
					Entrypoint []string
					Labels     map[string]string
				}
				Mounts []struct{ Source, Destination string }
			}
			if err = json.Unmarshal(raw, &containers); err != nil {
				return nil, err
			}
			for _, container := range containers {
				config := strings.Join(container.Config.Env, " ") + " " + strings.Join(container.Config.Cmd, " ") + " " + strings.Join(container.Config.Entrypoint, " ")
				start := []string{"docker", "start", container.ID}
				result = appendQuickConfig(result, config, "", start)
				if dir := container.Config.Labels["com.docker.compose.project.working_dir"]; dir != "" {
					for _, name := range []string{".env", "agent.env", "token"} {
						result = appendQuickConfig(result, readQuickFile(filepath.Join(dir, name)), dir, start)
					}
				}
				for _, mount := range container.Mounts {
					// Translate container configuration paths into their host bind/volume
					// sources; containers are not required to live in the current directory.
					translated := strings.ReplaceAll(config, mount.Destination, mount.Source)
					result = appendQuickConfig(result, translated, mount.Source, start)
					for _, file := range []string{mount.Source, filepath.Join(mount.Source, "token"), filepath.Join(mount.Source, "agent.env")} {
						result = appendQuickConfig(result, readQuickFile(file), mount.Source, start)
					}
				}
			}
		} else if err != nil {
			return nil, fmt.Errorf("Docker is installed but its inventory is unavailable; start Docker and rerun Quick setup")
		}
	}
	return uniqueQuickCandidates(result), nil
}

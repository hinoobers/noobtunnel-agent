package agent

import (
	"context"
	"sort"
	"strings"

	"github.com/hinoobers/noobtunnel-agent/internal/proto"
)

// netfilterSnapshot reads firewall packet counters for remote diagnostics.
func (a *Agent) netfilterSnapshot(ctx context.Context) []string {
	host := a.host()
	tool, err := host.LookPath("iptables-save")
	if err != nil {
		return nil
	}
	out, err := host.Run(ctx, tool, "-c")
	if err != nil {
		return nil
	}
	var entries []string
	table := ""
	for _, raw := range strings.Split(out, "\n") {
		line := strings.TrimSpace(raw)
		switch {
		case strings.HasPrefix(line, "*"):
			table = strings.TrimPrefix(line, "*")
		case strings.HasPrefix(line, "["):
			end := strings.Index(line, "]")
			if end < 0 {
				continue
			}
			header := strings.Trim(line[1:end], "[]")
			packets, _, _ := strings.Cut(header, ":")
			rule := strings.TrimSpace(line[end+1:])
			if packets == "" || rule == "" {
				continue
			}
			entries = append(entries, packets+" "+table+" "+rule)
		}
	}
	sort.Strings(entries)
	return entries
}

// sendCounters answers the control node's counter request.
func (a *Agent) sendCounters(cmd proto.Command, writer *connWriter) {
	result := proto.CounterResult{
		T:     proto.TCounters,
		Seq:   cmd.Seq,
		Rules: a.netfilterSnapshot(context.Background()),
	}
	if err := writer.send(result); err != nil {
		a.log.Warn("could not send firewall counters", "error", err)
	}
}

package agent

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"os"
)

const maxHostsBytes = 4 << 20
const maxHostsJournalBytes = 16 << 20

type hostsUpdate struct {
	Version int    `json:"version"`
	Before  []byte `json:"before"`
	After   []byte `json:"after"`
}

func readHostsData(file *os.File, limit int64) ([]byte, error) {
	data, err := io.ReadAll(io.NewSectionReader(file, 0, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > limit {
		return nil, fmt.Errorf("hosts data exceeds size limit")
	}
	return data, nil
}

func writeHostsData(file *os.File, data []byte) error {
	n, err := file.WriteAt(data, 0)
	if err != nil {
		return err
	}
	if n != len(data) {
		return io.ErrShortWrite
	}
	if err := file.Truncate(int64(len(data))); err != nil {
		return err
	}
	return file.Sync()
}

func clearHostsJournal(journal *os.File) error {
	if err := journal.Truncate(0); err != nil {
		return err
	}
	return journal.Sync()
}

// The hosts inode must remain intact for Docker bind mounts and OS metadata.
// Persist the intended update before touching it, then clear the recovery record
// only after both the file contents and its length are durable.
func commitHostsUpdate(file, journal *os.File, before, after []byte) error {
	if len(before) > maxHostsBytes || len(after) > maxHostsBytes {
		return fmt.Errorf("hosts data exceeds size limit")
	}
	raw, err := json.Marshal(hostsUpdate{Version: 1, Before: before, After: after})
	if err != nil {
		return err
	}
	if err := writeHostsData(journal, raw); err != nil {
		return fmt.Errorf("save hosts recovery journal: %w", err)
	}
	if err := writeHostsData(file, after); err != nil {
		return fmt.Errorf("hosts update interrupted; recovery journal retained: %w", err)
	}
	return clearHostsJournal(journal)
}

func recoverHostsUpdate(file, journal *os.File) error {
	raw, err := readHostsData(journal, maxHostsJournalBytes)
	if err != nil || len(raw) == 0 {
		return err
	}
	var update hostsUpdate
	if json.Unmarshal(raw, &update) != nil || update.Version != 1 || len(update.Before) > maxHostsBytes || len(update.After) > maxHostsBytes {
		return fmt.Errorf("invalid hosts recovery journal; original journal preserved")
	}
	current, err := readHostsData(file, maxHostsBytes)
	if err != nil {
		return err
	}
	if bytes.Equal(current, update.After) {
		return clearHostsJournal(journal)
	}
	if !interruptedHostsWrite(current, update.Before, update.After) {
		return fmt.Errorf("hosts file changed outside the pending update; file and recovery journal preserved")
	}
	if err := writeHostsData(file, update.After); err != nil {
		return fmt.Errorf("recover hosts update: %w", err)
	}
	return clearHostsJournal(journal)
}

func interruptedHostsWrite(current, before, after []byte) bool {
	if bytes.Equal(current, before) {
		return true
	}
	// A short WriteAt can extend the original file without completing the write.
	if len(current) >= len(before) && len(current) <= len(after) && bytes.Equal(current, after[:len(current)]) {
		return true
	}
	if len(current) != len(before) {
		return false
	}
	n := 0
	for n < len(current) && n < len(after) && current[n] == after[n] {
		n++
	}
	return bytes.Equal(current[n:], before[n:])
}

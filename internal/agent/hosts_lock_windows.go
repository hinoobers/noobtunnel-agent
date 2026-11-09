package agent

import (
	"errors"
	"fmt"
	"os"
	"time"

	"golang.org/x/sys/windows"
)

func lockHostsFile(file *os.File) (func(), error) {
	handle := windows.Handle(file.Fd())
	overlap := &windows.Overlapped{}
	deadline := time.Now().Add(3 * time.Second)
	for {
		err := windows.LockFileEx(handle, windows.LOCKFILE_EXCLUSIVE_LOCK|windows.LOCKFILE_FAIL_IMMEDIATELY, 0, 0xffffffff, 0xffffffff, overlap)
		if err == nil {
			return func() { _ = windows.UnlockFileEx(handle, 0, 0xffffffff, 0xffffffff, overlap) }, nil
		}
		if !errors.Is(err, windows.ERROR_LOCK_VIOLATION) {
			return nil, err
		}
		if time.Now().After(deadline) {
			return nil, fmt.Errorf("timed out waiting for hosts file lock")
		}
		time.Sleep(20 * time.Millisecond)
	}
}

func syncHostsJournalDirectory(string) error { return nil }

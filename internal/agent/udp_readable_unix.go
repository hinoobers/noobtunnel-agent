//go:build !windows

package agent

import (
	"errors"
	"syscall"

	"golang.org/x/sys/unix"
)

func waitUDPReadable(raw syscall.RawConn) error {
	var probe [1]byte
	var readErr error
	err := raw.Read(func(fd uintptr) bool {
		for {
			_, _, readErr = unix.Recvfrom(int(fd), probe[:], unix.MSG_PEEK|unix.MSG_DONTWAIT)
			if errors.Is(readErr, unix.EINTR) {
				continue
			}
			return !errors.Is(readErr, unix.EAGAIN) && !errors.Is(readErr, unix.EWOULDBLOCK)
		}
	})
	if err != nil {
		return err
	}
	return readErr
}

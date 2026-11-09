package agent

import "syscall"

func waitUDPReadable(raw syscall.RawConn) error {
	// Windows RawConn.Read waits with an overlapped zero-byte MSG_PEEK. The
	// readiness notification leaves the entire datagram available to UDPConn.Read.
	waited := false
	return raw.Read(func(uintptr) bool {
		if !waited {
			waited = true
			return false
		}
		return true
	})
}

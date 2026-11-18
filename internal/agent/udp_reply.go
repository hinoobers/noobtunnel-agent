package agent

import (
	"context"
	"net"
	"sync"
)

const udpReplyBufferSize = 64 * 1024
const udpReplyReaders = 64

var udpReplyPool struct {
	sync.Once
	buffers chan []byte
}

// Wait for a datagram before borrowing memory. Idle sessions retain no packet
// buffer; at most 64 full-size replies are being copied in this process.
func borrowUDPReplyBuffer(ctx context.Context, stopped <-chan struct{}) ([]byte, error) {
	udpReplyPool.Do(func() {
		udpReplyPool.buffers = make(chan []byte, udpReplyReaders)
		for i := 0; i < udpReplyReaders; i++ {
			udpReplyPool.buffers <- make([]byte, udpReplyBufferSize)
		}
	})
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-stopped:
		return nil, net.ErrClosed
	case buffer := <-udpReplyPool.buffers:
		return buffer, nil
	}
}

func returnUDPReplyBuffer(buffer []byte) {
	udpReplyPool.buffers <- buffer
}

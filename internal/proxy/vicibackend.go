package proxy

import (
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/rs/zerolog/log"
)

const (
	// Timeout waiting to connect to the vici socket
	viciSocketTimeout = 10 * time.Second
)

// ViciBackend is the vici socket implementation of the proxy interface
type ViciBackend struct {
	socket   string
	mu       sync.Mutex
	conn     net.Conn
	attempts int
}

// the vici socket should be a single read/writer session. Mutex is held inisde the session.
// The mutex is released when the backend.Close() method is invoked
func (b *ViciBackend) Connect() (net.Conn, error) {
	// WE lock here to make  this backend be exclusively 1 connection at a time.
	// you have to explicitly unlock on error as there is no defer.
	b.mu.Lock()
	if b.attempts > 0 {
		dur := DefaultBackOff.Duration(b.attempts)
		log.Warn().Msgf("Backing off %s due to '%d' failed backend attempts", dur, b.attempts)
		time.Sleep(dur)
	}

	dialer := &net.Dialer{Timeout: viciSocketTimeout}
	conn, err := dialer.Dial("unix", b.socket)
	if err != nil {
		// increment backoff and unlock
		b.attempts++
		b.mu.Unlock()
		return conn, err
	}

	if err != nil {
		// increment backoff and unlock
		b.attempts++
		b.mu.Unlock()
		return conn, fmt.Errorf("Failed to connect to charon socket: %w", err)
	}

	// for now we hold the pointer to the connection and we lock so that
	b.conn = conn
	// reset the backoff
	b.attempts = 0
	return conn, err
}

func (b *ViciBackend) Close() {
	b.conn.Close()
	b.mu.Unlock()
}

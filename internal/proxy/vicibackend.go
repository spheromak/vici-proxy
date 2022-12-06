package proxy

import (
	"fmt"
	"io"
	"log"
	"net"
	"sync"
	"time"
)

const (
	// Timeout waiting to connect to the vici socket
	viciSocketTimeout = 500 * time.Millisecond
)

// ViciBackend is the vici socket implementation of the proxy interface
type ViciBackend struct {
	conn   net.Conn
	socket string
	mu     sync.Mutex
}

// the vici socket should be a single read/writer session. Mutex is held inisde the session.
func (b *ViciBackend) Connect() error {
	b.mu.Lock()
	defer b.mu.Unlock()

	dialer := &net.Dialer{Timeout: viciSocketTimeout}
	conn, err := dialer.Dial("unix", b.socket)
	if err != nil {
		log.Fatal(err)
	}
	b.conn = conn

	if err != nil {
		return fmt.Errorf("Failed to connect to charon socket: %w", err)
	}

	b.conn = conn

	return nil
}

func (b *ViciBackend) Close() error {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.conn.Close()
}

// Send a msg to the backend and proxy respons to the clinet connection
func (b *ViciBackend) ProxyRaw(client io.Writer, msg []byte) error {
	// sned msg
	if _, err := fmt.Fprint(b.conn, msg); err != nil {
		return err
	}

	// proxy response back to client
	if _, err := io.Copy(client, b.conn); err != nil {
		return err
	}

	return nil
}

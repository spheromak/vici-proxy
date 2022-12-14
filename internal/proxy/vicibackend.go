package proxy

import (
	"fmt"
	"io"
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
	socket string
	mu     sync.Mutex
}

// the vici socket should be a single read/writer session. Mutex is held inisde the session.
func (b *ViciBackend) Connect() (error, net.Conn) {
	dialer := &net.Dialer{Timeout: viciSocketTimeout}
	conn, err := dialer.Dial("unix", b.socket)
	if err != nil {
		return err, conn
	}

	if err != nil {
		return fmt.Errorf("Failed to connect to charon socket: %w", err), conn
	}

	return nil, conn
}

func (b *ViciBackend) Lock() {
	// b.mu.Lock()
}

func (b *ViciBackend) Unlock() {
	//b.mu.Unlock()
}

// Send a msg to the backend and proxy respons to the clinet connection
func (b *ViciBackend) ProxyRaw(client io.Writer, msg []byte) error {
	err, conn := b.Connect()
	if err != nil {
		log.Debug().Err(err).Msg("Couldn't connect to backend")
		return err
	}
	defer conn.Close()

	log.Debug().Msg("Connecting response stream to client")
	// proxy response back to client
	go func() error {
		if i, err := io.Copy(client, conn); err != nil {
			log.Debug().Err(err).Msgf("couldn't send to client wrote: %d bytes", i)
			return err
		}
		return nil
	}()

	log.Debug().Msg("Sending request to backend")
	if _, err := conn.Write(msg); err != nil {
		log.Debug().Err(err).Msg("couldn't send to backend")
		return err
	}

	return nil
}

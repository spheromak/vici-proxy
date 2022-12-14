package proxy

import (
	"io"
	"net"
)

// Backend interface is a thin wrapper around a vici backend
type Backend interface {
	Connect() (error, net.Conn)
	ProxyRaw(io.Writer, []byte) error
	Lock()
	Unlock()
}

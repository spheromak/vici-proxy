package proxy

import (
	"net"
)

// Backend interface is a thin wrapper around a net.Conn
type Backend interface {
	Connect() (net.Conn, error)
	Close()
}

package proxy

import "io"

// Backend interface is a thin wrapper around a vici backend
type Backend interface {
	Connect() error
	Close() error
	ProxyRaw(io.Writer, []byte) error
}

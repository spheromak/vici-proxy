// Copyright (C) 2022 Jesse Nelson
// Copyright (C) 2019 Nick Rosbrook
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.

// much of this is taken from the private methods  of the govici client
//  https://github.com/strongswan/govici
package proxy

import (
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"time"

	"github.com/davecgh/go-spew/spew"
	"github.com/rs/zerolog/log"
)

const (
	// viciSocketTimeout is the time to wait connecting to charon.vici

	// proxyTimeout is the time we wait to handle a connection to the prox
	proxyTimeout = 10 * time.Second

	// each segment is prefixed by a 4byte header in network order
	// see https://github.com/strongswan/govici/blob/master/vici/transport.go
	headerLength = 4
)

var (
	// DefaultAllowed is the list of commands we set if none are provided.
	DefaultAllowed = []string{"stats", "version"}
)

type Proxy struct {
	allow      []string
	ClientName string

	timeout time.Duration

	listenSocket string

	backend Backend
}

func New(vici, listen string, allowed []string) (*Proxy, error) {
	p := &Proxy{
		backend:      &ViciBackend{socket: vici},
		listenSocket: listen,
		allow:        DefaultAllowed,
		timeout:      proxyTimeout,
	}

	if vici == "" || listen == "" {
		return p, fmt.Errorf("vici and listen sockets must not be empty vici: '%s', listen: '%s'\n", vici, listen)

	}

	return p, nil

}

// limited implementation of reading client commands based on the vici spec/doc:
// https://www.strongswan.org/apidoc/md_src_libcharon_plugins_vici_README.html
func (p *Proxy) Start() error {
	listener, err := net.Listen("unix", p.listenSocket)
	if err != nil {
		return fmt.Errorf("Error starting socket server at '%s' %w", p.listenSocket, err)
	}

	// ensure we can connect to vici before startup
	if err = p.backend.Connect(); err != nil {
		log.Error().Err(err).Msg("couldn't connect to vici socket")
	}

	log.Info().Str("listening", p.listenSocket).Msg("listener started")
	// begin connection serving loop
	for {
		conn, err := listener.Accept()
		if err != nil {
			log.Debug().Err(err).Msg("error accepting conneciton")
			continue
		}

		p.ClientName = conn.RemoteAddr().String()
		l := log.With().Str("client", p.ClientName).Logger()
		l.Debug().Msg("Got client conneciton")

		// Define Read/Write Deadline
		// if we need to split this the conn interface has both SetRead/WriteDeadline
		if err := conn.SetDeadline(time.Now().Add(p.timeout)); err != nil {
			l.Warn().Err(err).Msg("error setting keepalive, closing")
			conn.Close()
			return err
		}

		// handle the connection
		go p.ClientHandler(conn)
	}
}

// ClientHandler manages a client connection to the proxy
func (p *Proxy) ClientHandler(conn net.Conn) {
	l := log.With().Str("name", p.ClientName).Logger()
	defer conn.Close()

	// initialize
	if err := p.backend.Connect(); err != nil {
		l.Error().Err(err).Msg("couldn't handle connection")
		return
	}
	defer p.backend.Close()

	head := make([]byte, headerLength)

	// read header from client
	_, err := io.ReadFull(conn, head)
	if err != nil {
		l.Error().Err(err).Msg("couldn't read header")
		return
	}
	pl := binary.BigEndian.Uint32(head)

	// read message
	buf := make([]byte, int(pl))
	_, err = io.ReadFull(conn, buf)
	if err != nil {
		l.Error().Err(err).Msg("couldn't read packet")
		return
	}

	spew.Dump(buf)
	pkt := &packet{}
	err = pkt.parse(buf)
	if err != nil {
		l.Error().Err(err).Msg("failed parsing packet")
		return
	}

	allow := false
	for i := range p.allow {
		if p.allow[i] == pkt.Name {
			l.Debug().Str("command", pkt.Name).Msg("We should proxy this command")
			allow = true
			break
		}
	}

	if !allow {
		l.Error().Msgf("Command '%s' not allowed\n", pkt.Name)
		return
	}

	if err := p.backend.ProxyRaw(conn, buf); err != nil {
		l.Error().Err(err).Msgf("Trouble proxying command '%s'", pkt.Name)
		return
	}

	return
}

func (p *Proxy) Shutdown(ctx context.Context) error {
	p.backend.Close()
	return nil
}

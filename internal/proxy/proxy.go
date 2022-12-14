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
//
//	https://github.com/strongswan/govici
package proxy

import (
	"context"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"sync"
	"time"

	"github.com/rs/zerolog/log"
)

const (
	// viciSocketTimeout is the time to wait connecting to charon.vici

	// proxyTimeout is the time we wait to handle a connection to the prox
	proxyTimeout = 10 * time.Second

	// each segment is prefixed by a 4byte header in network order
	// see https://github.com/strongswan/govici/blob/master/vici/transport.go
	headerLength = 4

	errClosedConnection = "use of closed network connection"
)

var (
	// DefaultAllowed is the list of commands we set if none are provided.
	DefaultAllowed = []string{"stats", "version", "get-pools", "list-sa", "list-sas"}
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

	log.Info().Str("listening", p.listenSocket).Msg("listener started")
	// begin connection serving loop
	id := 0
	for {

		client, err := listener.Accept()
		if err != nil {
			log.Debug().Err(err).Msg("error accepting conneciton")
			continue
		}
		id++

		l := log.With().Int("client", id).Logger()
		l.Debug().Msg("Got client conneciton")

		// Define Read/Write Deadline
		// if we need to split this the conn interface has both SetRead/WriteDeadline
		if err := client.SetDeadline(time.Now().Add(p.timeout)); err != nil {
			l.Warn().Err(err).Msg("error setting keepalive, closing")
			client.Close()
			continue
		}

		// handle the connection
		p.ClientHandler(client, id)
		p.backend.Unlock()
	}
}

// validator should shuffle bytes into a buffer after it has read them and validated they are ok
// to send to the backend.
func (p *Proxy) vaildateClientCommand(client io.Reader, msg io.WriteCloser, id int) {
	l := log.With().Int("client", id).Logger()

	for {
		head := make([]byte, headerLength)

		// read header from client
		_, err := io.ReadFull(client, head)
		// IF we are at the EOF on the read or we have a closed connection shutdown validator pass-thru
		if err != nil {
			netOpError, ok := err.(*net.OpError)
			if err == io.EOF || (ok && netOpError.Err.Error() == errClosedConnection) {
				msg.Close()
				return
			}
			l.Error().Err(err).Msg("proxy couldn't read packet from client")
		}

		pl := binary.BigEndian.Uint32(head)

		// read message
		buf := make([]byte, int(pl))
		_, err = io.ReadFull(client, buf)
		if err != nil {
			l.Error().Err(err).Msg("proxy couldn't read packet from client")
			continue
		}

		pkt := &packet{}
		err = pkt.parse(buf)
		if err != nil {
			l.Error().Err(err).Msg("proxy failed parsing packet from client")
			continue
		}

		allowed := false
		for i := range p.allow {
			// l.Debug().Str("Command", pkt.Name).Msgf("Checking command vs '%s'", p.allow[i])
			if p.allow[i] == pkt.Name {
				l.Debug().Str("command", pkt.Name).Msg("We should proxy this command")
				_, _ = msg.Write(head)
				_, _ = msg.Write(buf)
				allowed = true
			}
		}
		if !allowed {
			l.Warn().Str("Command", pkt.Name).Msg("Command not allowed")
		}
	}
}

// ClientHandler manages a client connection to the proxy
func (p *Proxy) ClientHandler(client net.Conn, id int) {
	l := log.With().Int("client", id).Logger()
	var backend net.Conn
	var closer sync.Once

	// make sure connections get closed
	closeFunc := func() {
		l.Debug().Msg("Connection closed from client handler.")
		_ = client.Close()
		_ = backend.Close()
	}

	// connect to backend
	err, backend := p.backend.Connect()
	if err != nil {
		l.Error().Err(err).Msg("couldn't connect to vici socket")
		p.backend.Unlock()
		closer.Do(closeFunc)
		return
	}

	// handleBackend will process the response data from the backend and tee it to the teminal and to the client connection
	go p.handleBackendMessage(backend, client, id, &closer)

	// read from client. run through the validator and pipe to the backend / tee
	validR, validW := io.Pipe()
	go p.vaildateClientCommand(client, validW, id)

	// create a pipe that such that anything pushed on tee is written to the backend and the Teedumper
	r, w := io.Pipe()
	tee := io.MultiWriter(backend, w)
	go dumpData(r, "Client", id)

	// write the good message to the console dumper and the backend
	_, err = io.Copy(tee, validR)
	//	_, err = io.Copy(tee, client)
	if err != nil && err != io.EOF {
		l.Debug().Err(err).Msg("bad Copy to client")
	}

	closer.Do(closeFunc)
}

func (p *Proxy) Shutdown(ctx context.Context) error {
	return nil
}

func (p *Proxy) handleBackendMessage(backend, client net.Conn, id int, closer *sync.Once) {
	l := log.With().Int("client", id).Logger()
	closeFunc := func() {
		l.Info().Msg("Connections closed from backend handler.")
		_ = backend.Close()
		_ = client.Close()
	}

	//
	// Creates a pipe and dumper  R is the read on the pipe. W is the write to the open pipe
	// the Copy copies from the backend and pushes it over to W(via tee) on the pipe and to the client.
	// Dumper reads from the pipes R and dumps to screen
	//
	r, w := io.Pipe()
	// Connect the client to the pipe writer.  So that it gets data back.
	tee := io.MultiWriter(client, w)
	// Peek any data coming out of the server
	go dumpData(r, "Backend", id)
	// Start pumping bytes from the backend to the tee and the pipe which is the client and the dumper.
	_, err := io.Copy(tee, backend)

	// check for
	if err != nil && err != io.EOF {
		netOpError, ok := err.(*net.OpError)
		if ok && netOpError.Err.Error() != errClosedConnection {
			l.Error().Err(err).Msg("error copying from server to client")
		}
	}

	closer.Do(closeFunc)
}

func dumpData(r io.Reader, source string, id int) {
	data := make([]byte, 512)
	for {
		n, err := r.Read(data)
		if err != nil && err != io.EOF {
			log.Info().Err(err).Msg("unable to read data")
			return
		}
		if n > 0 {
			fmt.Printf("From %s [%d]:\n", source, id)
			fmt.Println(hex.Dump(data[:n]))
		}
		if n <= 0 {
			return
		}
	}
}

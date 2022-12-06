package proxy

import (
	"bytes"
	"errors"
	"fmt"
)

const (
	// A name request message
	pktCmdRequest uint8 = iota

	// An unnamed response message for a request
	pktCmdResponse

	// An unnamed response if requested command is unknown
	pktCmdUnkown

	// A named event registration request
	pktEventRegister

	// A name event deregistration request
	pktEventUnregister

	// An unnamed response for successful event (de-)registration
	pktEventConfirm

	// An unnamed response if event (de-)registration failed
	pktEventUnknown

	// A named event message
	pktEvent
)

var (
	// Generic packet parsing error
	errPacketParse = errors.New("error parsing packet")

	errBadName = fmt.Errorf("%v: expected name length does not match actual length", errPacketParse)
)

// A packet has a required type (an 8-bit identifier), a name (only required for named types),
type packet struct {
	ptype uint8
	Name  string
}

// isNamed returns a bool indicating the packet is a named type
func (p *packet) isNamed() bool {
	switch p.ptype {
	case /* Named packet types */
		pktCmdRequest,
		pktEventRegister,
		pktEventUnregister,
		pktEvent:

		return true

	case /* Un-named packet types */
		pktCmdResponse,
		pktCmdUnkown,
		pktEventConfirm,
		pktEventUnknown:

		return false
	}

	return false
}

// parse will parse the given bytes and populate its fields with that data
func (p *packet) parse(data []byte) error {
	buf := bytes.NewBuffer(data)

	// Read the packet type
	b, err := buf.ReadByte()
	if err != nil {
		return fmt.Errorf("%v: %v", errPacketParse, err)
	}
	p.ptype = b

	if p.isNamed() {
		// Get the length of the name
		l, err := buf.ReadByte()
		if err != nil {
			return fmt.Errorf("%v: %v", errPacketParse, err)
		}

		// Read the name
		name := buf.Next(int(l))
		if len(name) != int(l) {
			return errBadName
		}
		p.Name = string(name)
	}

	return nil
}

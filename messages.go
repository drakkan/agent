// Copyright 2025 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package agent

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"

	"golang.org/x/crypto/ssh"
)

func appendU32(buf []byte, v uint32) []byte {
	return append(buf, byte(v>>24), byte(v>>16), byte(v>>8), byte(v))
}

func appendString(buf []byte, s string) []byte {
	buf = appendU32(buf, uint32(len(s)))
	buf = append(buf, s...)
	return buf
}

func appendBytes(buf []byte, b []byte) []byte {
	buf = appendU32(buf, uint32(len(b)))
	buf = append(buf, b...)
	return buf
}

func parseString(in []byte) (out, rest []byte, ok bool) {
	if len(in) < 4 {
		return
	}
	length := binary.BigEndian.Uint32(in)
	in = in[4:]
	if uint32(len(in)) < length {
		return
	}
	out = in[:length]
	rest = in[length:]
	ok = true
	return
}

func parseSignatureBody(in []byte) (out *ssh.Signature, rest []byte, ok bool) {
	format, in, ok := parseString(in)
	if !ok {
		return
	}

	out = &ssh.Signature{
		Format: string(format),
	}

	if out.Blob, in, ok = parseString(in); !ok {
		return
	}

	switch out.Format {
	case ssh.KeyAlgoSKECDSA256, ssh.CertAlgoSKECDSA256v01, ssh.KeyAlgoSKED25519, ssh.CertAlgoSKED25519v01:
		out.Rest = in
		return out, nil, ok
	}

	return out, in, ok
}

// ParseSessionBind parses the payload of a "session-bind@openssh.com" extension
// message. It verifies the signature within the bind message to ensure the
// integrity of the hop.
func ParseSessionBind(data []byte) (SessionBind, error) {
	var tmp struct {
		HostKeyBlob       []byte
		SessionIdentifier []byte
		Signature         []byte
		IsForwarding      bool
	}

	if err := ssh.Unmarshal(data, &tmp); err != nil {
		return SessionBind{}, err
	}
	hostKey, err := ssh.ParsePublicKey(tmp.HostKeyBlob)
	if err != nil {
		return SessionBind{}, err
	}

	sig, rest, ok := parseSignatureBody(tmp.Signature)
	if len(rest) > 0 || !ok {
		return SessionBind{}, errors.New("ssh: signature parse error")
	}
	// See process_ext_session_bind
	if len(tmp.SessionIdentifier) > 128 {
		return SessionBind{}, fmt.Errorf("ssh: session bind sid len %d, max allowed 128", len(tmp.SessionIdentifier))
	}
	if err := hostKey.Verify(tmp.SessionIdentifier, sig); err != nil {
		return SessionBind{}, err
	}

	return SessionBind{
		HostKey:    hostKey,
		SessionID:  tmp.SessionIdentifier,
		Forwarding: tmp.IsForwarding,
	}, nil
}

// SessionBind represents a single hop in the agent forwarding chain, as defined
// by the "session-bind@openssh.com" extension in [PROTOCOL.agent].
type SessionBind struct {
	HostKey    ssh.PublicKey
	SessionID  []byte
	Forwarding bool
}

const (
	// RestrictDestinationExtensionName is the identifier for the destination
	// restriction extension.
	RestrictDestinationExtensionName = "restrict-destination-v00@openssh.com"
	maxDestConstraints               = 1024
)

// RestrictDestinationConstraintExtension represents the content of the
// "restrict-destination-v00@openssh.com" constraint.
type RestrictDestinationConstraintExtension struct {
	Constraints []DestinationConstraint
}

// Marshal serializes the restrict destination constraint extension  to SSH wire
// format.
func (e *RestrictDestinationConstraintExtension) Marshal() []byte {
	var out []byte
	for _, c := range e.Constraints {
		out = appendBytes(out, c.marshal())
	}
	return out
}

// ParseRestrictDestinationConstraintExtension parses the constraints blob
// associated with a key.
func ParseRestrictDestinationConstraintExtension(data []byte) (RestrictDestinationConstraintExtension, error) {
	var d RestrictDestinationConstraintExtension
	if len(data) == 0 {
		return d, io.ErrShortBuffer
	}
	for len(data) > 0 {
		var payload []byte
		var ok bool
		payload, data, ok = parseString(data)
		if !ok {
			return d, io.ErrShortBuffer
		}
		constraint := DestinationConstraint{}
		if err := constraint.unmarshal(payload); err != nil {
			return d, err
		}
		d.Constraints = append(d.Constraints, constraint)
		if len(d.Constraints) > maxDestConstraints {
			return d, errors.New("ssh: too many constraints")
		}
	}
	return d, nil
}

// DestinationConstraint defines a single rule allowing a key to be used
// from a specific source host to a specific destination host.
type DestinationConstraint struct {
	From HostIdentity
	To   HostIdentity
}

func (c *DestinationConstraint) marshal() []byte {
	var out []byte

	fromBytes := c.From.marshal()
	out = appendBytes(out, fromBytes)

	toBytes := c.To.marshal()
	out = appendBytes(out, toBytes)

	out = appendString(out, "") // Reserved field

	return out
}

func (c *DestinationConstraint) unmarshal(data []byte) error {
	from, data, ok := parseString(data)
	if !ok {
		return io.ErrShortBuffer
	}
	if err := c.From.unmarshal(from); err != nil {
		return err
	}
	// From username must be empty. See [PROTOCOL.agent].
	if c.From.Username != "" {
		return fmt.Errorf("ssh: from username must be empty, was %q", c.From.Hostname)
	}

	to, _, ok := parseString(data)
	if !ok {
		return io.ErrShortBuffer
	}
	if err := c.To.unmarshal(to); err != nil {
		return err
	}
	if c.To.Hostname == "" {
		return errors.New("ssh: to hostname must be set")
	}
	if len(c.To.HostKeys) == 0 {
		return errors.New("ssh: to host keys must be set")
	}
	// The remaining data, if any, is reserved.

	return nil
}

// HostIdentity represents a host and user specification within a constraint,
// including the expected host keys.
type HostIdentity struct {
	Username string
	Hostname string
	HostKeys []HostIdentityKeySpec
}

func (h *HostIdentity) marshal() []byte {
	var out []byte

	out = appendString(out, h.Username)
	out = appendString(out, h.Hostname)
	out = appendString(out, "") // Reserved field

	for _, ks := range h.HostKeys {
		var keyBytes []byte
		if ks.Key != nil {
			keyBytes = ks.Key.Marshal()
		}
		out = appendBytes(out, keyBytes)

		if ks.CA {
			out = append(out, 1)
		} else {
			out = append(out, 0)
		}
	}
	return out
}

func (h *HostIdentity) unmarshal(data []byte) error {
	username, data, ok := parseString(data)
	if !ok {
		return io.ErrShortBuffer
	}
	h.Username = string(username)

	hostname, data, ok := parseString(data)
	if !ok {
		return io.ErrShortBuffer
	}
	h.Hostname = string(hostname)

	// skip reserved data
	_, data, ok = parseString(data)
	if !ok {
		return io.ErrShortBuffer
	}

	for len(data) > 0 {
		var keyspec HostIdentityKeySpec
		var keyBlob []byte
		keyBlob, data, ok = parseString(data)
		if !ok {
			return io.ErrShortBuffer
		}
		pubKey, err := ssh.ParsePublicKey(keyBlob)
		if err != nil {
			return err
		}
		keyspec.Key = pubKey
		if len(data) == 0 {
			return io.ErrShortBuffer
		}
		keyspec.CA = data[0] != 0
		// FIXME: should we limit the number of host keys???
		h.HostKeys = append(h.HostKeys, keyspec)
		data = data[1:]
	}

	return nil
}

// HostIdentityKeySpec represents a specific key (and whether it is a CA)
// allowed for a host in a destination constraint.
type HostIdentityKeySpec struct {
	Key ssh.PublicKey
	CA  bool
}

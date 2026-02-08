package ssh

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"

	"golang.org/x/crypto/ssh"
)

// PublicKeyUserAuthRequest represents the parsed fields of an
// SSH_MSG_USERAUTH_REQUEST packet. See RFC 4252 section 5.
type PublicKeyUserAuthRequest struct {
	User      string
	Service   string
	Method    string
	SessionID []byte
	Algorithm string
	PublicKey ssh.PublicKey
	// HostKey is not nil for publickey-hostbound-v00@openssh.com method.
	HostKey ssh.PublicKey
}

// ParsePublicKeyUserAuthRequest parses the payload of an SSH_MSG_USERAUTH_REQUEST
// packet.
func ParsePublicKeyUserAuthRequest(data []byte) (PublicKeyUserAuthRequest, error) {
	var r PublicKeyUserAuthRequest
	sessionID, data, ok := parseString(data)
	if !ok {
		return r, io.ErrShortBuffer
	}
	r.SessionID = sessionID

	var req userAuthRequestMsg
	err := ssh.Unmarshal(data, &req)
	if err != nil {
		return r, err
	}
	r.User = req.User
	if req.Service != "ssh-connection" {
		return r, fmt.Errorf("ssh: unexpected service %q, want: ssh-connection", req.Service)
	}
	if req.Method != "publickey" && req.Method != "publickey-hostbound-v00@openssh.com" {
		return r, fmt.Errorf("ssh: unexpected authentication method %q", r.Method)
	}
	r.Service = req.Service
	r.Method = req.Method
	payload := req.Payload

	if len(payload) == 0 {
		return r, io.ErrShortBuffer
	}
	isQuery := payload[0] == 0
	if isQuery {
		return r, errors.New("ssh: query authentication request not accepted")
	}
	payload = payload[1:]
	algoBytes, payload, ok := parseString(payload)
	if !ok {
		return r, io.ErrShortBuffer
	}
	r.Algorithm = string(algoBytes)

	pubKeyData, payload, ok := parseString(payload)
	if !ok {
		return r, io.ErrShortBuffer
	}
	r.PublicKey, err = ssh.ParsePublicKey(pubKeyData)
	if err != nil {
		return r, err
	}

	if r.Method == "publickey-hostbound-v00@openssh.com" {
		hostKeyData, _, ok := parseString(payload)
		if !ok {
			return r, io.ErrShortBuffer
		}
		r.HostKey, err = ssh.ParsePublicKey(hostKeyData)
		if err != nil {
			return r, err
		}
	}

	return r, nil
}

type userAuthRequestMsg struct {
	User    string `sshtype:"50"`
	Service string
	Method  string
	Payload []byte `ssh:"rest"`
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

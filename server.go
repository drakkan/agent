// Copyright 2012 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package agent

import (
	"bytes"
	"context"
	"crypto/dsa"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rsa"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"log"
	"math/big"

	"golang.org/x/crypto/ssh"
)

// SignatureFlags represent additional flags that can be passed to the signature
// requests an defined in [PROTOCOL.agent] section 4.5.1.
type SignatureFlags uint32

// SignatureFlag values as defined in [PROTOCOL.agent] section 5.3.
const (
	SignatureFlagReserved SignatureFlags = 1 << iota
	SignatureFlagRsaSha256
	SignatureFlagRsaSha512
)

// Agent represents the server-side implementation of an SSH agent.
//
// This interface defines the capabilities required to manage SSH identities,
// process signing requests, and handle protocol extensions. All methods accept
// a context.Context for cancellation and timeout management. Crucially, most
// methods accept a [Session] or [SignOptions], allowing the implementation to
// enforce granular security policies.
type Agent interface {
	// List returns the identities known to the agent.
	//
	//
	// If a session is provided, the agent may filter the returned keys based
	// on destination constraints. For example, keys that are not permitted
	// for the current session hops may be hidden to prevent enumeration.
	List(ctx context.Context, session *Session) ([]*Key, error)

	// Sign has the agent sign the data using a protocol 2 key as defined
	// in [PROTOCOL.agent] section 2.6.2.
	//
	// The options parameter allows passing the current Session state. The agent
	// validates the request against the session bindings and the key's
	// constraints before signing.
	Sign(ctx context.Context, key ssh.PublicKey, data []byte, options *SignOptions) (*ssh.Signature, error)

	// Add adds a private key to the agent.
	//
	// If a session is provided, the agent verifies that the operation is
	// permitted within the context of that session.
	Add(ctx context.Context, key KeyEncoding, session *Session) error

	// Remove removes all identities with the given public key.
	//
	// If a session is provided, the agent may refuse to remove a key if the
	// session constraints do not allow visibility of that key (preventing
	// oracle attacks).
	Remove(ctx context.Context, key ssh.PublicKey, session *Session) error

	// RemoveAll removes all identities.
	RemoveAll(ctx context.Context, session *Session) error

	// Lock locks the agent. Sign and Remove will fail, and List will empty an empty list.
	Lock(ctx context.Context, passphrase []byte, session *Session) error

	// Unlock undoes the effect of Lock
	Unlock(ctx context.Context, passphrase []byte, session *Session) error

	// Extension processes a custom extension request. Standard-compliant agents
	// are not required to support any extensions, but this method allows agents
	// to implement vendor-specific methods or add experimental features. See
	// [PROTOCOL.agent] section 4.7.
	//
	// The session parameter provides the current session context, which may be
	// relevant for extensions that verify the connection topology or session
	// bindings.
	//
	// If agent extensions are unsupported entirely this method MUST return an
	// ErrExtensionUnsupported error. Similarly, if just the specific
	// extensionType in the request is unsupported by the agent then
	// ErrExtensionUnsupported MUST be returned.
	//
	// In the case of success, since [PROTOCOL.agent] section 4.7 specifies that
	// the contents of the response are unspecified (including the type of the
	// message), the complete response will be returned as a []byte slice,
	// including the "type" byte of the message.
	Extension(ctx context.Context, extensionType string, contents []byte, session *Session) ([]byte, error)
}

// SignOptions contains additional parameters for the Sign operation.
type SignOptions struct {
	Flags SignatureFlags
	// Session represents the current session state associated with the request.
	Session *Session
}

// Session represents the state of the current connection to the agent,
// specifically tracking the chain of session binds (hops) established via the
// "session-bind@openssh.com" extension.
type Session struct {
	// Binds contains the list of hops recorded for this connection.
	Binds []SessionBind
	// BindsAttempted indicates if the client has attempted to send session-bind
	// messages, even if the list is empty.
	BindsAttempted bool
}

// ConstraintExtension describes an optional constraint defined by users.
type ConstraintExtension struct {
	// ExtensionName consist of a UTF-8 string suffixed by the
	// implementation domain following the naming scheme defined
	// in Section 4.2 of RFC 4251, e.g.  "foo@example.com".
	ExtensionName string
	// ExtensionDetails contains the actual content of the extended
	// constraint.
	ExtensionDetails []byte
}

// server wraps an Agent and uses it to implement the agent side of
// the SSH-agent, wire protocol.
type server struct {
	agent         Agent
	sessionBinds  []SessionBind
	bindAttempted bool
}

func (s *server) Session() *Session {
	return &Session{
		Binds:          s.sessionBinds,
		BindsAttempted: s.bindAttempted,
	}
}

func (s *server) processRequestBytes(reqData []byte) []byte {
	rep, err := s.processRequest(reqData)
	if err != nil {
		if err != errLocked {
			// TODO(hanwen): provide better logging interface?
			log.Printf("agent %d: %v", reqData[0], err)
		}
		return []byte{agentFailure}
	}

	if rep == nil {
		return []byte{agentSuccess}
	}

	return ssh.Marshal(rep)
}

func marshalKey(k *Key) []byte {
	var record struct {
		Blob    []byte
		Comment string
	}
	record.Blob = k.Marshal()
	record.Comment = k.Comment

	return ssh.Marshal(&record)
}

// See [PROTOCOL.agent], section 2.5.1.
const agentV1IdentitiesAnswer = 2

type agentV1IdentityMsg struct {
	Numkeys uint32 `sshtype:"2"`
}

type agentRemoveIdentityMsg struct {
	KeyBlob []byte `sshtype:"18"`
}

type agentLockMsg struct {
	Passphrase []byte `sshtype:"22"`
}

type agentUnlockMsg struct {
	Passphrase []byte `sshtype:"23"`
}

func (s *server) processRequest(data []byte) (interface{}, error) {
	switch data[0] {
	case agentRequestV1Identities:
		return &agentV1IdentityMsg{0}, nil

	case agentRemoveAllV1Identities:
		return nil, nil

	case agentRemoveIdentity:
		var req agentRemoveIdentityMsg
		if err := ssh.Unmarshal(data, &req); err != nil {
			return nil, err
		}

		var wk wireKey
		if err := ssh.Unmarshal(req.KeyBlob, &wk); err != nil {
			return nil, err
		}
		k := &Key{Format: wk.Format, Blob: req.KeyBlob}
		return nil, s.agent.Remove(context.Background(), k, s.Session())

	case agentRemoveAllIdentities:
		return nil, s.agent.RemoveAll(context.Background(), s.Session())

	case agentLock:
		var req agentLockMsg
		if err := ssh.Unmarshal(data, &req); err != nil {
			return nil, err
		}

		return nil, s.agent.Lock(context.Background(), req.Passphrase, s.Session())

	case agentUnlock:
		var req agentUnlockMsg
		if err := ssh.Unmarshal(data, &req); err != nil {
			return nil, err
		}
		return nil, s.agent.Unlock(context.Background(), req.Passphrase, s.Session())

	case agentSignRequest:
		var req signRequestAgentMsg
		if err := ssh.Unmarshal(data, &req); err != nil {
			return nil, err
		}

		var wk wireKey
		if err := ssh.Unmarshal(req.KeyBlob, &wk); err != nil {
			return nil, err
		}

		k := &Key{
			Format: wk.Format,
			Blob:   req.KeyBlob,
		}

		options := &SignOptions{
			Flags:   SignatureFlags(req.Flags),
			Session: s.Session(),
		}
		sig, err := s.agent.Sign(context.Background(), k, req.Data, options)

		if err != nil {
			return nil, err
		}
		return &signResponseAgentMsg{SigBlob: ssh.Marshal(sig)}, nil

	case agentRequestIdentities:
		keys, err := s.agent.List(context.Background(), s.Session())
		if err != nil {
			return nil, err
		}

		rep := identitiesAnswerAgentMsg{
			NumKeys: uint32(len(keys)),
		}
		for _, k := range keys {
			rep.Keys = append(rep.Keys, marshalKey(k)...)
		}
		return rep, nil

	case agentAddIDConstrained, agentAddIdentity:
		return nil, s.insertIdentity(data)

	case agentExtension:
		// Return a stub object where the whole contents of the response gets marshaled.
		var responseStub struct {
			Rest []byte `ssh:"rest"`
		}

		var req extensionAgentMsg
		if err := ssh.Unmarshal(data, &req); err != nil {
			return nil, err
		}
		extReply := []byte{agentFailure}
		if req.ExtensionType == "session-bind@openssh.com" {
			s.bindAttempted = true
			if len(s.sessionBinds) < 16 {
				sessionBind, err := ParseSessionBind(req.Contents)
				if err == nil {
					// Check whether sid/key already recorded. New sid with
					// previously-seen key can happen, e.g. multiple
					// connections to the same host.
					found := false
					// Check if a previous bind in the chain was not for
					// forwarding (but for auth). In this case we cannot
					// extend the chain any further.
					validChain := true
					for _, bind := range s.sessionBinds {
						if !bind.Forwarding {
							validChain = false
							break
						}

						if bytes.Equal(bind.SessionID, sessionBind.SessionID) &&
							bytes.Equal(bind.HostKey.Marshal(), sessionBind.HostKey.Marshal()) {
							found = true
						}
					}
					if validChain && !found {
						s.sessionBinds = append(s.sessionBinds, sessionBind)
						extReply = []byte{agentSuccess}
					}
				}
			}
		}

		res, err := s.agent.Extension(context.Background(), req.ExtensionType, req.Contents, s.Session())
		if err != nil {
			// If agent extensions are unsupported, return a standard SSH_AGENT_FAILURE
			// message as required by [PROTOCOL.agent] section 4.7.
			if err == ErrExtensionUnsupported {
				responseStub.Rest = extReply
			} else {
				// As the result of any other error processing an extension request,
				// [PROTOCOL.agent] section 4.7 requires that we return a
				// SSH_AGENT_EXTENSION_FAILURE code.
				responseStub.Rest = []byte{agentExtensionFailure}
			}
		} else {
			if len(res) == 0 {
				return nil, nil
			}
			responseStub.Rest = res
		}

		return responseStub, nil
	}

	return nil, fmt.Errorf("unknown opcode %d", data[0])
}

func parseConstraints(constraints []byte) (lifetimeSecs uint32, confirmBeforeUse bool, extensions []ConstraintExtension, err error) {
	for len(constraints) != 0 {
		switch constraints[0] {
		case agentConstrainLifetime:
			if len(constraints) < 5 {
				return 0, false, nil, io.ErrUnexpectedEOF
			}
			lifetimeSecs = binary.BigEndian.Uint32(constraints[1:5])
			constraints = constraints[5:]
		case agentConstrainConfirm:
			confirmBeforeUse = true
			constraints = constraints[1:]
		case agentConstrainExtension, agentConstrainExtensionV00:
			var msg constrainExtensionAgentMsg
			if err = ssh.Unmarshal(constraints, &msg); err != nil {
				return 0, false, nil, err
			}
			extensions = append(extensions, ConstraintExtension{
				ExtensionName:    msg.ExtensionName,
				ExtensionDetails: msg.ExtensionDetails,
			})
			constraints = msg.Rest
		default:
			return 0, false, nil, fmt.Errorf("unknown constraint type: %d", constraints[0])
		}
	}
	return
}

func setConstraints(key *KeyEncoding, constraintBytes []byte) error {
	lifetimeSecs, confirmBeforeUse, constraintExtensions, err := parseConstraints(constraintBytes)
	if err != nil {
		return err
	}

	key.LifetimeSecs = lifetimeSecs
	key.ConfirmBeforeUse = confirmBeforeUse
	key.ConstraintExtensions = constraintExtensions
	return nil
}

func parseRSAKey(req []byte) (*KeyEncoding, error) {
	var k rsaKeyMsg
	if err := ssh.Unmarshal(req, &k); err != nil {
		return nil, err
	}
	if k.E.BitLen() > 30 {
		return nil, errors.New("agent: RSA public exponent too large")
	}
	priv := &rsa.PrivateKey{
		PublicKey: rsa.PublicKey{
			E: int(k.E.Int64()),
			N: k.N,
		},
		D:      k.D,
		Primes: []*big.Int{k.P, k.Q},
	}
	priv.Precompute()

	KeyEncoding := &KeyEncoding{PrivateKey: priv, Comment: k.Comments}
	if err := setConstraints(KeyEncoding, k.Constraints); err != nil {
		return nil, err
	}
	return KeyEncoding, nil
}

func parseEd25519Key(req []byte) (*KeyEncoding, error) {
	var k ed25519KeyMsg
	if err := ssh.Unmarshal(req, &k); err != nil {
		return nil, err
	}
	priv := ed25519.PrivateKey(k.Priv)

	KeyEncoding := &KeyEncoding{PrivateKey: &priv, Comment: k.Comments}
	if err := setConstraints(KeyEncoding, k.Constraints); err != nil {
		return nil, err
	}
	return KeyEncoding, nil
}

func parseDSAKey(req []byte) (*KeyEncoding, error) {
	var k dsaKeyMsg
	if err := ssh.Unmarshal(req, &k); err != nil {
		return nil, err
	}
	priv := &dsa.PrivateKey{
		PublicKey: dsa.PublicKey{
			Parameters: dsa.Parameters{
				P: k.P,
				Q: k.Q,
				G: k.G,
			},
			Y: k.Y,
		},
		X: k.X,
	}

	KeyEncoding := &KeyEncoding{PrivateKey: priv, Comment: k.Comments}
	if err := setConstraints(KeyEncoding, k.Constraints); err != nil {
		return nil, err
	}
	return KeyEncoding, nil
}

func unmarshalECDSA(curveName string, keyBytes []byte, privScalar *big.Int) (priv *ecdsa.PrivateKey, err error) {
	priv = &ecdsa.PrivateKey{
		D: privScalar,
	}

	switch curveName {
	case "nistp256":
		priv.Curve = elliptic.P256()
	case "nistp384":
		priv.Curve = elliptic.P384()
	case "nistp521":
		priv.Curve = elliptic.P521()
	default:
		return nil, fmt.Errorf("agent: unknown curve %q", curveName)
	}

	priv.X, priv.Y = elliptic.Unmarshal(priv.Curve, keyBytes)
	if priv.X == nil || priv.Y == nil {
		return nil, errors.New("agent: point not on curve")
	}

	return priv, nil
}

func parseEd25519Cert(req []byte) (*KeyEncoding, error) {
	var k ed25519CertMsg
	if err := ssh.Unmarshal(req, &k); err != nil {
		return nil, err
	}
	pubKey, err := ssh.ParsePublicKey(k.CertBytes)
	if err != nil {
		return nil, err
	}
	priv := ed25519.PrivateKey(k.Priv)
	cert, ok := pubKey.(*ssh.Certificate)
	if !ok {
		return nil, errors.New("agent: bad ED25519 certificate")
	}

	KeyEncoding := &KeyEncoding{PrivateKey: &priv, Certificate: cert, Comment: k.Comments}
	if err := setConstraints(KeyEncoding, k.Constraints); err != nil {
		return nil, err
	}
	return KeyEncoding, nil
}

func parseECDSAKey(req []byte) (*KeyEncoding, error) {
	var k ecdsaKeyMsg
	if err := ssh.Unmarshal(req, &k); err != nil {
		return nil, err
	}

	priv, err := unmarshalECDSA(k.Curve, k.KeyBytes, k.D)
	if err != nil {
		return nil, err
	}

	KeyEncoding := &KeyEncoding{PrivateKey: priv, Comment: k.Comments}
	if err := setConstraints(KeyEncoding, k.Constraints); err != nil {
		return nil, err
	}
	return KeyEncoding, nil
}

func parseRSACert(req []byte) (*KeyEncoding, error) {
	var k rsaCertMsg
	if err := ssh.Unmarshal(req, &k); err != nil {
		return nil, err
	}

	pubKey, err := ssh.ParsePublicKey(k.CertBytes)
	if err != nil {
		return nil, err
	}

	cert, ok := pubKey.(*ssh.Certificate)
	if !ok {
		return nil, errors.New("agent: bad RSA certificate")
	}

	// An RSA publickey as marshaled by rsaPublicKey.Marshal() in keys.go
	var rsaPub struct {
		Name string
		E    *big.Int
		N    *big.Int
	}
	if err := ssh.Unmarshal(cert.Key.Marshal(), &rsaPub); err != nil {
		return nil, fmt.Errorf("agent: Unmarshal failed to parse public key: %v", err)
	}

	if rsaPub.E.BitLen() > 30 {
		return nil, errors.New("agent: RSA public exponent too large")
	}

	priv := rsa.PrivateKey{
		PublicKey: rsa.PublicKey{
			E: int(rsaPub.E.Int64()),
			N: rsaPub.N,
		},
		D:      k.D,
		Primes: []*big.Int{k.Q, k.P},
	}
	priv.Precompute()

	KeyEncoding := &KeyEncoding{PrivateKey: &priv, Certificate: cert, Comment: k.Comments}
	if err := setConstraints(KeyEncoding, k.Constraints); err != nil {
		return nil, err
	}
	return KeyEncoding, nil
}

func parseDSACert(req []byte) (*KeyEncoding, error) {
	var k dsaCertMsg
	if err := ssh.Unmarshal(req, &k); err != nil {
		return nil, err
	}
	pubKey, err := ssh.ParsePublicKey(k.CertBytes)
	if err != nil {
		return nil, err
	}
	cert, ok := pubKey.(*ssh.Certificate)
	if !ok {
		return nil, errors.New("agent: bad DSA certificate")
	}

	// A DSA publickey as marshaled by dsaPublicKey.Marshal() in keys.go
	var w struct {
		Name       string
		P, Q, G, Y *big.Int
	}
	if err := ssh.Unmarshal(cert.Key.Marshal(), &w); err != nil {
		return nil, fmt.Errorf("agent: Unmarshal failed to parse public key: %v", err)
	}

	priv := &dsa.PrivateKey{
		PublicKey: dsa.PublicKey{
			Parameters: dsa.Parameters{
				P: w.P,
				Q: w.Q,
				G: w.G,
			},
			Y: w.Y,
		},
		X: k.X,
	}

	KeyEncoding := &KeyEncoding{PrivateKey: priv, Certificate: cert, Comment: k.Comments}
	if err := setConstraints(KeyEncoding, k.Constraints); err != nil {
		return nil, err
	}
	return KeyEncoding, nil
}

func parseECDSACert(req []byte) (*KeyEncoding, error) {
	var k ecdsaCertMsg
	if err := ssh.Unmarshal(req, &k); err != nil {
		return nil, err
	}

	pubKey, err := ssh.ParsePublicKey(k.CertBytes)
	if err != nil {
		return nil, err
	}
	cert, ok := pubKey.(*ssh.Certificate)
	if !ok {
		return nil, errors.New("agent: bad ECDSA certificate")
	}

	// An ECDSA publickey as marshaled by ecdsaPublicKey.Marshal() in keys.go
	var ecdsaPub struct {
		Name string
		ID   string
		Key  []byte
	}
	if err := ssh.Unmarshal(cert.Key.Marshal(), &ecdsaPub); err != nil {
		return nil, err
	}

	priv, err := unmarshalECDSA(ecdsaPub.ID, ecdsaPub.Key, k.D)
	if err != nil {
		return nil, err
	}

	KeyEncoding := &KeyEncoding{PrivateKey: priv, Certificate: cert, Comment: k.Comments}
	if err := setConstraints(KeyEncoding, k.Constraints); err != nil {
		return nil, err
	}
	return KeyEncoding, nil
}

func (s *server) insertIdentity(req []byte) error {
	var record struct {
		Type string `sshtype:"17|25"`
		Rest []byte `ssh:"rest"`
	}

	if err := ssh.Unmarshal(req, &record); err != nil {
		return err
	}

	var KeyEncoding *KeyEncoding
	var err error

	switch record.Type {
	case ssh.KeyAlgoRSA:
		KeyEncoding, err = parseRSAKey(req)
	case ssh.InsecureKeyAlgoDSA:
		KeyEncoding, err = parseDSAKey(req)
	case ssh.KeyAlgoECDSA256, ssh.KeyAlgoECDSA384, ssh.KeyAlgoECDSA521:
		KeyEncoding, err = parseECDSAKey(req)
	case ssh.KeyAlgoED25519:
		KeyEncoding, err = parseEd25519Key(req)
	case ssh.CertAlgoRSAv01:
		KeyEncoding, err = parseRSACert(req)
	case ssh.InsecureCertAlgoDSAv01:
		KeyEncoding, err = parseDSACert(req)
	case ssh.CertAlgoECDSA256v01, ssh.CertAlgoECDSA384v01, ssh.CertAlgoECDSA521v01:
		KeyEncoding, err = parseECDSACert(req)
	case ssh.CertAlgoED25519v01:
		KeyEncoding, err = parseEd25519Cert(req)
	default:
		return fmt.Errorf("agent: not implemented: %q", record.Type)
	}

	if err != nil {
		return err
	}

	return s.agent.Add(context.Background(), *KeyEncoding, s.Session())
}

// ServeAgent serves the Agent protocol on the given connection. It returns
// when an I/O error occurs.
//
// It supports the "session-bind@openssh.com" extension, maintaining the state
// of the connection's session binds and passing them to the underlying Agent
// implementation for constraint verification.
func ServeAgent(agent Agent, c io.ReadWriter) error {
	s := &server{agent, nil, false}

	var length [4]byte
	for {
		if _, err := io.ReadFull(c, length[:]); err != nil {
			return err
		}
		l := binary.BigEndian.Uint32(length[:])
		if l == 0 {
			return fmt.Errorf("agent: request size is 0")
		}
		if l > maxAgentResponseBytes {
			// We also cap requests.
			return fmt.Errorf("agent: request too large: %d", l)
		}

		req := make([]byte, l)
		if _, err := io.ReadFull(c, req); err != nil {
			return err
		}

		repData := s.processRequestBytes(req)
		if len(repData) > maxAgentResponseBytes {
			return fmt.Errorf("agent: reply too large: %d bytes", len(repData))
		}

		binary.BigEndian.PutUint32(length[:], uint32(len(repData)))
		if _, err := c.Write(length[:]); err != nil {
			return err
		}
		if _, err := c.Write(repData); err != nil {
			return err
		}
	}
}

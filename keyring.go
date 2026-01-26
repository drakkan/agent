// Copyright 2014 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package agent

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/subtle"
	"errors"
	"fmt"
	"log"
	"net"
	"sync"
	"time"

	"golang.org/x/crypto/ssh"
)

const (
	debugAgent = false
)

type privKey struct {
	signer               ssh.Signer
	comment              string
	expire               *time.Time
	restrictDestinations RestrictDestinationConstraintExtension
}

// isPermitted checks whether this key is allowed based on the defined
// constraints. A non-nil username indicates that the check is being performed
// for a signing request.
func (k *privKey) isPermitted(username *string, session *Session) error {
	if len(k.restrictDestinations.Constraints) == 0 {
		return nil
	}
	if session == nil {
		session = &Session{}
	}
	if session.BindsAttempted && len(session.Binds) == 0 {
		return fmt.Errorf("agent: previous session bind failed, bind attempted? %t", session.BindsAttempted)
	}
	if len(session.Binds) == 0 {
		// Local use
		return nil
	}
	// Walk through the session binds and try to find a constraint that
	// satisfies each.
	lastBindIdx := len(session.Binds) - 1
	var fromKey ssh.PublicKey
	for idx, bind := range session.Binds {
		if idx == lastBindIdx {
			if username != nil && bind.Forwarding {
				return errors.New("agent: tried to sign on forwarding hop")
			}
		} else {
			if !bind.Forwarding {
				return errors.New("agent: tried to forward though signing bind")
			}
		}
		if !k.permittedByDestConstraints(fromKey, bind.HostKey, username) {
			if debugAgent {
				var fkFingerprint string
				if fromKey != nil {
					fkFingerprint = ssh.FingerprintSHA256(fromKey)
				}
				var user string
				if username != nil {
					user = *username
				}
				log.Printf("key from %q to %q, username %q, not permitted by destination constraints",
					fkFingerprint, ssh.FingerprintSHA256(bind.HostKey), user)
			}
			return errors.New("agent: refused by destination constraint")
		}
		fromKey = bind.HostKey
	}
	if username == nil {
		// If the last bound session was for a forwarding, and this function
		// is not being called to check a sign request (username is nil), then
		// only permit the key if there is a permission that would allow it to
		// be used at another destination. This hides keys that are allowed to
		// be used to authenticate *to* a host but not permitted for *use*
		// beyond it.
		lastBind := session.Binds[lastBindIdx]
		if lastBind.Forwarding {
			if !k.permittedByDestConstraints(lastBind.HostKey, nil, nil) {
				return errors.New("agent: key permitted at host but not after")
			}
		}
	}
	return nil
}

func (k *privKey) checkForSigning(data []byte, session *Session) error {
	if debugAgent {
		log.Printf("key constraints %d", len(k.restrictDestinations.Constraints))
	}
	if len(k.restrictDestinations.Constraints) == 0 {
		return nil
	}
	if session == nil || len(session.Binds) == 0 {
		return errors.New("agent: refusing use of destination-constrained key to sign on unbound connection")
	}
	if debugAgent {
		fp := ssh.FingerprintSHA256(k.signer.PublicKey())
		for _, c := range k.restrictDestinations.Constraints {
			for _, keySpec := range c.From.HostKeys {
				log.Printf("key %q, constraint from %q, username %q, key %q", fp, c.From.Hostname, c.From.Username, ssh.FingerprintSHA256(keySpec.Key))
			}
			for _, keySpec := range c.To.HostKeys {
				log.Printf("key %q, constraint to %q, username %q, key %q", fp, c.To.Hostname, c.To.Username, ssh.FingerprintSHA256(keySpec.Key))
			}
		}
	}
	authRequest, err := ParsePublicKeyUserAuthRequest(data)
	if err != nil {
		return errors.New("agent: refusing use of destination-constrained key to sign an unidentified signature")
	}
	if debugAgent {
		log.Printf("public key in auth request %s, host key %s",
			ssh.FingerprintSHA256(authRequest.PublicKey), ssh.FingerprintSHA256(authRequest.HostKey))
	}
	if err := k.isPermitted(&authRequest.User, session); err != nil {
		return err
	}
	lastBindIdx := len(session.Binds) - 1
	lastSessionBind := session.Binds[lastBindIdx]
	// Ensure that the session ID is the most recent one registered on the
	// socket. It should have been bound by ssh client immediately before
	// userauth.
	if !bytes.Equal(authRequest.SessionID, lastSessionBind.SessionID) {
		return errors.New("agent: unexpected session ID on signature request")
	}
	// Ensure that the hostkey embedded in the signature matches the one most
	// recently bound to the socket. An exception is made for the initial
	// forwarding hop.
	if authRequest.HostKey == nil && len(session.Binds) > 1 {
		return errors.New("agent: refusing use of destination-constrained key: no hostkey in request and more than one bound session")
	}
	if authRequest.HostKey != nil && !bytes.Equal(authRequest.HostKey.Marshal(), lastSessionBind.HostKey.Marshal()) {
		return errors.New("agent: refusing use of destination-constrained key: mismatch between hostkey in request and most recently bound session")
	}
	// FIXME: For SK keys (see if (sshkey_is_sk(id->key)) {...}), verify that the
	// application field starts with "ssh:" or is a "WebAuthn" once support for this
	// is added.

	return nil
}

func (k *privKey) permittedByDestConstraints(fromKey, toKey ssh.PublicKey, username *string) bool {
	if fromKey == nil && toKey == nil {
		return false
	}
	for _, constraint := range k.restrictDestinations.Constraints {
		if fromKey == nil {
			// We are matching the first hop
			if constraint.From.Hostname != "" || len(constraint.From.HostKeys) != 0 {
				continue
			}
		} else if !matchKeyHop(fromKey, constraint.From) {
			continue
		}
		if debugAgent {
			var fromFP string
			if fromKey != nil {
				fromFP = ssh.FingerprintSHA256(fromKey)
			}
			log.Printf("key %q, ok for constraint from %q", fromFP, constraint.From.Hostname)
		}
		if toKey != nil && !matchKeyHop(toKey, constraint.To) {
			continue
		}
		if debugAgent {
			var toFP string
			if toKey != nil {
				toFP = ssh.FingerprintSHA256(toKey)
			}
			log.Printf("key %q, ok for constraint to %q", toFP, constraint.To.Hostname)
		}
		if username != nil && constraint.To.Username != "" {
			if !matchPattern(*username, constraint.To.Username) {
				if debugAgent {
					log.Printf("username %q for key %q does not match constraint %q",
						*username, ssh.FingerprintSHA256(toKey), constraint.To.Username)
				}
				continue
			}
		}
		return true
	}

	return false
}

func matchKeyHop(key ssh.PublicKey, identity HostIdentity) bool {
	for _, ks := range identity.HostKeys {
		if _, ok := key.(*ssh.Certificate); ok {
			if !ks.CA {
				continue
			}
			checker := &ssh.CertChecker{
				IsHostAuthority: func(p ssh.PublicKey, _ string) bool {
					return bytes.Equal(ks.Key.Marshal(), p.Marshal())
				},
			}
			if err := checker.CheckHostKey(normalizeHost(identity.Hostname), nil, key); err != nil {
				if debugAgent {
					log.Printf("CheckHostKey failed for host %s: %v", identity.Hostname, err)
				}
				continue
			}
			return true
		} else {
			if ks.CA || !bytes.Equal(key.Marshal(), ks.Key.Marshal()) {
				continue
			}
			return true
		}
	}
	return false
}

func normalizeHost(host string) string {
	if _, _, err := net.SplitHostPort(host); err == nil {
		return host
	}
	if len(host) > 0 && host[0] == '[' && host[len(host)-1] == ']' {
		return host + ":22"
	}
	return net.JoinHostPort(host, "22")
}

// matchPattern returns true if the given string matches the pattern (which may
// contain ? and * as wildcards), and false if it does not match.
func matchPattern(s, pattern string) bool {
	const maxRecursionDepth = 64
	return matchPatternRecursive(s, pattern, 0, maxRecursionDepth)
}

func matchPatternRecursive(s, pattern string, depth, maxDepth int) bool {
	if depth > maxDepth {
		return false
	}

	sIdx := 0
	pIdx := 0

	for {
		// If at end of pattern, accept if also at end of string.
		if pIdx >= len(pattern) {
			return sIdx >= len(s)
		}

		if pattern[pIdx] == '*' {
			// Skip this and any consecutive asterisks.
			for pIdx < len(pattern) && pattern[pIdx] == '*' {
				pIdx++
			}

			// If at end of pattern, accept immediately.
			if pIdx >= len(pattern) {
				return true
			}

			// If next character in pattern is known, optimize.
			if pattern[pIdx] != '?' && pattern[pIdx] != '*' {
				// Look for instances of the next character in
				// pattern, and try to match starting from those.
				for sIdx < len(s) {
					if s[sIdx] == pattern[pIdx] &&
						matchPatternRecursive(s[sIdx+1:], pattern[pIdx+1:], depth+1, maxDepth) {
						return true
					}
					sIdx++
				}
				// Failed.
				return false
			}

			// Move ahead one character at a time and try to
			// match at each position.
			for sIdx < len(s) {
				if matchPattern(s[sIdx:], pattern[pIdx:]) {
					return true
				}
				sIdx++
			}
			// Failed.
			return false
		}

		// There must be at least one more character in the string.
		// If we are at the end, fail.
		if sIdx >= len(s) {
			return false
		}

		// Check if the next character of the string is acceptable.
		if pattern[pIdx] != '?' && pattern[pIdx] != s[sIdx] {
			return false
		}

		// Move to the next character, both in string and in pattern.
		sIdx++
		pIdx++
	}
}

type keyring struct {
	mu   sync.Mutex
	keys []privKey

	locked     bool
	passphrase []byte
}

var errLocked = errors.New("agent: locked")

// NewKeyringV2 returns a new in-memory Agent implementation. It is safe for
// concurrent use by multiple goroutines.
//
// It supports "restrict-destination-v00@openssh.com" constraints and enforces
// them based on the Session information provided during calls.
func NewKeyring() Agent {
	return &keyring{}
}

// RemoveAll removes all identities.
func (r *keyring) RemoveAll(ctx context.Context, session *Session) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.locked {
		return errLocked
	}

	r.keys = nil
	return nil
}

// removeLocked does the actual key removal. The caller must already be holding the
// keyring mutex.
func (r *keyring) removeLocked(want []byte, session *Session) error {
	found := false
	for i := 0; i < len(r.keys); {
		if bytes.Equal(r.keys[i].signer.PublicKey().Marshal(), want) {
			found = true
			if session != nil {
				if err := r.keys[i].isPermitted(nil, session); err != nil {
					return err
				}
			}
			r.keys[i] = r.keys[len(r.keys)-1]
			r.keys = r.keys[:len(r.keys)-1]
			continue
		} else {
			i++
		}
	}

	if !found {
		return errors.New("agent: key not found")
	}
	return nil
}

// Remove removes all identities with the given public key.
func (r *keyring) Remove(ctx context.Context, key ssh.PublicKey, session *Session) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.locked {
		return errLocked
	}

	return r.removeLocked(key.Marshal(), session)
}

// Lock locks the agent. Sign and Remove will fail, and List will return an empty list.
func (r *keyring) Lock(ctx context.Context, passphrase []byte, session *Session) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.locked {
		return errLocked
	}

	r.locked = true
	r.passphrase = passphrase
	return nil
}

// Unlock undoes the effect of Lock
func (r *keyring) Unlock(ctx context.Context, passphrase []byte, session *Session) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if !r.locked {
		return errors.New("agent: not locked")
	}
	if 1 != subtle.ConstantTimeCompare(passphrase, r.passphrase) {
		return fmt.Errorf("agent: incorrect passphrase")
	}

	r.locked = false
	r.passphrase = nil
	return nil
}

// expireKeysLocked removes expired keys from the keyring. If a key was added
// with a lifetimesecs constraint and seconds >= lifetimesecs seconds have
// elapsed, it is removed. The caller *must* be holding the keyring mutex.
func (r *keyring) expireKeysLocked() {
	for _, k := range r.keys {
		if k.expire != nil && time.Now().After(*k.expire) {
			r.removeLocked(k.signer.PublicKey().Marshal(), nil)
		}
	}
}

// List returns the identities known to the agent.
func (r *keyring) List(ctx context.Context, session *Session) ([]*Key, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.locked {
		// section 2.7: locked agents return empty.
		return nil, nil
	}

	r.expireKeysLocked()
	var ids []*Key
	for _, k := range r.keys {
		if session != nil {
			if err := k.isPermitted(nil, session); err != nil {
				continue
			}
		}
		pub := k.signer.PublicKey()
		ids = append(ids, &Key{
			Format:  pub.Type(),
			Blob:    pub.Marshal(),
			Comment: k.comment})
	}
	return ids, nil
}

// Insert adds a private key to the keyring. If a certificate
// is given, that certificate is added as public key. Note that
// any constraints given are ignored.
func (r *keyring) Add(ctx context.Context, key InputKey, session *Session) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.locked {
		return errLocked
	}
	signer, err := ssh.NewSignerFromKey(key.PrivateKey)

	if err != nil {
		return err
	}

	if cert := key.Certificate; cert != nil {
		signer, err = ssh.NewCertSigner(cert, signer)
		if err != nil {
			return err
		}
	}

	p := privKey{
		signer:  signer,
		comment: key.Comment,
	}

	if key.LifetimeSecs > 0 {
		t := time.Now().Add(time.Duration(key.LifetimeSecs) * time.Second)
		p.expire = &t
	}

	for _, ext := range key.ConstraintExtensions {
		if ext.ExtensionName == RestrictDestinationExtensionName {
			if len(p.restrictDestinations.Constraints) > 0 {
				return fmt.Errorf("agent: extension %s already set", ext.ExtensionName)
			}
			if restrictions, err := ParseRestrictDestinationConstraintExtension(ext.ExtensionDetails); err == nil {
				p.restrictDestinations = restrictions
			}
		}
	}

	// If we already have a Signer with the same public key, replace it with the
	// new one.
	for idx, k := range r.keys {
		if bytes.Equal(k.signer.PublicKey().Marshal(), p.signer.PublicKey().Marshal()) {
			if session != nil {
				if err := p.isPermitted(nil, session); err != nil {
					return err
				}
			}
			r.keys[idx] = p
			return nil
		}
	}

	r.keys = append(r.keys, p)

	return nil
}

// Sign returns a signature for the data.
func (r *keyring) Sign(ctx context.Context, key ssh.PublicKey, data []byte, options *SignOptions) (*ssh.Signature, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.locked {
		return nil, errLocked
	}

	r.expireKeysLocked()
	wanted := key.Marshal()
	for _, k := range r.keys {
		if bytes.Equal(k.signer.PublicKey().Marshal(), wanted) {
			if options == nil {
				options = &SignOptions{}
			}
			err := k.checkForSigning(data, options.Session)
			if debugAgent {
				log.Printf("check restricted destination for signing for %q, result: %v", ssh.FingerprintSHA256(key), err)
			}
			if err != nil {
				return nil, err
			}
			if options.Flags == 0 {
				return k.signer.Sign(rand.Reader, data)
			} else {
				if algorithmSigner, ok := k.signer.(ssh.AlgorithmSigner); !ok {
					return nil, fmt.Errorf("agent: signature does not support non-default signature algorithm: %T", k.signer)
				} else {
					var algorithm string
					switch options.Flags {
					case SignatureFlagRsaSha256:
						algorithm = ssh.KeyAlgoRSASHA256
					case SignatureFlagRsaSha512:
						algorithm = ssh.KeyAlgoRSASHA512
					default:
						return nil, fmt.Errorf("agent: unsupported signature flags: %d", options.Flags)
					}
					return algorithmSigner.SignWithAlgorithm(rand.Reader, data, algorithm)
				}
			}
		}
	}
	return nil, errors.New("not found")
}

// The keyring does not support any extensions
func (r *keyring) Extension(ctx context.Context, extensionType string, contents []byte, session *Session) ([]byte, error) {
	return nil, ErrExtensionUnsupported
}

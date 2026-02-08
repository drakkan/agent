// Copyright 2015 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package agent

import (
	"bytes"
	"context"
	"crypto/rand"
	"testing"

	"golang.org/x/crypto/ssh"
)

func addTestKey(t *testing.T, a Agent, keyName string, session *Session) {
	err := a.Add(context.Background(), KeyEncoding{
		PrivateKey: testPrivateKeys[keyName],
		Comment:    keyName,
	}, session)
	if err != nil {
		t.Fatalf("failed to add key %q: %v", keyName, err)
	}
}

func removeTestKey(t *testing.T, a Agent, keyName string, session *Session) {
	err := a.Remove(context.Background(), testPublicKeys[keyName], session)
	if err != nil {
		t.Fatalf("failed to remove key %q: %v", keyName, err)
	}
}

func validateListedKeys(t *testing.T, a Agent, expectedKeys []string, session *Session) {
	listedKeys, err := a.List(context.Background(), session)
	if err != nil {
		t.Fatalf("failed to list keys: %v", err)
		return
	}
	if len(listedKeys) != len(expectedKeys) {
		t.Fatalf("expected %d key, got %d", len(expectedKeys), len(listedKeys))
		return
	}
	actualKeys := make(map[string]bool)
	for _, key := range listedKeys {
		actualKeys[key.Comment] = true
	}

	matchedKeys := make(map[string]bool)
	for _, expectedKey := range expectedKeys {
		if !actualKeys[expectedKey] {
			t.Fatalf("expected key %q, but was not found", expectedKey)
		} else {
			matchedKeys[expectedKey] = true
		}
	}

	for actualKey := range actualKeys {
		if !matchedKeys[actualKey] {
			t.Fatalf("key %q was found, but was not expected", actualKey)
		}
	}
}

func TestKeyringAddingAndRemoving(t *testing.T) {
	keyNames := []string{"dsa", "ecdsa", "rsa", "user"}

	// add all test private keys
	k := NewKeyring()
	for _, keyName := range keyNames {
		addTestKey(t, k, keyName, nil)
	}
	validateListedKeys(t, k, keyNames, nil)

	// remove a key in the middle
	keyToRemove := keyNames[1]
	keyNames = append(keyNames[:1], keyNames[2:]...)

	removeTestKey(t, k, keyToRemove, nil)
	validateListedKeys(t, k, keyNames, nil)

	// remove all keys
	err := k.RemoveAll(context.Background(), nil)
	if err != nil {
		t.Fatalf("failed to remove all keys: %v", err)
	}
	validateListedKeys(t, k, []string{}, nil)
}

func TestAddDuplicateKey(t *testing.T) {
	keyNames := []string{"rsa", "user"}

	k := NewKeyring()
	for _, keyName := range keyNames {
		addTestKey(t, k, keyName, nil)
	}
	validateListedKeys(t, k, keyNames, nil)
	// Add the keys again.
	for _, keyName := range keyNames {
		addTestKey(t, k, keyName, nil)
	}
	validateListedKeys(t, k, keyNames, nil)
	// Add an existing key with an updated comment.
	keyName := keyNames[0]
	KeyEncoding := KeyEncoding{
		PrivateKey: testPrivateKeys[keyName],
		Comment:    "comment updated",
	}
	err := k.Add(context.Background(), KeyEncoding, nil)
	if err != nil {
		t.Fatalf("failed to add key %q: %v", keyName, err)
	}
	// Check the that key is found and the comment was updated.
	keys, err := k.List(context.Background(), nil)
	if err != nil {
		t.Fatalf("failed to list keys: %v", err)
	}
	if len(keys) != len(keyNames) {
		t.Fatalf("expected %d keys, got %d", len(keyNames), len(keys))
	}
	isFound := false
	for _, key := range keys {
		if key.Comment == KeyEncoding.Comment {
			isFound = true
		}
	}
	if !isFound {
		t.Fatal("key with the updated comment not found")
	}
}

func TestAddKeyWithConstraints(t *testing.T) {
	// Verifies that the client sends constraint extensions
	// and the server refuses unknown constraints that cannot be enforced.
	agent, cleanup := startKeyringAgent(t)
	defer cleanup()

	constraints := []ConstraintExtension{
		{
			ExtensionName:    "extension1",
			ExtensionDetails: []byte("details1"),
		},
	}

	key := testPrivateKeys["rsa"]

	err := agent.Add(KeyEncoding{
		PrivateKey:           key,
		ConstraintExtensions: constraints,
	})
	if err == nil {
		t.Fatal("adding a key with unsupported constraints succeeded")
	}
}

func TestAddKeyWithConfirmBeforeUse(t *testing.T) {
	agent, cleanup := startKeyringAgent(t)
	defer cleanup()

	key := testPrivateKeys["rsa"]

	err := agent.Add(KeyEncoding{
		PrivateKey:       key,
		ConfirmBeforeUse: true,
	})
	if err == nil {
		t.Fatal("adding a key with confirm before use constraint succeeded")
	}
}

func TestMatchPatters(t *testing.T) {
	type testCase struct {
		value    string
		pattern  string
		expected bool
	}
	tests := []testCase{
		{"hello", "h?llo", true},
		{"hello", "he*o", true},
		{"hello", "*o", true},
		{"hello", "h*", true},
		{"hello", "*l*", true},
		{"hello", "he??o", true},
		{"hello", "he??a", false},
		{"", "*", true},
		{"", "?", false},
		{"abc", "a*c", true},
		{"abcd", "a*d", true},
		{"abcd", "a*e", false},
		{"abcd", "*", true},
		{"abcd", "abcd*", true},
		{"abcd", "abc?", true},
		{"abcd", "ab?d", true},
		{"abcdef", "a*e?f", false},
		{"abcdef", "a*d*f", true},
		{"abcdef", "a*?f", true},
		{"abcdef", "*a*b*c*d*e*f*", true},
		{"abc", "***a***b***c***", true},
		{"abc", "***a***b***d***", false},
		{"abcd", "????", true},
		{"abcd", "???", false},
		{"abcd", "*****", true},
		{"abcd", "*?*?*?*?*", true},
		{"abcd", "*?*?*?*", true},
		{"abcde", "?*?*?", true},
		{"abcde", "?*?*?*", true},
		{"abcde", "?*?*?*f", false},
		{"", "", true},
		{"a", "", false},
		{"", "a*", false},
		{"", "a", false},
	}

	for _, tc := range tests {
		result := matchPattern(tc.value, tc.pattern)
		if result != tc.expected {
			t.Errorf("value %q, pattern %q, expected %t, got %t", tc.value, tc.pattern, tc.expected, result)
		}
	}
}

type constraintBuilder struct {
	from HostIdentity
	to   HostIdentity
}

func newConstraint() *constraintBuilder {
	return &constraintBuilder{}
}

func (cb *constraintBuilder) fromHost(hostname string, keys ...ssh.PublicKey) *constraintBuilder {
	cb.from.Hostname = hostname
	for _, key := range keys {
		cb.from.HostKeys = append(cb.from.HostKeys, HostIdentityKeySpec{
			Key: key,
			CA:  false,
		})
	}
	return cb
}

func (cb *constraintBuilder) fromCA(hostname string, cas ...ssh.PublicKey) *constraintBuilder {
	cb.from.Hostname = hostname
	for _, ca := range cas {
		cb.from.HostKeys = append(cb.from.HostKeys, HostIdentityKeySpec{
			Key: ca,
			CA:  true,
		})
	}
	return cb
}

func (cb *constraintBuilder) toHost(hostname string, keys ...ssh.PublicKey) *constraintBuilder {
	cb.to.Hostname = hostname
	for _, key := range keys {
		cb.to.HostKeys = append(cb.to.HostKeys, HostIdentityKeySpec{
			Key: key,
			CA:  false,
		})
	}
	return cb
}

func (cb *constraintBuilder) toCA(hostname string, cas ...ssh.PublicKey) *constraintBuilder {
	cb.to.Hostname = hostname
	for _, ca := range cas {
		cb.to.HostKeys = append(cb.to.HostKeys, HostIdentityKeySpec{
			Key: ca,
			CA:  true,
		})
	}
	return cb
}

func (cb *constraintBuilder) toUser(username string) *constraintBuilder {
	cb.to.Username = username
	return cb
}

func (cb *constraintBuilder) build() DestinationConstraint {
	return DestinationConstraint{
		From: cb.from,
		To:   cb.to,
	}
}

type sessionBuilder struct {
	binds []SessionBind
}

func newSession() *sessionBuilder {
	return &sessionBuilder{}
}

func (sb *sessionBuilder) addBind(hostKey ssh.Signer, sessionID []byte, forwarding bool) *sessionBuilder {
	sb.binds = append(sb.binds, SessionBind{
		HostKey:    hostKey.PublicKey(),
		SessionID:  sessionID,
		Forwarding: forwarding,
	})
	return sb
}

func (sb *sessionBuilder) build() *Session {
	return &Session{
		Binds:          sb.binds,
		BindsAttempted: len(sb.binds) > 0,
	}
}

func createAuthRequest(t *testing.T, username string, clientKey, hostKey ssh.PublicKey, sessionID []byte) []byte {
	t.Helper()

	msg := struct {
		SessionID []byte
		Type      byte
		User      string
		Service   string
		Method    string
		IsQuery   byte
		Algorithm string
		PubKey    []byte
		HostKey   []byte
	}{
		SessionID: sessionID,
		Type:      50, // SSH_MSG_USERAUTH_REQUEST
		User:      username,
		Service:   "ssh-connection",
		Method:    "publickey-hostbound-v00@openssh.com",
		IsQuery:   1,
		Algorithm: clientKey.Type(),
		PubKey:    clientKey.Marshal(),
		HostKey:   hostKey.Marshal(),
	}

	return ssh.Marshal(msg)
}

func stringPtr(value string) *string {
	return &value
}

func TestKeyringIsKeyPermitted(t *testing.T) {
	testHostCert := &ssh.Certificate{
		ValidPrincipals: []string{"gopher1", "gopher2"},
		CertType:        ssh.HostCert,
		ValidAfter:      0,                    // unix epoch
		ValidBefore:     ssh.CertTimeInfinity, // The end of currently representable time.
		Key:             testPublicKeys["ecdsa"],
		SignatureKey:    testPublicKeys["rsa"],
		Permissions: ssh.Permissions{
			CriticalOptions: map[string]string{},
			Extensions:      map[string]string{},
		},
	}
	testHostCert.SignCert(rand.Reader, testSigners["rsa"])
	certSigner, err := ssh.NewCertSigner(testHostCert, testSigners["ecdsa"])
	if err != nil {
		t.Errorf("NewCertSigner: %v", err)
	}

	tests := []struct {
		name        string
		constraints []DestinationConstraint
		session     *Session
		username    *string
		wantErr     bool
		errContains string
	}{
		{
			name:        "no constraints - always permitted",
			constraints: nil,
			session:     nil,
			username:    nil,
			wantErr:     false,
		},
		{
			name: "constraints but no session - local use permitted",
			constraints: []DestinationConstraint{
				newConstraint().
					toHost("dest.example.com", testPublicKeys["rsa"]).
					build(),
			},
			session:  nil,
			username: nil,
			wantErr:  false,
		},
		{
			name: "empty session binds - local use permitted",
			constraints: []DestinationConstraint{
				newConstraint().
					toHost("dest.example.com", testPublicKeys["rsa"]).
					build(),
			},
			session:  &Session{Binds: []SessionBind{}},
			username: nil,
			wantErr:  false,
		},
		{
			name: "failed bind attempt",
			constraints: []DestinationConstraint{
				newConstraint().
					toHost("host1.example.com", testPublicKeys["rsa"]).
					build(),
			},
			session: &Session{
				Binds:          []SessionBind{},
				BindsAttempted: true,
			},
			username:    stringPtr("user1"),
			wantErr:     true,
			errContains: "previous session bind failed",
		},
		{
			name: "single hop - matching constraint",
			constraints: []DestinationConstraint{
				newConstraint().
					toHost("host1.example.com", testPublicKeys["rsa"]).
					build(),
			},
			session: newSession().
				addBind(testSigners["rsa"], []byte("session1"), false).
				build(),
			username: stringPtr("user1"),
			wantErr:  false,
		},
		{
			name: "single hop - non-matching host key",
			constraints: []DestinationConstraint{
				newConstraint().
					toHost("host1.example.com", testPublicKeys["rsa"]).
					build(),
			},
			session: newSession().
				addBind(testSigners["ecdsa"], []byte("session1"), false).
				build(),
			username:    stringPtr("user1"),
			wantErr:     true,
			errContains: "refused by destination constraint",
		},
		{
			name: "username constraint - matching",
			constraints: []DestinationConstraint{
				newConstraint().
					toHost("host1.example.com", testPublicKeys["rsa"]).
					toUser("alice").
					build(),
			},
			session: newSession().
				addBind(testSigners["rsa"], []byte("session1"), false).
				build(),
			username: stringPtr("alice"),
			wantErr:  false,
		},
		{
			name: "username constraint - non-matching",
			constraints: []DestinationConstraint{
				newConstraint().
					toHost("host1.example.com", testPublicKeys["rsa"]).
					toUser("alice").
					build(),
			},
			session: newSession().
				addBind(testSigners["rsa"], []byte("session1"), false).
				build(),
			username:    stringPtr("bob"),
			wantErr:     true,
			errContains: "refused by destination constraint",
		},
		{
			name: "username constraint - empty username",
			constraints: []DestinationConstraint{
				newConstraint().
					toHost("host1.example.com", testPublicKeys["rsa"]).
					toUser("alice").
					build(),
			},
			session: newSession().
				addBind(testSigners["rsa"], []byte("session1"), false).
				build(),
			username:    stringPtr(""),
			wantErr:     true,
			errContains: "refused by destination constraint",
		},
		{
			name: "username constraint - nil username",
			constraints: []DestinationConstraint{
				newConstraint().
					toHost("host1.example.com", testPublicKeys["rsa"]).
					toUser("alice").
					build(),
			},
			session: newSession().
				addBind(testSigners["rsa"], []byte("session1"), false).
				build(),
			username: nil,
			wantErr:  false,
		},
		{
			name: "username wildcard - matching",
			constraints: []DestinationConstraint{
				newConstraint().
					toHost("host1.example.com", testPublicKeys["rsa"]).
					toUser("admin-*").
					build(),
			},
			session: newSession().
				addBind(testSigners["rsa"], []byte("session1"), false).
				build(),
			username: stringPtr("admin-alice"),
			wantErr:  false,
		},
		{
			name: "username wildcard - non-matching",
			constraints: []DestinationConstraint{
				newConstraint().
					toHost("host1.example.com", testPublicKeys["rsa"]).
					toUser("admin-*").
					build(),
			},
			session: newSession().
				addBind(testSigners["rsa"], []byte("session1"), false).
				build(),
			username:    stringPtr("user-alice"),
			wantErr:     true,
			errContains: "refused by destination constraint",
		},
		{
			name: "two hop forwarding - both match",
			constraints: []DestinationConstraint{
				newConstraint().
					toHost("host1.example.com", testPublicKeys["rsa"]).
					build(),
				newConstraint().
					fromHost("host1.example.com", testPublicKeys["rsa"]).
					toHost("host2.example.com", testPublicKeys["ecdsa"]).
					build(),
			},
			session: newSession().
				addBind(testSigners["rsa"], []byte("session1"), true).
				addBind(testSigners["ecdsa"], []byte("session2"), false).
				build(),
			username: stringPtr("user1"),
			wantErr:  false,
		},
		{
			name: "two hop forwarding - first hop not matching",
			constraints: []DestinationConstraint{
				newConstraint().
					toHost("host1.example.com", testPublicKeys["ecdsa"]).
					build(),
			},
			session: newSession().
				addBind(testSigners["rsa"], []byte("session1"), true).
				addBind(testSigners["ecdsa"], []byte("session2"), false).
				build(),
			username:    stringPtr("user1"),
			wantErr:     true,
			errContains: "refused by destination constraint",
		},
		{
			name: "two hop forwarding - second hop not matching",
			constraints: []DestinationConstraint{
				newConstraint().
					toHost("host1.example.com", testPublicKeys["rsa"]).
					build(),
				newConstraint().
					fromHost("host1.example.com", testPublicKeys["rsa"]).
					toHost("host2.example.com", testPublicKeys["ecdsa"]).
					build(),
			},
			session: newSession().
				addBind(testSigners["rsa"], []byte("session1"), true).
				addBind(testSigners["ed25519"], []byte("session2"), false).
				build(),
			username:    stringPtr("user1"),
			wantErr:     true,
			errContains: "refused by destination constraint",
		},
		{
			name: "three hop forwarding chain",
			constraints: []DestinationConstraint{
				newConstraint().
					toHost("host1.example.com", testPublicKeys["rsa"]).
					build(),
				newConstraint().
					fromHost("host1.example.com", testPublicKeys["rsa"]).
					toHost("host2.example.com", testPublicKeys["ecdsa"]).
					build(),
				newConstraint().
					fromHost("host2.example.com", testPublicKeys["ecdsa"]).
					toHost("host3.example.com", testPublicKeys["ed25519"]).
					build(),
			},
			session: newSession().
				addBind(testSigners["rsa"], []byte("session1"), true).
				addBind(testSigners["ecdsa"], []byte("session2"), true).
				addBind(testSigners["ed25519"], []byte("session3"), false).
				build(),
			username: stringPtr("user1"),
			wantErr:  false,
		},
		{
			name: "try to sign on forwarding hop - should fail",
			constraints: []DestinationConstraint{
				newConstraint().
					toHost("host1.example.com", testPublicKeys["rsa"]).
					build(),
				newConstraint().
					fromHost("host1.example.com", testPublicKeys["rsa"]).
					toHost("host2.example.com", testPublicKeys["ecdsa"]).
					build(),
			},
			session: newSession().
				addBind(testSigners["rsa"], []byte("session1"), true).
				build(),
			username:    stringPtr("user1"),
			wantErr:     true,
			errContains: "tried to sign on forwarding hop",
		},
		{
			name: "try to forward through signing bind - should fail",
			constraints: []DestinationConstraint{
				newConstraint().
					toHost("host1.example.com", testPublicKeys["rsa"]).
					build(),
				newConstraint().
					fromHost("host1.example.com", testPublicKeys["rsa"]).
					toHost("host2.example.com", testPublicKeys["ecdsa"]).
					build(),
			},
			session: newSession().
				addBind(testSigners["rsa"], []byte("session1"), false).
				addBind(testSigners["ecdsa"], []byte("session2"), true).
				build(),
			username:    stringPtr("user1"),
			wantErr:     true,
			errContains: "tried to forward though signing bind",
		},
		{
			name: "multiple constraints - first matches",
			constraints: []DestinationConstraint{
				newConstraint().
					toHost("host1.example.com", testPublicKeys["rsa"]).
					build(),
				newConstraint().
					toHost("host2.example.com", testPublicKeys["ecdsa"]).
					build(),
			},
			session: newSession().
				addBind(testSigners["rsa"], []byte("session1"), false).
				build(),
			username: stringPtr("user1"),
			wantErr:  false,
		},
		{
			name: "multiple constraints - second matches",
			constraints: []DestinationConstraint{
				newConstraint().
					toHost("host1.example.com", testPublicKeys["rsa"]).
					build(),
				newConstraint().
					toHost("host2.example.com", testPublicKeys["ecdsa"]).
					build(),
			},
			session: newSession().
				addBind(testSigners["ecdsa"], []byte("session1"), false).
				build(),
			username: stringPtr("user1"),
			wantErr:  false,
		},
		{
			name: "key permitted at host but not beyond",
			constraints: []DestinationConstraint{
				newConstraint().
					toHost("host1.example.com", testPublicKeys["rsa"]).
					build(),
			},
			session: newSession().
				addBind(testSigners["rsa"], []byte("session1"), true).
				build(),
			username:    nil,
			wantErr:     true,
			errContains: "key permitted at host but not after",
		},
		{
			name: "key permitted at host and beyond",
			constraints: []DestinationConstraint{
				newConstraint().
					toHost("host1.example.com", testPublicKeys["rsa"]).
					build(),
				newConstraint().
					fromHost("host1.example.com", testPublicKeys["rsa"]).
					toHost("host2.example.com", testPublicKeys["ecdsa"]).
					build(),
			},
			session: newSession().
				addBind(testSigners["rsa"], []byte("session1"), true).
				build(),
			username: nil,
			wantErr:  false,
		},
		{
			name: "last bind is not forwarding with nil username",
			constraints: []DestinationConstraint{
				newConstraint().
					toHost("host1.example.com", testPublicKeys["rsa"]).
					build(),
			},
			session: newSession().
				addBind(testSigners["rsa"], []byte("session1"), false).
				build(),
			username: nil,
			wantErr:  false,
		},
		{
			name: "certificate host key - matching CA and valid principal",
			constraints: []DestinationConstraint{
				newConstraint().
					toCA("gopher1", testPublicKeys["rsa"]).
					build(),
			},
			session: newSession().
				addBind(certSigner, []byte("session1"), false).
				build(),
			username: stringPtr("user1"),
			wantErr:  false,
		},
		{
			name: "certificate host key - matching CA, valid principal, no host cert",
			constraints: []DestinationConstraint{
				newConstraint().
					toCA("gopher1", testPublicKeys["rsa"]).
					build(),
			},
			session: newSession().
				addBind(testSigners["cert"], []byte("session1"), false).
				build(),
			username: stringPtr("user1"),
			wantErr:  true,
		},
		{
			name: "certificate host key - matching CA but invalid principal",
			constraints: []DestinationConstraint{
				newConstraint().
					toCA("wrong.host", testPublicKeys["rsa"]).
					build(),
			},
			session: newSession().
				addBind(certSigner, []byte("session1"), false).
				build(),
			username:    stringPtr("user1"),
			wantErr:     true,
			errContains: "refused by destination constraint",
		},
		{
			name: "certificate host key - wrong CA",
			// Cert is signed by RSA, but constraint requires ECDSA as CA
			constraints: []DestinationConstraint{
				newConstraint().
					toCA("gopher1", testPublicKeys["ecdsa"]).
					build(),
			},
			session: newSession().
				addBind(certSigner, []byte("session1"), false).
				build(),
			username:    stringPtr("user1"),
			wantErr:     true,
			errContains: "refused by destination constraint",
		},
		{
			name: "certificate host key - constraint expects plain key",
			// toHost creates a constraint with IsCA=false.
			constraints: []DestinationConstraint{
				newConstraint().
					toHost("gopher1", testPublicKeys["rsa"]).
					build(),
			},
			session: newSession().
				addBind(certSigner, []byte("session1"), false).
				build(),
			username:    stringPtr("user1"),
			wantErr:     true,
			errContains: "refused by destination constraint",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			k := &privKey{
				signer:  testSigners["rsa"],
				comment: "test key",
				restrictDestinations: RestrictDestinationConstraintExtension{
					Constraints: tt.constraints,
				},
			}

			err := k.isPermitted(tt.username, tt.session)
			if (err != nil) != tt.wantErr {
				t.Errorf("isPermitted() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if err != nil && tt.errContains != "" {
				if !bytes.Contains([]byte(err.Error()), []byte(tt.errContains)) {
					t.Errorf("isPermitted() error = %v, should contain %q", err, tt.errContains)
				}
			}
		})
	}
}

func TestKeyringCheckForSigning(t *testing.T) {
	sessionID := []byte("test-session-id-12345")

	tests := []struct {
		name        string
		keySigner   ssh.Signer
		constraints []DestinationConstraint
		session     *Session
		authData    []byte
		wantErr     bool
		errContains string
	}{
		{
			name:        "no constraints - always allowed",
			keySigner:   testSigners["rsa"],
			constraints: nil,
			session:     nil,
			authData:    createAuthRequest(t, "user1", testPublicKeys["rsa"], testPublicKeys["ecdsa"], sessionID),
			wantErr:     false,
		},
		{
			name:      "constraints but no session - should fail",
			keySigner: testSigners["rsa"],
			constraints: []DestinationConstraint{
				newConstraint().
					toHost("host1.example.com", testPublicKeys["rsa"]).
					build(),
			},
			session:     nil,
			authData:    createAuthRequest(t, "user1", testPublicKeys["rsa"], testPublicKeys["ecdsa"], sessionID),
			wantErr:     true,
			errContains: "refusing use of destination-constrained key to sign on unbound connection",
		},
		{
			name:      "valid signing request - single hop",
			keySigner: testSigners["rsa"],
			constraints: []DestinationConstraint{
				newConstraint().
					toHost("host1.example.com", testPublicKeys["ecdsa"]).
					toUser("alice").
					build(),
			},
			session: newSession().
				addBind(testSigners["ecdsa"], sessionID, false).
				build(),
			authData: createAuthRequest(t, "alice", testPublicKeys["rsa"], testPublicKeys["ecdsa"], sessionID),
			wantErr:  false,
		},
		{
			name:      "session ID mismatch",
			keySigner: testSigners["rsa"],
			constraints: []DestinationConstraint{
				newConstraint().
					toHost("host1.example.com", testPublicKeys["ecdsa"]).
					build(),
			},
			session: newSession().
				addBind(testSigners["ecdsa"], []byte("different-session-id"), false).
				build(),
			authData:    createAuthRequest(t, "user1", testPublicKeys["rsa"], testPublicKeys["ecdsa"], sessionID),
			wantErr:     true,
			errContains: "unexpected session ID",
		},
		{
			name:      "host key mismatch",
			keySigner: testSigners["rsa"],
			constraints: []DestinationConstraint{
				newConstraint().
					toHost("host1.example.com", testPublicKeys["ecdsa"]).
					build(),
			},
			session: newSession().
				addBind(testSigners["ecdsa"], sessionID, false).
				build(),
			authData:    createAuthRequest(t, "user1", testPublicKeys["rsa"], testPublicKeys["ed25519"], sessionID),
			wantErr:     true,
			errContains: "mismatch between hostkey in request and most recently bound session",
		},
		{
			name:      "username constraint violation",
			keySigner: testSigners["rsa"],
			constraints: []DestinationConstraint{
				newConstraint().
					toHost("host1.example.com", testPublicKeys["ecdsa"]).
					toUser("alice").
					build(),
			},
			session: newSession().
				addBind(testSigners["ecdsa"], sessionID, false).
				build(),
			authData:    createAuthRequest(t, "bob", testPublicKeys["rsa"], testPublicKeys["ecdsa"], sessionID),
			wantErr:     true,
			errContains: "refused by destination constraint",
		},
		{
			name:      "malformed auth request",
			keySigner: testSigners["rsa"],
			constraints: []DestinationConstraint{
				newConstraint().
					toHost("host1.example.com", testPublicKeys["ecdsa"]).
					build(),
			},
			session: newSession().
				addBind(testSigners["ecdsa"], sessionID, false).
				build(),
			authData:    []byte("invalid data"),
			wantErr:     true,
			errContains: "refusing use of destination-constrained key to sign an unidentified signature",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			k := &privKey{
				signer: tt.keySigner,
				restrictDestinations: RestrictDestinationConstraintExtension{
					Constraints: tt.constraints,
				},
			}

			err := k.checkForSigning(tt.authData, tt.session)
			if (err != nil) != tt.wantErr {
				t.Errorf("checkForSigning() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if err != nil && tt.errContains != "" {
				if !bytes.Contains([]byte(err.Error()), []byte(tt.errContains)) {
					t.Errorf("checkForSigning() error = %v, should contain %q", err, tt.errContains)
				}
			}
		})
	}
}

func TestNormalizeHost(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{
			name:     "hostname simple",
			input:    "example.com",
			expected: "example.com:22",
		},
		{
			name:     "hostname with port",
			input:    "example.com:2222",
			expected: "example.com:2222",
		},
		{
			name:     "ipv4 simple",
			input:    "1.2.3.4",
			expected: "1.2.3.4:22",
		},
		{
			name:     "ipv4 with port",
			input:    "1.2.3.4:80",
			expected: "1.2.3.4:80",
		},
		{
			name:     "ipv6 raw",
			input:    "::1",
			expected: "[::1]:22",
		},
		{
			name:     "ipv6 raw complex",
			input:    "2001:db8::1",
			expected: "[2001:db8::1]:22",
		},
		{
			name:     "ipv6 brackets no port",
			input:    "[::1]",
			expected: "[::1]:22",
		},
		{
			name:     "ipv6 brackets with port",
			input:    "[::1]:2222",
			expected: "[::1]:2222",
		},
		{
			name:     "ipv6 brackets complex no port",
			input:    "[2001:db8::1]",
			expected: "[2001:db8::1]:22",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := normalizeHost(tc.input)
			if got != tc.expected {
				t.Errorf("normalizeHost(%q) = %q, want %q", tc.input, got, tc.expected)
			}
		})
	}
}

func TestAgentConstraintsOperations(t *testing.T) {
	k := NewKeyring()

	jumpHostKey := testPublicKeys["ecdsa"]
	destHostKey := testPublicKeys["rsa"]

	constraints := []DestinationConstraint{
		newConstraint().
			toHost("jump.host", jumpHostKey).
			build(),
		newConstraint().
			fromHost("jump.host", jumpHostKey).
			toHost("dest.host", destHostKey).
			build(),
	}
	restrictedDestinations := RestrictDestinationConstraintExtension{
		Constraints: constraints,
	}
	extData := restrictedDestinations.Marshal()

	restrictedKey := KeyEncoding{
		PrivateKey: testPrivateKeys["rsa"],
		Comment:    "restricted-rsa",
		ConstraintExtensions: []ConstraintExtension{
			{
				ExtensionName:    RestrictDestinationExtensionName,
				ExtensionDetails: extData,
			},
		},
	}

	unrestrictedKey := KeyEncoding{
		PrivateKey: testPrivateKeys["ed25519"],
		Comment:    "unrestricted-ed25519",
	}

	t.Run("Add", func(t *testing.T) {
		if err := k.Add(context.Background(), restrictedKey, nil); err != nil {
			t.Fatalf("Add (restricted) failed: %v", err)
		}
		if err := k.Add(context.Background(), unrestrictedKey, nil); err != nil {
			t.Fatalf("Add (unrestricted) failed: %v", err)
		}
	})

	validSession := &Session{
		Binds: []SessionBind{
			{
				HostKey:    jumpHostKey,
				SessionID:  []byte("valid-session-id"),
				Forwarding: false,
			},
		},
	}

	restrictedSession := &Session{
		Binds: []SessionBind{
			{
				HostKey:    testPublicKeys["ed25519"],
				SessionID:  []byte("invalid-session-id"),
				Forwarding: false,
			},
		},
	}

	t.Run("List", func(t *testing.T) {
		keys, err := k.List(context.Background(), validSession)
		if err != nil {
			t.Fatalf("Valid session list failed: %v", err)
		}
		if len(keys) != 2 {
			t.Errorf("Valid session: expected 2 keys, got %d", len(keys))
		}

		keys, err = k.List(context.Background(), restrictedSession)
		if err != nil {
			t.Fatalf("Invalid session list failed: %v", err)
		}
		if len(keys) != 1 {
			t.Errorf("Invalid session: expected 1 key, got %d", len(keys))
		}
		if len(keys) == 1 && keys[0].Comment != "unrestricted-ed25519" {
			t.Errorf("Invalid session: expected unrestricted key, got %s", keys[0].Comment)
		}
	})

	t.Run("SignWithOptions", func(t *testing.T) {
		authRequestData := createAuthRequest(t,
			"user",
			testPublicKeys["rsa"],
			jumpHostKey,
			validSession.Binds[0].SessionID,
		)

		sig, err := k.Sign(context.Background(), validSession, testPublicKeys["rsa"], authRequestData, nil)
		if err != nil {
			t.Fatalf("Sign restricted (valid session) failed: %v", err)
		}
		if err := testPublicKeys["rsa"].Verify(authRequestData, sig); err != nil {
			t.Fatalf("Verify signature failed: %v", err)
		}

		_, err = k.Sign(context.Background(), restrictedSession, testPublicKeys["rsa"], authRequestData, nil)
		if err == nil {
			t.Fatal("Sign restricted (invalid session) succeeded, expected failure")
		}

		authRequestUnrestricted := createAuthRequest(t,
			"user",
			testPublicKeys["ed25519"],
			testPublicKeys["ed25519"], // Matching the invalid session host key
			restrictedSession.Binds[0].SessionID,
		)
		sig, err = k.Sign(context.Background(), restrictedSession, testPublicKeys["ed25519"], authRequestUnrestricted, nil)
		if err != nil {
			t.Fatalf("Sign unrestricted (invalid session) failed: %v", err)
		}
		if err := testPublicKeys["ed25519"].Verify(authRequestUnrestricted, sig); err != nil {
			t.Fatalf("Verify unrestricted signature failed: %v", err)
		}

		opts := &SignOptions{
			Flags: SignatureFlagRsaSha256,
		}
		sig, err = k.Sign(context.Background(), validSession, testPublicKeys["rsa"], authRequestData, opts)
		if err != nil {
			t.Fatalf("Sign with flags failed: %v", err)
		}
		if sig.Format != ssh.KeyAlgoRSASHA256 {
			t.Errorf("Expected signature format %s, got %s", ssh.KeyAlgoRSASHA256, sig.Format)
		}
	})

	t.Run("Remove", func(t *testing.T) {
		err := k.Remove(context.Background(), testPublicKeys["rsa"], validSession)
		if err != nil {
			t.Fatalf("Remove restricted key (valid session) failed: %v", err)
		}

		keys, _ := k.List(context.Background(), validSession)
		for _, k := range keys {
			if k.Comment == "restricted-rsa" {
				t.Fatal("Restricted key should have been removed")
			}
		}

		err = k.Remove(context.Background(), testPublicKeys["ed25519"], validSession)
		if err != nil {
			t.Fatalf("Remove unrestricted key failed: %v", err)
		}

		keys, _ = k.List(context.Background(), nil)
		if len(keys) != 0 {
			t.Fatalf("Keyring should be empty, got %d keys", len(keys))
		}
	})
}

func TestRemoveAllIgnoresConstraints(t *testing.T) {
	k := NewKeyring()

	constraints := []DestinationConstraint{
		newConstraint().
			toHost("jump.host", testPublicKeys["ecdsa"]).
			build(),
		newConstraint().
			fromHost("jump.host", testPublicKeys["ecdsa"]).
			toHost("dest.host", testPublicKeys["rsa"]).
			build(),
	}

	restrictedDestinations := RestrictDestinationConstraintExtension{
		Constraints: constraints,
	}
	extData := restrictedDestinations.Marshal()

	keyToAdd := KeyEncoding{
		PrivateKey: testPrivateKeys["rsa"],
		ConstraintExtensions: []ConstraintExtension{
			{
				ExtensionName:    RestrictDestinationExtensionName,
				ExtensionDetails: extData,
			},
		},
	}

	if err := k.Add(context.Background(), keyToAdd, nil); err != nil {
		t.Fatalf("Add failed: %v", err)
	}

	validSession := &Session{
		Binds: []SessionBind{
			{
				HostKey:    testPublicKeys["ecdsa"], // Matches "jump.host"
				SessionID:  []byte("valid-session"),
				Forwarding: true,
			},
		},
	}

	keys, err := k.List(context.Background(), validSession)
	if err != nil {
		t.Fatalf("List (valid) failed: %v", err)
	}
	if len(keys) != 1 {
		t.Fatalf("Expected 1 key visible for valid session, got %d", len(keys))
	}

	invalidSession := &Session{
		Binds: []SessionBind{
			{
				HostKey:    testPublicKeys["ed25519"], // Wrong key
				SessionID:  []byte("invalid-session"),
				Forwarding: true,
			},
		},
	}

	keys, err = k.List(context.Background(), invalidSession)
	if err != nil {
		t.Fatalf("List (invalid) failed: %v", err)
	}
	if len(keys) != 0 {
		t.Fatalf("Expected 0 keys visible for restricted session, got %d", len(keys))
	}

	err = k.Remove(context.Background(), testPublicKeys["rsa"], invalidSession)
	if err == nil {
		t.Fatal("Remove (single) should have failed due to unmet constraints, but succeeded")
	}

	if err := k.RemoveAll(context.Background(), invalidSession); err != nil {
		t.Fatalf("RemoveAll failed: %v", err)
	}

	keys, err = k.List(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(keys) != 0 {
		t.Fatalf("Keyring should be empty after RemoveAll, got %d keys", len(keys))
	}
}

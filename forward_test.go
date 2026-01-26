// Copyright 2026 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package agent

import (
	"bytes"
	"context"
	"io"
	"net"
	"path/filepath"
	"sync"
	"testing"

	"golang.org/x/crypto/ssh"
)

// setupSSHPipe creates a connected SSH client and server for testing
func setupSSHPipe(t *testing.T) (*ssh.Client, *ssh.Client, func()) {
	c1, c2, err := netPipe()
	if err != nil {
		t.Fatalf("netPipe: %v", err)
	}

	serverConf := &ssh.ServerConfig{
		NoClientAuth: true,
	}
	serverConf.AddHostKey(testSigners["rsa"])

	clientConf := &ssh.ClientConfig{
		User:            "test",
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
	}

	var serverConn ssh.Conn
	var serverChans <-chan ssh.NewChannel
	var serverReqs <-chan *ssh.Request
	var clientConn *ssh.Client
	var wg sync.WaitGroup
	wg.Add(2)

	go func() {
		defer wg.Done()
		var err error
		serverConn, serverChans, serverReqs, err = ssh.NewServerConn(c1, serverConf)
		if err != nil {
			t.Logf("NewServerConn: %v", err)
		}
	}()

	go func() {
		defer wg.Done()
		var err error
		conn, chans, reqs, err := ssh.NewClientConn(c2, "test", clientConf)
		if err != nil {
			t.Logf("NewClientConn: %v", err)
			return
		}
		clientConn = ssh.NewClient(conn, chans, reqs)
	}()

	wg.Wait()

	if serverConn == nil || clientConn == nil {
		t.Fatal("failed to establish SSH connection")
	}

	serverClient := ssh.NewClient(serverConn, serverChans, serverReqs)

	cleanup := func() {
		if clientConn != nil {
			clientConn.Close()
		}
		if serverClient != nil {
			serverClient.Close()
		}
		c1.Close()
		c2.Close()
	}

	return clientConn, serverClient, cleanup
}

func TestSetupAgentForwarding(t *testing.T) {
	client, server, cleanup := setupSSHPipe(t)
	defer cleanup()

	agent := NewKeyring()
	accept, err := SetupAgentForwarding(server)
	if err != nil {
		t.Fatalf("SetupAgentForwarding: %v", err)
	}

	err = agent.Add(context.Background(), KeyEncoding{
		PrivateKey: testPrivateKeys["rsa"],
		Comment:    "test key",
	}, nil)
	if err != nil {
		t.Fatalf("Add: %v", err)
	}

	done := make(chan error, 1)
	go func() {
		serverChannel, err := accept()
		if err != nil {
			done <- err
			return
		}
		ServeAgent(agent, serverChannel)
		serverChannel.Close()
		done <- nil
	}()

	// Open an agent channel from the client
	channel, reqs, err := client.OpenChannel(authAgentChannelType, nil)
	if err != nil {
		t.Fatalf("OpenChannel: %v", err)
	}
	go ssh.DiscardRequests(reqs)

	// Use the channel as an agent client
	agentClient := NewClientFromConn(channel)

	// Verify we can list keys
	keys, err := agentClient.List()
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(keys) != 1 {
		t.Fatalf("got %d keys, want 1", len(keys))
	}

	// Sign some data
	signer, err := ssh.NewSignerFromKey(testPrivateKeys["rsa"])
	if err != nil {
		t.Fatalf("NewSignerFromKey: %v", err)
	}
	data := []byte("test data")
	sig, err := agentClient.Sign(signer.PublicKey(), data)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	if err := signer.PublicKey().Verify(data, sig); err != nil {
		t.Fatalf("Verify: %v", err)
	}

	channel.Close()

	// Wait for server goroutine to finish
	if err := <-done; err != nil {
		t.Fatalf("server error: %v", err)
	}
}

func TestSetupAgentForwardingMultipleConnections(t *testing.T) {
	client, server, cleanup := setupSSHPipe(t)
	defer cleanup()

	agent := NewKeyring()
	accept, err := SetupAgentForwarding(server)
	if err != nil {
		t.Fatalf("SetupAgentForwarding: %v", err)
	}

	agent.Add(context.Background(), KeyEncoding{
		PrivateKey: testPrivateKeys["rsa"],
		Comment:    "test key",
	}, nil)

	var wg sync.WaitGroup
	numConnections := 5

	wg.Go(func() {
		for range numConnections {
			serverChannel, err := accept()
			if err != nil {
				t.Logf("accept error: %v", err)
				return
			}
			wg.Add(1)
			go func(ch ssh.Channel) {
				defer wg.Done()
				ServeAgent(agent, ch)
				ch.Close()
			}(serverChannel)
		}
	})

	// Open multiple channels from client
	for i := range numConnections {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()

			channel, reqs, err := client.OpenChannel(authAgentChannelType, nil)
			if err != nil {
				t.Logf("OpenChannel %d: %v", idx, err)
				return
			}
			go ssh.DiscardRequests(reqs)

			agentClient := NewClientFromConn(channel)
			keys, err := agentClient.List()
			if err != nil {
				t.Logf("List %d: %v", idx, err)
			} else if len(keys) != 1 {
				t.Logf("connection %d: got %d keys, want 1", idx, len(keys))
			}

			channel.Close()
		}(i)
	}

	wg.Wait()
}

func TestSetupAgentForwardingAlreadyRegistered(t *testing.T) {
	_, server, cleanup := setupSSHPipe(t)
	defer cleanup()

	// Setup agent forwarding
	_, err := SetupAgentForwarding(server)
	if err != nil {
		t.Fatalf("SetupAgentForwarding: %v", err)
	}

	// Try to setup again - should fail
	_, err = SetupAgentForwarding(server)
	if err == nil {
		t.Fatal("expected error when registering handler twice")
	}
	if err.Error() != "agent: already have handler for auth-agent@openssh.com" {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestSetupRemoteForwarding(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping test in short mode")
	}

	// Create a temporary directory for the socket
	tmpDir := t.TempDir()
	socketPath := filepath.Join(tmpDir, "agent.sock")

	// Start a real agent on a unix socket
	listener, err := net.Listen("unix", socketPath)
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	defer listener.Close()

	agent := NewKeyring()
	agent.Add(context.Background(), KeyEncoding{
		PrivateKey: testPrivateKeys["ecdsa"],
		Comment:    "remote key",
	}, nil)

	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				ServeAgent(agent, c)
				c.Close()
			}(conn)
		}
	}()

	client, server, cleanup := setupSSHPipe(t)
	defer cleanup()

	accept, err := SetupRemoteForwarding(server, socketPath)
	if err != nil {
		t.Fatalf("SetupRemoteForwarding: %v", err)
	}

	done := make(chan error, 1)
	go func() {
		serverChannel, err := accept()
		if err != nil {
			done <- err
			return
		}
		forwardUnixSocket(serverChannel, socketPath)
		done <- nil
	}()

	channel, reqs, err := client.OpenChannel(authAgentChannelType, nil)
	if err != nil {
		t.Fatalf("OpenChannel: %v", err)
	}
	go ssh.DiscardRequests(reqs)

	agentClient := NewClientFromConn(channel)

	keys, err := agentClient.List()
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(keys) != 1 {
		t.Fatalf("got %d keys, want 1", len(keys))
	}
	if keys[0].Comment != "remote key" {
		t.Fatalf("got comment %q, want %q", keys[0].Comment, "remote key")
	}

	channel.Close()

	if err := <-done; err != nil {
		t.Fatalf("server error: %v", err)
	}
}

func TestSetupRemoteForwardingInvalidSocket(t *testing.T) {
	_, server, cleanup := setupSSHPipe(t)
	defer cleanup()

	// Try to setup forwarding to non-existent socket
	_, err := SetupRemoteForwarding(server, "/nonexistent/socket")
	if err == nil {
		t.Fatal("expected error for non-existent socket")
	}
}

func TestForwardUnixSocketHelper(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping test in short mode")
	}

	// Create a temporary directory for the socket
	tmpDir := t.TempDir()
	socketPath := filepath.Join(tmpDir, "test.sock")

	// Start a simple echo server on the socket
	listener, err := net.Listen("unix", socketPath)
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	defer listener.Close()

	go func() {
		conn, err := listener.Accept()
		if err != nil {
			return
		}
		io.Copy(conn, conn) // Echo back
		conn.Close()
	}()

	// Create a mock SSH channel using net.Pipe
	c1, c2 := net.Pipe()
	defer c1.Close()
	defer c2.Close()

	// Create a mock channel
	mockChannel := &mockSSHChannel{conn: c1}

	// Forward in a goroutine
	done := make(chan bool)
	go func() {
		forwardUnixSocket(mockChannel, socketPath)
		done <- true
	}()

	// Send some data
	testData := []byte("hello world")
	_, err = c2.Write(testData)
	if err != nil {
		t.Fatalf("Write: %v", err)
	}

	// Read it back
	buf := make([]byte, len(testData))
	_, err = io.ReadFull(c2, buf)
	if err != nil {
		t.Fatalf("Read: %v", err)
	}

	if !bytes.Equal(buf, testData) {
		t.Fatalf("got %q, want %q", buf, testData)
	}

	c2.Close()
	<-done
}

// mockSSHChannel implements ssh.Channel for testing
type mockSSHChannel struct {
	conn net.Conn
}

func (m *mockSSHChannel) Read(data []byte) (int, error) {
	return m.conn.Read(data)
}

func (m *mockSSHChannel) Write(data []byte) (int, error) {
	return m.conn.Write(data)
}

func (m *mockSSHChannel) Close() error {
	return m.conn.Close()
}

func (m *mockSSHChannel) CloseWrite() error {
	if c, ok := m.conn.(*net.TCPConn); ok {
		return c.CloseWrite()
	}
	if c, ok := m.conn.(interface{ CloseWrite() error }); ok {
		return c.CloseWrite()
	}
	return nil
}

func (m *mockSSHChannel) SendRequest(name string, wantReply bool, payload []byte) (bool, error) {
	return false, nil
}

func (m *mockSSHChannel) Stderr() io.ReadWriter {
	return nil
}

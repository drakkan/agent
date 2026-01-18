// Copyright 2014 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package agent

import (
	"errors"
	"fmt"
	"io"
	"net"
	"sync"

	"golang.org/x/crypto/ssh"
)

// RequestAgentForwarding sets up agent forwarding for the session.
// ForwardToAgent or ForwardToRemote should be called to route
// the authentication requests.
func RequestAgentForwarding(session *ssh.Session) error {
	ok, err := session.SendRequest("auth-agent-req@openssh.com", true, nil)
	if err != nil {
		return err
	}
	if !ok {
		return errors.New("forwarding request denied")
	}
	return nil
}

// ForwardToAgent routes authentication requests to the given keyring.
//
// If the keyring was created using [NewKeyring], this function automatically
// utilizes the underlying [AgentV2] implementation, enabling support for
// extended capabilities such as destination restrictions and session binding.
func ForwardToAgent(client *ssh.Client, keyring Agent) error {
	channels := client.HandleChannelOpen(authAgentChannelType)
	if channels == nil {
		return errors.New("agent: already have handler for " + authAgentChannelType)
	}

	go func() {
		for ch := range channels {
			channel, reqs, err := ch.Accept()
			if err != nil {
				continue
			}
			go ssh.DiscardRequests(reqs)
			go func() {
				ServeAgent(keyring, channel)
				channel.Close()
			}()
		}
	}()
	return nil
}

const authAgentChannelType = "auth-agent@openssh.com"

// ForwardToRemote routes authentication requests to the ssh-agent
// process serving on the given unix socket.
func ForwardToRemote(client *ssh.Client, addr string) error {
	channels := client.HandleChannelOpen(authAgentChannelType)
	if channels == nil {
		return errors.New("agent: already have handler for " + authAgentChannelType)
	}
	conn, err := net.Dial("unix", addr)
	if err != nil {
		return err
	}
	conn.Close()

	go func() {
		for ch := range channels {
			channel, reqs, err := ch.Accept()
			if err != nil {
				continue
			}
			go ssh.DiscardRequests(reqs)
			go forwardUnixSocket(channel, addr)
		}
	}()
	return nil
}

// FIXME: should we made this helper public???
func forwardUnixSocket(channel ssh.Channel, addr string) {
	conn, err := net.Dial("unix", addr)
	if err != nil {
		return
	}

	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		io.Copy(conn, channel)
		conn.(*net.UnixConn).CloseWrite()
		wg.Done()
	}()
	go func() {
		io.Copy(channel, conn)
		channel.CloseWrite()
		wg.Done()
	}()

	wg.Wait()
	conn.Close()
	channel.Close()
}

// ErrAgentChannelClosed is returned by the accept function created by
// SetupAgentForwarding or SetupRemoteForwarding when the underlying agent
// channel has been closed.
var ErrAgentChannelClosed = errors.New("agent: channel closed")

// SetupAgentForwarding registers a handler for agent forwarding channels and
// returns a function that can be called multiple times to accept individual
// connections.
//
// The returned accept function blocks until a connection is received or an
// error occurs. When the SSH client disconnects, the accept function will
// return [ErrAgentChannelClosed].
//
// Example usage:
//
//	accept, err := SetupAgentForwarding(client)
//	if err != nil {
//	    // Handle error
//	}
//	for {
//	    channel, err := accept()
//	    if err != nil {
//	        // Handle error (e.g., client disconnected)
//	        break
//	    }
//	    go func(ch ssh.Channel) {
//	        ServeAgent(agent, ch)
//	        ch.Close()
//	    }(channel)
//	}
//
// This function will return an error if the channel type is already registered.
func SetupAgentForwarding(client *ssh.Client) (func() (ssh.Channel, error), error) {
	channels := client.HandleChannelOpen(authAgentChannelType)
	if channels == nil {
		return nil, fmt.Errorf("agent: already have handler for %s", authAgentChannelType)
	}

	accept := func() (ssh.Channel, error) {
		newChannel, ok := <-channels
		if !ok {
			return nil, ErrAgentChannelClosed
		}

		channel, reqs, err := newChannel.Accept()
		if err != nil {
			return nil, err
		}
		go ssh.DiscardRequests(reqs)

		return channel, nil
	}

	return accept, nil
}

// SetupRemoteForwarding registers a handler for agent forwarding channels and
// returns a function that can be called multiple times to accept individual
// connections to forward to a remote ssh-agent process.
//
// The returned accept function blocks until a connection is received or an
// error occurs. When the SSH client disconnects, the accept function will
// return [ErrAgentChannelClosed].
//
// Example usage:
//
//	accept, err := SetupRemoteForwarding(client, "/path/to/agent.sock")
//	if err != nil {
//	    // Handle error
//	}
//	for {
//	    channel, err := accept()
//	    if err != nil {
//	        // Handle error
//	        break
//	    }
//	    go forwardUnixSocket(channel, "/path/to/agent.sock")
//	}
//
// This function will return an error if the channel type is already registered
// or if the unix socket cannot be accessed.
func SetupRemoteForwarding(client *ssh.Client, addr string) (func() (ssh.Channel, error), error) {
	// Verify the socket exists before registering the handler.
	conn, err := net.Dial("unix", addr)
	if err != nil {
		return nil, err
	}
	conn.Close()

	channels := client.HandleChannelOpen(authAgentChannelType)
	if channels == nil {
		return nil, errors.New("agent: already have handler for " + authAgentChannelType)
	}

	accept := func() (ssh.Channel, error) {
		newChannel, ok := <-channels
		if !ok {
			return nil, ErrAgentChannelClosed
		}

		channel, reqs, err := newChannel.Accept()
		if err != nil {
			return nil, err
		}
		go ssh.DiscardRequests(reqs)

		return channel, nil
	}

	return accept, nil
}

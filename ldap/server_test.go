// Copyright 2022 The Casdoor Authors. All Rights Reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package ldap

import (
	"crypto/tls"
	"net"
	"testing"
	"time"

	ldapserver "github.com/casdoor/ldapserver"
	goldap "github.com/go-ldap/ldap/v3"
	"github.com/stretchr/testify/assert"

	"github.com/casdoor/casdoor/object"
)

// startTestPlaintextLdapServer starts a real, unencrypted LDAP listener
// wired to the production handleBind route (matching StartLdapServer's own
// wiring) on an ephemeral loopback port, and returns its address.
func startTestPlaintextLdapServer(t *testing.T) string {
	t.Helper()

	server := ldapserver.NewServer()
	routes := ldapserver.NewRouteMux()
	routes.Bind(handleBind)
	server.Handle(routes)

	go func() {
		_ = server.ListenAndServe("127.0.0.1:0")
	}()
	t.Cleanup(server.Stop)

	// ListenAndServe assigns server.Listener synchronously before it starts
	// accepting connections, but does so in the goroutine above, so poll
	// briefly for it to appear.
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if server.Listener != nil {
			return server.Listener.Addr().String()
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("timed out waiting for test LDAP server to start listening")
	return ""
}

// TestSimpleBindWithPasswordOverPlaintextIsRejected reproduces TC-644149AE:
// a `simple` BindRequest carrying a non-empty password must not be accepted
// over an unencrypted connection. handleBind calls the exact same
// object.CheckUserPassword path the web login uses, so this test initializes
// the real adapter (as the project's own object-package tests do via
// InitConfig) to exercise handleBind end-to-end, on the wire, precisely as
// the finding's PoC did against the live LDAP listener.
//
// Before the fix, handleBind ran this credentialed bind straight through to
// CheckUserPassword regardless of transport, returning either resultCode 0
// (success, if the password happened to be correct) or resultCode 49
// (invalid credentials) — never resultCode 13. After the fix, the transport
// guard fires first and the connection never reaches CheckUserPassword at
// all: it must always get resultCode 13 (confidentialityRequired).
func TestSimpleBindWithPasswordOverPlaintextIsRejected(t *testing.T) {
	object.InitConfig()

	addr := startTestPlaintextLdapServer(t)

	conn, err := goldap.Dial("tcp", addr)
	assert.NoError(t, err)
	defer conn.Close()

	_, err = conn.SimpleBind(&goldap.SimpleBindRequest{
		Username: "cn=admin,ou=built-in,dc=example,dc=com",
		Password: "some-real-looking-password",
	})

	assert.Error(t, err, "a simple bind carrying a password over a plaintext connection must be refused")
	ldapErr, ok := err.(*goldap.Error)
	if assert.True(t, ok, "expected an *ldap.Error, got %T: %v", err, err) {
		assert.Equal(t, uint16(goldap.LDAPResultConfidentialityRequired), ldapErr.ResultCode,
			"expected confidentialityRequired (13), got resultCode=%d (%s)", ldapErr.ResultCode, ldapErr.Error())
	}
}

// TestIsUnprotectedSimpleBind unit-tests the extracted transport guard in
// isolation, covering cases the end-to-end test above does not:
//   - a plaintext connection with a password must be flagged;
//   - a plaintext connection with an empty (anonymous) password must not be
//     flagged, since there is no secret on the wire to protect;
//   - a TLS-wrapped connection with a password must not be flagged, proving
//     the guard is specifically about transport confidentiality, not a
//     blanket rejection of credentialed binds (isolating the fix from a
//     broken-environment false positive).
func TestIsUnprotectedSimpleBind(t *testing.T) {
	plainConn, plainPeer := net.Pipe()
	defer plainConn.Close()
	defer plainPeer.Close()

	assert.True(t, isUnprotectedSimpleBind(plainConn, "some-real-looking-password"),
		"a plaintext connection carrying a password must be flagged as unprotected")
	assert.False(t, isUnprotectedSimpleBind(plainConn, ""),
		"an anonymous bind (empty password) carries no secret and must not be flagged")

	// tls.Server() wraps a net.Conn as *tls.Conn without performing a
	// handshake; that's enough to exercise the guard's type check.
	rawConn, rawPeer := net.Pipe()
	defer rawConn.Close()
	defer rawPeer.Close()
	tlsConn := tls.Server(rawConn, &tls.Config{})
	defer tlsConn.Close()

	assert.False(t, isUnprotectedSimpleBind(tlsConn, "some-real-looking-password"),
		"a TLS-wrapped connection carrying a password must not be flagged")
}

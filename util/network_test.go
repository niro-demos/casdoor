// Copyright 2026 The Casdoor Authors. All Rights Reserved.
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

package util

import (
	"net"
	"testing"
)

func TestIsUnsafeOutboundIp(t *testing.T) {
	unsafe := []string{
		"127.0.0.1",       // loopback
		"169.254.169.254", // link-local / cloud metadata (AWS/Azure/GCP)
		"10.0.0.5",        // private
		"172.16.0.5",      // private
		"192.168.1.5",     // private
		"0.0.0.0",         // unspecified
		"224.0.0.1",       // multicast
		"::1",             // loopback (v6)
		"fe80::1",         // link-local (v6)
	}
	for _, s := range unsafe {
		ip := net.ParseIP(s)
		if ip == nil {
			t.Fatalf("test bug: %q did not parse as an IP", s)
		}
		if !IsUnsafeOutboundIp(ip) {
			t.Errorf("IsUnsafeOutboundIp(%s) = false, want true", s)
		}
	}

	// Positive control: ordinary public IPs must not be flagged, proving the
	// checks above are about the reserved ranges, not a blanket rejection.
	safe := []string{
		"93.184.216.34", // example.com
		"8.8.8.8",       // public DNS
	}
	for _, s := range safe {
		ip := net.ParseIP(s)
		if IsUnsafeOutboundIp(ip) {
			t.Errorf("IsUnsafeOutboundIp(%s) = true, want false", s)
		}
	}
}

func TestValidateOutboundUrl(t *testing.T) {
	blocked := []string{
		"http://169.254.169.254/latest/meta-data/", // cloud metadata
		"http://127.0.0.1:8080/",                   // loopback
		"http://10.0.0.5/",                          // private
		"http://192.168.1.5/",                       // private
		"http://[::1]/",                              // loopback (v6)
		"http://[fe80::1]/",                          // link-local (v6)
	}
	for _, u := range blocked {
		if err := ValidateOutboundUrl(u); err == nil {
			t.Errorf("ValidateOutboundUrl(%q) = nil error, want rejection", u)
		}
	}

	// Positive control: a normal-looking public destination must be
	// accepted, proving the rejections above are specific to the
	// destination, not a broken validator.
	allowed := []string{
		"https://93.184.216.34/",
		"http://8.8.8.8/webhook",
	}
	for _, u := range allowed {
		if err := ValidateOutboundUrl(u); err != nil {
			t.Errorf("ValidateOutboundUrl(%q) unexpected error: %v", u, err)
		}
	}

	badSchemes := []string{
		"file:///etc/passwd",
		"ftp://example.com/",
		"gopher://127.0.0.1/",
	}
	for _, u := range badSchemes {
		if err := ValidateOutboundUrl(u); err == nil {
			t.Errorf("ValidateOutboundUrl(%q) = nil error, want scheme rejection", u)
		}
	}
}

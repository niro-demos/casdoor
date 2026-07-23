// Copyright 2025 The Casdoor Authors. All Rights Reserved.
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
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"syscall"
	"time"
)

func GetHostname() string {
	name, err := os.Hostname()
	if err != nil {
		panic(err)
	}

	return name
}

func IsInternetIp(ip string) bool {
	ipStr, _, err := net.SplitHostPort(ip)
	if err != nil {
		ipStr = ip
	}

	parsedIP := net.ParseIP(ipStr)
	if parsedIP == nil {
		return false
	}

	return !parsedIP.IsPrivate() && !parsedIP.IsLoopback() && !parsedIP.IsMulticast() && !parsedIP.IsUnspecified()
}

func IsHostIntranet(ip string) bool {
	ipStr, _, err := net.SplitHostPort(ip)
	if err != nil {
		ipStr = ip
	}

	parsedIP := net.ParseIP(ipStr)
	if parsedIP == nil {
		return false
	}

	return parsedIP.IsPrivate() || parsedIP.IsLoopback() || parsedIP.IsLinkLocalUnicast() || parsedIP.IsLinkLocalMulticast()
}

func ResolveDomainToIp(domain string) string {
	ips, err := net.LookupIP(domain)
	if err != nil {
		if strings.Contains(err.Error(), "no such host") {
			return "(empty)"
		}

		fmt.Printf("resolveDomainToIp() error: %s\n", err.Error())
		return err.Error()
	}

	for _, ip := range ips {
		if ipv4 := ip.To4(); ipv4 != nil {
			return ipv4.String()
		}
	}
	return "(empty)"
}

func PingUrl(url string) (bool, string) {
	client := http.Client{
		Timeout: 5 * time.Second,
	}
	resp, err := client.Get(url)
	if err != nil {
		return false, err.Error()
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 200 && resp.StatusCode <= 299 {
		return true, ""
	}
	return false, fmt.Sprintf("Status: %s", resp.Status)
}

func IsIntranetIp(ip string) bool {
	ipStr, _, err := net.SplitHostPort(ip)
	if err != nil {
		ipStr = ip
	}

	parsedIP := net.ParseIP(ipStr)
	if parsedIP == nil {
		return false
	}

	return parsedIP.IsPrivate() ||
		parsedIP.IsLoopback() ||
		parsedIP.IsLinkLocalUnicast() ||
		parsedIP.IsLinkLocalMulticast()
}

// ErrDisallowedOutboundDestination is returned by the egress guard when a
// server-side outbound request would target an internal / non-routable address.
var ErrDisallowedOutboundDestination = fmt.Errorf("destination resolves to a disallowed internal address")

// IsDisallowedOutboundIP reports whether a server-side outbound request must not
// be made to the given IP. It rejects loopback, private (RFC1918/RFC4193),
// link-local (incl. the 169.254.169.254 cloud-metadata address), unspecified,
// multicast, and other non-globally-routable ranges. It is the single source of
// truth for every SSRF egress check in the codebase.
func IsDisallowedOutboundIP(ip net.IP) bool {
	if ip == nil {
		// A host we cannot resolve to a concrete IP is treated as disallowed:
		// fail closed rather than dial an unknown destination.
		return true
	}

	return ip.IsLoopback() ||
		ip.IsPrivate() ||
		ip.IsLinkLocalUnicast() ||
		ip.IsLinkLocalMulticast() ||
		ip.IsInterfaceLocalMulticast() ||
		ip.IsMulticast() ||
		ip.IsUnspecified() ||
		!ip.IsGlobalUnicast()
}

// CheckOutboundHost resolves host (accepting either "host" or "host:port") and
// returns an error if the host is empty, unresolvable, or resolves to any
// disallowed internal address. Every resolved IP must be allowed — a host that
// resolves to a mix of public and internal addresses is rejected, closing the
// DNS-rebinding gap at check time. Callers should additionally use
// SafeOutboundDialControl on the http.Client so the address actually dialed is
// re-validated after resolution.
func CheckOutboundHost(host string) error {
	host = strings.TrimSpace(host)
	if host == "" {
		return fmt.Errorf("outbound destination host is empty")
	}

	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}
	host = strings.Trim(host, "[]")

	if literal := net.ParseIP(host); literal != nil {
		if IsDisallowedOutboundIP(literal) {
			return ErrDisallowedOutboundDestination
		}
		return nil
	}

	ips, err := net.LookupIP(host)
	if err != nil {
		return fmt.Errorf("could not resolve outbound destination host %q: %w", host, err)
	}
	if len(ips) == 0 {
		return fmt.Errorf("could not resolve outbound destination host %q", host)
	}

	for _, ip := range ips {
		if IsDisallowedOutboundIP(ip) {
			return ErrDisallowedOutboundDestination
		}
	}

	return nil
}

// CheckOutboundURL parses rawURL and applies CheckOutboundHost to its hostname.
// It is the convenience entry point for sinks that hold a URL string.
func CheckOutboundURL(rawURL string) error {
	u, err := url.Parse(strings.TrimSpace(rawURL))
	if err != nil {
		return err
	}
	return CheckOutboundHost(u.Host)
}

// SafeOutboundDialControl is a net.Dialer.Control hook that re-validates the
// concrete address the dialer is about to connect to, after DNS resolution.
// Wiring it into an http.Client's transport closes the DNS-rebinding window that
// a pre-resolution hostname check alone leaves open: even if a public-looking
// hostname resolves to an internal IP at connect time, the connection is
// refused here before any bytes are exchanged.
func SafeOutboundDialControl(_ string, address string, _ syscall.RawConn) error {
	host, _, err := net.SplitHostPort(address)
	if err != nil {
		host = address
	}
	ip := net.ParseIP(strings.Trim(host, "[]"))
	if IsDisallowedOutboundIP(ip) {
		return ErrDisallowedOutboundDestination
	}
	return nil
}

// NewSafeOutboundTransport returns an *http.Transport whose dialer re-validates
// every connected address against the egress guard, so clients built from it
// cannot be steered to internal destinations even via DNS rebinding.
func NewSafeOutboundTransport() *http.Transport {
	dialer := &net.Dialer{
		Timeout: 30 * time.Second,
		Control: SafeOutboundDialControl,
	}
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.DialContext = dialer.DialContext
	return transport
}

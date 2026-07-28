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

// IsUnsafeOutboundIp reports whether ip must not be used as the destination
// of a server-initiated outbound request: loopback, link-local (which
// includes the cloud-metadata address 169.254.169.254 on AWS/Azure/GCP),
// private (RFC1918/RFC4193), multicast, and unspecified addresses. It is the
// server-side-request-forgery (SSRF) guard shared by every feature that lets
// a user configure a URL the server itself later dials (e.g. webhooks).
func IsUnsafeOutboundIp(ip net.IP) bool {
	if ip == nil {
		return true
	}

	if ip.IsUnspecified() || ip.IsMulticast() {
		return true
	}

	return IsIntranetIp(ip.String())
}

// ValidateOutboundUrl parses rawUrl and rejects it unless it is a plain
// http(s) URL whose host resolves only to public, non-reserved IP
// addresses. It exists to close server-side-request-forgery (SSRF) paths
// where a persisted, user-supplied URL (e.g. a webhook) is later dialed by
// the server process itself: without this check, a caller could point the
// server at loopback/private/link-local addresses or a cloud-metadata
// endpoint (169.254.169.254) and read back the raw response.
//
// This validates the URL at the time it is checked; a host that resolves
// safely now can still be re-pointed at an unsafe address later (DNS
// rebinding), so callers that actually dial the URL must re-validate the
// resolved IP immediately before connecting (see object/webhook_util.go).
func ValidateOutboundUrl(rawUrl string) error {
	parsedUrl, err := url.Parse(rawUrl)
	if err != nil {
		return fmt.Errorf("invalid URL: %w", err)
	}

	if parsedUrl.Scheme != "http" && parsedUrl.Scheme != "https" {
		return fmt.Errorf("invalid URL scheme %q: only http and https are allowed", parsedUrl.Scheme)
	}

	host := parsedUrl.Hostname()
	if host == "" {
		return fmt.Errorf("invalid URL: missing host")
	}

	ips, err := resolveHostIps(host)
	if err != nil {
		return fmt.Errorf("failed to resolve host %q: %w", host, err)
	}
	if len(ips) == 0 {
		return fmt.Errorf("host %q did not resolve to any IP address", host)
	}

	for _, ip := range ips {
		if IsUnsafeOutboundIp(ip) {
			return fmt.Errorf("URL host %q resolves to a disallowed address (%s): loopback, link-local, private and other reserved destinations are not permitted", host, ip.String())
		}
	}

	return nil
}

// resolveHostIps resolves host to its IP addresses. If host is already a
// literal IP address, it is returned as-is with no DNS lookup.
func resolveHostIps(host string) ([]net.IP, error) {
	if ip := net.ParseIP(host); ip != nil {
		return []net.IP{ip}, nil
	}

	return net.LookupIP(host)
}

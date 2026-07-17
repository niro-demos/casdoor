// Copyright 2021 The Casdoor Authors. All Rights Reserved.
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

package object

import (
	"fmt"
	"net"
	"net/url"
	"syscall"
	"time"
)

// isDisallowedWebhookIp reports whether ip is a destination a server-side
// webhook must never be allowed to reach: loopback (127.0.0.0/8, ::1),
// link-local (169.254.0.0/16 - which covers the AWS/GCP/Azure cloud-metadata
// address 169.254.169.254 - and fe80::/10), RFC1918/RFC4193 private ranges,
// unspecified (0.0.0.0, ::), or multicast.
func isDisallowedWebhookIp(ip net.IP) bool {
	if ip == nil {
		return true
	}

	return ip.IsLoopback() ||
		ip.IsLinkLocalUnicast() ||
		ip.IsLinkLocalMulticast() ||
		ip.IsPrivate() ||
		ip.IsUnspecified() ||
		ip.IsMulticast()
}

// resolveWebhookUrlIPs resolves host (a hostname or literal IP) to the set of
// IP addresses it points at.
func resolveWebhookUrlIPs(host string) ([]net.IP, error) {
	if ip := net.ParseIP(host); ip != nil {
		return []net.IP{ip}, nil
	}

	return net.LookupIP(host)
}

// validateWebhookUrl rejects a webhook destination URL that is not a plain
// http(s) URL resolving exclusively to public, non-reserved addresses. It is
// the input-side control: it runs once, at webhook create/update time, before
// the URL is ever persisted.
//
// This alone is not sufficient against DNS rebinding (a hostname can resolve
// to a public IP at save time and a private/metadata IP at delivery time), so
// sendWebhook() additionally enforces the same rule at the transport/dial
// layer for every actual delivery - see webhookSafeDialer().
func validateWebhookUrl(rawUrl string) error {
	if rawUrl == "" {
		return fmt.Errorf("webhook url cannot be empty")
	}

	parsed, err := url.Parse(rawUrl)
	if err != nil {
		return fmt.Errorf("invalid webhook url: %w", err)
	}

	if parsed.Scheme != "http" && parsed.Scheme != "https" {
		return fmt.Errorf("webhook url scheme must be http or https")
	}

	host := parsed.Hostname()
	if host == "" {
		return fmt.Errorf("webhook url must include a host")
	}

	ips, err := resolveWebhookUrlIPs(host)
	if err != nil {
		return fmt.Errorf("failed to resolve webhook url host %q: %w", host, err)
	}
	if len(ips) == 0 {
		return fmt.Errorf("webhook url host %q did not resolve to any address", host)
	}

	for _, ip := range ips {
		if isDisallowedWebhookIp(ip) {
			return fmt.Errorf("webhook url is not allowed: host %q resolves to a private, loopback, link-local, or reserved address (%s)", host, ip.String())
		}
	}

	return nil
}

// webhookSafeDialer returns a *net.Dialer whose Control hook re-checks the
// resolved destination address immediately before the TCP connection is
// established, rejecting loopback/link-local/private/reserved addresses.
//
// Control is invoked by the net package with the already-DNS-resolved
// address, right before the raw socket connects - so this closes the
// DNS-rebinding gap that a one-time, save-time-only check (validateWebhookUrl)
// cannot: a hostname that resolved to a public IP when the webhook was saved
// but now resolves to 169.254.169.254 or 127.0.0.1 is still blocked here.
func webhookSafeDialer() *net.Dialer {
	return &net.Dialer{
		Timeout: 10 * time.Second,
		Control: func(network, address string, c syscall.RawConn) error {
			host, _, err := net.SplitHostPort(address)
			if err != nil {
				host = address
			}

			ip := net.ParseIP(host)
			if ip == nil {
				return fmt.Errorf("webhook destination blocked: could not parse resolved address %q", address)
			}

			if isDisallowedWebhookIp(ip) {
				return fmt.Errorf("webhook destination blocked: %s resolves to a private, loopback, link-local, or reserved address", ip.String())
			}

			return nil
		},
	}
}

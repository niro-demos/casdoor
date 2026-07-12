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

package object

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"
)

type webhookLookupIP func(context.Context, string) ([]net.IPAddr, error)

func validateWebhookURL(ctx context.Context, target string, lookup webhookLookupIP) error {
	u, err := url.Parse(target)
	if err != nil {
		return fmt.Errorf("invalid webhook URL: %w", err)
	}
	if (u.Scheme != "http" && u.Scheme != "https") || u.Hostname() == "" {
		return fmt.Errorf("webhook URL must use HTTP or HTTPS and include a host")
	}

	_, err = resolveWebhookHost(ctx, u.Hostname(), lookup, "tcp")
	return err
}

func resolveWebhookHost(ctx context.Context, host string, lookup webhookLookupIP, network string) (net.IP, error) {
	addresses, err := lookup(ctx, host)
	if err != nil {
		return nil, fmt.Errorf("resolve webhook host %q: %w", host, err)
	}
	if len(addresses) == 0 {
		return nil, fmt.Errorf("webhook host %q did not resolve to an IP address", host)
	}

	var selected net.IP
	for _, address := range addresses {
		ip := address.IP
		if !ip.IsGlobalUnicast() || ip.IsPrivate() || ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() {
			return nil, fmt.Errorf("webhook host %q resolves to a non-public IP address", host)
		}
		if selected == nil && ((network != "tcp4" && network != "tcp6") || (network == "tcp4" && ip.To4() != nil) || (network == "tcp6" && ip.To4() == nil)) {
			selected = ip
		}
	}
	if selected == nil {
		return nil, fmt.Errorf("webhook host %q has no address compatible with %s", host, network)
	}
	return selected, nil
}

func resolveWebhookDialAddress(ctx context.Context, network, address string, lookup webhookLookupIP) (string, error) {
	host, port, err := net.SplitHostPort(address)
	if err != nil {
		return "", fmt.Errorf("invalid webhook dial address: %w", err)
	}
	ip, err := resolveWebhookHost(ctx, host, lookup, network)
	if err != nil {
		return "", err
	}
	return net.JoinHostPort(ip.String(), port), nil
}

func newWebhookHTTPClient() *http.Client {
	dialer := &net.Dialer{Timeout: 30 * time.Second, KeepAlive: 30 * time.Second}
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.Proxy = nil
	transport.DialContext = func(ctx context.Context, network, address string) (net.Conn, error) {
		resolved, err := resolveWebhookDialAddress(ctx, network, address, net.DefaultResolver.LookupIPAddr)
		if err != nil {
			return nil, err
		}
		return dialer.DialContext(ctx, network, resolved)
	}

	return &http.Client{
		Timeout:   30 * time.Second,
		Transport: transport,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 10 {
				return fmt.Errorf("stopped after 10 redirects")
			}
			if err := validateWebhookURL(req.Context(), req.URL.String(), net.DefaultResolver.LookupIPAddr); err != nil {
				return fmt.Errorf("unsafe webhook redirect: %w", err)
			}
			return nil
		},
	}
}

func validateWebhookTarget(target string) error {
	if strings.TrimSpace(target) == "" {
		return fmt.Errorf("webhook URL cannot be empty")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	return validateWebhookURL(ctx, target, net.DefaultResolver.LookupIPAddr)
}

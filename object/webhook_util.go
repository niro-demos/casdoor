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
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"reflect"
	"strings"
	"time"

	"github.com/casdoor/casdoor/util"
)

type lookupIPAddrFunc func(context.Context, string) ([]net.IPAddr, error)

var nonPublicWebhookPrefixes = []netip.Prefix{
	netip.MustParsePrefix("0.0.0.0/8"),
	netip.MustParsePrefix("100.64.0.0/10"),
	netip.MustParsePrefix("192.0.0.0/24"),
	netip.MustParsePrefix("192.0.2.0/24"),
	netip.MustParsePrefix("192.88.99.0/24"),
	netip.MustParsePrefix("198.18.0.0/15"),
	netip.MustParsePrefix("198.51.100.0/24"),
	netip.MustParsePrefix("203.0.113.0/24"),
	netip.MustParsePrefix("240.0.0.0/4"),
	netip.MustParsePrefix("100::/64"),
	netip.MustParsePrefix("2001:db8::/32"),
}

func validateWebhookURL(ctx context.Context, rawURL string, lookupIPAddr lookupIPAddrFunc) error {
	u, err := url.Parse(rawURL)
	if err != nil {
		return fmt.Errorf("invalid webhook URL: %w", err)
	}
	if (u.Scheme != "http" && u.Scheme != "https") || u.Hostname() == "" {
		return fmt.Errorf("webhook URL must use http or https and include a hostname")
	}
	if u.User != nil {
		return fmt.Errorf("webhook URL must not include credentials")
	}

	host := u.Hostname()
	if ip := net.ParseIP(host); ip != nil {
		if !isPublicWebhookIP(ip) {
			return fmt.Errorf("webhook URL resolves to a non-public address")
		}
		return nil
	}

	addresses, err := lookupIPAddr(ctx, host)
	if err != nil {
		return fmt.Errorf("cannot resolve webhook hostname: %w", err)
	}
	if len(addresses) == 0 {
		return fmt.Errorf("webhook hostname did not resolve to an address")
	}
	for _, address := range addresses {
		if !isPublicWebhookIP(address.IP) {
			return fmt.Errorf("webhook URL resolves to a non-public address")
		}
	}

	return nil
}

func isPublicWebhookIP(ip net.IP) bool {
	addr, ok := netip.AddrFromSlice(ip)
	if !ok {
		return false
	}
	addr = addr.Unmap()
	if !addr.IsGlobalUnicast() || addr.IsPrivate() || addr.IsLoopback() || addr.IsUnspecified() ||
		addr.IsLinkLocalUnicast() || addr.IsLinkLocalMulticast() || addr.IsMulticast() {
		return false
	}
	for _, prefix := range nonPublicWebhookPrefixes {
		if prefix.Contains(addr) {
			return false
		}
	}
	return true
}

func validateWebhookDestination(rawURL string) error {
	return validateWebhookURL(context.Background(), rawURL, net.DefaultResolver.LookupIPAddr)
}

func webhookDialContext(ctx context.Context, network, address string) (net.Conn, error) {
	host, port, err := net.SplitHostPort(address)
	if err != nil {
		return nil, fmt.Errorf("invalid webhook destination: %w", err)
	}
	addresses, err := net.DefaultResolver.LookupIPAddr(ctx, host)
	if err != nil {
		return nil, fmt.Errorf("cannot resolve webhook hostname: %w", err)
	}
	if len(addresses) == 0 {
		return nil, fmt.Errorf("webhook hostname did not resolve to an address")
	}
	for _, resolved := range addresses {
		if !isPublicWebhookIP(resolved.IP) {
			return nil, fmt.Errorf("webhook URL resolves to a non-public address")
		}
	}

	dialer := &net.Dialer{}
	var lastErr error
	for _, resolved := range addresses {
		conn, dialErr := dialer.DialContext(ctx, network, net.JoinHostPort(resolved.IP.String(), port))
		if dialErr == nil {
			return conn, nil
		}
		lastErr = dialErr
	}
	return nil, lastErr
}

func sendWebhook(webhook *Webhook, record *Record, extendedUser *User) (int, string, error) {
	if err := validateWebhookDestination(webhook.Url); err != nil {
		return 0, "", err
	}
	client := &http.Client{
		Timeout: 30 * time.Second,
		Transport: &http.Transport{
			DialContext: webhookDialContext,
		},
	}
	userMap := make(map[string]interface{})
	var body io.Reader

	if webhook.TokenFields != nil && len(webhook.TokenFields) > 0 && extendedUser != nil {
		userValue := reflect.ValueOf(extendedUser).Elem()

		for _, field := range webhook.TokenFields {
			userField := userValue.FieldByName(field)
			if userField.IsValid() {
				newfield := util.SnakeToCamel(util.CamelToSnakeCase(field))
				userMap[newfield] = userField.Interface()
			}
		}

		type RecordEx struct {
			Record
			ExtendedUser map[string]interface{} `json:"extendedUser"`
		}

		recordEx := &RecordEx{
			Record:       *record,
			ExtendedUser: userMap,
		}

		body = strings.NewReader(util.StructToJson(recordEx))
	} else {
		type RecordEx struct {
			Record
			ExtendedUser *User `xorm:"-" json:"extendedUser"`
		}
		recordEx := &RecordEx{
			Record:       *record,
			ExtendedUser: extendedUser,
		}

		body = strings.NewReader(util.StructToJson(recordEx))
	}

	req, err := http.NewRequest(webhook.Method, webhook.Url, body)
	if err != nil {
		return 0, "", err
	}

	req.Header.Set("Content-Type", webhook.ContentType)

	for _, header := range webhook.Headers {
		req.Header.Set(header.Name, header.Value)
	}

	resp, err := client.Do(req)
	if err != nil {
		return 0, "", err
	}

	defer resp.Body.Close()
	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return 0, "", err
	}
	return resp.StatusCode, string(bodyBytes), err
}

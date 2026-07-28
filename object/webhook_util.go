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
	"reflect"
	"strings"
	"time"

	"github.com/casdoor/casdoor/util"
)

// webhookHTTPClient is used for every outbound webhook delivery. Its
// Transport re-resolves and re-validates the destination IP immediately
// before dialing (see safeWebhookDialContext), which closes the
// DNS-rebinding gap that a one-time check of webhook.Url at send time would
// leave open: a hostname that resolves to a public IP when validated could
// otherwise be re-pointed at an internal/metadata address by the time the
// connection is actually made.
var webhookHTTPClient = &http.Client{
	Timeout: 30 * time.Second,
	Transport: &http.Transport{
		DialContext: safeWebhookDialContext,
	},
}

// safeWebhookDialContext resolves addr's host, rejects any resolved IP that
// util.IsUnsafeOutboundIp flags (loopback/link-local/private/cloud-metadata/
// multicast/unspecified), and only then dials directly to the validated IP.
// This is the SSRF guard's last line of defense: it runs at actual
// connection time, not just when the webhook URL was validated earlier.
func safeWebhookDialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, err
	}

	var ips []net.IP
	if ip := net.ParseIP(host); ip != nil {
		ips = []net.IP{ip}
	} else {
		ips, err = net.DefaultResolver.LookupIP(ctx, "ip", host)
		if err != nil {
			return nil, err
		}
	}

	dialer := &net.Dialer{}
	var lastErr error
	for _, ip := range ips {
		if util.IsUnsafeOutboundIp(ip) {
			lastErr = fmt.Errorf("refusing to dial disallowed address %s", ip.String())
			continue
		}

		conn, dialErr := dialer.DialContext(ctx, network, net.JoinHostPort(ip.String(), port))
		if dialErr == nil {
			return conn, nil
		}
		lastErr = dialErr
	}

	if lastErr == nil {
		lastErr = fmt.Errorf("no route to host %q", host)
	}
	return nil, lastErr
}

func sendWebhook(webhook *Webhook, record *Record, extendedUser *User) (int, string, error) {
	if err := util.ValidateOutboundUrl(webhook.Url); err != nil {
		return 0, "", fmt.Errorf("webhook URL rejected: %w", err)
	}

	client := webhookHTTPClient
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

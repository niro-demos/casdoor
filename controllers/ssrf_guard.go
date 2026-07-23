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

package controllers

import (
	"fmt"
	"net/url"
	"strings"

	"github.com/casdoor/casdoor/util"
)

// validateProxyCallbackURL applies the shared egress guard to the CAS
// serviceValidate pgtUrl callback: the caller-supplied callback must be a valid
// https URL that does not resolve to an internal / loopback / link-local /
// private / cloud-metadata address, so the server cannot be steered into making
// an outbound verification request against an internal host.
func validateProxyCallbackURL(pgtUrl string) error {
	u, err := url.Parse(strings.TrimSpace(pgtUrl))
	if err != nil {
		return err
	}
	if u.Scheme != "https" {
		return fmt.Errorf("callback is not https")
	}
	return util.CheckOutboundHost(u.Host)
}

// validateProxyTargetURL applies the shared egress guard to the per-server
// reverse-proxy (MCP) upstream URL: the target must be an absolute http/https
// URL that does not resolve to an internal / loopback / private / link-local
// address, so ProxyServer cannot be steered into proxying to internal hosts.
func validateProxyTargetURL(rawURL string) error {
	u, err := url.Parse(strings.TrimSpace(rawURL))
	if err != nil {
		return err
	}
	if !u.IsAbs() || u.Host == "" {
		return fmt.Errorf("server URL is invalid")
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return fmt.Errorf("server URL scheme is invalid")
	}
	return util.CheckOutboundHost(u.Host)
}

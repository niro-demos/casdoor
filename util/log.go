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

package util

import (
	"fmt"
	"net"
	"net/http"
	"strings"

	"github.com/beego/beego/v2/core/logs"
	"github.com/beego/beego/v2/server/web/context"

	"github.com/casdoor/casdoor/conf"
)

func getIpInfo(clientIp string) string {
	if clientIp == "" {
		return ""
	}

	first := strings.TrimSpace(strings.Split(clientIp, ",")[0])
	if host, _, err := net.SplitHostPort(first); err == nil {
		return strings.Trim(host, "[]")
	}

	return strings.Trim(first, "[]")
}

// isTrustedProxy reports whether remoteAddr -- the direct TCP peer of the
// request, as seen by this process -- belongs to a reverse proxy that this
// deployment has explicitly opted to trust via the "trustedProxies" config
// item (a comma-separated list of IPs and/or CIDR ranges, e.g.
// "10.0.0.9,172.16.0.0/12"). Only a request whose direct peer is a trusted
// proxy may have its client IP determined by a client-supplied header
// (X-Forwarded-For); for anyone else that header is fully attacker
// controlled and must be ignored.
func isTrustedProxy(remoteAddr string) bool {
	trusted := conf.GetConfigString("trustedProxies")
	if trusted == "" {
		return false
	}

	host := remoteAddr
	if h, _, err := net.SplitHostPort(remoteAddr); err == nil {
		host = h
	}
	peerIp := net.ParseIP(strings.Trim(host, "[]"))
	if peerIp == nil {
		return false
	}

	for _, entry := range strings.Split(trusted, ",") {
		entry = strings.TrimSpace(entry)
		if entry == "" {
			continue
		}

		if strings.Contains(entry, "/") {
			if _, cidr, err := net.ParseCIDR(entry); err == nil && cidr.Contains(peerIp) {
				return true
			}
			continue
		}

		if entryIp := net.ParseIP(entry); entryIp != nil && entryIp.Equal(peerIp) {
			return true
		}
	}

	return false
}

func GetClientIpFromRequest(req *http.Request) string {
	var clientIp string
	// Only honor a client-supplied X-Forwarded-For header when the request's
	// direct peer is a configured, trusted reverse proxy. Otherwise any
	// unauthenticated caller could set this header to an arbitrary value and
	// impersonate any IP address (e.g. to defeat an IP-based allowlist).
	if isTrustedProxy(req.RemoteAddr) {
		clientIp = req.Header.Get("x-forwarded-for")
	}

	if clientIp == "" {
		ipPort := strings.Split(req.RemoteAddr, ":")
		if len(ipPort) >= 1 && len(ipPort) <= 2 {
			clientIp = ipPort[0]
		} else if len(ipPort) > 2 {
			idx := strings.LastIndex(req.RemoteAddr, ":")
			clientIp = req.RemoteAddr[0:idx]
			clientIp = strings.TrimLeft(clientIp, "[")
			clientIp = strings.TrimRight(clientIp, "]")
		}
	}

	return getIpInfo(clientIp)
}

func LogInfo(ctx *context.Context, f string, v ...interface{}) {
	ipString := fmt.Sprintf("(%s) ", GetClientIpFromRequest(ctx.Request))
	logs.Info(ipString+f, v...)
}

func LogWarning(ctx *context.Context, f string, v ...interface{}) {
	ipString := fmt.Sprintf("(%s) ", GetClientIpFromRequest(ctx.Request))
	logs.Warning(ipString+f, v...)
}

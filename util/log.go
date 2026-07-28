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

// getRemoteIp extracts the bare IP (no port) from an http.Request.RemoteAddr
// value, i.e. the address of the actual TCP peer that connected to us. This
// value cannot be forged by the client the way a header can.
func getRemoteIp(remoteAddr string) string {
	ipPort := strings.Split(remoteAddr, ":")
	if len(ipPort) >= 1 && len(ipPort) <= 2 {
		return ipPort[0]
	} else if len(ipPort) > 2 {
		idx := strings.LastIndex(remoteAddr, ":")
		ip := remoteAddr[0:idx]
		ip = strings.TrimLeft(ip, "[")
		ip = strings.TrimRight(ip, "]")
		return ip
	}
	return ""
}

// isTrustedProxy reports whether remoteIp is allowed to supply a
// X-Forwarded-For value that we honor. Trusted proxies are configured via
// the "trustedProxies" config item (or env var of the same name): a
// comma-separated list of exact IPs and/or CIDR blocks. An empty/unset list
// (the default) trusts no one, so forwarding headers are never honored and
// the real TCP peer address is always used instead.
func isTrustedProxy(remoteIp string) bool {
	trustedProxies := conf.GetConfigString("trustedProxies")
	if trustedProxies == "" || remoteIp == "" {
		return false
	}

	ip := net.ParseIP(remoteIp)
	if ip == nil {
		return false
	}

	for _, entry := range strings.Split(trustedProxies, ",") {
		entry = strings.TrimSpace(entry)
		if entry == "" {
			continue
		}

		if strings.Contains(entry, "/") {
			if _, ipNet, err := net.ParseCIDR(entry); err == nil && ipNet.Contains(ip) {
				return true
			}
			continue
		}

		if entry == remoteIp {
			return true
		}
	}

	return false
}

// GetClientIpFromRequest returns the caller's IP address. It only trusts the
// client-supplied X-Forwarded-For header when the request's actual TCP peer
// (req.RemoteAddr) is itself a configured trusted proxy (see isTrustedProxy);
// otherwise -- including in the default configuration, where no trusted
// proxy is configured -- the header is ignored and the real peer address is
// used. This value is relied upon as an authentication input (e.g. matching
// an OpenClaw agent's registered IP in controllers/entry_util.go), so it
// must not be spoofable by an unprivileged caller.
func GetClientIpFromRequest(req *http.Request) string {
	remoteIp := getRemoteIp(req.RemoteAddr)

	clientIp := ""
	if isTrustedProxy(remoteIp) {
		clientIp = req.Header.Get("x-forwarded-for")
	}
	if clientIp == "" {
		clientIp = remoteIp
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

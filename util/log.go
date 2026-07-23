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

// getRemoteIp extracts the bare IP (no port) from an http.Request.RemoteAddr,
// which is the real, TCP-observed source of the request and cannot be forged by
// the client.
func getRemoteIp(remoteAddr string) string {
	if remoteAddr == "" {
		return ""
	}
	if host, _, err := net.SplitHostPort(remoteAddr); err == nil {
		return strings.Trim(host, "[]")
	}
	return strings.Trim(remoteAddr, "[]")
}

// parseTrustedProxies reads the `trustedProxies` config value: a comma-separated
// list of proxy IPs or CIDR ranges whose `X-Forwarded-For` header may be
// trusted. Empty (the default) means no proxy is trusted, so the header is
// ignored entirely and the real TCP peer is used.
func parseTrustedProxies() ([]*net.IPNet, []net.IP) {
	raw := conf.GetConfigString("trustedProxies")
	if strings.TrimSpace(raw) == "" {
		return nil, nil
	}

	var nets []*net.IPNet
	var ips []net.IP
	for _, part := range strings.Split(raw, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		if _, ipNet, err := net.ParseCIDR(part); err == nil {
			nets = append(nets, ipNet)
			continue
		}
		if ip := net.ParseIP(part); ip != nil {
			ips = append(ips, ip)
		}
	}
	return nets, ips
}

// isTrustedProxy reports whether the immediate TCP peer (remoteIp) is a
// configured, trusted reverse proxy / load balancer.
func isTrustedProxy(remoteIp string) bool {
	ip := net.ParseIP(remoteIp)
	if ip == nil {
		return false
	}
	nets, ips := parseTrustedProxies()
	for _, trusted := range ips {
		if trusted.Equal(ip) {
			return true
		}
	}
	for _, ipNet := range nets {
		if ipNet.Contains(ip) {
			return true
		}
	}
	return false
}

// GetClientIpFromRequest returns the source IP of the request.
//
// SECURITY: `X-Forwarded-For` is a client-supplied header that any caller can
// forge. It is only honored when the immediate TCP peer (req.RemoteAddr) is a
// configured trusted proxy (see the `trustedProxies` config). Otherwise the
// header is ignored and the real, TCP-observed peer address is used. This
// prevents an unauthenticated client from spoofing its source IP — e.g. to
// bypass an IP allow-list — by setting the header itself.
func GetClientIpFromRequest(req *http.Request) string {
	remoteIp := getRemoteIp(req.RemoteAddr)

	if xff := req.Header.Get("x-forwarded-for"); xff != "" && isTrustedProxy(remoteIp) {
		return getIpInfo(xff)
	}

	return remoteIp
}

func LogInfo(ctx *context.Context, f string, v ...interface{}) {
	ipString := fmt.Sprintf("(%s) ", GetClientIpFromRequest(ctx.Request))
	logs.Info(ipString+f, v...)
}

func LogWarning(ctx *context.Context, f string, v ...interface{}) {
	ipString := fmt.Sprintf("(%s) ", GetClientIpFromRequest(ctx.Request))
	logs.Warning(ipString+f, v...)
}

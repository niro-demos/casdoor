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
	"sync"

	"github.com/beego/beego/v2/core/logs"
	"github.com/beego/beego/v2/server/web/context"
)

// trustedProxies is the set of immediate-peer addresses (RemoteAddr) that are
// allowed to set forwarded client-IP headers (X-Forwarded-For / X-Real-IP).
// A caller-supplied forwarded header is only honored when the direct connection
// originates from one of these trusted reverse proxies; otherwise the header is
// ignored and the real RemoteAddr is used. This prevents an untrusted internet
// caller from forging its source IP (see TC-B8325909).
//
// Entries may be single IPs (e.g. "10.0.0.9") or CIDR ranges (e.g. "10.0.0.0/8").
var (
	trustedProxiesMu   sync.RWMutex
	trustedProxyIPs    []net.IP
	trustedProxyNets   []*net.IPNet
	trustedProxiesSpec []string
)

// SetTrustedProxies configures the trusted reverse-proxy allowlist. Invalid
// entries are silently skipped. Passing nil/empty means no proxy is trusted,
// so forwarded headers are never honored.
func SetTrustedProxies(specs []string) {
	trustedProxiesMu.Lock()
	defer trustedProxiesMu.Unlock()

	trustedProxyIPs = nil
	trustedProxyNets = nil
	trustedProxiesSpec = append([]string(nil), specs...)

	for _, s := range specs {
		s = strings.TrimSpace(s)
		if s == "" {
			continue
		}
		if _, ipNet, err := net.ParseCIDR(s); err == nil {
			trustedProxyNets = append(trustedProxyNets, ipNet)
			continue
		}
		if ip := net.ParseIP(s); ip != nil {
			trustedProxyIPs = append(trustedProxyIPs, ip)
		}
	}
}

// GetTrustedProxies returns the currently configured trusted-proxy specs.
func GetTrustedProxies() []string {
	trustedProxiesMu.RLock()
	defer trustedProxiesMu.RUnlock()
	return append([]string(nil), trustedProxiesSpec...)
}

// isTrustedProxy reports whether the given remote address (RemoteAddr, possibly
// "ip:port") belongs to a configured trusted reverse proxy.
func isTrustedProxy(remoteAddr string) bool {
	host := remoteAddr
	if h, _, err := net.SplitHostPort(remoteAddr); err == nil {
		host = h
	}
	host = strings.Trim(host, "[]")
	ip := net.ParseIP(host)
	if ip == nil {
		return false
	}

	trustedProxiesMu.RLock()
	defer trustedProxiesMu.RUnlock()

	for _, tip := range trustedProxyIPs {
		if tip.Equal(ip) {
			return true
		}
	}
	for _, n := range trustedProxyNets {
		if n.Contains(ip) {
			return true
		}
	}
	return false
}

// remoteAddrIP extracts the bare IP (no port) from an http.Request RemoteAddr.
func remoteAddrIP(remoteAddr string) string {
	if host, _, err := net.SplitHostPort(remoteAddr); err == nil {
		return strings.Trim(host, "[]")
	}
	return strings.Trim(remoteAddr, "[]")
}

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

// GetClientIpFromRequest resolves the originating client IP for a request.
//
// The client-supplied forwarded headers (X-Forwarded-For, X-Real-IP) are only
// honored when the immediate connection (req.RemoteAddr) is a configured trusted
// reverse proxy (see SetTrustedProxies / the "trustedProxies" config). For any
// untrusted direct caller the headers are ignored and the real RemoteAddr is
// used, so an anonymous internet client cannot forge its source IP — which is
// used as an authorization/identity signal by the OTLP ingestion endpoints and
// by record/audit logging (see TC-B8325909).
func GetClientIpFromRequest(req *http.Request) string {
	if isTrustedProxy(req.RemoteAddr) {
		if xff := req.Header.Get("x-forwarded-for"); xff != "" {
			return getIpInfo(xff)
		}
		if xri := req.Header.Get("x-real-ip"); xri != "" {
			return getIpInfo(xri)
		}
	}

	return getIpInfo(remoteAddrIP(req.RemoteAddr))
}

func LogInfo(ctx *context.Context, f string, v ...interface{}) {
	ipString := fmt.Sprintf("(%s) ", GetClientIpFromRequest(ctx.Request))
	logs.Info(ipString+f, v...)
}

func LogWarning(ctx *context.Context, f string, v ...interface{}) {
	ipString := fmt.Sprintf("(%s) ", GetClientIpFromRequest(ctx.Request))
	logs.Warning(ipString+f, v...)
}

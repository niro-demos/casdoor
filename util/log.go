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

// ipFromRemoteAddr extracts just the IP portion of an http.Request's
// RemoteAddr (which is "IP:port", or "[IP]:port" for IPv6) - the address of
// the immediate TCP peer as reported by the Go runtime, not anything a
// client can influence via a header.
func ipFromRemoteAddr(remoteAddr string) string {
	ipPort := strings.Split(remoteAddr, ":")
	if len(ipPort) >= 1 && len(ipPort) <= 2 {
		return ipPort[0]
	} else if len(ipPort) > 2 {
		idx := strings.LastIndex(remoteAddr, ":")
		clientIp := remoteAddr[0:idx]
		clientIp = strings.TrimLeft(clientIp, "[")
		clientIp = strings.TrimRight(clientIp, "]")
		return clientIp
	}
	return ""
}

// GetClientIpFromRequest returns the caller's IP, preferring the
// X-Forwarded-For header when present. This is intended for logging /
// display purposes only: X-Forwarded-For is a plain client-supplied header
// that any caller can set to an arbitrary value unless a trusted reverse
// proxy in front of Casdoor is known to overwrite it, so this value must
// never be used to make an access-control decision. Use GetRealClientIp for
// that instead.
func GetClientIpFromRequest(req *http.Request) string {
	clientIp := req.Header.Get("x-forwarded-for")
	if clientIp == "" {
		clientIp = ipFromRemoteAddr(req.RemoteAddr)
	}

	return getIpInfo(clientIp)
}

// GetRealClientIp returns the IP address of the immediate TCP peer only,
// ignoring X-Forwarded-For and any other client-supplied header. Use this
// wherever the client IP feeds into a security decision (e.g. an IP
// allowlist), since - unlike GetClientIpFromRequest - it cannot be forged by
// the caller.
func GetRealClientIp(req *http.Request) string {
	return getIpInfo(ipFromRemoteAddr(req.RemoteAddr))
}

func LogInfo(ctx *context.Context, f string, v ...interface{}) {
	ipString := fmt.Sprintf("(%s) ", GetClientIpFromRequest(ctx.Request))
	logs.Info(ipString+f, v...)
}

func LogWarning(ctx *context.Context, f string, v ...interface{}) {
	ipString := fmt.Sprintf("(%s) ", GetClientIpFromRequest(ctx.Request))
	logs.Warning(ipString+f, v...)
}

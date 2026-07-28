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
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"

	"github.com/casdoor/casdoor/mcpself"
	"github.com/casdoor/casdoor/object"
	"github.com/casdoor/casdoor/util"
)

// ProxyServer
// @Title ProxyServer
// @Tag Server API
// @Description proxy request to the upstream MCP server by Server URL
// @Param   owner    path    string  true        "The owner name of the server"
// @Param   name     path    string  true        "The name of the server"
// @Success 200 {object} mcp.McpResponse The Response object
// @router /server/:owner/:name [get,post]
func (c *ApiController) ProxyServer() {
	owner := c.Ctx.Input.Param(":owner")
	name := c.Ctx.Input.Param(":name")

	var mcpReq *mcpself.McpRequest
	err := json.Unmarshal(c.Ctx.Input.RequestBody, &mcpReq)
	if err != nil {
		c.McpResponseError(1, -32700, "Parse error", err.Error())
		return
	}
	if util.IsStringsEmpty(owner, name) {
		c.McpResponseError(1, -32600, "invalid server identifier", nil)
		return
	}

	server, err := object.GetServer(util.GetId(owner, name))
	if err != nil {
		c.McpResponseError(mcpReq.ID, -32600, "server not found", err.Error())
		return
	}
	if server == nil {
		c.McpResponseError(mcpReq.ID, -32600, "server not found", nil)
		return
	}
	if server.Url == "" {
		c.McpResponseError(mcpReq.ID, -32600, "server URL is empty", nil)
		return
	}

	targetUrl, err := validateServerUrl(server.Url)
	if err != nil {
		c.McpResponseError(mcpReq.ID, -32600, err.Error(), nil)
		return
	}

	if mcpReq.Method == "tools/call" {
		var params mcpself.McpCallToolParams
		err = json.Unmarshal(mcpReq.Params, &params)
		if err != nil {
			c.McpResponseError(mcpReq.ID, -32600, "Invalid request", err.Error())
			return
		}

		if len(server.Tools) > 0 {
			toolAllowed := false
			for _, tool := range server.Tools {
				if tool.Name == params.Name {
					if !tool.IsAllowed {
						c.McpResponseError(mcpReq.ID, -32600, "tool is forbidden", nil)
						return
					}
					toolAllowed = true
					break
				}
			}
			if !toolAllowed {
				c.McpResponseError(mcpReq.ID, -32600, "tool is not in the allowlist", nil)
				return
			}
		}
	}

	proxy := httputil.NewSingleHostReverseProxy(targetUrl)
	// Pin the actual dial to a re-resolved, re-validated IP (see
	// safeProxyDialContext). validateServerUrl already rejected a
	// disallowed address above, but that check and this dial happen at
	// different times: a hostname that resolved to a public IP at
	// validation time could be re-pointed at an internal/metadata address
	// by DNS rebinding before the connection is actually made. Without
	// this, the pre-flight check alone would be a TOCTOU gap.
	proxy.Transport = &http.Transport{
		DialContext: safeProxyDialContext,
	}
	proxy.ErrorHandler = func(writer http.ResponseWriter, request *http.Request, proxyErr error) {
		c.Ctx.Output.SetStatus(http.StatusBadGateway)
		c.McpResponseError(mcpReq.ID, -32603, "failed to proxy server request: %s", proxyErr.Error())
	}
	proxy.Director = func(request *http.Request) {
		request.URL.Scheme = targetUrl.Scheme
		request.URL.Host = targetUrl.Host
		request.Host = targetUrl.Host
		request.URL.Path = targetUrl.Path
		request.URL.RawPath = ""
		request.URL.RawQuery = targetUrl.RawQuery

		if server.Token != "" {
			request.Header.Set("Authorization", "Bearer "+server.Token)
		}
	}

	proxy.ServeHTTP(c.Ctx.ResponseWriter, c.Ctx.Request)
}

// validateServerUrl parses rawUrl and ensures it is a well-formed, absolute
// http(s) URL with a host, and that the host does not resolve to a
// loopback, link-local (which includes the cloud-metadata address
// 169.254.169.254 on AWS/Azure/GCP), or private (RFC1918/RFC4193) address.
//
// This is the SSRF guard for the MCP server proxy: any org admin (not just
// a Casdoor global admin) can register a Server object, so without this
// check they could point Server.Url at an internal service or a
// cloud-metadata endpoint and have Casdoor's own backend fetch it on their
// behalf via ProxyServer.
func validateServerUrl(rawUrl string) (*url.URL, error) {
	targetUrl, err := url.Parse(rawUrl)
	if err != nil || !targetUrl.IsAbs() || targetUrl.Host == "" {
		return nil, fmt.Errorf("server URL is invalid")
	}
	if targetUrl.Scheme != "http" && targetUrl.Scheme != "https" {
		return nil, fmt.Errorf("server URL scheme is invalid")
	}

	ips, err := lookupHostIps(targetUrl.Hostname())
	if err != nil {
		return nil, fmt.Errorf("failed to resolve server URL host: %s", err.Error())
	}
	if len(ips) == 0 {
		return nil, fmt.Errorf("server URL host did not resolve to any IP address")
	}
	for _, ip := range ips {
		if util.IsIntranetIp(ip.String()) {
			return nil, fmt.Errorf("server URL targets a disallowed address")
		}
	}

	return targetUrl, nil
}

// lookupHostIps resolves host to its IP addresses. If host is already a
// literal IP address, it is returned as-is with no DNS lookup.
func lookupHostIps(host string) ([]net.IP, error) {
	if ip := net.ParseIP(host); ip != nil {
		return []net.IP{ip}, nil
	}
	return net.LookupIP(host)
}

// safeProxyDialContext is used as the DialContext for the MCP server
// proxy's transport. It re-resolves addr's host and refuses to dial any
// resolved IP that util.IsIntranetIp flags (loopback/link-local/private),
// then dials directly to the validated IP. This closes the TOCTOU/DNS-
// rebinding gap that a one-time validateServerUrl check at request-handling
// time would leave open: a hostname that resolved to a public IP when
// validated could be re-pointed at an internal/metadata address by the time
// the connection is actually made.
func safeProxyDialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, err
	}

	ips, err := lookupHostIps(host)
	if err != nil {
		return nil, err
	}

	dialer := &net.Dialer{}
	var lastErr error
	for _, ip := range ips {
		if util.IsIntranetIp(ip.String()) {
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

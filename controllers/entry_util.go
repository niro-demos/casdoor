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
	"io"
	"strings"

	"github.com/beego/beego/v2/server/web/context"
	"github.com/casdoor/casdoor/log"
	"github.com/casdoor/casdoor/object"
	"github.com/casdoor/casdoor/util"
)

func responseOtlpError(ctx *context.Context, status int, body []byte, format string, args ...interface{}) {
	msg := fmt.Sprintf(format, args...)
	req := ctx.Request
	bodyInfo := "(no body)"
	if len(body) > 0 {
		bodyInfo = fmt.Sprintf("%d bytes: %q", len(body), truncate(body, 256))
	}
	fmt.Printf("responseOtlpError: [%d] %s | %s %s | remoteAddr=%s | Content-Type=%s | User-Agent=%s | body=%s\n",
		status, msg,
		req.Method, req.URL.Path,
		req.RemoteAddr,
		req.Header.Get("Content-Type"),
		req.Header.Get("User-Agent"),
		bodyInfo,
	)
	ctx.Output.SetStatus(status)
	ctx.Output.Body([]byte(msg))
}

func truncate(b []byte, max int) []byte {
	if len(b) <= max {
		return b
	}
	return b[:max]
}

// otlpTokenFromRequest extracts the per-provider ingestion secret presented by
// an OTLP client, from either "Authorization: Bearer <token>" or the
// "X-OpenClaw-Token" header.
func otlpTokenFromRequest(ctx *context.Context) string {
	if auth := ctx.Request.Header.Get("Authorization"); auth != "" {
		if len(auth) > 7 && strings.EqualFold(auth[:7], "Bearer ") {
			return strings.TrimSpace(auth[7:])
		}
	}
	return strings.TrimSpace(ctx.Request.Header.Get("X-OpenClaw-Token"))
}

// resolveOpenClawProvider authorizes an OTLP ingestion request and returns the
// provider it is authorized to write to.
//
// Authorization is credential-based whenever any enabled OpenClaw provider has
// an ingestion secret (ClientSecret) configured: the request must present a
// valid per-provider token (Authorization: Bearer / X-OpenClaw-Token), matched
// in constant time. This is the primary defense — a client-forgeable source IP
// alone can never authorize ingestion (TC-B8325909).
//
// For legacy deployments where no provider has a secret configured, it falls
// back to matching the provider by client IP. That IP is now derived by
// util.GetClientIpFromRequest, which only honors forwarded headers from a
// configured trusted proxy, so a direct untrusted caller cannot forge it.
func resolveOpenClawProvider(ctx *context.Context) (*log.OpenClawProvider, int, error) {
	requiresToken, err := object.OpenClawProviderRequiresToken()
	if err != nil {
		return nil, 500, fmt.Errorf("provider lookup failed: %w", err)
	}

	if requiresToken {
		token := otlpTokenFromRequest(ctx)
		if token == "" {
			return nil, 401, fmt.Errorf("unauthorized: missing OpenClaw ingestion token")
		}
		provider, err := object.GetOpenClawProviderByToken(token)
		if err != nil {
			return nil, 500, fmt.Errorf("provider lookup failed: %w", err)
		}
		if provider == nil {
			return nil, 403, fmt.Errorf("forbidden: invalid OpenClaw ingestion token")
		}
		return provider, 0, nil
	}

	clientIP := util.GetClientIpFromRequest(ctx.Request)
	provider, err := object.GetOpenClawProviderByIP(clientIP)
	if err != nil {
		return nil, 500, fmt.Errorf("provider lookup failed: %w", err)
	}
	if provider == nil {
		return nil, 403, fmt.Errorf("forbidden: no OpenClaw provider configured for IP %s", clientIP)
	}
	return provider, 0, nil
}

func readProtobufBody(ctx *context.Context) []byte {
	if !strings.HasPrefix(ctx.Input.Header("Content-Type"), "application/x-protobuf") {
		preview, _ := io.ReadAll(io.LimitReader(ctx.Request.Body, 256))
		responseOtlpError(ctx, 415, preview, "unsupported content type")
		return nil
	}
	body, err := io.ReadAll(ctx.Request.Body)
	if err != nil {
		responseOtlpError(ctx, 400, nil, "read body failed")
		return nil
	}
	return body
}

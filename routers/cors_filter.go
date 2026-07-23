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

package routers

import (
	"net/http"

	"github.com/beego/beego/v2/server/web/context"
	"github.com/casdoor/casdoor/conf"
	"github.com/casdoor/casdoor/object"
	"github.com/casdoor/casdoor/util"
)

const (
	headerOrigin           = "Origin"
	headerAllowOrigin      = "Access-Control-Allow-Origin"
	headerAllowMethods     = "Access-Control-Allow-Methods"
	headerAllowHeaders     = "Access-Control-Allow-Headers"
	headerAllowCredentials = "Access-Control-Allow-Credentials"
)

// corsIsOriginAllowed is the DB-backed application origin allow-list check.
// It is a package variable so tests can inject a stub and exercise CorsFilter
// without a database. In production it is object.IsOriginAllowed.
var corsIsOriginAllowed = object.IsOriginAllowed

// isOriginAllowedForCors is the single source of truth for whether an inbound
// Origin may receive credential-allowing CORS headers
// (Access-Control-Allow-Origin: <origin> + Access-Control-Allow-Credentials: true).
//
// It deliberately never consults the caller-supplied Host header
// (ctx.Request.Host): Host is an attacker-controlled request header on any direct
// (non-browser) HTTP call, so it must not be used as a trust anchor for
// cross-origin decisions. Trust is derived only from server-side configuration
// and the DB-backed application allow-list, neither of which the client can
// influence. There are also no per-route carve-outs that reflect the raw Origin
// unconditionally — every route goes through this same allow-list.
func isOriginAllowedForCors(origin, originConf string) (bool, error) {
	if origin == "" {
		return false, nil
	}

	// Fixed, server-known safe origins
	// (localhost / 127.0.0.1 / casdoor-authenticator / *.chromiumapp.org).
	isValid, err := util.IsValidOrigin(origin)
	if err != nil {
		return false, err
	}
	if isValid {
		return true, nil
	}

	// Apple's Sign in with Apple posts from this fixed, trusted origin. This is a
	// server-known constant, not a reflection of an attacker-chosen value.
	if getHostname(origin) == "appleid.apple.com" {
		return true, nil
	}

	// Exact match against the server-configured public origin.
	if origin == originConf {
		return true, nil
	}

	// DB-backed application allow-list (registered application origins).
	return corsIsOriginAllowed(origin)
}

func setCorsHeaders(ctx *context.Context, origin string) {
	ctx.Output.Header(headerAllowOrigin, origin)
	ctx.Output.Header(headerAllowMethods, "POST, GET, OPTIONS, DELETE")
	ctx.Output.Header(headerAllowHeaders, "Content-Type, Authorization")
	ctx.Output.Header(headerAllowCredentials, "true")

	if ctx.Input.Method() == "OPTIONS" {
		ctx.ResponseWriter.WriteHeader(http.StatusOK)
	}
}

func CorsFilter(ctx *context.Context) {
	origin := ctx.Input.Header(headerOrigin)
	originConf := conf.GetConfigString("origin")

	if origin == "null" {
		origin = ""
	}

	// A single allow-list decision governs every route. There are no per-route
	// carve-outs that reflect the raw Origin unconditionally, and the decision
	// never trusts the caller-supplied Host header.
	allowed, err := isOriginAllowedForCors(origin, originConf)
	if err != nil {
		ctx.ResponseWriter.WriteHeader(http.StatusForbidden)
		responseError(ctx, err.Error())
		return
	}

	if allowed {
		setCorsHeaders(ctx, origin)
		return
	}

	// Origin is present but not allowed: reject credentialed cross-origin access
	// for real requests, exactly as the pre-existing fallback did for
	// non-allowlisted origins.
	if origin != "" && ctx.Input.Method() != "OPTIONS" {
		ctx.ResponseWriter.WriteHeader(http.StatusForbidden)
		return
	}

	if ctx.Input.Method() == "OPTIONS" {
		ctx.Output.Header(headerAllowOrigin, "*")
		ctx.Output.Header(headerAllowMethods, "POST, GET, OPTIONS, DELETE")
		ctx.ResponseWriter.WriteHeader(http.StatusOK)
		return
	}
}

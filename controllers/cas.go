// Copyright 2022 The Casdoor Authors. All Rights Reserved.
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
	"encoding/xml"
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"github.com/beego/beego/v2/core/logs"
	"github.com/casdoor/casdoor/object"
)

const (
	InvalidRequest           string = "INVALID_REQUEST"
	InvalidTicketSpec        string = "INVALID_TICKET_SPEC"
	UnauthorizedServiceProxy string = "UNAUTHORIZED_SERVICE_PROXY"
	InvalidProxyCallback     string = "INVALID_PROXY_CALLBACK"
	InvalidTicket            string = "INVALID_TICKET"
	InvalidService           string = "INVALID_SERVICE"
	InternalError            string = "INTERNAL_ERROR"
	UnauthorizedService      string = "UNAUTHORIZED_SERVICE"
)

func queryUnescape(service string) string {
	s, _ := url.QueryUnescape(service)
	return s
}

func (c *RootController) CasValidate() {
	ticket := c.Ctx.Input.Query("ticket")
	service := c.Ctx.Input.Query("service")
	c.Ctx.Output.Header("Content-Type", "text/html; charset=utf-8")
	if service == "" || ticket == "" {
		c.Ctx.Output.Body([]byte("no\n"))
		return
	}
	if ok, response, issuedService, _ := object.GetCasTokenByTicket(ticket); ok {
		// check whether service is the one for which we previously issued token
		if issuedService == service {
			c.Ctx.Output.Body([]byte(fmt.Sprintf("yes\n%s\n", response.User)))
			return
		}
	}
	// token not found
	c.Ctx.Output.Body([]byte("no\n"))
}

func (c *RootController) CasServiceValidate() {
	ticket := c.Ctx.Input.Query("ticket")
	format := c.Ctx.Input.Query("format")
	if !strings.HasPrefix(ticket, "ST") {
		c.sendCasAuthenticationResponseErr(InvalidTicket, fmt.Sprintf("Ticket %s not recognized", ticket), format)
	}
	c.CasP3ProxyValidate()
}

func (c *RootController) CasProxyValidate() {
	// https://apereo.github.io/cas/6.6.x/protocol/CAS-Protocol-Specification.html#26-proxyvalidate-cas-20
	// "/proxyValidate" should accept both service tickets and proxy tickets.
	c.CasP3ProxyValidate()
}

func (c *RootController) CasP3ServiceValidate() {
	ticket := c.Ctx.Input.Query("ticket")
	format := c.Ctx.Input.Query("format")
	if !strings.HasPrefix(ticket, "ST") {
		c.sendCasAuthenticationResponseErr(InvalidTicket, fmt.Sprintf("Ticket %s not recognized", ticket), format)
	}
	c.CasP3ProxyValidate()
}

func (c *RootController) CasP3ProxyValidate() {
	ticket := c.Ctx.Input.Query("ticket")
	format := c.Ctx.Input.Query("format")
	service := c.Ctx.Input.Query("service")
	pgtUrl := c.Ctx.Input.Query("pgtUrl")

	serviceResponse := object.CasServiceResponse{
		Xmlns: "http://www.yale.edu/tp/cas",
	}

	// check whether all required parameters are met
	if service == "" || ticket == "" {
		c.sendCasAuthenticationResponseErr(InvalidRequest, "service and ticket must exist", format)
		return
	}
	ok, response, issuedService, userId := object.GetCasTokenByTicket(ticket)
	// find the token
	if ok {
		// check whether service is the one for which we previously issued token
		if strings.HasPrefix(service, issuedService) || strings.HasPrefix(queryUnescape(service), issuedService) {
			serviceResponse.Success = response
		} else {
			// service not match
			c.sendCasAuthenticationResponseErr(InvalidService, fmt.Sprintf("service %s and %s does not match", service, issuedService), format)
			return
		}
	} else {
		// token not found
		c.sendCasAuthenticationResponseErr(InvalidTicket, fmt.Sprintf("Ticket %s not recognized", ticket), format)
		return
	}

	if pgtUrl != "" && serviceResponse.Failure == nil {
		// that means we are in proxy web flow
		pgt := object.StoreCasTokenForPgt(serviceResponse.Success, service, userId)
		pgtiou := serviceResponse.Success.ProxyGrantingTicket
		pgtUrlObj, err := url.Parse(pgtUrl)
		if err != nil {
			c.sendCasAuthenticationResponseErr(InvalidProxyCallback, "invalid pgtUrl", format)
			return
		}

		if pgtUrlObj.Scheme != "https" {
			c.sendCasAuthenticationResponseErr(InvalidProxyCallback, "callback is not https", format)
			return
		}

		// pgtUrl drives an outbound HTTPS request the server itself makes
		// (below), so - like the service ticket's service parameter - it must
		// be pinned to a URL the application owner explicitly registered
		// (application.RedirectUris), not any caller-supplied host. Without
		// this, an authenticated caller could redeem any ticket issued for
		// this application's own (legitimate) service and redirect the
		// server's outbound request to an arbitrary attacker-chosen host
		// (SSRF), entirely independent of the service ticket's own
		// validation. Resolved by :organization/:application route params
		// rather than the request's service value, since service is only
		// validated as a prefix match above (strings.HasPrefix), which is
		// not a safe anchor for an allowlist decision.
		organization := c.Ctx.Input.Param(":organization")
		applicationName := c.Ctx.Input.Param(":application")
		application, err := object.GetApplication(fmt.Sprintf("admin/%s", applicationName))
		if err != nil || application == nil || application.Organization != organization {
			c.sendCasAuthenticationResponseErr(InvalidProxyCallback, "invalid service application", format)
			return
		}
		if !application.IsUriInRedirectUris(pgtUrl) {
			c.sendCasAuthenticationResponseErr(InvalidProxyCallback, "pgtUrl is not in the allowed Redirect URI list", format)
			return
		}

		// make a request to pgturl passing pgt and pgtiou
		param := pgtUrlObj.Query()
		param.Add("pgtId", pgt)
		param.Add("pgtIou", pgtiou)
		pgtUrlObj.RawQuery = param.Encode()

		request, err := http.NewRequest("GET", pgtUrlObj.String(), nil)
		if err != nil {
			logs.Error("CasP3ProxyValidate: failed to build pgtUrl callback request: %s", err.Error())
			c.sendCasAuthenticationResponseErr(InternalError, "internal error", format)
			return
		}

		resp, err := http.DefaultClient.Do(request)
		// The outbound network error (DNS failure vs. connection refused vs.
		// TLS handshake) is a reconnaissance oracle for the caller's internal
		// network - log it server-side instead of echoing it back.
		if err != nil {
			logs.Error("CasP3ProxyValidate: pgtUrl callback request failed: %s", err.Error())
			c.sendCasAuthenticationResponseErr(InvalidProxyCallback, "proxy callback failed", format)
			return
		}
		if !(resp.StatusCode >= 200 && resp.StatusCode < 400) {
			c.sendCasAuthenticationResponseErr(InvalidProxyCallback, "proxy callback failed", format)
			return
		}
	}
	// everything is ok, send the response
	if format == "json" {
		c.Data["json"] = serviceResponse
		c.ServeJSON()
	} else {
		c.Data["xml"] = serviceResponse
		c.ServeXML()
	}
}

func (c *RootController) CasProxy() {
	pgt := c.Ctx.Input.Query("pgt")
	targetService := c.Ctx.Input.Query("targetService")
	format := c.Ctx.Input.Query("format")
	if pgt == "" || targetService == "" {
		c.sendCasProxyResponseErr(InvalidRequest, "pgt and targetService must exist", format)
		return
	}

	ok, authenticationSuccess, issuedService, userId := object.GetCasTokenByPgt(pgt)
	if !ok {
		c.sendCasProxyResponseErr(UnauthorizedService, "service not authorized", format)
		return
	}

	newAuthenticationSuccess := authenticationSuccess.DeepCopy()
	if newAuthenticationSuccess.Proxies == nil {
		newAuthenticationSuccess.Proxies = &object.CasProxies{}
	}
	newAuthenticationSuccess.Proxies.Proxies = append(newAuthenticationSuccess.Proxies.Proxies, issuedService)
	proxyTicket := object.StoreCasTokenForProxyTicket(&newAuthenticationSuccess, targetService, userId)

	serviceResponse := object.CasServiceResponse{
		Xmlns: "http://www.yale.edu/tp/cas",
		ProxySuccess: &object.CasProxySuccess{
			ProxyTicket: proxyTicket,
		},
	}

	if format == "json" {
		c.Data["json"] = serviceResponse
		c.ServeJSON()
	} else {
		c.Data["xml"] = serviceResponse
		c.ServeXML()
	}
}

func (c *RootController) SamlValidate() {
	c.Ctx.Output.Header("Content-Type", "text/xml; charset=utf-8")
	target := c.Ctx.Input.Query("TARGET")
	body := c.Ctx.Input.RequestBody
	envelopRequest := struct {
		XMLName xml.Name `xml:"Envelope"`
		Body    struct {
			XMLName xml.Name `xml:"Body"`
			Content string   `xml:",innerxml"`
		}
	}{}

	err := xml.Unmarshal(body, &envelopRequest)
	if err != nil {
		c.ResponseError(err.Error())
		return
	}

	response, service, err := object.GetValidationBySaml(envelopRequest.Body.Content, c.Ctx.Request.Host)
	if err != nil {
		c.ResponseError(err.Error())
		return
	}

	if !strings.HasPrefix(target, service) {
		c.ResponseError(fmt.Sprintf(c.T("cas:Service %s and %s do not match"), target, service))
		return
	}

	envelopResponse := struct {
		XMLName xml.Name `xml:"SOAP-ENV:Envelope"`
		Xmlns   string   `xml:"xmlns:SOAP-ENV"`
		Body    struct {
			XMLName xml.Name `xml:"SOAP-ENV:Body"`
			Content string   `xml:",innerxml"`
		}
	}{}
	envelopResponse.Xmlns = "http://schemas.xmlsoap.org/soap/envelope/"
	envelopResponse.Body.Content = response

	data, err := xml.Marshal(envelopResponse)
	if err != nil {
		c.ResponseError(err.Error())
		return
	}
	c.Ctx.Output.Body(data)
}

func (c *RootController) sendCasProxyResponseErr(code, msg, format string) {
	serviceResponse := object.CasServiceResponse{
		Xmlns: "http://www.yale.edu/tp/cas",
		ProxyFailure: &object.CasProxyFailure{
			Code:    code,
			Message: msg,
		},
	}
	if format == "json" {
		c.Data["json"] = serviceResponse
		c.ServeJSON()
	} else {
		c.Data["xml"] = serviceResponse
		c.ServeXML()
	}
}

func (c *RootController) sendCasAuthenticationResponseErr(code, msg, format string) {
	serviceResponse := object.CasServiceResponse{
		Xmlns: "http://www.yale.edu/tp/cas",
		Failure: &object.CasAuthenticationFailure{
			Code:    code,
			Message: msg,
		},
	}
	if format == "json" {
		c.Data["json"] = serviceResponse
		c.ServeJSON()
	} else {
		c.Data["xml"] = serviceResponse
		c.ServeXML()
	}
}

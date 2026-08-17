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
	"net"
	"net/http"
	"net/url"
	"strings"

	"github.com/beego/beego/v2/core/logs"
	"github.com/casdoor/casdoor/object"
	"github.com/casdoor/casdoor/util"
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

// isPgtUrlHostAllowed reports whether every IP address the pgtUrl's host
// resolves to is a routable public address. It rejects loopback,
// link-local (including the 169.254.0.0/16 cloud metadata range), and
// RFC1918 private-range destinations so that a caller-supplied pgtUrl
// cannot be used to make the server dial an internal host it has no
// legitimate reason to reach.
func isPgtUrlHostAllowed(pgtUrlObj *url.URL) bool {
	hostname := pgtUrlObj.Hostname()
	if hostname == "" {
		return false
	}

	// A literal IP address needs no DNS resolution.
	if ip := net.ParseIP(hostname); ip != nil {
		return isRoutablePublicIp(ip)
	}

	ips, err := net.LookupIP(hostname)
	if err != nil || len(ips) == 0 {
		return false
	}

	for _, ip := range ips {
		if !isRoutablePublicIp(ip) {
			return false
		}
	}
	return true
}

// isRoutablePublicIp reports whether ip is a globally-routable public
// address. util.IsIntranetIp already covers private/loopback/link-local
// (including the 169.254.0.0/16 cloud metadata range) ranges; this adds the
// remaining non-routable classes (multicast, unspecified) so no
// non-internet destination slips through.
func isRoutablePublicIp(ip net.IP) bool {
	if util.IsIntranetIp(ip.String()) {
		return false
	}
	return !ip.IsMulticast() && !ip.IsInterfaceLocalMulticast() && !ip.IsUnspecified()
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
			logs.Warning(fmt.Sprintf("CasP3ProxyValidate: failed to parse pgtUrl %q: %v", pgtUrl, err))
			c.sendCasAuthenticationResponseErr(InvalidProxyCallback, "invalid proxy callback url", format)
			return
		}

		if pgtUrlObj.Scheme != "https" {
			c.sendCasAuthenticationResponseErr(InvalidProxyCallback, "callback is not https", format)
			return
		}

		// The pgtUrl host is caller-supplied, so it must not be usable to make
		// the server dial an internal/loopback/link-local destination (SSRF).
		if !isPgtUrlHostAllowed(pgtUrlObj) {
			logs.Warning(fmt.Sprintf("CasP3ProxyValidate: rejected pgtUrl with disallowed host: %s", pgtUrlObj.Host))
			c.sendCasAuthenticationResponseErr(InvalidProxyCallback, "proxy callback url is not allowed", format)
			return
		}

		// make a request to pgturl passing pgt and pgtiou
		param := pgtUrlObj.Query()
		param.Add("pgtId", pgt)
		param.Add("pgtIou", pgtiou)
		pgtUrlObj.RawQuery = param.Encode()

		request, err := http.NewRequest("GET", pgtUrlObj.String(), nil)
		if err != nil {
			logs.Warning(fmt.Sprintf("CasP3ProxyValidate: failed to build proxy callback request: %v", err))
			c.sendCasAuthenticationResponseErr(InternalError, "failed to build proxy callback request", format)
			return
		}

		resp, err := http.DefaultClient.Do(request)
		if err != nil {
			// Never echo the raw dial/connect error back to the caller: it
			// leaks whether an internal host:port is reachable.
			logs.Warning(fmt.Sprintf("CasP3ProxyValidate: failed to call proxy callback url: %v", err))
			c.sendCasAuthenticationResponseErr(InvalidProxyCallback, "failed to reach proxy callback url", format)
			return
		}
		if !(resp.StatusCode >= 200 && resp.StatusCode < 400) {
			logs.Warning(fmt.Sprintf("CasP3ProxyValidate: proxy callback url returned status %d", resp.StatusCode))
			c.sendCasAuthenticationResponseErr(InvalidProxyCallback, "proxy callback url returned an unexpected response", format)
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

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
	"context"
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
		pgtUrlObj, err := url.Parse(pgtUrl)
		if err != nil {
			c.sendCasAuthenticationResponseErr(InvalidProxyCallback, "invalid pgtUrl", format)
			return
		}

		if pgtUrlObj.Scheme != "https" {
			c.sendCasAuthenticationResponseErr(InvalidProxyCallback, "callback is not https", format)
			return
		}

		// Ownership + SSRF guard: the callback target must belong to the same
		// host as the service this ticket was actually issued for (mirroring
		// the ownership check already applied to "service" above), and must
		// not resolve to a loopback/link-local/private address. Without this,
		// any holder of a valid CAS service ticket could direct the server to
		// make an outbound HTTPS request to an arbitrary attacker-chosen host.
		if err := validatePgtCallbackTarget(pgtUrlObj, issuedService); err != nil {
			logs.Warning("CasP3ProxyValidate: rejected pgtUrl callback %s: %s", pgtUrl, err.Error())
			c.sendCasAuthenticationResponseErr(InvalidProxyCallback, "callback target is not allowed", format)
			return
		}

		// The pgt id is generated but intentionally NOT stored/activated yet:
		// it only becomes a valid, redeemable proxy-granting ticket once the
		// callback below confirms this caller actually controls pgtUrl.
		pgt := object.GenerateCasPgt()
		pgtiou := serviceResponse.Success.ProxyGrantingTicket

		if err := performPgtCallback(casProxyCallbackClient, pgtUrlObj, pgt, pgtiou); err != nil {
			// Failed to confirm the callback: never store/expose the PGT.
			// performPgtCallback already logged the real cause server-side;
			// the client only ever gets a generic message, since the real
			// transport error would embed the callback URL, including the
			// pgtId/pgtIou query parameters just added above.
			c.sendCasAuthenticationResponseErr(InvalidProxyCallback, "failed to reach proxy callback", format)
			return
		}

		// Callback confirmed: only now is it safe to activate the PGT.
		object.StoreCasTokenForPgt(pgt, serviceResponse.Success, service, userId)
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

// casProxyCallbackClient performs the synchronous pgtUrl callback in
// CasP3ProxyValidate. Its DialContext re-resolves and re-validates the
// destination at dial time (see safeCasProxyDialContext) to close the
// TOCTOU/DNS-rebinding gap a one-time host check in validatePgtCallbackTarget
// would otherwise leave open.
var casProxyCallbackClient = &http.Client{
	Transport: &http.Transport{
		DialContext: safeCasProxyDialContext,
	},
}

// validatePgtCallbackTarget ensures pgtUrlObj is safe to dial as a CAS
// proxy-granting-ticket callback for the ticket that was issued to
// issuedService:
//  1. its host must match the host of the service the ticket was actually
//     issued for (mirroring the ownership check already applied to the
//     "service" parameter in CasP3ProxyValidate), so an arbitrary
//     attacker-chosen host can never be used as a callback target, and
//  2. it must not resolve to a loopback/link-local/private address, closing
//     DNS-rebinding on an otherwise allow-listed hostname.
func validatePgtCallbackTarget(pgtUrlObj *url.URL, issuedService string) error {
	issuedServiceUrl, err := url.Parse(issuedService)
	if err != nil || issuedServiceUrl.Hostname() == "" {
		return fmt.Errorf("registered service URL is invalid")
	}

	if !strings.EqualFold(pgtUrlObj.Hostname(), issuedServiceUrl.Hostname()) {
		return fmt.Errorf("callback host %q does not match the registered service host %q", pgtUrlObj.Hostname(), issuedServiceUrl.Hostname())
	}

	ips, err := lookupHostIps(pgtUrlObj.Hostname())
	if err != nil || len(ips) == 0 {
		return fmt.Errorf("failed to resolve callback host")
	}
	for _, ip := range ips {
		if util.IsIntranetIp(ip.String()) {
			return fmt.Errorf("callback host resolves to a disallowed address")
		}
	}
	return nil
}

// lookupHostIps resolves host to its IP addresses. If host is already a
// literal IP address, it is returned as-is with no DNS lookup.
func lookupHostIps(host string) ([]net.IP, error) {
	if ip := net.ParseIP(host); ip != nil {
		return []net.IP{ip}, nil
	}
	return net.LookupIP(host)
}

// safeCasProxyDialContext is the DialContext for casProxyCallbackClient. It
// re-resolves addr's host at dial time and refuses to connect to any
// resolved IP that util.IsIntranetIp flags, then dials the validated IP
// directly - closing the gap where a hostname that looked safe when
// validatePgtCallbackTarget ran could be re-pointed at an internal address
// by the time the connection is actually made (DNS rebinding).
func safeCasProxyDialContext(ctx context.Context, network, addr string) (net.Conn, error) {
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

// performPgtCallback sends the pgt/pgtiou callback GET request to pgtUrlObj
// and reports whether the callback confirmed success (2xx/3xx). It never
// returns the underlying transport error or response detail to the caller:
// a net/http transport error's Error() text embeds the full request URL -
// including the pgtId/pgtIou query parameters this function adds - so
// echoing it back to the CAS client would disclose an unconfirmed PGT's id.
func performPgtCallback(client *http.Client, pgtUrlObj *url.URL, pgt, pgtiou string) error {
	param := pgtUrlObj.Query()
	param.Add("pgtId", pgt)
	param.Add("pgtIou", pgtiou)
	pgtUrlObj.RawQuery = param.Encode()

	request, err := http.NewRequest("GET", pgtUrlObj.String(), nil)
	if err != nil {
		// err.Error() here could embed the pgtId/pgtIou-bearing URL; keep it
		// server-side only and return a generic, detail-free error.
		logs.Warning("CasP3ProxyValidate: failed to build pgtUrl callback request: %s", err.Error())
		return fmt.Errorf("failed to build proxy callback request")
	}

	resp, err := client.Do(request)
	if err != nil {
		// A net/http transport error's Error() text embeds the full request
		// URL (including pgtId/pgtIou) - log it server-side only, never
		// return it to the caller.
		logs.Warning("CasP3ProxyValidate: pgtUrl callback transport error: %s", err.Error())
		return fmt.Errorf("failed to reach proxy callback")
	}
	defer resp.Body.Close()

	if !(resp.StatusCode >= 200 && resp.StatusCode < 400) {
		logs.Warning("CasP3ProxyValidate: pgtUrl callback returned status %d", resp.StatusCode)
		return fmt.Errorf("proxy callback returned an unsuccessful status")
	}
	return nil
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

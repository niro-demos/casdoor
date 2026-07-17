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

package controllers

import (
	"errors"
	"fmt"
	"strings"

	"github.com/casdoor/casdoor/conf"
	"github.com/casdoor/casdoor/i18n"
	"github.com/casdoor/casdoor/object"
	"github.com/casdoor/casdoor/util"
)

// ResponseJsonData ...
func (c *ApiController) ResponseJsonData(resp *Response, data ...interface{}) {
	switch len(data) {
	case 2:
		resp.Data2 = data[1]
		fallthrough
	case 1:
		resp.Data = data[0]
	}
	c.Data["json"] = resp
	c.ServeJSON()
}

// ResponseOk ...
func (c *ApiController) ResponseOk(data ...interface{}) {
	resp := &Response{Status: "ok"}
	c.ResponseJsonData(resp, data...)
}

// ResponseError ...
func (c *ApiController) ResponseError(error string, data ...interface{}) {
	enableErrorMask2 := conf.GetConfigBool("enableErrorMask2")
	if enableErrorMask2 {
		error = c.T("subscription:Error")

		resp := &Response{Status: "error", Msg: error}
		c.ResponseJsonData(resp, data...)
		return
	}

	resp := &Response{Status: "error", Msg: error}
	c.ResponseJsonData(resp, data...)
}

func (c *ApiController) T(error string) string {
	return i18n.Translate(c.GetAcceptLanguage(), error)
}

// GetAcceptLanguage ...
func (c *ApiController) GetAcceptLanguage() string {
	language := c.Ctx.Request.Header.Get("Accept-Language")
	if len(language) > 2 {
		language = language[0:2]
	}
	return conf.GetLanguage(language)
}

// SetTokenErrorHttpStatus ...
func (c *ApiController) SetTokenErrorHttpStatus() {
	_, ok := c.Data["json"].(*object.TokenError)
	if ok {
		if c.Data["json"].(*object.TokenError).Error == object.InvalidClient {
			c.Ctx.Output.SetStatus(401)
			c.Ctx.Output.Header("WWW-Authenticate", "Basic realm=\"OAuth2\"")
		} else {
			c.Ctx.Output.SetStatus(400)
		}
	}
	_, ok = c.Data["json"].(*object.TokenWrapper)
	if ok {
		c.Ctx.Output.SetStatus(200)
	}
}

// RequireSignedIn ...
func (c *ApiController) RequireSignedIn() (string, bool) {
	userId := c.GetSessionUsername()
	if userId == "" {
		c.ResponseError(c.T("general:Please login first"), "Please login first")
		return "", false
	}
	return userId, true
}

// RequireSignedInUser ...
func (c *ApiController) RequireSignedInUser() (*object.User, bool) {
	userId, ok := c.RequireSignedIn()
	if !ok {
		return nil, false
	}

	if object.IsAppUser(userId) {
		tmpUserId := c.Ctx.Input.Query("userId")
		if tmpUserId != "" {
			userId = tmpUserId
		}
	}

	user, err := object.GetUser(userId)
	if err != nil {
		c.ResponseError(err.Error())
		return nil, false
	}
	if user == nil {
		c.ClearUserSession()
		c.ResponseError(fmt.Sprintf(c.T("general:The user: %s doesn't exist"), userId))
		return nil, false
	}

	return user, true
}

// RequireAdmin ...
func (c *ApiController) RequireAdmin() (string, bool) {
	user, ok := c.RequireSignedInUser()
	if !ok {
		return "", false
	}

	if user.Owner == "built-in" {
		return "", true
	}

	if !user.IsAdmin {
		c.ResponseError(c.T("general:this operation requires administrator to perform"))
		return "", false
	}

	return user.Owner, true
}

func (c *ApiController) IsOrgAdmin() (bool, bool) {
	userId, ok := c.RequireSignedIn()
	if !ok {
		return false, true
	}

	if object.IsAppUser(userId) {
		return true, true
	}

	user, err := object.GetUser(userId)
	if err != nil {
		c.ResponseError(err.Error())
		return false, false
	}
	if user == nil {
		c.ClearUserSession()
		c.ResponseError(fmt.Sprintf(c.T("general:The user: %s doesn't exist"), userId))
		return false, false
	}

	return user.IsAdmin, true
}

// RequireGlobalAdmin requires the caller to be a true global admin (an
// account whose Owner is "built-in"), rejecting org-scoped admins whose
// IsAdmin flag is true but whose Owner is a different organization. This is
// stricter than RequireAdmin, which treats any org-scoped admin as
// sufficient. Use it for boundaries that must not be crossed by org admins,
// such as the shared, platform-wide (Owner=="admin") provider pool that
// requireProviderPermission already protects on the write path.
func (c *ApiController) RequireGlobalAdmin() bool {
	_, ok := c.RequireSignedInUser()
	if !ok {
		return false
	}

	if !c.IsGlobalAdmin() {
		c.ResponseError(c.T("general:this operation requires administrator to perform"))
		return false
	}

	return true
}

// IsMaskedEnabled ...
func (c *ApiController) IsMaskedEnabled() (bool, bool) {
	isMaskEnabled := true
	withSecret := c.Ctx.Input.Query("withSecret")
	if withSecret == "1" {
		isMaskEnabled = false

		if conf.IsDemoMode() {
			c.ResponseError(c.T("general:this operation is not allowed in demo mode"))
			return false, isMaskEnabled
		}

		// Unmasking provider secrets must be limited to true global admins:
		// GetProviders/GetPaginationProviders always OR in the shared,
		// platform-wide provider pool (Owner=="admin") alongside the
		// requested org's own providers, so an org-scoped admin (IsAdmin
		// but Owner != "built-in") who merely passed RequireAdmin() would
		// also receive that shared pool's real secrets. This mirrors the
		// isGlobalAdmin() check controllers/provider.go
		// requireProviderPermission() already uses for the same
		// Owner=="admin" boundary on the write path.
		if !c.RequireGlobalAdmin() {
			return false, isMaskEnabled
		}
	}

	return true, isMaskEnabled
}

func refineFullFilePath(fullFilePath string) (string, string) {
	tokens := strings.Split(fullFilePath, "/")
	if len(tokens) >= 2 && tokens[0] == "Direct" && tokens[1] != "" {
		providerName := tokens[1]
		res := strings.Join(tokens[2:], "/")
		return providerName, "/" + res
	} else {
		return "", fullFilePath
	}
}

func (c *ApiController) GetProviderFromContext(category string) (*object.Provider, error) {
	// The caller must be signed in before any provider is resolved and
	// returned, regardless of which branch below resolves it. This check
	// used to sit only in the "no provider name given" branch, so a caller
	// who supplied a `provider` query param (or a `Direct/<provider>/...`
	// fullFilePath, or field=provider&value=...) could reach
	// object.GetProvider(...) and get a live provider back without ever
	// being authenticated.
	//
	// This intentionally checks the session directly instead of calling
	// c.RequireSignedIn() (which also writes the error response itself):
	// every caller of GetProviderFromContext already writes its own
	// response from the returned error, so also writing one here would
	// send two response bodies on the same request for any caller that
	// hits this branch unauthenticated.
	userId := c.GetSessionUsername()
	if userId == "" {
		return nil, errors.New(c.T("general:Please login first"))
	}

	providerName := c.Ctx.Input.Query("provider")
	if providerName == "" {
		field := c.Ctx.Input.Query("field")
		value := c.Ctx.Input.Query("value")
		if field == "provider" && value != "" {
			providerName = value
		} else {
			fullFilePath := c.Ctx.Input.Query("fullFilePath")
			providerName, _ = refineFullFilePath(fullFilePath)
		}
	}

	if providerName != "" {
		provider, err := object.GetProvider(util.GetId("admin", providerName))
		if err != nil {
			return nil, err
		}

		if provider == nil {
			err = fmt.Errorf(c.T("util:The provider: %s is not found"), providerName)
			return nil, err
		}

		return provider, nil
	}

	application, err := object.GetApplicationByUserId(userId)
	if err != nil {
		return nil, err
	}

	if application == nil {
		return nil, fmt.Errorf(c.T("util:No application is found for userId: %s"), userId)
	}

	provider, err := application.GetProviderByCategory(category)
	if err != nil {
		return nil, err
	}

	if provider == nil {
		return nil, fmt.Errorf(c.T("util:No provider for category: %s is found for application: %s"), category, application.Name)
	}

	return provider, nil
}

func checkQuotaForApplication(count int) error {
	quota := conf.GetConfigQuota().Application
	if quota == -1 {
		return nil
	}
	if count >= quota {
		return fmt.Errorf("application quota is exceeded")
	}
	return nil
}

func checkQuotaForOrganization(count int) error {
	quota := conf.GetConfigQuota().Organization
	if quota == -1 {
		return nil
	}
	if count >= quota {
		return fmt.Errorf("organization quota is exceeded")
	}
	return nil
}

func checkQuotaForProvider(count int) error {
	quota := conf.GetConfigQuota().Provider
	if quota == -1 {
		return nil
	}
	if count >= quota {
		return fmt.Errorf("provider quota is exceeded")
	}
	return nil
}

func checkQuotaForUser() error {
	quota := conf.GetConfigQuota().User
	if quota == -1 {
		return nil
	}

	count, err := object.GetUserCount("", "", "", "")
	if err != nil {
		return err
	}

	if int(count) >= quota {
		return fmt.Errorf("user quota is exceeded")
	}
	return nil
}

func getInvalidSmsReceivers(smsForm SmsForm) []string {
	var invalidReceivers []string
	for _, receiver := range smsForm.Receivers {
		// The receiver phone format: E164 like +8613854673829 +441932567890
		if !util.IsPhoneValid(receiver, "") {
			invalidReceivers = append(invalidReceivers, receiver)
		}
	}
	return invalidReceivers
}

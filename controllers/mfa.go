// Copyright 2023 The Casdoor Authors. All Rights Reserved.
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
	"net/http"

	"github.com/casdoor/casdoor/object"
	"github.com/casdoor/casdoor/util"
)

// MfaSetupInitiate
// @Title MfaSetupInitiate
// @Tag MFA API
// @Description setup MFA
// @Param   mfaType formData string true "The type of MFA to set up (app/sms/email)"
// @Param   owner   formData string true "The owner of the user"
// @Param   name    formData string true "The name of the user"
// @Success 200 {object} controllers.Response The Response object
// @router /mfa/setup/initiate [post]
func (c *ApiController) MfaSetupInitiate() {
	owner := c.Ctx.Request.Form.Get("owner")
	name := c.Ctx.Request.Form.Get("name")
	mfaType := c.Ctx.Request.Form.Get("mfaType")
	userId := util.GetId(owner, name)

	if len(userId) == 0 {
		c.ResponseError(http.StatusText(http.StatusBadRequest))
		return
	}

	MfaUtil := object.GetMfaUtil(mfaType, nil)
	if MfaUtil == nil {
		c.ResponseError("Invalid auth type")
	}

	user, err := object.GetUser(userId)
	if err != nil {
		c.ResponseError(err.Error())
		return
	}

	if user == nil {
		c.ResponseError("User doesn't exist")
		return
	}

	organization, err := object.GetOrganizationByUser(user)
	if err != nil {
		c.ResponseError(err.Error())
		return
	}

	issuer := ""
	if organization != nil && organization.DisplayName != "" {
		issuer = organization.DisplayName
	} else if organization != nil {
		issuer = organization.Name
	}

	mfaProps, err := MfaUtil.Initiate(user.GetId(), issuer)
	if err != nil {
		c.ResponseError(err.Error())
		return
	}

	recoveryCode := util.GenerateUUID()
	mfaProps.RecoveryCodes = []string{recoveryCode}
	mfaProps.MfaRememberInHours = organization.MfaRememberInHours

	resp := mfaProps
	c.ResponseOk(resp)
}

// MfaSetupVerify
// @Title MfaSetupVerify
// @Tag MFA API
// @Description setup verify totp
// @Param   secret   formData string true "The MFA secret"
// @Param   passcode formData string true "The MFA passcode"
// @Success 200 {object} controllers.Response The Response object
// @router /mfa/setup/verify [post]
func (c *ApiController) MfaSetupVerify() {
	mfaType := c.Ctx.Request.Form.Get("mfaType")
	passcode := c.Ctx.Request.Form.Get("passcode")
	secret := c.Ctx.Request.Form.Get("secret")
	dest := c.Ctx.Request.Form.Get("dest")
	countryCode := c.Ctx.Request.Form.Get("countryCode")

	if mfaType == "" || passcode == "" {
		c.ResponseError("missing auth type or passcode")
		return
	}

	config := &object.MfaProps{
		MfaType: mfaType,
	}
	if mfaType == object.TotpType {
		if secret == "" {
			c.ResponseError("totp secret is missing")
			return
		}
		config.Secret = secret
	} else if mfaType == object.SmsType {
		if dest == "" {
			c.ResponseError("destination is missing")
			return
		}
		config.Secret = dest
		if countryCode == "" {
			c.ResponseError("country code is missing")
			return
		}
		config.CountryCode = countryCode
	} else if mfaType == object.EmailType {
		if dest == "" {
			c.ResponseError("destination is missing")
			return
		}
		config.Secret = dest
	} else if mfaType == object.RadiusType {
		if dest == "" {
			c.ResponseError("RADIUS username is missing")
			return
		}
		config.Secret = dest
		if secret == "" {
			c.ResponseError("RADIUS provider is missing")
			return
		}
		config.URL = secret
	} else if mfaType == object.PushType {
		if dest == "" {
			c.ResponseError("push notification receiver is missing")
			return
		}
		config.Secret = dest
		if secret == "" {
			c.ResponseError("push notification provider is missing")
			return
		}
		config.URL = secret
	}

	mfaUtil := object.GetMfaUtil(mfaType, config)
	if mfaUtil == nil {
		c.ResponseError("Invalid multi-factor authentication type")
		return
	}

	err := mfaUtil.SetupVerify(passcode)
	if err != nil {
		c.ResponseError(err.Error())
	} else {
		c.ResponseOk(http.StatusText(http.StatusOK))
	}
}

// MfaSetupEnable
// @Title MfaSetupEnable
// @Tag MFA API
// @Description enable totp
// @Param   owner   formData string true "The owner of the user"
// @Param   name    formData string true "The name of the user"
// @Param   mfaType formData string true "The MFA auth type"
// @Success 200 {object} controllers.Response The Response object
// @router /mfa/setup/enable [post]
func (c *ApiController) MfaSetupEnable() {
	owner := c.Ctx.Request.Form.Get("owner")
	name := c.Ctx.Request.Form.Get("name")
	mfaType := c.Ctx.Request.Form.Get("mfaType")
	secret := c.Ctx.Request.Form.Get("secret")
	dest := c.Ctx.Request.Form.Get("dest")
	countryCode := c.Ctx.Request.Form.Get("countryCode")
	recoveryCodes := c.Ctx.Request.Form.Get("recoveryCodes")

	user, err := object.GetUser(util.GetId(owner, name))
	if err != nil {
		c.ResponseError(err.Error())
		return
	}

	if user == nil {
		c.ResponseError("User doesn't exist")
		return
	}

	config := &object.MfaProps{
		MfaType: mfaType,
	}

	if mfaType == object.TotpType {
		if secret == "" {
			c.ResponseError("totp secret is missing")
			return
		}
		config.Secret = secret
	} else if mfaType == object.EmailType {
		if user.Email == "" {
			if dest == "" {
				c.ResponseError("destination is missing")
				return
			}
			user.Email = dest
		}
	} else if mfaType == object.SmsType {
		if user.Phone == "" {
			if dest == "" {
				c.ResponseError("destination is missing")
				return
			}
			user.Phone = dest
			if countryCode == "" {
				c.ResponseError("country code is missing")
				return
			}
			user.CountryCode = countryCode
		}
	} else if mfaType == object.RadiusType {
		if dest == "" {
			c.ResponseError("RADIUS username is missing")
			return
		}
		config.Secret = dest
		if secret == "" {
			c.ResponseError("RADIUS provider is missing")
			return
		}
		config.URL = secret
	} else if mfaType == object.PushType {
		if dest == "" {
			c.ResponseError("push notification receiver is missing")
			return
		}
		config.Secret = dest
		if secret == "" {
			c.ResponseError("push notification provider is missing")
			return
		}
		config.URL = secret
	}

	if recoveryCodes == "" {
		c.ResponseError("recovery codes is missing")
		return
	}
	config.RecoveryCodes = []string{recoveryCodes}

	mfaUtil := object.GetMfaUtil(mfaType, config)
	if mfaUtil == nil {
		c.ResponseError("Invalid multi-factor authentication type")
		return
	}

	err = mfaUtil.Enable(user)
	if err != nil {
		c.ResponseError(err.Error())
		return
	}

	c.ResponseOk(http.StatusText(http.StatusOK))
}

// DeleteMfa
// @Title DeleteMfa
// @Tag MFA API
// @Description Delete MFA
// @Param   owner    formData string true  "The owner of the user"
// @Param   name     formData string true  "The name of the user"
// @Param   password formData string false "The caller's current password. Required when disabling your own MFA; not required (and not known) when an admin resets another user's MFA."
// @Success 200 {object} controllers.Response The Response object
// @router /delete-mfa/ [post]
func (c *ApiController) DeleteMfa() {
	owner := c.Ctx.Request.Form.Get("owner")
	name := c.Ctx.Request.Form.Get("name")
	password := c.Ctx.Request.Form.Get("password")
	userId := util.GetId(owner, name)

	user, err := object.GetUser(userId)
	if err != nil {
		c.ResponseError(err.Error())
		return
	}
	if user == nil {
		c.ResponseError("User doesn't exist")
		return
	}

	if err = c.checkMfaReauthIfSelf(user, password); err != nil {
		c.ResponseError(err.Error())
		return
	}

	err = object.DisabledMultiFactorAuth(user)
	if err != nil {
		c.ResponseError(err.Error())
		return
	}

	c.ResponseOk(object.GetAllMfaProps(user, true))
}

// checkMfaReauthIfSelf re-verifies the caller's current password before an
// operation that weakens an account's authentication posture (disabling MFA,
// changing the preferred MFA method) is applied to the caller's *own*
// account. A valid session cookie is not, by itself, sufficient proof that
// the request wasn't made with a stolen/replayed session — the caller must
// additionally still know the account's current password.
//
// When the caller is acting on someone *else's* account (e.g. an org/global
// admin resetting a locked-out user's MFA), this check is skipped: that
// action is already gated by the authorization filter (ApiFilter ->
// authz.IsAllowed), and the admin cannot be expected to know the target
// user's password.
func (c *ApiController) checkMfaReauthIfSelf(user *object.User, password string) error {
	requester := c.getCurrentUser()
	isSelf := requester == nil || (requester.Owner == user.Owner && requester.Name == user.Name)
	if !isSelf {
		return nil
	}

	return object.CheckPassword(user, password, c.GetAcceptLanguage())
}

// SetPreferredMfa
// @Title SetPreferredMfa
// @Tag MFA API
// @Description Set preferred MFA
// @Param   mfaType  formData string true  "The MFA type to set as preferred"
// @Param   owner    formData string true  "The owner of the user"
// @Param   name     formData string true  "The name of the user"
// @Param   password formData string false "The caller's current password. Required when changing your own preferred MFA method; not required (and not known) when an admin acts on another user's MFA."
// @Success 200 {object} controllers.Response The Response object
// @router /set-preferred-mfa [post]
func (c *ApiController) SetPreferredMfa() {
	mfaType := c.Ctx.Request.Form.Get("mfaType")
	owner := c.Ctx.Request.Form.Get("owner")
	name := c.Ctx.Request.Form.Get("name")
	password := c.Ctx.Request.Form.Get("password")
	userId := util.GetId(owner, name)

	user, err := object.GetUser(userId)
	if err != nil {
		c.ResponseError(err.Error())
		return
	}
	if user == nil {
		c.ResponseError("User doesn't exist")
		return
	}

	if err = c.checkMfaReauthIfSelf(user, password); err != nil {
		c.ResponseError(err.Error())
		return
	}

	err = object.SetPreferredMultiFactorAuth(user, mfaType)
	if err != nil {
		c.ResponseError(err.Error())
		return
	}
	c.ResponseOk(object.GetAllMfaProps(user, true))
}

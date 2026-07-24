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

	// Bind proof of possession to the session: remember the server-generated
	// TOTP secret so setup/verify checks a passcode against a secret the server
	// chose, and clear any previously verified state from an earlier attempt.
	if mfaType == object.TotpType {
		c.SetSession(object.MfaTotpSecretSession, mfaProps.Secret)
		c.DelSession(object.MfaTotpVerifiedSession)
	}

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
		// Verify the passcode against the server-generated secret bound to this
		// session by setup/initiate, not against a secret the client supplies —
		// so a passing verify actually proves possession of that pending secret.
		pendingSecret := c.getMfaTotpPendingSecret()
		if pendingSecret == "" {
			c.ResponseError("totp secret is missing")
			return
		}
		config.Secret = pendingSecret
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
		// Record that possession of this session's pending TOTP secret has been
		// proven, so setup/enable is allowed to persist exactly that secret.
		if mfaType == object.TotpType {
			c.SetSession(object.MfaTotpVerifiedSession, config.Secret)
		}
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
		// Proof-of-possession gate: enable persists ONLY the secret whose
		// possession was proven by a successful setup/verify in this session —
		// never a secret carried on the enable request. This ties the
		// initiate -> verify -> enable steps together so an attacker acting with
		// a victim's session cannot plant a TOTP factor they alone control.
		verifiedSecret, err := object.ResolveMfaEnableSecret(mfaType, c.getMfaTotpVerifiedSecret(), secret)
		if err != nil {
			c.ResponseError(err.Error())
			return
		}
		config.Secret = verifiedSecret
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

	// Consume the one-time proof-of-possession state so it cannot be replayed to
	// enable a second time without going through the handshake again.
	if mfaType == object.TotpType {
		c.DelSession(object.MfaTotpSecretSession)
		c.DelSession(object.MfaTotpVerifiedSession)
	}

	c.ResponseOk(http.StatusText(http.StatusOK))
}

// DeleteMfa
// @Title DeleteMfa
// @Tag MFA API
// @Description Delete MFA
// @Param   owner formData string true "The owner of the user"
// @Param   name  formData string true "The name of the user"
// @Success 200 {object} controllers.Response The Response object
// @router /delete-mfa/ [post]
func (c *ApiController) DeleteMfa() {
	owner := c.Ctx.Request.Form.Get("owner")
	name := c.Ctx.Request.Form.Get("name")
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

	err = object.DisabledMultiFactorAuth(user)
	if err != nil {
		c.ResponseError(err.Error())
		return
	}

	c.ResponseOk(object.GetAllMfaProps(user, true))
}

// SetPreferredMfa
// @Title SetPreferredMfa
// @Tag MFA API
// @Description Set preferred MFA
// @Param   mfaType formData string true "The MFA type to set as preferred"
// @Param   owner   formData string true "The owner of the user"
// @Param   name    formData string true "The name of the user"
// @Success 200 {object} controllers.Response The Response object
// @router /set-preferred-mfa [post]
func (c *ApiController) SetPreferredMfa() {
	mfaType := c.Ctx.Request.Form.Get("mfaType")
	owner := c.Ctx.Request.Form.Get("owner")
	name := c.Ctx.Request.Form.Get("name")
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

	err = object.SetPreferredMultiFactorAuth(user, mfaType)
	if err != nil {
		c.ResponseError(err.Error())
		return
	}
	c.ResponseOk(object.GetAllMfaProps(user, true))
}

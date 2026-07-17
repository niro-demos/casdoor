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
	"net/mail"
	"net/url"
	"regexp"
	"strings"

	"github.com/nyaruka/phonenumbers"
)

var (
	rePhone                    *regexp.Regexp
	ReWhiteSpace               *regexp.Regexp
	ReFieldWhiteList           *regexp.Regexp
	ReFieldWhiteListIdentifier *regexp.Regexp
	ReUserName                 *regexp.Regexp
	ReUserNameWithEmail        *regexp.Regexp
)

func init() {
	rePhone, _ = regexp.Compile(`(\d{3})\d*(\d{4})`)
	ReWhiteSpace, _ = regexp.Compile(`\s`)
	ReFieldWhiteList, _ = regexp.Compile(`^[A-Za-z0-9]+$`)
	ReFieldWhiteListIdentifier, _ = regexp.Compile(`^[A-Za-z][A-Za-z0-9_]*$`)
	ReUserName, _ = regexp.Compile("^[a-zA-Z0-9]+([-._][a-zA-Z0-9]+)*$")
	ReUserNameWithEmail, _ = regexp.Compile(`^([a-zA-Z0-9]+([-._][a-zA-Z0-9]+)*)|([a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,})$`) // Add support for email formats
}

func IsEmailValid(email string) bool {
	_, err := mail.ParseAddress(email)
	return err == nil
}

func IsPhoneValid(phone string, countryCode string) bool {
	phoneNumber, err := phonenumbers.Parse(phone, countryCode)
	if err != nil {
		return false
	}
	return phonenumbers.IsValidNumber(phoneNumber)
}

func IsPhoneAllowInRegin(countryCode string, allowRegions []string) bool {
	if InSlice(allowRegions, "All") {
		return true
	}
	return InSlice(allowRegions, countryCode)
}

func IsRegexp(s string) (bool, error) {
	if _, err := regexp.Compile(s); err != nil {
		return false, err
	}
	return regexp.QuoteMeta(s) != s, nil
}

func IsInvitationCodeMatch(pattern string, invitationCode string) (bool, error) {
	if !strings.HasPrefix(pattern, "^") {
		pattern = "^" + pattern
	}
	if !strings.HasSuffix(pattern, "$") {
		pattern = pattern + "$"
	}
	return regexp.MatchString(pattern, invitationCode)
}

func GetE164Number(phone string, countryCode string) (string, bool) {
	phoneNumber, _ := phonenumbers.Parse(phone, countryCode)
	return phonenumbers.Format(phoneNumber, phonenumbers.E164), phonenumbers.IsValidNumber(phoneNumber)
}

func GetCountryCode(prefix string, phone string) (string, error) {
	if prefix == "" || phone == "" {
		return "", nil
	}

	phoneNumber, err := phonenumbers.Parse(fmt.Sprintf("+%s%s", prefix, phone), "")
	if err != nil {
		return "", err
	}

	countryCode := phonenumbers.GetRegionCodeForNumber(phoneNumber)
	if countryCode == "" {
		return "", fmt.Errorf("country code not found for phone prefix: %s", prefix)
	}

	return countryCode, nil
}

func FilterField(field string) bool {
	return ReFieldWhiteList.MatchString(field)
}

// FilterSQLIdentifier validates that field is a safe SQL column identifier.
// It allows letters, digits, and underscores (e.g. "id_card", "created_time"),
// and requires the name to start with a letter to block numeric/special-char attacks.
func FilterSQLIdentifier(field string) bool {
	return ReFieldWhiteListIdentifier.MatchString(field)
}

// IsValidOrigin used to grant an unconditional, application-agnostic pass to
// any origin/redirect_uri whose host (ignoring port) was "localhost",
// "127.0.0.1", "casdoor-authenticator", or suffixed with ".chromiumapp.org".
// That blanket pass was used both to grant credentialed CORS headers
// (routers/cors_filter.go, on every endpoint including the
// session-cookie-authenticated GET /api/get-account) and to skip the OAuth
// redirect_uri allow-list (object/application_util.go
// Application.IsRedirectUriValid), for every application in the instance --
// letting any local process on an arbitrary loopback port, or any
// *.chromiumapp.org browser extension, win a credentialed CORS grant and
// have the authorization server hand it an authorization code and full
// token set for a redirect_uri no application had actually registered.
//
// It is kept, still returning (bool, error), only so existing callers keep
// compiling and keep their url.Parse-error handling; it no longer grants any
// origin a special pass. A native/desktop or browser-extension client that
// needs a loopback or *.chromiumapp.org redirect URI must have that exact
// URI (or an explicit pattern for it) registered on the application's own
// RedirectUris, like any other client -- see
// Application.IsRedirectUriValid and Application.IsOriginValid, which match
// against RedirectUris directly.
func IsValidOrigin(origin string) (bool, error) {
	if _, err := url.Parse(origin); err != nil {
		return false, err
	}
	return false, nil
}

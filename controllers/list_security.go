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

import "fmt"

const invalidListParameterMessage = "Invalid list query parameter"

var sessionListFields = map[string]struct{}{
	"owner":       {},
	"name":        {},
	"application": {},
	"createdTime": {},
	"sessionId":   {},
}

var tokenListFields = map[string]struct{}{
	"owner":        {},
	"name":         {},
	"createdTime":  {},
	"application":  {},
	"organization": {},
	"user":         {},
	"expiresIn":    {},
	"scope":        {},
	"tokenType":    {},
	"grantType":    {},
	"codeIsUsed":   {},
	"codeExpireIn": {},
	"resource":     {},
	"dPoPJkt":      {},
}

func validateListQuery(field, value, sortField, sortOrder string, allowedFields map[string]struct{}) error {
	if field != "" && value != "" {
		if _, ok := allowedFields[field]; !ok {
			return fmt.Errorf("%s: field", invalidListParameterMessage)
		}
	}

	if sortField != "" {
		if _, ok := allowedFields[sortField]; !ok {
			return fmt.Errorf("%s: sortField", invalidListParameterMessage)
		}
	}

	if sortOrder != "" && sortOrder != "ascend" && sortOrder != "descend" {
		return fmt.Errorf("%s: sortOrder", invalidListParameterMessage)
	}

	return nil
}

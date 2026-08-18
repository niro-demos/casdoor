// Copyright 2026 The Casdoor Authors. All Rights Reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0

package controllers

import "github.com/casdoor/casdoor/util"

func canReadOrganization(sessionUserID, resourceOwner string, globalAdmin bool) (bool, error) {
	if globalAdmin {
		return true, nil
	}

	sessionOwner, _, err := util.GetOwnerAndNameFromIdWithError(sessionUserID)
	if err != nil {
		return false, err
	}

	return sessionOwner == resourceOwner, nil
}

func (c *ApiController) requireOrganizationRead(resourceOwner string) bool {
	allowed, err := canReadOrganization(c.GetSessionUsername(), resourceOwner, c.IsGlobalAdmin())
	if err != nil {
		c.ResponseError(err.Error())
		return false
	}
	if !allowed {
		c.ResponseError("Forbidden")
		return false
	}
	return true
}

func readableRecordOrganization(authenticatedOrganization, requestedOrganization string, globalAdmin bool) string {
	if globalAdmin {
		return requestedOrganization
	}
	return authenticatedOrganization
}

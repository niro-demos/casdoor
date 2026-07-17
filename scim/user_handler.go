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

package scim

import (
	"fmt"
	"net/http"

	"github.com/casdoor/casdoor/object"
	"github.com/elimity-com/scim"
	"github.com/elimity-com/scim/errors"
)

type UserResourceHandler struct{}

// https://github.com/elimity-com/scim/blob/master/resource_handler_test.go Example in-memory resource handler
// https://datatracker.ietf.org/doc/html/rfc7644#section-3.4 How to query/update resources

func (h UserResourceHandler) Create(r *http.Request, attrs scim.ResourceAttributes) (scim.Resource, error) {
	resource := &scim.Resource{Attributes: attrs}
	err := AddScimUser(r, resource)
	return *resource, err
}

func (h UserResourceHandler) Get(r *http.Request, id string) (scim.Resource, error) {
	user, err := object.GetUserByUserIdOnly(id)
	if err != nil {
		return scim.Resource{}, err
	}
	if user == nil || !callerScope(r).canAccess(user.Owner) {
		// A caller confined to one organization gets the same "not found"
		// response for a foreign-org resource as for one that truly doesn't
		// exist, so the boundary can't be probed for existence either.
		return scim.Resource{}, errors.ScimErrorResourceNotFound(id)
	}
	return *user2resource(user), nil
}

func (h UserResourceHandler) Delete(r *http.Request, id string) error {
	user, err := object.GetUserByUserIdOnly(id)
	if err != nil {
		return err
	}
	if user == nil || !callerScope(r).canAccess(user.Owner) {
		return errors.ScimErrorResourceNotFound(id)
	}
	_, err = object.DeleteUser(user)
	return err
}

func (h UserResourceHandler) GetAll(r *http.Request, params scim.ListRequestParams) (scim.Page, error) {
	sc := callerScope(r)
	// "" means unfiltered (every organization) to the object package's
	// pagination helpers -- exactly the semantics of a global admin.
	owner := ""
	if !sc.isGlobalAdmin {
		owner = sc.owner
	}

	if params.Count == 0 {
		var count int64
		var err error
		if sc.isGlobalAdmin {
			count, err = object.GetGlobalUserCount("", "")
		} else {
			count, err = object.GetUserCount(owner, "", "", "")
		}
		if err != nil {
			return scim.Page{}, err
		}
		return scim.Page{TotalResults: int(count)}, nil
	}

	resources := make([]scim.Resource, 0)
	// startIndex is 1-based index
	var users []*object.User
	var err error
	if sc.isGlobalAdmin {
		users, err = object.GetPaginationGlobalUsers(params.StartIndex-1, params.Count, "", "", "", "")
	} else {
		users, err = object.GetPaginationUsers(owner, params.StartIndex-1, params.Count, "", "", "", "", "")
	}
	if err != nil {
		return scim.Page{}, err
	}
	for _, user := range users {
		resources = append(resources, *user2resource(user))
	}
	return scim.Page{
		TotalResults: len(resources),
		Resources:    resources,
	}, nil
}

func (h UserResourceHandler) Patch(r *http.Request, id string, operations []scim.PatchOperation) (scim.Resource, error) {
	user, err := object.GetUserByUserIdOnly(id)
	if err != nil {
		return scim.Resource{}, err
	}
	if user == nil || !callerScope(r).canAccess(user.Owner) {
		return scim.Resource{}, errors.ScimErrorResourceNotFound(id)
	}
	return UpdateScimUserByPatchOperation(r, id, operations)
}

func (h UserResourceHandler) Replace(r *http.Request, id string, attrs scim.ResourceAttributes) (scim.Resource, error) {
	user, err := object.GetUserByUserIdOnly(id)
	if err != nil {
		return scim.Resource{}, err
	}
	if user == nil || !callerScope(r).canAccess(user.Owner) {
		return scim.Resource{}, errors.ScimErrorResourceNotFound(id)
	}
	resource := &scim.Resource{Attributes: attrs}
	err = UpdateScimUser(r, id, resource)
	return *resource, err
}

func AddScimUser(r *http.Request, res *scim.Resource) error {
	newUser, err := resource2user(res.Attributes)
	if err != nil {
		return err
	}

	// An org-scoped admin may only provision users into their OWN
	// organization: force Owner to the caller's org, ignoring a
	// client-supplied organization extension value that differs from it.
	// A global admin may create into any organization, as before.
	if sc := callerScope(r); !sc.isGlobalAdmin {
		newUser.Owner = sc.owner
	}

	// Check whether the user exists.
	oldUser, err := object.GetUser(newUser.GetId())
	if err != nil {
		return err
	}
	if oldUser != nil {
		return errors.ScimErrorUniqueness
	}

	affect, err := object.AddUser(newUser, "en")
	if err != nil {
		return err
	}
	if !affect {
		return fmt.Errorf("add new user failed")
	}

	res.Attributes = user2resource(newUser).Attributes
	res.ID = newUser.Id
	res.ExternalID = buildExternalId(newUser)
	res.Meta = buildMeta(newUser)
	return nil
}

func UpdateScimUser(r *http.Request, id string, res *scim.Resource) error {
	oldUser, err := object.GetUserByUserIdOnly(id)
	if err != nil {
		return err
	}
	if oldUser == nil {
		return errors.ScimErrorResourceNotFound(id)
	}
	newUser, err := resource2user(res.Attributes)
	if err != nil {
		return err
	}
	// An org-scoped admin cannot use a full Replace to move the user into a
	// different organization than the one they are confined to.
	if sc := callerScope(r); !sc.isGlobalAdmin {
		newUser.Owner = sc.owner
	}
	_, err = object.UpdateUser(oldUser.GetId(), newUser, nil, true)
	if err != nil {
		return err
	}

	res.ID = newUser.Id
	res.ExternalID = buildExternalId(newUser)
	res.Meta = buildMeta(newUser)
	return nil
}

// https://datatracker.ietf.org/doc/html/rfc7644#section-3.5.2 Modifying with PATCH
func UpdateScimUserByPatchOperation(r *http.Request, id string, ops []scim.PatchOperation) (res scim.Resource, err error) {
	user, err := object.GetUserByUserIdOnly(id)
	if err != nil {
		return scim.Resource{}, err
	}
	sc := callerScope(r)
	if user == nil || !sc.canAccess(user.Owner) {
		return scim.Resource{}, errors.ScimErrorResourceNotFound(id)
	}
	defer func() {
		if rec := recover(); rec != nil {
			err = fmt.Errorf("invalid patch op value: %v", rec)
		}
	}()
	old := user.GetId()
	for _, op := range ops {
		value := op.Value
		if op.Op == scim.PatchOperationRemove {
			value = nil
		}
		// PatchOperationAdd and PatchOperationReplace is same in Casdoor, just replace the value
		switch op.Path.String() {
		case "userName":
			user.Name = ToString(value, "")
		case "password":
			user.Password = ToString(value, "")
		case "externalId":
			user.ExternalId = ToString(value, "")
		case "displayName":
			user.DisplayName = ToString(value, "")
		case "profileUrl":
			user.Homepage = ToString(value, "")
		case "userType":
			user.Type = ToString(value, "")
		case "name.givenName":
			user.FirstName = ToString(value, "")
		case "name.familyName":
			user.LastName = ToString(value, "")
		case "name":
			defaultV := AnyMap{"givenName": "", "familyName": ""}
			v := ToAnyMap(value, defaultV) // e.g. {"givenName": "AA", "familyName": "BB"}
			user.FirstName = ToString(v["givenName"], user.FirstName)
			user.LastName = ToString(v["familyName"], user.LastName)
		case "emails":
			defaultV := AnyArray{AnyMap{"value": ""}}
			vs := ToAnyArray(value, defaultV) // e.g. [{"value": "test@casdoor"}]
			if len(vs) > 0 {
				v := ToAnyMap(vs[0])
				user.Email = ToString(v["value"], user.Email)
			}
		case "phoneNumbers":
			defaultV := AnyArray{AnyMap{"value": ""}}
			vs := ToAnyArray(value, defaultV) // e.g. [{"value": "18750004417"}]
			if len(vs) > 0 {
				v := ToAnyMap(vs[0])
				user.Phone = ToString(v["value"], user.Phone)
			}
		case "photos":
			defaultV := AnyArray{AnyMap{"value": ""}}
			vs := ToAnyArray(value, defaultV) // e.g. [{"value": "https://cdn.casbin.org/img/casbin.svg"}]
			if len(vs) > 0 {
				v := ToAnyMap(vs[0])
				user.Avatar = ToString(v["value"], user.Avatar)
			}
		case "addresses":
			defaultV := AnyArray{AnyMap{"locality": "", "region": "", "country": ""}}
			vs := ToAnyArray(value, defaultV) // e.g. [{"locality": "Hollywood", "region": "CN", "country": "USA"}]
			if len(vs) > 0 {
				v := ToAnyMap(vs[0])
				user.Location = ToString(v["locality"], user.Location)
				user.Region = ToString(v["region"], user.Region)
				user.CountryCode = ToString(v["country"], user.CountryCode)
			}
		case UserExtensionKey:
			defaultV := AnyMap{"organization": user.Owner}
			v := ToAnyMap(value, defaultV) // e.g. {"organization": "org1"}
			user.Owner = ToString(v["organization"], user.Owner)
		case fmt.Sprintf("%v.%v", UserExtensionKey, "organization"):
			user.Owner = ToString(value, user.Owner)
		}
	}
	// An org-scoped admin cannot use the enterprise-user "organization"
	// extension field to move a user out of the org they are confined to,
	// even one they were authorized to patch in the first place.
	if !sc.isGlobalAdmin {
		user.Owner = sc.owner
	}
	_, err = object.UpdateUser(old, user, nil, true)
	if err != nil {
		return scim.Resource{}, err
	}
	res = *user2resource(user)
	return res, nil
}

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

// resolveScimUserForCaller loads the user identified by id and enforces tenant
// isolation against the caller's organization carried on the request context.
//
// It returns a SCIM "resource not found" error when the user does not exist OR
// when the caller (an org-scoped admin) is not allowed to see the user's tenant,
// so a cross-tenant probe is indistinguishable from a missing resource. A
// global/built-in admin (empty caller owner) resolves any user. A request with
// no caller-owner context is denied rather than treated as global admin.
func resolveScimUserForCaller(r *http.Request, id string) (*object.User, error) {
	callerOwner, ok := callerOwnerFromRequest(r)
	if !ok {
		// No tenant context was established (HandleScim did not run). Fail
		// closed: never operate on the global user table without a caller org.
		return nil, errors.ScimErrorResourceNotFound(id)
	}

	user, err := object.GetUserByUserIdOnly(id)
	if err != nil {
		return nil, err
	}
	if user == nil || !callerCanAccessOwner(callerOwner, user.Owner) {
		return nil, errors.ScimErrorResourceNotFound(id)
	}
	return user, nil
}

func (h UserResourceHandler) Create(r *http.Request, attrs scim.ResourceAttributes) (scim.Resource, error) {
	resource := &scim.Resource{Attributes: attrs}
	err := AddScimUser(resource)
	return *resource, err
}

func (h UserResourceHandler) Get(r *http.Request, id string) (scim.Resource, error) {
	user, err := resolveScimUserForCaller(r, id)
	if err != nil {
		return scim.Resource{}, err
	}
	return *user2resource(user), nil
}

func (h UserResourceHandler) Delete(r *http.Request, id string) error {
	user, err := resolveScimUserForCaller(r, id)
	if err != nil {
		return err
	}
	_, err = object.DeleteUser(user)
	return err
}

func (h UserResourceHandler) GetAll(r *http.Request, params scim.ListRequestParams) (scim.Page, error) {
	callerOwner, ok := callerOwnerFromRequest(r)
	if !ok {
		// No tenant context: return nothing rather than the whole global table.
		return scim.Page{}, nil
	}

	// An empty callerOwner (global/built-in admin) means "all tenants"; the
	// owner-scoped object queries below apply the owner filter only when it is
	// non-empty, so an org-scoped admin sees exactly its own organization.
	if params.Count == 0 {
		count, err := object.GetUserCount(callerOwner, "", "", "")
		if err != nil {
			return scim.Page{}, err
		}
		return scim.Page{TotalResults: int(count)}, nil
	}

	resources := make([]scim.Resource, 0)
	// startIndex is 1-based index
	users, err := object.GetPaginationUsers(callerOwner, params.StartIndex-1, params.Count, "", "", "", "", "")
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
	if _, err := resolveScimUserForCaller(r, id); err != nil {
		return scim.Resource{}, err
	}
	return UpdateScimUserByPatchOperation(id, operations)
}

func (h UserResourceHandler) Replace(r *http.Request, id string, attrs scim.ResourceAttributes) (scim.Resource, error) {
	if _, err := resolveScimUserForCaller(r, id); err != nil {
		return scim.Resource{}, err
	}
	resource := &scim.Resource{Attributes: attrs}
	err := UpdateScimUser(id, resource)
	return *resource, err
}

func AddScimUser(r *scim.Resource) error {
	newUser, err := resource2user(r.Attributes)
	if err != nil {
		return err
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

	r.Attributes = user2resource(newUser).Attributes
	r.ID = newUser.Id
	r.ExternalID = buildExternalId(newUser)
	r.Meta = buildMeta(newUser)
	return nil
}

func UpdateScimUser(id string, r *scim.Resource) error {
	oldUser, err := object.GetUserByUserIdOnly(id)
	if err != nil {
		return err
	}
	if oldUser == nil {
		return errors.ScimErrorResourceNotFound(id)
	}
	newUser, err := resource2user(r.Attributes)
	if err != nil {
		return err
	}
	_, err = object.UpdateUser(oldUser.GetId(), newUser, nil, true)
	if err != nil {
		return err
	}

	r.ID = newUser.Id
	r.ExternalID = buildExternalId(newUser)
	r.Meta = buildMeta(newUser)
	return nil
}

// https://datatracker.ietf.org/doc/html/rfc7644#section-3.5.2 Modifying with PATCH
func UpdateScimUserByPatchOperation(id string, ops []scim.PatchOperation) (r scim.Resource, err error) {
	user, err := object.GetUserByUserIdOnly(id)
	if err != nil {
		return scim.Resource{}, err
	}
	if user == nil {
		return scim.Resource{}, errors.ScimErrorResourceNotFound(id)
	}
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("invalid patch op value: %v", r)
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
	_, err = object.UpdateUser(old, user, nil, true)
	if err != nil {
		return scim.Resource{}, err
	}
	r = *user2resource(user)
	return r, nil
}

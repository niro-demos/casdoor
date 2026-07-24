package scim

import (
	"context"
	"net/http"

	"github.com/casdoor/casdoor/object"
	"github.com/elimity-com/scim/errors"
)

const requesterOrganizationContextKey = "casdoorScimRequesterOrganization"

func WithRequesterOrganization(r *http.Request, organization string) *http.Request {
	return r.WithContext(context.WithValue(r.Context(), requesterOrganizationContextKey, organization))
}

func requesterOrganization(r *http.Request) string {
	if r == nil {
		return ""
	}
	organization, _ := r.Context().Value(requesterOrganizationContextKey).(string)
	return organization
}

func scimForbidden() errors.ScimError {
	return errors.ScimError{
		Detail: "The authenticated administrator cannot access this SCIM resource.",
		Status: http.StatusForbidden,
	}
}

func requireUserOwner(r *http.Request, user *object.User) error {
	organization := requesterOrganization(r)
	if organization == "" || user == nil || user.Owner == organization {
		return nil
	}
	return scimForbidden()
}

func requireGroupOwner(r *http.Request, group *object.Group) error {
	organization := requesterOrganization(r)
	if organization == "" || group == nil || group.Owner == organization {
		return nil
	}
	return scimForbidden()
}

func requireRequestedOwner(r *http.Request, owner string) error {
	organization := requesterOrganization(r)
	if organization == "" || owner == organization {
		return nil
	}
	return scimForbidden()
}

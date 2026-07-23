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
	"encoding/json"

	"github.com/beego/beego/v2/core/utils/pagination"
	"github.com/casdoor/casdoor/object"
	"github.com/casdoor/casdoor/util"
)

// recordFieldsFromSession contains the trusted attribution/outcome fields for a
// record. They are always derived server-side (from the authenticated session
// and the real request transport), never from the client-supplied request body.
type recordFieldsFromSession struct {
	Owner        string
	Name         string
	Organization string
	User         string
	ClientIp     string
}

// GetRecords
// @Title GetRecords
// @Tag Record API
// @Description get all records
// @Param   pageSize     query    string  true        "The size of each page"
// @Param   p     query    string  true        "The number of the page"
// @Success 200 {object} object.Record The Response object
// @router /get-records [get]
func (c *ApiController) GetRecords() {
	organization, ok := c.RequireAdmin()
	if !ok {
		return
	}

	limit := c.Ctx.Input.Query("pageSize")
	page := c.Ctx.Input.Query("p")
	field := c.Ctx.Input.Query("field")
	value := c.Ctx.Input.Query("value")
	sortField := c.Ctx.Input.Query("sortField")
	sortOrder := c.Ctx.Input.Query("sortOrder")
	organizationName := c.Ctx.Input.Query("organizationName")

	if limit == "" || page == "" {
		records, err := object.GetRecords()
		if err != nil {
			c.ResponseError(err.Error())
			return
		}

		c.ResponseOk(records)
	} else {
		limit := util.ParseInt(limit)
		if c.IsGlobalAdmin() && organizationName != "" {
			organization = organizationName
		}
		filterRecord := &object.Record{Organization: organization}
		count, err := object.GetRecordCount(field, value, filterRecord)
		if err != nil {
			c.ResponseError(err.Error())
			return
		}

		paginator := pagination.NewPaginator(c.Ctx.Request, limit, count)
		records, err := object.GetPaginationRecords(paginator.Offset(), limit, field, value, sortField, sortOrder, filterRecord)
		if err != nil {
			c.ResponseError(err.Error())
			return
		}

		c.ResponseOk(records, paginator.Nums())
	}
}

// GetRecordsByFilter
// @Tag Record API
// @Title GetRecordsByFilter
// @Description get records by filter
// @Param   filter  body string     true  "filter Record message"
// @Success 200 {object} object.Record The Response object
// @router /get-records-filter [post]
func (c *ApiController) GetRecordsByFilter() {
	_, ok := c.RequireAdmin()
	if !ok {
		return
	}

	body := string(c.Ctx.Input.RequestBody)

	record := &object.Record{}
	err := util.JsonToStruct(body, record)
	if err != nil {
		c.ResponseError(err.Error())
		return
	}

	records, err := object.GetRecordsByField(record)
	if err != nil {
		c.ResponseError(err.Error())
		return
	}

	c.ResponseOk(records)
}

// AddRecord
// @Title AddRecord
// @Tag Record API
// @Description add a record
// @Param   body    body   object.Record  true        "The details of the record"
// @Success 200 {object} controllers.Response The Response object
// @router /add-record [post]
func (c *ApiController) AddRecord() {
	// The public /api/add-record endpoint must not be usable to fabricate audit
	// entries. Require an authenticated session and derive every attribution/
	// outcome field server-side, so a caller can only ever create a record
	// attributed to its own real identity and network origin.
	userId, ok := c.RequireSignedIn()
	if !ok {
		return
	}

	var record object.Record
	err := json.Unmarshal(c.Ctx.Input.RequestBody, &record)
	if err != nil {
		c.ResponseError(err.Error())
		return
	}

	sanitizeRecordForAdd(&record, userId, util.GetClientIpFromRequest(c.Ctx.Request))

	c.Data["json"] = wrapActionResponse(object.AddRecord(&record))
	c.ServeJSON()
}

// sanitizeRecordForAdd overwrites the record's trusted attribution/outcome
// fields from the authenticated session and real request transport, discarding
// whatever the client supplied for them. This is what prevents a non-admin
// caller from forging an audit entry attributed to another principal. It never
// trusts the request body for owner/name/organization/user/clientIp, and clears
// client-supplied statusCode/response so a caller cannot stamp a fabricated
// outcome. Non-attribution content the caller may legitimately describe (action,
// detail, requestUri, object) is left untouched.
func sanitizeRecordForAdd(record *object.Record, sessionUserId, clientIp string) {
	fields := deriveRecordFieldsFromSession(sessionUserId, clientIp)

	record.Owner = fields.Owner
	record.Name = fields.Name
	record.Organization = fields.Organization
	record.User = fields.User
	record.ClientIp = fields.ClientIp

	// The outcome of a real action is recorded server-side by the router
	// middleware; a client-submitted record must not carry a self-asserted
	// status/response, which is the core of the forgery (a fake "200 ok").
	record.StatusCode = 0
	record.Response = ""
}

// deriveRecordFieldsFromSession maps the authenticated session id
// ("<org>/<user>") and the real transport IP to the trusted record fields. If
// the session id is not a well-formed "<org>/<user>" pair, owner/name/org are
// left empty rather than trusting any client value.
func deriveRecordFieldsFromSession(sessionUserId, clientIp string) recordFieldsFromSession {
	fields := recordFieldsFromSession{
		User:     sessionUserId,
		ClientIp: clientIp,
	}

	owner, name, err := util.GetOwnerAndNameFromIdWithError(sessionUserId)
	if err == nil {
		fields.Owner = owner
		fields.Name = name
		fields.Organization = owner
	}

	return fields
}

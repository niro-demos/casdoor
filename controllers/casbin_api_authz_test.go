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

import (
	"encoding/json"
	"net/http/httptest"
	"testing"

	beecontext "github.com/beego/beego/v2/server/web/context"
)

// Security invariant (TC-2459EA3F):
//
//	The Casbin enumeration endpoints /api/get-all-objects, /api/get-all-actions
//	and /api/get-all-roles must NOT return another user's authorization
//	configuration to a caller who is neither that user nor an admin. In
//	particular this data must not be readable by an *unauthenticated* caller who
//	merely names a victim's userId in the query string.
//
// These handlers read `userId` straight from the query string. The outer casbin
// policy layer wildcards the subject (`p, *, *, GET, /api/get-all-roles, *, *`),
// so the ONLY place an ownership check can live is the controller. This test
// pins that check in place.
//
// The test is hermetic: it drives the real handlers with a synthetic Beego
// context and injects the caller's session identity via the `currentUserId`
// context datum that ApiFilter populates in production (the same path
// GetSessionUsername reads first). It never touches a database or a live target.
//
//   - An *unauthenticated* caller who names a victim's userId reaches the
//     ownership guard with no session. The guard must reject the request BEFORE
//     any data-access call, producing a `status:"error"` response and never
//     touching the DB.
//   - A caller reading their OWN userId (positive control) must pass the guard
//     and proceed to the data-access layer. Because this hermetic test has no
//     DB, "reached the data layer" surfaces as a panic on the nil ORM engine,
//     which we recover and treat as "guard allowed the request through". This
//     control proves the RED below is the authorization guard firing, not a
//     blanket denial or a broken setup.

type authzOutcome struct {
	// deniedByGuard is true when the handler returned an error response WITHOUT
	// reaching the data-access layer (the ownership guard rejected the caller).
	deniedByGuard bool
	// reachedDataLayer is true when the handler passed the guard and attempted a
	// real data lookup (observed as a panic on the nil ORM engine in this
	// DB-less test).
	reachedDataLayer bool
	status           string
}

// driveHandler invokes one enumeration handler as `sessionUser` (empty == an
// unauthenticated caller, exactly as ApiFilter records it) requesting the authz
// config of `targetUserId`, and reports whether the ownership guard denied it.
func driveHandler(handler func(*ApiController), sessionUser, targetUserId string) authzOutcome {
	rec := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/api/enumerate?userId="+targetUserId, nil)
	ctx := beecontext.NewContext()
	ctx.Reset(rec, req)

	c := &ApiController{}
	c.Ctx = ctx
	c.Data = map[interface{}]interface{}{}
	// ApiFilter stores the resolved caller identity here for every request;
	// "" models an anonymous (unauthenticated) caller.
	ctx.Input.SetData("currentUserId", sessionUser)

	out := authzOutcome{}
	func() {
		defer func() {
			if r := recover(); r != nil {
				// The handler passed the ownership guard and reached the
				// DB-backed object.GetAll* / GetUser call, which panics on the
				// nil ORM engine in this hermetic test.
				out.reachedDataLayer = true
			}
		}()
		handler(c)
	}()

	if !out.reachedDataLayer {
		var resp struct {
			Status string `json:"status"`
		}
		_ = json.Unmarshal(rec.Body.Bytes(), &resp)
		out.status = resp.Status
		out.deniedByGuard = resp.Status == "error"
	}
	return out
}

func TestCasbinEnumerationEndpointsEnforceOwnership(t *testing.T) {
	const (
		victim     = "acme/alice"   // victim tenant's user
		selfCaller = "acme/alice"   // legitimate: reading one's OWN config
		anonymous  = ""             // no session at all
	)

	endpoints := []struct {
		name    string
		handler func(*ApiController)
	}{
		{"GetAllObjects", (*ApiController).GetAllObjects},
		{"GetAllActions", (*ApiController).GetAllActions},
		{"GetAllRoles", (*ApiController).GetAllRoles},
	}

	for _, ep := range endpoints {
		ep := ep
		t.Run(ep.name, func(t *testing.T) {
			// Positive control: a caller reading their OWN authz config must pass
			// the ownership guard (and only then hit the data layer). If this
			// fails, the environment is unhealthy and the RED below would be
			// meaningless.
			self := driveHandler(ep.handler, selfCaller, selfCaller)
			if self.deniedByGuard {
				t.Fatalf("%s: positive control failed — a caller reading their OWN userId (%s) was denied by the ownership guard (status=%q); setup is broken, RED would be meaningless",
					ep.name, selfCaller, self.status)
			}
			if !self.reachedDataLayer {
				t.Fatalf("%s: positive control failed — self-request neither reached the data layer nor was denied; unexpected outcome", ep.name)
			}

			// Invariant: an UNAUTHENTICATED caller that names the victim's userId
			// must be denied by the ownership guard, without any data access.
			anon := driveHandler(ep.handler, anonymous, victim)
			if anon.reachedDataLayer {
				t.Errorf("%s: INVARIANT VIOLATED — an unauthenticated caller enumerated %s's authorization config (request reached the data-access layer instead of being rejected). Anonymous, cross-tenant enumeration is possible.",
					ep.name, victim)
			}
			if !anon.deniedByGuard {
				t.Errorf("%s: INVARIANT VIOLATED — an unauthenticated caller naming userId=%s was not rejected by the ownership guard (status=%q, want \"error\").",
					ep.name, victim, anon.status)
			}
		})
	}
}

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
	"net/http/httptest"
	"strings"
	"testing"

	beecontext "github.com/beego/beego/v2/server/web/context"
)

// Security regression test for the "unauthenticated file upload via explicit
// `provider` query param" issue.
//
// Invariant under test:
//
//	Every path through (*ApiController).GetProviderFromContext must require a
//	signed-in session. An anonymous caller must be rejected with
//	"Please login first" on ALL branches — including when they supply an explicit
//	`provider` query param (or `field=provider&value=...`, or a
//	`fullFilePath`-derived `Direct` provider). The auth check must happen BEFORE
//	any provider / database lookup, exactly like the empty-`provider` fallback
//	path already does.
//
// Before the fix, GetProviderFromContext returned the provider on the explicit-
// `provider` branch without ever calling RequireSignedIn(), so an anonymous
// caller reached the storage-write path in UploadResource (and the storage
// lookups in GetResource/DeleteResource). This test drives GetProviderFromContext
// directly, at the controller layer, with no DB behind it: with the auth gate in
// the wrong place the anonymous+provider request tries to resolve the provider
// (touching the DB / the nil ormer), instead of stopping at the login gate.

// newTestController builds an *ApiController whose request carries the given raw
// query string and whose session identity is set in the exact slot ApiFilter
// uses in production: the Ctx.Input data key "currentUserId". GetSessionUsername()
// reads that slot first, so this resolves the caller's identity without needing a
// real session store.
//
//   - signedInUser == ""  -> anonymous  (GetSessionUsername() returns "")
//   - signedInUser != ""  -> signed in as that user id
//
// We always SetData("currentUserId", ...) (even to "") so GetSessionUsername()
// short-circuits on that slot and never falls through to the session store,
// which is intentionally not wired in this unit test.
func newTestController(t *testing.T, rawQuery string, signedInUser string) *ApiController {
	t.Helper()

	req := httptest.NewRequest("POST", "/api/upload-resource?"+rawQuery, nil)
	rec := httptest.NewRecorder()

	ctx := beecontext.NewContext()
	ctx.Reset(rec, req)

	ctx.Input.SetData("currentUserId", signedInUser)

	c := &ApiController{}
	c.Ctx = ctx
	// Data map is used by ResponseError/ServeJSON when RequireSignedIn rejects.
	c.Data = map[interface{}]interface{}{}
	return c
}

// callProviderCtx invokes GetProviderFromContext and reports whether it stopped
// at the login gate. It recovers any panic: reaching the provider/DB lookup with
// no database wired panics on the nil ormer, and that panic is itself proof the
// call proceeded PAST authentication — i.e. the invariant was violated, so we
// report reachedLoginGate=false in that case.
func callProviderCtx(t *testing.T, c *ApiController) (reachedLoginGate bool, detail string) {
	t.Helper()

	defer func() {
		if r := recover(); r != nil {
			// A panic means execution reached the provider/DB lookup instead of
			// being stopped at the login gate. That is exactly the bypass.
			reachedLoginGate = false
			detail = "panic (reached provider/DB lookup past auth): " + strings.TrimSpace(toStr(r))
		}
	}()

	_, err := c.GetProviderFromContext("Storage")
	if err != nil && strings.Contains(err.Error(), "Please login first") {
		return true, "rejected with \"Please login first\""
	}
	if err != nil {
		return false, "proceeded past auth, returned non-login error: " + err.Error()
	}
	return false, "proceeded past auth, returned a provider with no error"
}

func toStr(v interface{}) string {
	if s, ok := v.(string); ok {
		return s
	}
	if e, ok := v.(error); ok {
		return e.Error()
	}
	return "non-string panic value"
}

// TestGetProviderFromContext_RequiresSignInOnAllBranches asserts the security
// invariant: an anonymous caller is rejected with "Please login first" on every
// branch of GetProviderFromContext, while a signed-in caller is NOT stopped at
// the login gate (proving the fix does not over-block legitimate callers).
func TestGetProviderFromContext_RequiresSignInOnAllBranches(t *testing.T) {
	anonBranches := []struct {
		name  string
		query string
	}{
		{
			// Positive control / baseline: no provider hint at all. This path
			// already required sign-in before the fix; it proves the test
			// harness is healthy and the login gate works.
			name:  "baseline_no_provider",
			query: "owner=acme&user=alice&application=app-acme&fullFilePath=/tc/baseline.txt",
		},
		{
			// The exploit: an explicit `provider` name. Before the fix this
			// branch returned the provider with NO auth check.
			name:  "explicit_provider_param",
			query: "owner=acme&user=alice&application=app-acme&provider=some-storage&fullFilePath=/tc/exploit.txt",
		},
		{
			// Same bypass via field=provider&value=...
			name:  "field_provider_value",
			query: "owner=acme&user=alice&application=app-acme&field=provider&value=some-storage&fullFilePath=/tc/exploit.txt",
		},
		{
			// Same bypass via a `Direct`-prefixed fullFilePath.
			name:  "direct_fullfilepath",
			query: "owner=acme&user=alice&application=app-acme&fullFilePath=Direct/some-storage/tc/exploit.txt",
		},
	}

	for _, tc := range anonBranches {
		t.Run("anonymous/"+tc.name, func(t *testing.T) {
			c := newTestController(t, tc.query, "" /* anonymous */)
			reachedLoginGate, detail := callProviderCtx(t, c)
			if !reachedLoginGate {
				t.Fatalf("INVARIANT VIOLATED: anonymous request (%s) was NOT stopped at "+
					"the login gate: %s. An unauthenticated caller reached logic behind "+
					"authentication (the storage lookup used by upload/delete resource).",
					tc.query, detail)
			}
		})
	}

	// Negative control: a signed-in caller supplying an explicit provider must
	// NOT be rejected with "Please login first" — the auth gate lets them
	// through (and then fails later at the DB lookup, which is fine here: the
	// point is only that the login gate did not fire). This proves the fix
	// gates on the *session*, not on the presence of the provider param.
	t.Run("signed_in/explicit_provider_not_login_blocked", func(t *testing.T) {
		c := newTestController(t,
			"owner=acme&user=alice&application=app-acme&provider=some-storage&fullFilePath=/tc/legit.txt",
			"built-in/admin" /* signed in */)
		reachedLoginGate, detail := callProviderCtx(t, c)
		if reachedLoginGate {
			t.Fatalf("REGRESSION: a signed-in caller was wrongly rejected with "+
				"\"Please login first\": %s. The fix must gate on the session, not "+
				"block legitimate authenticated callers.", detail)
		}
	})
}

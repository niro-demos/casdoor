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

package controllers_test

// Regression test for: an organization-scoped administrator (Owner !=
// "built-in", IsAdmin == true) must NOT be able to trigger the server-wide
// Casbin CLI download/execute surface at GET /api/run-casbin-command or
// POST /api/refresh-engines - only a true global admin (Owner == "built-in")
// may, since both actions affect the whole server (installing binaries into
// the shared PATH, running them with attacker-suppliable args), not just the
// caller's own organization. See controllers/casbin_cli_api.go
// RunCasbinCommand() and controllers/cli_downloader.go RefreshEngines().
//
// This builds the real casdoor binary from the current checkout and runs it
// as a subprocess against a disposable, isolated sqlite database seeded from
// the fixture at controllers/testdata/casbin_cli_admin_scope_init_data.json
// (a minimal, version-controlled org/application/user set, loaded through
// the app's own object.InitFromFile mechanism) - self-contained, so this
// test does not depend on, or interfere with, any separately running
// instance. It exercises the exact startup path (main.go, routers.InitAPI,
// beego session middleware) that production traffic goes through, so the
// authorization check runs for real rather than being mocked.
//
// The RefreshEngines positive control (global admin) deliberately signs its
// request with an invalid hash, so the request is rejected at the existing
// "invalid identifier" replay-guard check *after* passing authorization,
// instead of proceeding into downloadCLI() - which would perform real
// network calls to GitHub and install binaries on the host running this
// test. That still proves the authorization gate let the global admin
// through (a different error than "Unauthorized operation"), without the
// destructive, non-hermetic side effect.

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"testing"
	"time"
)

type cliTestServer struct {
	baseURL string
	cmd     *exec.Cmd
	workDir string
}

// repoRoot returns the repository root, derived from this test file's own
// path (controllers/casbin_cli_admin_scope_test.go is one level below root).
func repoRoot(t *testing.T) string {
	t.Helper()
	_, thisFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("could not determine test file path via runtime.Caller")
	}
	return filepath.Dir(filepath.Dir(thisFile))
}

// freePort asks the OS for an ephemeral port and immediately releases it, so
// the test server instance doesn't collide with any other instance
// (including a separately running Niro harness) on the same host.
func freePort(t *testing.T) int {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("could not reserve a free port: %v", err)
	}
	defer l.Close()
	return l.Addr().(*net.TCPAddr).Port
}

// writeTestAppConf copies the real conf/app.conf and rewrites only its
// httpport line to an isolated, freshly reserved port, then writes the
// result to destPath. Passed to the test subprocess via -config so the real
// tracked conf/app.conf (and whatever port it names) is never touched and
// never at risk of being mistaken by main.go's util.StopOldInstance() for a
// stale copy of itself.
func writeTestAppConf(t *testing.T, root, destPath string, httpPort int) {
	t.Helper()
	src, err := os.ReadFile(filepath.Join(root, "conf", "app.conf"))
	if err != nil {
		t.Fatalf("could not read conf/app.conf: %v", err)
	}

	lines := strings.Split(string(src), "\n")
	replaced := false
	for i, line := range lines {
		if strings.HasPrefix(strings.TrimSpace(line), "httpport") {
			lines[i] = fmt.Sprintf("httpport = %d", httpPort)
			replaced = true
		}
	}
	if !replaced {
		lines = append(lines, fmt.Sprintf("httpport = %d", httpPort))
	}

	if err := os.WriteFile(destPath, []byte(strings.Join(lines, "\n")), 0o600); err != nil {
		t.Fatalf("could not write test app.conf: %v", err)
	}
}

func startCliTestServer(t *testing.T) *cliTestServer {
	t.Helper()
	root := repoRoot(t)

	workDir := t.TempDir()
	binPath := filepath.Join(workDir, "casdoor-test-server")

	build := exec.Command("go", "build", "-o", binPath, ".")
	build.Dir = root
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("failed to build casdoor for the integration test: %v\n%s", err, out)
	}

	httpPort := freePort(t)
	ldapPort := freePort(t)
	ldapsPort := freePort(t)
	radiusPort := freePort(t)
	baseURL := fmt.Sprintf("http://127.0.0.1:%d", httpPort)

	dbFile := filepath.Join(workDir, "casdoor.db")
	logFile := filepath.Join(workDir, "casdoor-server.log")
	logConfig := fmt.Sprintf(`{"adapter":"file","filename":%q,"maxdays":1,"perm":"0770"}`, logFile)
	// A minimal, version-controlled fixture (not the transient Niro harness
	// scaffolding, which is not guaranteed to exist in every checkout):
	// one non-built-in org ("acme"), its login application, an org-scoped
	// admin user (Owner="acme", IsAdmin=true) and a standard non-admin user.
	initDataFile := filepath.Join(root, "controllers", "testdata", "casbin_cli_admin_scope_init_data.json")

	// IMPORTANT: the actual HTTP listener in main.go reads its port via
	// `web.AppConfig.DefaultInt("httpport", 8000)`, which is populated by
	// `web.LoadAppConfig("ini", configPath)` from the ini file - an OS
	// environment variable named "httpport" does NOT reach that call (a
	// package-level init() in conf/conf.go sets it early, but InitFlag's
	// LoadAppConfig call replaces web.AppConfig from the ini file afterwards
	// and wipes it out). So the port MUST be supplied via a real config
	// file passed with -config, never via env alone - an env-only override
	// silently falls back to the real conf/app.conf's httpport (8000) and,
	// worse, main.go calls util.StopOldInstance(port) before binding, which
	// kills whatever process already owns that port. Getting this wrong
	// here would kill an unrelated, already-running instance on 8000.
	testConfPath := filepath.Join(workDir, "app.conf")
	writeTestAppConf(t, root, testConfPath, httpPort)

	cmd := exec.Command(binPath, "-config="+testConfPath)
	cmd.Dir = root
	cmd.Env = append(os.Environ(),
		"appname=casdoor",
		"runmode=dev",
		"driverName=sqlite",
		fmt.Sprintf("dataSourceName=file:%s?cache=shared", dbFile),
		"dbName=casdoor",
		fmt.Sprintf("initDataFile=%s", initDataFile),
		"initDataNewOnly=false",
		fmt.Sprintf("logConfig=%s", logConfig),
		fmt.Sprintf("origin=%s", baseURL),
		fmt.Sprintf("originFrontend=%s", baseURL),
		"RUNNING_IN_DOCKER=false",
		fmt.Sprintf("ldapServerPort=%d", ldapPort),
		fmt.Sprintf("ldapsServerPort=%d", ldapsPort),
		fmt.Sprintf("radiusServerPort=%d", radiusPort),
	)

	stdoutFile, err := os.Create(filepath.Join(workDir, "stdout.log"))
	if err != nil {
		t.Fatalf("could not create stdout log: %v", err)
	}
	cmd.Stdout = stdoutFile
	cmd.Stderr = stdoutFile

	if err := cmd.Start(); err != nil {
		t.Fatalf("failed to start casdoor test server: %v", err)
	}

	ts := &cliTestServer{baseURL: baseURL, cmd: cmd, workDir: workDir}

	if !ts.waitHealthy(90 * time.Second) {
		logData, _ := os.ReadFile(filepath.Join(workDir, "stdout.log"))
		ts.stop()
		t.Fatalf("casdoor test server did not become healthy in time; log:\n%s", logData)
	}

	return ts
}

func (ts *cliTestServer) waitHealthy(timeout time.Duration) bool {
	deadline := time.Now().Add(timeout)
	client := &http.Client{Timeout: 2 * time.Second}
	for time.Now().Before(deadline) {
		resp, err := client.Get(ts.baseURL + "/api/health")
		if err == nil {
			resp.Body.Close()
			if resp.StatusCode == http.StatusOK {
				return true
			}
		}
		time.Sleep(500 * time.Millisecond)
	}
	return false
}

func (ts *cliTestServer) stop() {
	if ts.cmd == nil || ts.cmd.Process == nil {
		return
	}
	_ = ts.cmd.Process.Kill()
	_, _ = ts.cmd.Process.Wait()
}

type cliLoginResp struct {
	Status string `json:"status"`
	Msg    string `json:"msg"`
}

func cliLogin(t *testing.T, baseURL, username, password, org, app string) *http.Client {
	t.Helper()
	jar, err := cookiejar.New(nil)
	if err != nil {
		t.Fatalf("cookiejar.New: %v", err)
	}
	client := &http.Client{Jar: jar, Timeout: 10 * time.Second}

	body := fmt.Sprintf(`{"username":%q,"password":%q,"organization":%q,"application":%q,"type":"login"}`,
		username, password, org, app)
	resp, err := client.Post(baseURL+"/api/login", "application/json", strings.NewReader(body))
	if err != nil {
		t.Fatalf("login request for %s failed: %v", username, err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	var lr cliLoginResp
	if err := json.Unmarshal(b, &lr); err != nil {
		t.Fatalf("login response for %s was not JSON: %s", username, b)
	}
	if lr.Status != "ok" {
		t.Fatalf("login as %s failed: %s (raw: %s)", username, lr.Msg, b)
	}
	return client
}

type cliApiResp struct {
	Status string          `json:"status"`
	Msg    string          `json:"msg"`
	Data   json.RawMessage `json:"data"`
}

// isUnauthorizedDenial reports whether a JSON API response is the standard
// "Unauthorized operation" denial envelope produced by
// `!conf.IsDemoMode() && !c.IsAdmin()` / `!conf.IsDemoMode() && !c.IsGlobalAdmin()`.
func isUnauthorizedDenial(t *testing.T, raw []byte) bool {
	t.Helper()
	var ar cliApiResp
	if err := json.Unmarshal(raw, &ar); err != nil {
		return false
	}
	return ar.Status == "error" && strings.Contains(strings.ToLower(ar.Msg), "unauthorized")
}

// runCasbinCommandHash mirrors controllers/casbin_cli_api.go
// validateIdentifier(): SHA-256 of "casbin-editor-v1|<t>|<sorted
// lang=..&args=.. params>" - no server secret, so any caller (including this
// test) can self-compute a valid m for any t within 5 minutes of "now".
func runCasbinCommandHash(language, argsJSON, t string) string {
	params := map[string]string{"language": language, "args": argsJSON}
	keys := make([]string, 0, len(params))
	for k := range params {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var parts []string
	for _, k := range keys {
		parts = append(parts, fmt.Sprintf("%s=%s", k, params[k]))
	}
	raw := fmt.Sprintf("casbin-editor-v1|%s|%s", t, strings.Join(parts, "&"))
	sum := sha256.Sum256([]byte(raw))
	return hex.EncodeToString(sum[:])
}

// TestOrgScopedAdminCannotTriggerCasbinCliEndpoints is the regression test
// for TC-2E29F14E: a user who is only an org-scoped admin (Owner="acme",
// IsAdmin=true) must be denied at GET /api/run-casbin-command and
// POST /api/refresh-engines, while a true global admin (Owner="built-in")
// must still pass the authorization gate - proving the failure is specific
// to the org-admin/global-admin distinction and not a broken test
// environment. A genuine non-admin (alice) must also still be denied.
func TestOrgScopedAdminCannotTriggerCasbinCliEndpoints(t *testing.T) {
	ts := startCliTestServer(t)
	defer ts.stop()

	// Seeded by controllers/testdata/casbin_cli_admin_scope_init_data.json:
	// acme-admin is an org-scoped admin of org "acme" (Owner="acme",
	// IsAdmin=true, NOT the built-in org). Disposable password for a
	// throwaway user in an ephemeral, single-test sqlite DB.
	orgAdminClient := cliLogin(t, ts.baseURL, "acme-admin", "OrgAdminRegressionTest-Pw1!", "acme", "app-acme")

	// A genuine non-admin in the same org - negative control confirming the
	// gate isn't simply open for everyone.
	standardClient := cliLogin(t, ts.baseURL, "alice", "StandardUserRegressionTest-Pw1!", "acme", "app-acme")

	// Casdoor's own first-boot bootstrap (object.InitDb) always creates the
	// built-in org's admin/123 account - the true global admin.
	globalAdminClient := cliLogin(t, ts.baseURL, "admin", "123", "built-in", "app-built-in")

	now := time.Now().UTC().Format(time.RFC3339)
	versionArgsJSON := `["--version"]`
	runCasbinQuery := url.Values{}
	runCasbinQuery.Set("language", "go")
	runCasbinQuery.Set("args", versionArgsJSON)
	runCasbinQuery.Set("t", now)
	runCasbinQuery.Set("m", runCasbinCommandHash("go", versionArgsJSON, now))
	runCasbinCommandURL := ts.baseURL + "/api/run-casbin-command?" + runCasbinQuery.Encode()

	t.Run("org admin denied run-casbin-command", func(t *testing.T) {
		resp, err := orgAdminClient.Get(runCasbinCommandURL)
		if err != nil {
			t.Fatalf("GET /api/run-casbin-command: %v", err)
		}
		defer resp.Body.Close()
		raw, _ := io.ReadAll(resp.Body)

		if !isUnauthorizedDenial(t, raw) {
			t.Fatalf("invariant violated: org-scoped admin (acme-admin) was not denied at "+
				"/api/run-casbin-command; expected the \"Unauthorized operation\" error envelope, got: %s", raw)
		}
	})

	t.Run("standard non-admin denied run-casbin-command", func(t *testing.T) {
		resp, err := standardClient.Get(runCasbinCommandURL)
		if err != nil {
			t.Fatalf("GET /api/run-casbin-command: %v", err)
		}
		defer resp.Body.Close()
		raw, _ := io.ReadAll(resp.Body)

		if !isUnauthorizedDenial(t, raw) {
			t.Fatalf("harness problem: standard non-admin (alice) was not denied at "+
				"/api/run-casbin-command; got: %s", raw)
		}
	})

	// Positive control: the true global admin must still pass the
	// authorization gate. It may still fail downstream (e.g. the
	// casbin-go-cli binary not being installed on the test host), which is
	// fine - we only assert it is NOT the "Unauthorized operation" denial,
	// proving the gate itself let the global admin through.
	t.Run("global admin passes authorization on run-casbin-command", func(t *testing.T) {
		resp, err := globalAdminClient.Get(runCasbinCommandURL)
		if err != nil {
			t.Fatalf("GET /api/run-casbin-command: %v", err)
		}
		defer resp.Body.Close()
		raw, _ := io.ReadAll(resp.Body)

		if isUnauthorizedDenial(t, raw) {
			t.Fatalf("harness problem: true global admin was unexpectedly denied "+
				"/api/run-casbin-command with \"Unauthorized operation\": %s", raw)
		}
	})

	// Both refresh-engines requests below deliberately sign with a WRONG
	// hash. RefreshEngines() checks authorization first and the replay-guard
	// hash second, and the hash check is unrelated to (and unchanged by) the
	// authorization fix under test - so a wrong hash never reaches
	// downloadCLI() regardless of authorization outcome, avoiding a real,
	// non-hermetic GitHub download/install into the host running this test,
	// while still exercising the exact `!c.IsAdmin()`/`!c.IsGlobalAdmin()`
	// line the finding is about: a denied caller gets "Unauthorized
	// operation" from the first check; an authorized caller instead reaches
	// the second check and gets "invalid identifier" - a different, later
	// error that proves authorization passed.
	refreshNow := time.Now().UTC().Format(time.RFC3339)
	badRefreshQuery := url.Values{}
	badRefreshQuery.Set("t", refreshNow)
	badRefreshQuery.Set("m", "0000000000000000000000000000000000000000000000000000000000000000")
	badRefreshURL := ts.baseURL + "/api/refresh-engines?" + badRefreshQuery.Encode()

	t.Run("org admin denied refresh-engines", func(t *testing.T) {
		resp, err := orgAdminClient.Post(badRefreshURL, "application/json", nil)
		if err != nil {
			t.Fatalf("POST /api/refresh-engines: %v", err)
		}
		defer resp.Body.Close()
		raw, _ := io.ReadAll(resp.Body)

		if !isUnauthorizedDenial(t, raw) {
			t.Fatalf("invariant violated: org-scoped admin (acme-admin) was not denied at "+
				"/api/refresh-engines; expected the \"Unauthorized operation\" error envelope, got: %s", raw)
		}
	})

	t.Run("global admin passes authorization on refresh-engines", func(t *testing.T) {
		resp, err := globalAdminClient.Post(badRefreshURL, "application/json", nil)
		if err != nil {
			t.Fatalf("POST /api/refresh-engines: %v", err)
		}
		defer resp.Body.Close()
		raw, _ := io.ReadAll(resp.Body)

		if isUnauthorizedDenial(t, raw) {
			t.Fatalf("harness problem: true global admin was unexpectedly denied "+
				"/api/refresh-engines with \"Unauthorized operation\": %s", raw)
		}

		var ar cliApiResp
		if err := json.Unmarshal(raw, &ar); err != nil {
			t.Fatalf("global admin response to /api/refresh-engines was not JSON: %s", raw)
		}
		if !(ar.Status == "error" && strings.Contains(strings.ToLower(ar.Msg), "invalid identifier")) {
			t.Fatalf("expected global admin to be rejected by the (unrelated, pre-existing) replay-guard "+
				"hash check with \"invalid identifier\" - proving authorization passed - got: %s", raw)
		}
	})
}

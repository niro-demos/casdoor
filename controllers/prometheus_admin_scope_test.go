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
// "built-in", IsAdmin == true) must NOT be able to read instance-wide
// Prometheus/system metrics via GET /api/get-prometheus-info or
// GET /api/metrics (no accessKey) — only a true global admin
// (Owner == "built-in") may. See controllers/util.go RequireGlobalAdmin()
// and controllers/prometheus.go.
//
// This builds the real casdoor binary from the current checkout and runs it
// as a subprocess against a disposable, isolated sqlite database seeded from
// the fixture at controllers/testdata/prometheus_admin_scope_init_data.json
// (a minimal, version-controlled org/application/user set, loaded through
// the app's own object.InitFromFile mechanism) — self-contained, so this
// test does not depend on, or interfere with, any separately running
// instance. It exercises the exact startup path (main.go, routers.InitAPI,
// beego session middleware) that production traffic goes through, so the
// authorization check runs for real rather than being mocked.

import (
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/cookiejar"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

type testServer struct {
	baseURL string
	cmd     *exec.Cmd
	workDir string
}

// repoRoot returns the repository root, derived from this test file's own
// path (controllers/prometheus_admin_scope_test.go is one level below root).
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

func startTestServer(t *testing.T) *testServer {
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
	// one non-built-in org ("acme"), its login application, and one
	// org-scoped admin user (Owner="acme", IsAdmin=true).
	initDataFile := filepath.Join(root, "controllers", "testdata", "prometheus_admin_scope_init_data.json")

	// IMPORTANT: the actual HTTP listener in main.go reads its port via
	// `web.AppConfig.DefaultInt("httpport", 8000)`, which is populated by
	// `web.LoadAppConfig("ini", configPath)` from the ini file — an OS
	// environment variable named "httpport" does NOT reach that call (a
	// package-level init() in conf/conf.go sets it early, but InitFlag's
	// LoadAppConfig call replaces web.AppConfig from the ini file afterwards
	// and wipes it out). So the port MUST be supplied via a real config
	// file passed with -config, never via env alone — an env-only override
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

	ts := &testServer{baseURL: baseURL, cmd: cmd, workDir: workDir}

	if !ts.waitHealthy(90 * time.Second) {
		logData, _ := os.ReadFile(filepath.Join(workDir, "stdout.log"))
		ts.stop()
		t.Fatalf("casdoor test server did not become healthy in time; log:\n%s", logData)
	}

	return ts
}

func (ts *testServer) waitHealthy(timeout time.Duration) bool {
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

func (ts *testServer) stop() {
	if ts.cmd == nil || ts.cmd.Process == nil {
		return
	}
	_ = ts.cmd.Process.Kill()
	_, _ = ts.cmd.Process.Wait()
}

type loginResp struct {
	Status string `json:"status"`
	Msg    string `json:"msg"`
}

func login(t *testing.T, baseURL, username, password, org, app string) *http.Client {
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
	var lr loginResp
	if err := json.Unmarshal(b, &lr); err != nil {
		t.Fatalf("login response for %s was not JSON: %s", username, b)
	}
	if lr.Status != "ok" {
		t.Fatalf("login as %s failed: %s (raw: %s)", username, lr.Msg, b)
	}
	return client
}

type apiResp struct {
	Status string          `json:"status"`
	Msg    string          `json:"msg"`
	Data   json.RawMessage `json:"data"`
}

// isAdminDenial reports whether a JSON API response is the standard
// "administrator required" denial envelope.
func isAdminDenial(t *testing.T, raw []byte) bool {
	t.Helper()
	var ar apiResp
	if err := json.Unmarshal(raw, &ar); err != nil {
		return false
	}
	return ar.Status == "error" && strings.Contains(strings.ToLower(ar.Msg), "administrator")
}

// TestOrgScopedAdminCannotReadInstanceWidePrometheusMetrics is the
// regression test for TC-3239B739: a user who is only an org-scoped admin
// (Owner="acme", IsAdmin=true) must be denied instance-wide Prometheus/
// system metrics at GET /api/get-prometheus-info and GET /api/metrics,
// while a true global admin (Owner="built-in") must still be allowed —
// proving the failure is specific to the org-admin/global-admin distinction
// and not a broken test environment.
func TestOrgScopedAdminCannotReadInstanceWidePrometheusMetrics(t *testing.T) {
	ts := startTestServer(t)
	defer ts.stop()

	// Seeded by controllers/testdata/prometheus_admin_scope_init_data.json:
	// acme-admin is an org-scoped admin of org "acme" (Owner="acme",
	// IsAdmin=true, NOT the built-in org). This is a disposable password for
	// a throwaway user created fresh in an ephemeral, single-test sqlite DB
	// — not a credential for any real environment.
	orgAdminClient := login(t, ts.baseURL, "acme-admin", "OrgAdminRegressionTest-Pw1!", "acme", "app-acme")

	// Casdoor's own first-boot bootstrap (object.InitDb) always creates the
	// built-in org's admin/123 account — the true global admin.
	globalAdminClient := login(t, ts.baseURL, "admin", "123", "built-in", "app-built-in")

	t.Run("org admin denied get-prometheus-info", func(t *testing.T) {
		resp, err := orgAdminClient.Get(ts.baseURL + "/api/get-prometheus-info")
		if err != nil {
			t.Fatalf("GET /api/get-prometheus-info: %v", err)
		}
		defer resp.Body.Close()
		raw, _ := io.ReadAll(resp.Body)

		if !isAdminDenial(t, raw) {
			t.Fatalf("invariant violated: org-scoped admin (acme-admin) was not denied at "+
				"/api/get-prometheus-info; expected the \"administrator\" error envelope, got: %s", raw)
		}
	})

	t.Run("org admin denied metrics", func(t *testing.T) {
		resp, err := orgAdminClient.Get(ts.baseURL + "/api/metrics")
		if err != nil {
			t.Fatalf("GET /api/metrics: %v", err)
		}
		defer resp.Body.Close()
		raw, _ := io.ReadAll(resp.Body)

		if strings.Contains(string(raw), "casdoor_api_latency") || strings.Contains(string(raw), "# HELP") {
			t.Fatalf("invariant violated: org-scoped admin (acme-admin) got the full instance-wide "+
				"Prometheus text exposition (%d lines) from /api/metrics with no accessKey; expected denial",
				strings.Count(string(raw), "\n"))
		}
		if !isAdminDenial(t, raw) {
			t.Fatalf("unexpected response to /api/metrics for org admin (neither a clean denial nor "+
				"Prometheus text): %s", raw)
		}
	})

	// Positive control: the true global admin must still be able to read
	// both endpoints. This proves the harness/environment is healthy and
	// that the denials above are specific to the org-admin/global-admin
	// distinction, not a broken setup.
	t.Run("global admin allowed get-prometheus-info", func(t *testing.T) {
		resp, err := globalAdminClient.Get(ts.baseURL + "/api/get-prometheus-info")
		if err != nil {
			t.Fatalf("GET /api/get-prometheus-info: %v", err)
		}
		defer resp.Body.Close()
		raw, _ := io.ReadAll(resp.Body)

		var ar apiResp
		if err := json.Unmarshal(raw, &ar); err != nil {
			t.Fatalf("global admin response was not JSON: %s", raw)
		}
		if ar.Status != "ok" || len(ar.Data) <= len("null") {
			t.Fatalf("harness problem: global admin was unexpectedly denied /api/get-prometheus-info: %s", raw)
		}
	})

	t.Run("global admin allowed metrics", func(t *testing.T) {
		resp, err := globalAdminClient.Get(ts.baseURL + "/api/metrics")
		if err != nil {
			t.Fatalf("GET /api/metrics: %v", err)
		}
		defer resp.Body.Close()
		raw, _ := io.ReadAll(resp.Body)

		if !strings.Contains(string(raw), "casdoor_api_latency") && !strings.Contains(string(raw), "# HELP") {
			t.Fatalf("harness problem: global admin was unexpectedly denied /api/metrics: %s", raw)
		}
	})
}

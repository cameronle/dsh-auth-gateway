package gateway

import (
	"crypto/sha256"
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func testConfig() Config {
	salt := []byte("0123456789abcdef")
	key := "test-management-key-with-enough-entropy"
	hash := deriveKey([]byte(key), salt)
	return Config{
		KeySalt:        base64.RawURLEncoding.EncodeToString(salt),
		KeyHash:        base64.RawURLEncoding.EncodeToString(hash),
		SessionTTL:     time.Hour,
		CookieName:     "dsh_gateway_session",
		PublicScheme:   "https",
		MaxFailures:    3,
		FailureWindow:  time.Minute,
		Lockout:        5 * time.Minute,
		TrustedProxyIP: "127.0.0.1",
	}
}

func TestVerifyAcceptsBearerAndRejectsWrongKey(t *testing.T) {
	g, err := New(testConfig())
	if err != nil {
		t.Fatal(err)
	}

	good := httptest.NewRequest(http.MethodGet, "http://auth/verify", nil)
	good.Header.Set("Authorization", "Bearer test-management-key-with-enough-entropy")
	good.RemoteAddr = "127.0.0.1:1234"
	goodRec := httptest.NewRecorder()
	g.Handler().ServeHTTP(goodRec, good)
	if goodRec.Code != http.StatusNoContent {
		t.Fatalf("good bearer: got %d", goodRec.Code)
	}

	bad := httptest.NewRequest(http.MethodGet, "http://auth/verify", nil)
	bad.Header.Set("Authorization", "Bearer wrong")
	bad.RemoteAddr = "127.0.0.1:1234"
	badRec := httptest.NewRecorder()
	g.Handler().ServeHTTP(badRec, bad)
	if badRec.Code != http.StatusUnauthorized {
		t.Fatalf("bad bearer: got %d", badRec.Code)
	}
}

func TestLoginIssuesHttpOnlyCookieAndVerifyAcceptsIt(t *testing.T) {
	g, err := New(testConfig())
	if err != nil {
		t.Fatal(err)
	}

	login := httptest.NewRequest(http.MethodPost, "http://auth/__dsh_auth/session", strings.NewReader(`{"key":"test-management-key-with-enough-entropy"}`))
	login.Header.Set("Content-Type", "application/json")
	login.Header.Set("Origin", "https://dsh.example.test")
	login.Host = "dsh.example.test"
	login.RemoteAddr = "127.0.0.1:1234"
	rec := httptest.NewRecorder()
	g.Handler().ServeHTTP(rec, login)
	if rec.Code != http.StatusNoContent {
		t.Fatalf("login got %d body=%s", rec.Code, rec.Body.String())
	}
	cookies := rec.Result().Cookies()
	if len(cookies) != 1 {
		t.Fatalf("cookies=%d", len(cookies))
	}
	cookie := cookies[0]
	if !cookie.HttpOnly || !cookie.Secure || cookie.SameSite != http.SameSiteStrictMode {
		t.Fatalf("unsafe cookie: %#v", cookie)
	}

	verify := httptest.NewRequest(http.MethodGet, "http://auth/verify", nil)
	verify.RemoteAddr = "127.0.0.1:1234"
	verify.AddCookie(cookie)
	verifyRec := httptest.NewRecorder()
	g.Handler().ServeHTTP(verifyRec, verify)
	if verifyRec.Code != http.StatusNoContent {
		t.Fatalf("cookie verify got %d", verifyRec.Code)
	}
}

func TestRejectsUnexpectedPublicHost(t *testing.T) {
	cfg := testConfig()
	cfg.ExpectedHost = "dsh.example.test"
	g, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}

	for _, path := range []string{"/__dsh_auth/login", "/__dsh_auth/session", "/verify", "/healthz"} {
		req := httptest.NewRequest(http.MethodGet, "http://auth"+path, nil)
		req.Host = "evil.example"
		req.RemoteAddr = "127.0.0.1:1234"
		rec := httptest.NewRecorder()
		g.Handler().ServeHTTP(rec, req)
		if rec.Code != http.StatusForbidden {
			t.Fatalf("%s got %d", path, rec.Code)
		}
	}
}

func TestAcceptsExpectedPublicHostWithDefaultHTTPSPort(t *testing.T) {
	cfg := testConfig()
	cfg.ExpectedHost = "dsh.example.test"
	g, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodGet, "http://auth/__dsh_auth/login", nil)
	req.Host = "dsh.example.test:443"
	req.RemoteAddr = "127.0.0.1:1234"
	rec := httptest.NewRecorder()
	g.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("got %d", rec.Code)
	}
}

func TestLoginRejectsCrossOrigin(t *testing.T) {
	g, err := New(testConfig())
	if err != nil {
		t.Fatal(err)
	}
	login := httptest.NewRequest(http.MethodPost, "http://auth/__dsh_auth/session", strings.NewReader(`{"key":"test-management-key-with-enough-entropy"}`))
	login.Header.Set("Content-Type", "application/json")
	login.Header.Set("Origin", "https://evil.example")
	login.Host = "dsh.example.test"
	login.RemoteAddr = "127.0.0.1:1234"
	rec := httptest.NewRecorder()
	g.Handler().ServeHTTP(rec, login)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("got %d", rec.Code)
	}
}

func TestLoginRejectsNonJSONContentType(t *testing.T) {
	g, err := New(testConfig())
	if err != nil {
		t.Fatal(err)
	}
	login := httptest.NewRequest(http.MethodPost, "http://auth/__dsh_auth/session", strings.NewReader(`{"key":"test-management-key-with-enough-entropy"}`))
	login.Header.Set("Content-Type", "text/plain")
	login.Header.Set("Origin", "https://dsh.example.test")
	login.Host = "dsh.example.test"
	login.RemoteAddr = "127.0.0.1:1234"
	rec := httptest.NewRecorder()
	g.Handler().ServeHTTP(rec, login)
	if rec.Code != http.StatusUnsupportedMediaType {
		t.Fatalf("got %d", rec.Code)
	}
}

func TestLoginRejectsUnknownFieldsAndTrailingJSONWithoutChargingFailures(t *testing.T) {
	for _, body := range []string{
		`{"key":"test-management-key-with-enough-entropy","extra":true}`,
		`{"key":"test-management-key-with-enough-entropy"} {"key":"second"}`,
		`{"Key":"test-management-key-with-enough-entropy"}`,
		`{"KEY":"test-management-key-with-enough-entropy"}`,
		`{"key":"first","key":"test-management-key-with-enough-entropy"}`,
		`[]`,
	} {
		t.Run(body, func(t *testing.T) {
			g, err := New(testConfig())
			if err != nil {
				t.Fatal(err)
			}
			login := httptest.NewRequest(http.MethodPost, "http://auth/__dsh_auth/session", strings.NewReader(body))
			login.Header.Set("Content-Type", "application/json; charset=utf-8")
			login.Header.Set("Origin", "https://dsh.example.test")
			login.Host = "dsh.example.test"
			login.RemoteAddr = "127.0.0.1:1234"
			rec := httptest.NewRecorder()
			g.Handler().ServeHTTP(rec, login)
			if rec.Code != http.StatusBadRequest {
				t.Fatalf("got %d", rec.Code)
			}
			if g.blocked("127.0.0.1") {
				t.Fatal("malformed JSON charged credential failure state")
			}
		})
	}
}

func TestLogoutRejectsCrossOriginWithoutDeletingSession(t *testing.T) {
	g, err := New(testConfig())
	if err != nil {
		t.Fatal(err)
	}
	cookie := loginCookie(t, g)
	logout := httptest.NewRequest(http.MethodPost, "http://auth/__dsh_auth/logout", nil)
	logout.Header.Set("Origin", "https://evil.example")
	logout.Host = "dsh.example.test"
	logout.RemoteAddr = "127.0.0.1:1234"
	logout.AddCookie(cookie)
	rec := httptest.NewRecorder()
	g.Handler().ServeHTTP(rec, logout)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("logout got %d", rec.Code)
	}
	verify := httptest.NewRequest(http.MethodGet, "http://auth/verify", nil)
	verify.RemoteAddr = "127.0.0.1:1234"
	verify.AddCookie(cookie)
	verifyRec := httptest.NewRecorder()
	g.Handler().ServeHTTP(verifyRec, verify)
	if verifyRec.Code != http.StatusNoContent {
		t.Fatalf("cross-origin logout deleted session: verify got %d", verifyRec.Code)
	}
}

func TestSameOriginNormalizesHTTPSDefaultPortAndRejectsUnsafeOrigins(t *testing.T) {
	for _, tc := range []struct {
		name, origin, host string
		want               bool
	}{
		{name: "implicit HTTPS port", origin: "https://DSH.EXAMPLE.TEST", host: "dsh.example.test:443", want: true},
		{name: "explicit HTTPS port", origin: "https://dsh.example.test:443", host: "dsh.example.test", want: true},
		{name: "wrong port", origin: "https://dsh.example.test:444", host: "dsh.example.test"},
		{name: "empty origin port", origin: "https://dsh.example.test:", host: "dsh.example.test"},
		{name: "empty request port", origin: "https://dsh.example.test", host: "dsh.example.test:"},
		{name: "userinfo", origin: "https://user@dsh.example.test", host: "dsh.example.test"},
		{name: "path", origin: "https://dsh.example.test/path", host: "dsh.example.test"},
		{name: "query", origin: "https://dsh.example.test?x=1", host: "dsh.example.test"},
		{name: "empty query marker", origin: "https://dsh.example.test?", host: "dsh.example.test"},
		{name: "empty fragment marker", origin: "https://dsh.example.test#", host: "dsh.example.test"},
		{name: "empty query and fragment markers", origin: "https://dsh.example.test?#", host: "dsh.example.test"},
		{name: "opaque null", origin: "null", host: "dsh.example.test"},
		{name: "non HTTPS", origin: "http://dsh.example.test", host: "dsh.example.test"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodPost, "http://auth/__dsh_auth/session", nil)
			req.Header.Set("Origin", tc.origin)
			req.Host = tc.host
			g, err := New(testConfig())
			if err != nil {
				t.Fatal(err)
			}
			defer g.Close()
			if got := g.sameOrigin(req); got != tc.want {
				t.Fatalf("sameOrigin=%v want %v", got, tc.want)
			}
		})
	}
}

func loginCookie(t *testing.T, g *Gateway) *http.Cookie {
	t.Helper()
	login := httptest.NewRequest(http.MethodPost, "http://auth/__dsh_auth/session", strings.NewReader(`{"key":"test-management-key-with-enough-entropy"}`))
	login.Header.Set("Content-Type", "application/json")
	login.Header.Set("Origin", "https://dsh.example.test")
	login.Host = "dsh.example.test"
	login.RemoteAddr = "127.0.0.1:1234"
	rec := httptest.NewRecorder()
	g.Handler().ServeHTTP(rec, login)
	if rec.Code != http.StatusNoContent {
		t.Fatalf("login got %d body=%s", rec.Code, rec.Body.String())
	}
	cookies := rec.Result().Cookies()
	if len(cookies) != 1 {
		t.Fatalf("cookies=%d", len(cookies))
	}
	return cookies[0]
}

func TestLockoutAfterFailures(t *testing.T) {
	cfg := testConfig()
	cfg.MaxFailures = 2
	g, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 2; i++ {
		req := httptest.NewRequest(http.MethodGet, "http://auth/verify", nil)
		req.Header.Set("Authorization", "Bearer wrong")
		req.RemoteAddr = "127.0.0.1:1234"
		rec := httptest.NewRecorder()
		g.Handler().ServeHTTP(rec, req)
	}
	good := httptest.NewRequest(http.MethodGet, "http://auth/verify", nil)
	good.Header.Set("Authorization", "Bearer test-management-key-with-enough-entropy")
	good.RemoteAddr = "127.0.0.1:1234"
	rec := httptest.NewRecorder()
	g.Handler().ServeHTTP(rec, good)
	if rec.Code != http.StatusNoContent {
		t.Fatalf("got %d", rec.Code)
	}
}

func TestClientIPDoesNotTrustCallerControlledForwardedHeaders(t *testing.T) {
	g, err := New(testConfig())
	if err != nil {
		t.Fatal(err)
	}

	req := httptest.NewRequest(http.MethodGet, "http://auth/verify", nil)
	req.RemoteAddr = "127.0.0.1:9999"
	req.Header.Set("CF-Connecting-IP", "203.0.113.8")
	if got := g.clientIP(req); got != "127.0.0.1" {
		t.Fatalf("got %s", got)
	}
}

func TestVerifyMissingCredentialsDoesNotWriteAuditNoise(t *testing.T) {
	var logs strings.Builder
	cfg := testConfig()
	cfg.AuditWriter = &logs
	g, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 3; i++ {
		req := httptest.NewRequest(http.MethodGet, "http://auth/verify", nil)
		req.RemoteAddr = "127.0.0.1:1234"
		rec := httptest.NewRecorder()
		g.Handler().ServeHTTP(rec, req)
		if rec.Code != http.StatusUnauthorized {
			t.Fatalf("got %d", rec.Code)
		}
	}
	if logs.Len() != 0 {
		t.Fatalf("ordinary missing credentials were audited: %s", logs.String())
	}
}

func TestAuditDoesNotContainCredential(t *testing.T) {
	var logs strings.Builder
	cfg := testConfig()
	cfg.AuditWriter = &logs
	g, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodGet, "http://auth/verify", nil)
	req.RemoteAddr = "127.0.0.1:1234"
	req.Header.Set("Authorization", "Bearer wrong-secret-value")
	rec := httptest.NewRecorder()
	g.Handler().ServeHTTP(rec, req)
	if strings.Contains(logs.String(), "wrong-secret-value") {
		t.Fatal("credential leaked to audit")
	}
}

func TestLoginPageFollowsSystemThemeAndHasAccessibleForm(t *testing.T) {
	g, err := New(testConfig())
	if err != nil {
		t.Fatal(err)
	}
	defer g.Close()

	// 1. Anonymous user accesses login page
	req := httptest.NewRequest(http.MethodGet, "http://auth/__dsh_auth/login", nil)
	req.RemoteAddr = "127.0.0.1:1234"
	rec := httptest.NewRecorder()
	g.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("got %d", rec.Code)
	}
	body := rec.Body.String()
	for _, want := range []string{
		`prefers-color-scheme:dark`,
		`name="color-scheme" content="light dark"`,
		`name="theme-color"`,
		`<label for="k">Management key</label>`,
		`aria-live="polite"`,
		`Signing in…`,
		`autofocus`,
		`Toggle password visibility`,
		`redirect`,
		`Network error`,
		`<body class="is-anon">`,
		`Continue to Harness`,
		`Sign out`,
	} {
		if !strings.Contains(body, want) {
			t.Fatalf("login page missing %q", want)
		}
	}

	// 2. Authenticated user accesses login page
	cookie := loginAndGetCookie(t, g)
	reqAuth := httptest.NewRequest(http.MethodGet, "http://auth/__dsh_auth/login", nil)
	reqAuth.RemoteAddr = "127.0.0.1:1234"
	reqAuth.AddCookie(cookie)
	recAuth := httptest.NewRecorder()
	g.Handler().ServeHTTP(recAuth, reqAuth)
	if recAuth.Code != http.StatusOK {
		t.Fatalf("authenticated login page got %d", recAuth.Code)
	}
	bodyAuth := recAuth.Body.String()
	if !strings.Contains(bodyAuth, `<body class="is-authed">`) {
		t.Fatalf("expected is-authed body class, got body=%s", bodyAuth)
	}
	if !strings.Contains(bodyAuth, `You are currently signed in.`) {
		t.Fatalf("expected signed-in message")
	}
}

func loginAndGetCookie(t *testing.T, g *Gateway) *http.Cookie {
	login := httptest.NewRequest(http.MethodPost, "http://auth/__dsh_auth/session", strings.NewReader(`{"key":"test-management-key-with-enough-entropy"}`))
	login.Header.Set("Content-Type", "application/json")
	login.Header.Set("Origin", "https://dsh.example.test")
	login.Host = "dsh.example.test"
	login.RemoteAddr = "127.0.0.1:1234"
	rec := httptest.NewRecorder()
	g.Handler().ServeHTTP(rec, login)
	if rec.Code != http.StatusNoContent {
		t.Fatalf("login failed: %d", rec.Code)
	}
	cookies := rec.Result().Cookies()
	if len(cookies) != 1 {
		t.Fatalf("expected 1 cookie, got %d", len(cookies))
	}
	return cookies[0]
}

func TestHashShape(t *testing.T) {
	salt := []byte("0123456789abcdef")
	h := deriveKey([]byte("x"), salt)
	if len(h) != sha256.Size {
		t.Fatalf("hash len=%d", len(h))
	}
}

func TestVerifyRedirectsBrowserRequestsToLogin(t *testing.T) {
	g, err := New(testConfig())
	if err != nil {
		t.Fatal(err)
	}
	defer g.Close()

	// 1. Browser root page visit -> redirect to /__dsh_auth/login
	req := httptest.NewRequest(http.MethodGet, "http://auth/verify", nil)
	req.RemoteAddr = "127.0.0.1:1234"
	req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8")
	rec := httptest.NewRecorder()
	g.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusFound {
		t.Fatalf("browser root got %d, want 302", rec.Code)
	}
	if loc := rec.Header().Get("Location"); loc != "/__dsh_auth/login" {
		t.Fatalf("browser root location = %q, want /__dsh_auth/login", loc)
	}

	// 2. Browser deep link visit with X-Forwarded-Uri -> redirect with target preserved
	reqDeep := httptest.NewRequest(http.MethodGet, "http://auth/verify", nil)
	reqDeep.RemoteAddr = "127.0.0.1:1234"
	reqDeep.Header.Set("Accept", "text/html,application/xhtml+xml")
	reqDeep.Header.Set("X-Forwarded-Uri", "/workspace/project-1?tab=chat#bottom")
	reqDeep.Header.Set("X-Forwarded-Method", "GET")
	recDeep := httptest.NewRecorder()
	g.Handler().ServeHTTP(recDeep, reqDeep)
	if recDeep.Code != http.StatusFound {
		t.Fatalf("deep link got %d, want 302", recDeep.Code)
	}
	wantLoc := "/__dsh_auth/login?redirect=%2Fworkspace%2Fproject-1%3Ftab%3Dchat%23bottom"
	if loc := recDeep.Header().Get("Location"); loc != wantLoc {
		t.Fatalf("deep link location = %q, want %q", loc, wantLoc)
	}

	// 3. Dangerous / malicious target URI -> sanitized to /__dsh_auth/login
	for _, evil := range []string{"//evil.com", "/\\evil.com", "https://evil.com", "/__dsh_auth/login"} {
		reqEvil := httptest.NewRequest(http.MethodGet, "http://auth/verify", nil)
		reqEvil.RemoteAddr = "127.0.0.1:1234"
		reqEvil.Header.Set("Accept", "text/html")
		reqEvil.Header.Set("X-Forwarded-Uri", evil)
		recEvil := httptest.NewRecorder()
		g.Handler().ServeHTTP(recEvil, reqEvil)
		if recEvil.Code != http.StatusFound {
			t.Fatalf("evil target %q got %d", evil, recEvil.Code)
		}
		if loc := recEvil.Header().Get("Location"); loc != "/__dsh_auth/login" {
			t.Fatalf("evil target %q location = %q, want /__dsh_auth/login", evil, loc)
		}
	}

	// 4. API / JSON requests -> returns 401, not 302
	reqAPI := httptest.NewRequest(http.MethodGet, "http://auth/verify", nil)
	reqAPI.RemoteAddr = "127.0.0.1:1234"
	reqAPI.Header.Set("Accept", "application/json")
	recAPI := httptest.NewRecorder()
	g.Handler().ServeHTTP(recAPI, reqAPI)
	if recAPI.Code != http.StatusUnauthorized {
		t.Fatalf("API request got %d, want 401", recAPI.Code)
	}

	// 5. POST request with Accept text/html -> returns 401, not 302
	reqPost := httptest.NewRequest(http.MethodPost, "http://auth/verify", nil)
	reqPost.RemoteAddr = "127.0.0.1:1234"
	reqPost.Header.Set("Accept", "text/html")
	recPost := httptest.NewRecorder()
	g.Handler().ServeHTTP(recPost, reqPost)
	if recPost.Code != http.StatusUnauthorized {
		t.Fatalf("POST request got %d, want 401", recPost.Code)
	}

	// 6. WebSocket upgrade with text/html -> returns 401
	reqWS := httptest.NewRequest(http.MethodGet, "http://auth/verify", nil)
	reqWS.RemoteAddr = "127.0.0.1:1234"
	reqWS.Header.Set("Accept", "text/html")
	reqWS.Header.Set("Upgrade", "websocket")
	recWS := httptest.NewRecorder()
	g.Handler().ServeHTTP(recWS, reqWS)
	if recWS.Code != http.StatusUnauthorized {
		t.Fatalf("WebSocket request got %d, want 401", recWS.Code)
	}

	// 7. Request with wrong Bearer token -> always returns 401 even if Accept is text/html
	reqBearer := httptest.NewRequest(http.MethodGet, "http://auth/verify", nil)
	reqBearer.RemoteAddr = "127.0.0.1:1234"
	reqBearer.Header.Set("Accept", "text/html")
	reqBearer.Header.Set("Authorization", "Bearer invalid-token")
	recBearer := httptest.NewRecorder()
	g.Handler().ServeHTTP(recBearer, reqBearer)
	if recBearer.Code != http.StatusUnauthorized {
		t.Fatalf("invalid Bearer got %d, want 401", recBearer.Code)
	}
}

func TestSessionSlidingExpiration(t *testing.T) {
	cfg := testConfig()
	cfg.SessionTTL = 2 * time.Hour
	g, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer g.Close()

	curTime := time.Date(2026, 8, 15, 12, 0, 0, 0, time.UTC)
	g.now = func() time.Time { return curTime }

	// 1. Initial Login
	login := httptest.NewRequest(http.MethodPost, "http://auth/__dsh_auth/session", strings.NewReader(`{"key":"test-management-key-with-enough-entropy"}`))
	login.Header.Set("Content-Type", "application/json")
	login.Header.Set("Origin", "https://dsh.example.test")
	login.Host = "dsh.example.test"
	login.RemoteAddr = "127.0.0.1:1234"
	rec := httptest.NewRecorder()
	g.Handler().ServeHTTP(rec, login)
	if rec.Code != http.StatusNoContent {
		t.Fatalf("login failed: %d", rec.Code)
	}
	cookies := rec.Result().Cookies()
	if len(cookies) != 1 {
		t.Fatalf("expected 1 cookie, got %d", len(cookies))
	}
	cookie := cookies[0]

	// 2. Advance 30 mins (remaining 1h30m > 1h half-window) -> valid, no extension needed
	curTime = curTime.Add(30 * time.Minute)
	req := httptest.NewRequest(http.MethodGet, "http://auth/verify", nil)
	req.RemoteAddr = "127.0.0.1:1234"
	req.AddCookie(cookie)
	rec = httptest.NewRecorder()
	g.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusNoContent {
		t.Fatalf("verify at +30m got %d, want 204", rec.Code)
	}

	// 3. Advance to +1h15m (remaining 45m < 1h half-window) -> valid, triggers sliding extension to curTime + 2h
	curTime = curTime.Add(45 * time.Minute) // now +1h15m from start (13:15)
	req = httptest.NewRequest(http.MethodGet, "http://auth/verify", nil)
	req.RemoteAddr = "127.0.0.1:1234"
	req.AddCookie(cookie)
	rec = httptest.NewRecorder()
	g.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusNoContent {
		t.Fatalf("verify at +1h15m got %d, want 204", rec.Code)
	}

	// 4. Advance to +2h30m from start (14:30).
	// Without sliding expiration, initial 2h TTL would have expired at 14:00.
	// With sliding expiration, new expiration is 13:15 + 2h = 15:15.
	curTime = curTime.Add(1 * time.Hour + 15 * time.Minute) // 14:30
	req = httptest.NewRequest(http.MethodGet, "http://auth/verify", nil)
	req.RemoteAddr = "127.0.0.1:1234"
	req.AddCookie(cookie)
	rec = httptest.NewRecorder()
	g.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusNoContent {
		t.Fatalf("verify at +2h30m (after original expiration) got %d, want 204", rec.Code)
	}

	// 5. Inactive for 3 hours (advance to 17:30) -> session expires
	curTime = curTime.Add(3 * time.Hour)
	req = httptest.NewRequest(http.MethodGet, "http://auth/verify", nil)
	req.RemoteAddr = "127.0.0.1:1234"
	req.AddCookie(cookie)
	rec = httptest.NewRecorder()
	g.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("verify after 3h inactivity got %d, want 401", rec.Code)
	}
}

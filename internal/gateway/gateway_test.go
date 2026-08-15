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
	} {
		if !strings.Contains(body, want) {
			t.Fatalf("login page missing %q", want)
		}
	}
}

func TestHashShape(t *testing.T) {
	salt := []byte("0123456789abcdef")
	h := deriveKey([]byte("x"), salt)
	if len(h) != sha256.Size {
		t.Fatalf("hash len=%d", len(h))
	}
}

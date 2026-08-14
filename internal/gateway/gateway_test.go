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
		SecureCookie:   true,
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
	if rec.Code != http.StatusTooManyRequests {
		t.Fatalf("got %d", rec.Code)
	}
}

func TestClientIPOnlyTrustsForwardedHeaderFromConfiguredProxy(t *testing.T) {
	g, err := New(testConfig())
	if err != nil {
		t.Fatal(err)
	}

	trusted := httptest.NewRequest(http.MethodGet, "http://auth/verify", nil)
	trusted.RemoteAddr = "127.0.0.1:9999"
	trusted.Header.Set("CF-Connecting-IP", "203.0.113.8")
	if got := g.clientIP(trusted); got != "203.0.113.8" {
		t.Fatalf("trusted got %s", got)
	}

	untrusted := httptest.NewRequest(http.MethodGet, "http://auth/verify", nil)
	untrusted.RemoteAddr = "192.0.2.4:9999"
	untrusted.Header.Set("CF-Connecting-IP", "203.0.113.8")
	if got := g.clientIP(untrusted); got != "192.0.2.4" {
		t.Fatalf("untrusted got %s", got)
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

func TestHashShape(t *testing.T) {
	salt := []byte("0123456789abcdef")
	h := deriveKey([]byte("x"), salt)
	if len(h) != sha256.Size {
		t.Fatalf("hash len=%d", len(h))
	}
}

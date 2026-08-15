package gateway

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestDynamicHostPolicyAcceptsChangingHTTPSHosts(t *testing.T) {
	cfg := testConfig()
	cfg.PublicScheme = "https"
	g, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer g.Close()
	for _, host := range []string{"old.example.test", "new.example.test", "192.0.2.10", "[2001:db8::10]"} {
		req := transportLoginRequest("https", host)
		rec := httptest.NewRecorder()
		g.Handler().ServeHTTP(rec, req)
		if rec.Code != http.StatusNoContent {
			t.Fatalf("host %q got %d body=%s", host, rec.Code, rec.Body.String())
		}
	}
}

func TestHTTPDynamicHostOriginAndCookie(t *testing.T) {
	cfg := testConfig()
	cfg.PublicScheme = "http"
	g, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer g.Close()
	for _, host := range []string{"192.168.1.37:19080", "100.64.12.8:19080", "dsh-host:19080", "[fd7a:115c:a1e0::7]:19080"} {
		req := transportLoginRequest("http", host)
		rec := httptest.NewRecorder()
		g.Handler().ServeHTTP(rec, req)
		if rec.Code != http.StatusNoContent {
			t.Fatalf("host %q got %d body=%s", host, rec.Code, rec.Body.String())
		}
		cookies := rec.Result().Cookies()
		if len(cookies) != 1 || cookies[0].Secure || !cookies[0].HttpOnly || cookies[0].SameSite != http.SameSiteStrictMode {
			t.Fatalf("HTTP cookie for %q: %#v", host, cookies)
		}
	}
}

func TestConfiguredSchemeRejectsOriginSchemeOrAuthorityMismatch(t *testing.T) {
	for _, tc := range []struct{ name, scheme, origin, host string }{
		{"HTTP rejects HTTPS", "http", "https://192.168.1.37:19080", "192.168.1.37:19080"},
		{"HTTPS rejects HTTP", "https", "http://new.example.test", "new.example.test"},
		{"different host", "http", "http://192.168.1.38:19080", "192.168.1.37:19080"},
		{"different port", "http", "http://192.168.1.37:19081", "192.168.1.37:19080"},
		{"empty request port", "http", "http://192.168.1.37:19080", "192.168.1.37:"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := testConfig()
			cfg.PublicScheme = tc.scheme
			g, err := New(cfg)
			if err != nil {
				t.Fatal(err)
			}
			defer g.Close()
			req := transportLoginRequest(tc.scheme, tc.host)
			req.Header.Set("Origin", tc.origin)
			rec := httptest.NewRecorder()
			g.Handler().ServeHTTP(rec, req)
			if rec.Code != http.StatusForbidden {
				t.Fatalf("got %d body=%s", rec.Code, rec.Body.String())
			}
		})
	}
}

func TestFixedHostPolicyRemainsOptionalCompatibilityMode(t *testing.T) {
	cfg := testConfig()
	cfg.PublicScheme = "https"
	cfg.ExpectedHost = "dsh.example.test"
	g, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer g.Close()
	for _, tc := range []struct {
		host string
		want int
	}{{"dsh.example.test", http.StatusOK}, {"other.example.test", http.StatusForbidden}} {
		req := httptest.NewRequest(http.MethodGet, "http://auth/__dsh_auth/login", nil)
		req.Host = tc.host
		req.RemoteAddr = "127.0.0.1:1234"
		rec := httptest.NewRecorder()
		g.Handler().ServeHTTP(rec, req)
		if rec.Code != tc.want {
			t.Fatalf("host %q got %d want %d", tc.host, rec.Code, tc.want)
		}
	}
}

func transportLoginRequest(scheme, host string) *http.Request {
	req := httptest.NewRequest(http.MethodPost, "http://auth/__dsh_auth/session", strings.NewReader(`{"key":"test-management-key-with-enough-entropy"}`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Origin", scheme+"://"+host)
	req.Host = host
	req.RemoteAddr = "127.0.0.1:1234"
	return req
}

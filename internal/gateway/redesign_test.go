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

func redesignedConfig() Config {
	key := "test-management-key-with-enough-entropy"
	digest := sha256.Sum256([]byte(key))
	return Config{
		KeyHash:               "sha256:" + base64.RawURLEncoding.EncodeToString(digest[:]),
		SessionTTL:            time.Hour,
		CookieName:            "dsh_gateway_session",
		PublicScheme:          "https",
		ExpectedHost:          "dsh.example.test",
		TrustedProxyIP:        "127.0.0.1",
		ClientIPHeader:        "X-DSH-Client-IP",
		RequireClientIdentity: true,
		FailureBurst:          2,
		FailureRefill:         time.Minute,
		GlobalBurst:           3,
		GlobalRefill:          time.Minute,
		StateTTL:              time.Hour,
		StateMaxClients:       4,
		CleanupInterval:       time.Minute,
		SessionMax:            4,
		KeyCheckConcurrency:   1,
		KeyCheckBurst:         1,
		KeyCheckRefill:        time.Minute,
	}
}

func requestWithIdentity(method, path, identity string) *http.Request {
	req := httptest.NewRequest(method, "http://auth"+path, nil)
	req.Host = "dsh.example.test"
	req.RemoteAddr = "127.0.0.1:1234"
	if identity != "" {
		req.Header.Set("X-DSH-Client-IP", identity)
	}
	return req
}

func TestCorrectBearerBypassesExhaustedFailureBudget(t *testing.T) {
	g, err := New(redesignedConfig())
	if err != nil {
		t.Fatal(err)
	}
	defer g.Close()
	for i := 0; i < 2; i++ {
		req := requestWithIdentity(http.MethodGet, "/verify", "203.0.113.10")
		req.Header.Set("Authorization", "Bearer wrong")
		rec := httptest.NewRecorder()
		g.Handler().ServeHTTP(rec, req)
		if rec.Code != http.StatusUnauthorized {
			t.Fatalf("failure %d got %d", i, rec.Code)
		}
	}
	req := requestWithIdentity(http.MethodGet, "/verify", "203.0.113.10")
	req.Header.Set("Authorization", "Bearer test-management-key-with-enough-entropy")
	rec := httptest.NewRecorder()
	g.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusNoContent {
		t.Fatalf("correct key got %d", rec.Code)
	}
}

func TestValidCookieWinsOverBadAuthorization(t *testing.T) {
	g, err := New(redesignedConfig())
	if err != nil {
		t.Fatal(err)
	}
	defer g.Close()
	cookie := redesignedLoginCookie(t, g, "203.0.113.11")
	req := requestWithIdentity(http.MethodGet, "/verify", "203.0.113.11")
	req.Header.Set("Authorization", "Bearer wrong")
	req.AddCookie(cookie)
	rec := httptest.NewRecorder()
	g.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusNoContent {
		t.Fatalf("valid cookie got %d", rec.Code)
	}
}

func TestTrustedIdentitySeparatesClientsAndGroupsIPv6By64(t *testing.T) {
	g, err := New(redesignedConfig())
	if err != nil {
		t.Fatal(err)
	}
	defer g.Close()
	for _, tc := range []struct{ in, want string }{
		{"203.0.113.8", "203.0.113.8"},
		{"::ffff:203.0.113.8", "203.0.113.8"},
		{"2001:db8:abcd:12::1", "2001:db8:abcd:12::/64"},
		{"2001:db8:abcd:12:ffff::9", "2001:db8:abcd:12::/64"},
	} {
		req := requestWithIdentity(http.MethodGet, "/verify", tc.in)
		got, err := g.clientIdentity(req)
		if err != nil || got != tc.want {
			t.Fatalf("%q got %q err=%v", tc.in, got, err)
		}
	}
}

func TestMissingTrustedIdentityFailsClosed(t *testing.T) {
	g, err := New(redesignedConfig())
	if err != nil {
		t.Fatal(err)
	}
	defer g.Close()
	req := requestWithIdentity(http.MethodGet, "/verify", "")
	req.Header.Set("Authorization", "Bearer wrong")
	rec := httptest.NewRecorder()
	g.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("got %d", rec.Code)
	}
}

func TestFailureBucketReturnsRetryAfterAndRefills(t *testing.T) {
	cfg := redesignedConfig()
	cfg.FailureBurst = 1
	cfg.FailureRefill = time.Second
	g, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer g.Close()
	now := time.Unix(1000, 0)
	g.now = func() time.Time { return now }
	wrong := func() *httptest.ResponseRecorder {
		req := requestWithIdentity(http.MethodGet, "/verify", "203.0.113.20")
		req.Header.Set("Authorization", "Bearer wrong")
		rec := httptest.NewRecorder()
		g.Handler().ServeHTTP(rec, req)
		return rec
	}
	if got := wrong().Code; got != http.StatusUnauthorized {
		t.Fatalf("first=%d", got)
	}
	second := wrong()
	if second.Code != http.StatusTooManyRequests || second.Header().Get("Retry-After") != "1" {
		t.Fatalf("second=%d retry=%q", second.Code, second.Header().Get("Retry-After"))
	}
	now = now.Add(time.Second)
	if got := wrong().Code; got != http.StatusUnauthorized {
		t.Fatalf("after refill=%d", got)
	}
}

func TestGlobalBudgetLimitsDistributedFailures(t *testing.T) {
	cfg := redesignedConfig()
	cfg.FailureBurst = 5
	cfg.GlobalBurst = 2
	g, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer g.Close()
	for i, ip := range []string{"203.0.113.1", "203.0.113.2", "203.0.113.3"} {
		req := requestWithIdentity(http.MethodGet, "/verify", ip)
		req.Header.Set("Authorization", "Bearer wrong")
		rec := httptest.NewRecorder()
		g.Handler().ServeHTTP(rec, req)
		want := http.StatusUnauthorized
		if i == 2 {
			want = http.StatusTooManyRequests
		}
		if rec.Code != want {
			t.Fatalf("%d got %d want %d", i, rec.Code, want)
		}
	}
}

func TestSessionCapacityIsBounded(t *testing.T) {
	cfg := redesignedConfig()
	cfg.SessionMax = 1
	g, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer g.Close()
	_ = redesignedLoginCookie(t, g, "203.0.113.30")
	req := requestWithIdentity(http.MethodPost, "/__dsh_auth/session", "203.0.113.31")
	req.Header.Set("Origin", "https://dsh.example.test")
	req.Header.Set("Content-Type", "application/json")
	req.Body = ioNopCloser(`{"key":"test-management-key-with-enough-entropy"}`)
	rec := httptest.NewRecorder()
	g.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("got %d", rec.Code)
	}
}

func TestNewKeyGenerationUsesVersionedSHA256(t *testing.T) {
	plain, hash, err := GenerateKeyHash()
	if err != nil {
		t.Fatal(err)
	}
	if plain == "" || !strings.HasPrefix(hash, "sha256:") {
		t.Fatalf("plain/hash shape invalid")
	}
	cfg := redesignedConfig()
	cfg.KeyHash = hash
	g, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer g.Close()
	if !g.validKey(plain) {
		t.Fatal("generated key rejected")
	}
}

func redesignedLoginCookie(t *testing.T, g *Gateway, identity string) *http.Cookie {
	t.Helper()
	req := requestWithIdentity(http.MethodPost, "/__dsh_auth/session", identity)
	req.Header.Set("Origin", "https://dsh.example.test")
	req.Header.Set("Content-Type", "application/json")
	req.Body = ioNopCloser(`{"key":"test-management-key-with-enough-entropy"}`)
	rec := httptest.NewRecorder()
	g.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusNoContent {
		t.Fatalf("login got %d body=%s", rec.Code, rec.Body.String())
	}
	cookies := rec.Result().Cookies()
	if len(cookies) != 1 {
		t.Fatalf("cookies=%d", len(cookies))
	}
	return cookies[0]
}

type stringReadCloser struct{ *strings.Reader }

func (stringReadCloser) Close() error       { return nil }
func ioNopCloser(s string) stringReadCloser { return stringReadCloser{strings.NewReader(s)} }

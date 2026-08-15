package gateway

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/scrypt"
)

type Config struct {
	KeySalt        string
	KeyHash        string
	SessionTTL     time.Duration
	CookieName     string
	SecureCookie   bool
	MaxFailures    int
	FailureWindow  time.Duration
	Lockout        time.Duration
	TrustedProxyIP string
	ExpectedHost   string
	AuditWriter    io.Writer
}

type session struct {
	expires time.Time
}

type failureState struct {
	attempts []time.Time
	blocked  time.Time
}

type Gateway struct {
	cfg      Config
	salt     []byte
	hash     []byte
	now      func() time.Time
	mu       sync.Mutex
	sessions map[[sha256.Size]byte]session
	failures map[string]failureState
}

func New(cfg Config) (*Gateway, error) {
	if cfg.CookieName == "" {
		cfg.CookieName = "dsh_gateway_session"
	}
	if cfg.SessionTTL <= 0 {
		cfg.SessionTTL = 12 * time.Hour
	}
	if cfg.MaxFailures <= 0 {
		cfg.MaxFailures = 5
	}
	if cfg.FailureWindow <= 0 {
		cfg.FailureWindow = 5 * time.Minute
	}
	if cfg.Lockout <= 0 {
		cfg.Lockout = 15 * time.Minute
	}
	salt, err := base64.RawURLEncoding.DecodeString(cfg.KeySalt)
	if err != nil || len(salt) < 16 {
		return nil, errors.New("invalid key salt")
	}
	hash, err := base64.RawURLEncoding.DecodeString(cfg.KeyHash)
	if err != nil || len(hash) != sha256.Size {
		return nil, errors.New("invalid key hash")
	}
	return &Gateway{cfg: cfg, salt: salt, hash: hash, now: time.Now, sessions: make(map[[sha256.Size]byte]session), failures: make(map[string]failureState)}, nil
}

// deriveKey uses scrypt with parameters selected for an interactive
// management-key check. The stored value is salted and compared in constant
// time; the plaintext key is never persisted by this package.
func deriveKey(key, salt []byte) []byte {
	derived, err := scrypt.Key(key, salt, 1<<15, 8, 1, sha256.Size)
	if err != nil {
		panic("scrypt parameters are invalid: " + err.Error())
	}
	return derived
}

func GenerateKeyHash() (plain, saltEncoded, hashEncoded string, err error) {
	key := make([]byte, 64)
	salt := make([]byte, 16)
	if _, err = rand.Read(key); err != nil {
		return
	}
	if _, err = rand.Read(salt); err != nil {
		return
	}
	plain = base64.RawURLEncoding.EncodeToString(key)
	saltEncoded = base64.RawURLEncoding.EncodeToString(salt)
	hashEncoded = base64.RawURLEncoding.EncodeToString(deriveKey([]byte(plain), salt))
	return
}

func (g *Gateway) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", g.health)
	mux.HandleFunc("/__dsh_auth/login", g.loginPage)
	mux.HandleFunc("/__dsh_auth/session", g.login)
	mux.HandleFunc("/__dsh_auth/logout", g.logout)
	mux.HandleFunc("/verify", g.verify)
	return g.securityHeaders(g.requireExpectedHost(mux))
}

func (g *Gateway) requireExpectedHost(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if g.cfg.ExpectedHost != "" {
			host := strings.ToLower(r.Host)
			if parsedHost, port, err := net.SplitHostPort(host); err == nil && port == "443" {
				host = parsedHost
			}
			if host != strings.ToLower(g.cfg.ExpectedHost) {
				http.Error(w, "forbidden", http.StatusForbidden)
				return
			}
		}
		next.ServeHTTP(w, r)
	})
}

func (g *Gateway) health(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusOK)
	_, _ = io.WriteString(w, "ok\n")
}

func (g *Gateway) loginPage(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	_, _ = io.WriteString(w, loginHTML)
}

func (g *Gateway) login(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !sameOrigin(r) {
		g.audit(r, "login", "cross-origin")
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	ip := g.clientIP(r)
	if g.blocked(ip) {
		g.audit(r, "login", "blocked")
		http.Error(w, "too many attempts", http.StatusTooManyRequests)
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 4096)
	defer r.Body.Close()
	var body struct {
		Key string `json:"key"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil || len(body.Key) > 512 {
		g.recordFailure(ip)
		g.audit(r, "login", "invalid")
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	if !g.validKey(body.Key) {
		g.recordFailure(ip)
		g.audit(r, "login", "invalid")
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	g.clearFailures(ip)
	token, err := randomToken()
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	g.mu.Lock()
	g.sessions[sha256.Sum256([]byte(token))] = session{expires: g.now().Add(g.cfg.SessionTTL)}
	g.mu.Unlock()
	http.SetCookie(w, &http.Cookie{Name: g.cfg.CookieName, Value: token, Path: "/", MaxAge: int(g.cfg.SessionTTL.Seconds()), HttpOnly: true, Secure: g.cfg.SecureCookie, SameSite: http.SameSiteStrictMode})
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusNoContent)
	g.audit(r, "login", "success")
}

func (g *Gateway) logout(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if cookie, err := r.Cookie(g.cfg.CookieName); err == nil {
		g.mu.Lock()
		delete(g.sessions, sha256.Sum256([]byte(cookie.Value)))
		g.mu.Unlock()
	}
	http.SetCookie(w, &http.Cookie{Name: g.cfg.CookieName, Value: "", Path: "/", MaxAge: -1, HttpOnly: true, Secure: g.cfg.SecureCookie, SameSite: http.SameSiteStrictMode})
	w.WriteHeader(http.StatusNoContent)
	g.audit(r, "logout", "success")
}

func (g *Gateway) verify(w http.ResponseWriter, r *http.Request) {
	ip := g.clientIP(r)
	if g.blocked(ip) {
		http.Error(w, "too many attempts", http.StatusTooManyRequests)
		return
	}
	if key, ok := bearer(r.Header.Values("Authorization")); ok {
		if g.validKey(key) {
			g.clearFailures(ip)
			w.WriteHeader(http.StatusNoContent)
			return
		}
		g.recordFailure(ip)
		g.audit(r, "verify", "invalid-bearer")
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	if cookie, err := r.Cookie(g.cfg.CookieName); err == nil && g.validSession(cookie.Value) {
		w.WriteHeader(http.StatusNoContent)
		return
	}
	g.audit(r, "verify", "missing")
	http.Error(w, "unauthorized", http.StatusUnauthorized)
}

func bearer(values []string) (string, bool) {
	if len(values) != 1 {
		return "", false
	}
	parts := strings.Fields(values[0])
	if len(parts) != 2 || !strings.EqualFold(parts[0], "Bearer") || parts[1] == "" {
		return "", false
	}
	return parts[1], true
}

func (g *Gateway) validKey(key string) bool {
	if len(key) == 0 || len(key) > 512 {
		return false
	}
	got := deriveKey([]byte(key), g.salt)
	return hmac.Equal(got, g.hash)
}

func (g *Gateway) validSession(token string) bool {
	if token == "" || len(token) > 512 {
		return false
	}
	key := sha256.Sum256([]byte(token))
	g.mu.Lock()
	defer g.mu.Unlock()
	s, ok := g.sessions[key]
	if !ok {
		return false
	}
	if !g.now().Before(s.expires) {
		delete(g.sessions, key)
		return false
	}
	return true
}

func randomToken() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

func sameOrigin(r *http.Request) bool {
	origin := r.Header.Get("Origin")
	if origin == "" {
		return true
	}
	u, err := url.Parse(origin)
	if err != nil || u.Host == "" {
		return false
	}
	return strings.EqualFold(u.Host, r.Host)
}

func (g *Gateway) clientIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = r.RemoteAddr
	}
	if ip := net.ParseIP(host); ip != nil {
		return ip.String()
	}
	return host
}

func (g *Gateway) blocked(ip string) bool {
	g.mu.Lock()
	defer g.mu.Unlock()
	s := g.failures[ip]
	return g.now().Before(s.blocked)
}

func (g *Gateway) recordFailure(ip string) {
	now := g.now()
	g.mu.Lock()
	defer g.mu.Unlock()
	s := g.failures[ip]
	cutoff := now.Add(-g.cfg.FailureWindow)
	kept := s.attempts[:0]
	for _, at := range s.attempts {
		if at.After(cutoff) {
			kept = append(kept, at)
		}
	}
	s.attempts = append(kept, now)
	if len(s.attempts) >= g.cfg.MaxFailures {
		s.blocked = now.Add(g.cfg.Lockout)
		s.attempts = nil
	}
	g.failures[ip] = s
}

func (g *Gateway) clearFailures(ip string) { g.mu.Lock(); delete(g.failures, ip); g.mu.Unlock() }

func (g *Gateway) audit(r *http.Request, event, result string) {
	if g.cfg.AuditWriter == nil {
		return
	}
	entry := map[string]string{"time": g.now().UTC().Format(time.RFC3339), "event": event, "result": result, "ip": g.clientIP(r), "method": r.Method}
	b, _ := json.Marshal(entry)
	_, _ = fmt.Fprintln(g.cfg.AuditWriter, string(b))
}

func (g *Gateway) securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("Referrer-Policy", "no-referrer")
		next.ServeHTTP(w, r)
	})
}

const loginHTML = `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1,viewport-fit=cover">
<meta name="robots" content="noindex,nofollow">
<meta name="color-scheme" content="light dark">
<meta name="theme-color" content="#fafafa" media="(prefers-color-scheme: light)">
<meta name="theme-color" content="#0a0a0a" media="(prefers-color-scheme: dark)">
<title>Sign in · DeepSeek Harness</title>
<style>
:root{color-scheme:light dark;--bg:#fafafa;--surface:#fff;--text:#171717;--muted:#666;--line:rgba(0,0,0,.12);--field:#fff;--button:#171717;--button-text:#fff;--focus:#0072f5;--error:#d93025}
@media(prefers-color-scheme:dark){:root{--bg:#0a0a0a;--surface:#111;--text:#ededed;--muted:#8f8f8f;--line:rgba(255,255,255,.14);--field:#111;--button:#ededed;--button-text:#171717;--focus:#52a8ff;--error:#ff7b72}}
*{box-sizing:border-box}
html,body{min-height:100%}
body{margin:0;background:var(--bg);color:var(--text);font:15px/1.5 system-ui,-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif;-webkit-font-smoothing:antialiased}
.page{min-height:100svh;display:grid;place-items:center;padding:max(24px,env(safe-area-inset-top)) max(20px,env(safe-area-inset-right)) max(24px,env(safe-area-inset-bottom)) max(20px,env(safe-area-inset-left))}
.panel{width:min(100%,360px)}
.mark{width:28px;height:28px;margin-bottom:28px;color:var(--text)}
h1{margin:0;font-size:28px;line-height:1.15;letter-spacing:-.9px;font-weight:600}
.intro{margin:10px 0 28px;color:var(--muted)}
label{display:block;margin-bottom:8px;font-size:13px;font-weight:500}
input,button{display:block;width:100%;height:48px;border:0;border-radius:8px;font:inherit}
input{padding:0 14px;background:var(--field);color:var(--text);box-shadow:0 0 0 1px var(--line);outline:none}
input::placeholder{color:var(--muted)}
input:focus-visible{box-shadow:0 0 0 2px var(--focus)}
button{margin-top:14px;background:var(--button);color:var(--button-text);font-weight:550;cursor:pointer;transition:opacity .15s ease,transform .05s ease}
button:hover{opacity:.88}
button:active{transform:translateY(1px)}
button:focus-visible{outline:2px solid var(--focus);outline-offset:2px}
button:disabled{cursor:wait;opacity:.55}
#msg{min-height:21px;margin:12px 0 0;color:var(--error);font-size:13px}
@media(max-height:520px){.page{place-items:start center}.panel{padding-top:20px}.mark{margin-bottom:20px}.intro{margin-bottom:20px}}
</style>
</head>
<body>
<main class="page"><section class="panel" aria-labelledby="title">
<svg class="mark" viewBox="0 0 24 24" aria-hidden="true"><path fill="currentColor" d="M12 2 3.3 7v10L12 22l8.7-5V7L12 2Zm0 2.3 6.7 3.8v7.8L12 19.7l-6.7-3.8V8.1L12 4.3Z"/></svg>
<h1 id="title">DeepSeek Harness</h1>
<p class="intro">Enter your management key to continue.</p>
<form id="f"><label for="k">Management key</label><input id="k" name="key" type="password" autocomplete="current-password" placeholder="Enter your key" spellcheck="false" autocapitalize="none" required><button id="submit" type="submit">Sign in</button></form>
<p id="msg" role="alert" aria-live="polite"></p>
</section></main>
<script>f.onsubmit=async(e)=>{e.preventDefault();msg.textContent='';submit.disabled=true;submit.textContent='Signing in…';try{let r=await fetch('/__dsh_auth/session',{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify({key:k.value})});k.value='';if(r.ok)location.href='/';else msg.textContent=r.status===429?'Too many attempts. Try again later.':'Invalid management key.'}catch(_){msg.textContent='Unable to sign in. Try again.'}finally{submit.disabled=false;submit.textContent='Sign in'}}</script>
</body>
</html>`

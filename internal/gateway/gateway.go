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
	return g.securityHeaders(mux)
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
	if host == g.cfg.TrustedProxyIP {
		if cf := net.ParseIP(strings.TrimSpace(r.Header.Get("CF-Connecting-IP"))); cf != nil {
			return cf.String()
		}
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

const loginHTML = `<!doctype html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><meta name="robots" content="noindex,nofollow"><title>DSH Login</title><style>body{font:16px system-ui;background:#0b1220;color:#e5edf8;display:grid;place-items:center;min-height:100vh;margin:0}.box{width:min(420px,88vw);padding:28px;border:1px solid #263650;border-radius:16px;background:#111c2e}input,button{box-sizing:border-box;width:100%;padding:12px;margin-top:12px;border-radius:9px}button{cursor:pointer}#msg{min-height:1.5em;color:#ff9a9a}</style></head><body><main class="box"><h1>DeepSeek Harness</h1><p>Enter the management key.</p><form id="f"><input id="k" type="password" autocomplete="current-password" required><button>Sign in</button></form><p id="msg"></p></main><script>f.onsubmit=async(e)=>{e.preventDefault();msg.textContent='';let r=await fetch('/__dsh_auth/session',{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify({key:k.value})});k.value='';if(r.ok)location.href='/';else msg.textContent=r.status===429?'Too many attempts. Try later.':'Invalid management key.'}</script></body></html>`

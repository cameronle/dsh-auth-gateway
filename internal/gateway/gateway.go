package gateway

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"mime"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/scrypt"
)

type Config struct {
	KeySalt               string
	KeyHash               string
	SessionTTL            time.Duration
	CookieName            string
	PublicScheme          string
	ExpectedHost          string
	TrustedProxyIP        string
	ClientIPHeader        string
	RequireClientIdentity bool
	FailureBurst          int
	FailureRefill         time.Duration
	GlobalBurst           int
	GlobalRefill          time.Duration
	StateTTL              time.Duration
	StateMaxClients       int
	CleanupInterval       time.Duration
	SessionMax            int
	KeyCheckConcurrency   int
	KeyCheckBurst         int
	KeyCheckRefill        time.Duration
	// Deprecated source-compatibility fields; runtime uses token buckets.
	MaxFailures   int
	FailureWindow time.Duration
	Lockout       time.Duration
	AuditWriter   io.Writer
}

type session struct{ expires time.Time }
type bucket struct {
	tokens                       float64
	updated, lastSeen, lastAudit time.Time
	suppressed                   uint64
}
type credentialMode uint8

const (
	credentialSHA256 credentialMode = iota + 1
	credentialLegacyScrypt
)

type Gateway struct {
	cfg          Config
	mode         credentialMode
	salt, hash   []byte
	now          func() time.Time
	mu           sync.Mutex
	sessions     map[[sha256.Size]byte]session
	clients      map[string]*bucket
	overflow     bucket
	global       bucket
	legacyBucket bucket
	legacySem    chan struct{}
	cachedValid  [sha256.Size]byte
	cached       bool
	stop         chan struct{}
	done         chan struct{}
	closeOnce    sync.Once
}

func New(cfg Config) (*Gateway, error) {
	defaults(&cfg)
	if cfg.PublicScheme != "http" && cfg.PublicScheme != "https" {
		return nil, errors.New("public scheme must be http or https")
	}
	if cfg.ExpectedHost != "" {
		if _, ok := canonicalAuthority(cfg.PublicScheme, cfg.ExpectedHost); !ok {
			return nil, errors.New("invalid expected host")
		}
	}
	g := &Gateway{cfg: cfg, now: time.Now, sessions: make(map[[sha256.Size]byte]session), clients: make(map[string]*bucket), legacySem: make(chan struct{}, cfg.KeyCheckConcurrency), stop: make(chan struct{}), done: make(chan struct{})}
	if strings.HasPrefix(cfg.KeyHash, "sha256:") {
		d, err := base64.RawURLEncoding.DecodeString(strings.TrimPrefix(cfg.KeyHash, "sha256:"))
		if err != nil || len(d) != sha256.Size {
			return nil, errors.New("invalid sha256 key hash")
		}
		g.mode, g.hash = credentialSHA256, d
	} else {
		hashText, saltText := cfg.KeyHash, cfg.KeySalt
		if strings.HasPrefix(hashText, "scrypt:") {
			parts := strings.Split(hashText, ":")
			if len(parts) != 3 {
				return nil, errors.New("invalid scrypt key hash")
			}
			saltText, hashText = parts[1], parts[2]
		} else if strings.Contains(hashText, ":") {
			return nil, errors.New("unknown key hash format")
		}
		salt, e1 := base64.RawURLEncoding.DecodeString(saltText)
		hash, e2 := base64.RawURLEncoding.DecodeString(hashText)
		if e1 != nil || len(salt) < 16 || e2 != nil || len(hash) != sha256.Size {
			return nil, errors.New("invalid legacy scrypt key material")
		}
		g.mode, g.salt, g.hash = credentialLegacyScrypt, salt, hash
	}
	now := g.now()
	g.global = bucket{tokens: float64(cfg.GlobalBurst), updated: now, lastSeen: now}
	g.overflow = bucket{tokens: float64(cfg.FailureBurst), updated: now, lastSeen: now}
	g.legacyBucket = bucket{tokens: float64(cfg.KeyCheckBurst), updated: now, lastSeen: now}
	go g.cleanupLoop()
	return g, nil
}

func defaults(c *Config) {
	if c.CookieName == "" {
		c.CookieName = "dsh_gateway_session"
	}
	if c.SessionTTL <= 0 {
		c.SessionTTL = 12 * time.Hour
	}
	if c.PublicScheme == "" {
		c.PublicScheme = "https"
	}

	if c.ClientIPHeader == "" {
		c.ClientIPHeader = "X-DSH-Client-IP"
	}
	if c.TrustedProxyIP == "" {
		c.TrustedProxyIP = "127.0.0.1"
	}
	if c.FailureBurst <= 0 {
		c.FailureBurst = 5
	}
	if c.FailureRefill <= 0 {
		c.FailureRefill = 30 * time.Second
	}
	if c.GlobalBurst <= 0 {
		c.GlobalBurst = 100
	}
	if c.GlobalRefill <= 0 {
		c.GlobalRefill = 200 * time.Millisecond
	}
	if c.StateTTL <= 0 {
		c.StateTTL = time.Hour
	}
	if c.StateMaxClients <= 0 {
		c.StateMaxClients = 10000
	}
	if c.CleanupInterval <= 0 {
		c.CleanupInterval = time.Minute
	}
	if c.SessionMax <= 0 {
		c.SessionMax = 10000
	}
	if c.KeyCheckConcurrency <= 0 {
		c.KeyCheckConcurrency = 2
	}
	if c.KeyCheckBurst <= 0 {
		c.KeyCheckBurst = 4
	}
	if c.KeyCheckRefill <= 0 {
		c.KeyCheckRefill = 2 * time.Second
	}
}

func deriveKey(key, salt []byte) []byte {
	d, err := scrypt.Key(key, salt, 1<<15, 8, 1, sha256.Size)
	if err != nil {
		panic(err)
	}
	return d
}
func GenerateKeyHash() (plain, hash string, err error) {
	key := make([]byte, 64)
	if _, err = rand.Read(key); err != nil {
		return
	}
	plain = base64.RawURLEncoding.EncodeToString(key)
	d := sha256.Sum256([]byte(plain))
	hash = "sha256:" + base64.RawURLEncoding.EncodeToString(d[:])
	return
}
func (g *Gateway) Close() error { g.closeOnce.Do(func() { close(g.stop); <-g.done }); return nil }

func (g *Gateway) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", g.health)
	mux.HandleFunc("/__dsh_auth/login", g.loginPage)
	mux.HandleFunc("/__dsh_auth/session", g.login)
	mux.HandleFunc("/__dsh_auth/logout", g.logout)
	mux.HandleFunc("/verify", g.verify)
	return g.securityHeaders(g.requireValidHost(mux))
}
func (g *Gateway) requireValidHost(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h, ok := canonicalAuthority(g.cfg.PublicScheme, r.Host)
		if !ok || (g.cfg.ExpectedHost != "" && h != expectedAuthority(g.cfg.PublicScheme, g.cfg.ExpectedHost)) {
			http.Error(w, "forbidden", http.StatusForbidden)
			return
		}
		next.ServeHTTP(w, r)
	})
}
func (g *Gateway) health(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(200)
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
	if !g.sameOrigin(r) {
		g.audit(r, "login", "cross-origin", "", "")
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	mt, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if err != nil || !strings.EqualFold(mt, "application/json") {
		http.Error(w, "unsupported media type", http.StatusUnsupportedMediaType)
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 4096)
	defer r.Body.Close()
	key, err := decodeLoginKey(r.Body)
	if err != nil {
		g.audit(r, "login", "malformed", "", "")
		http.Error(w, "bad request", 400)
		return
	}
	identity, err := g.clientIdentity(r)
	if err != nil {
		g.audit(r, "login", "unavailable", "client-identity-unavailable", "")
		serviceUnavailable(w)
		return
	}
	valid, wait := g.verifyKey(key)
	if wait > 0 {
		rateLimited(w, wait)
		g.audit(r, "login", "rate-limited", "verifier-capacity", identity)
		return
	}
	if !valid {
		ok, retry, reason := g.chargeFailure(identity)
		if !ok {
			rateLimited(w, retry)
			g.auditRateLimited(r, identity, reason)
			return
		}
		g.audit(r, "login", "invalid", "", identity)
		unauthorized(w)
		return
	}
	g.resetClient(identity)
	token, err := randomToken()
	if err != nil {
		http.Error(w, "internal error", 500)
		return
	}
	now := g.now()
	g.mu.Lock()
	g.cleanupLocked(now)
	if len(g.sessions) >= g.cfg.SessionMax {
		g.mu.Unlock()
		g.audit(r, "login", "unavailable", "session-capacity", identity)
		serviceUnavailable(w)
		return
	}
	g.sessions[sha256.Sum256([]byte(token))] = session{expires: now.Add(g.cfg.SessionTTL)}
	g.mu.Unlock()
	// #nosec G124 -- Secure is deliberately derived from the validated external scheme; HTTP is an explicit private-network mode.
	http.SetCookie(w, &http.Cookie{Name: g.cfg.CookieName, Value: token, Path: "/", MaxAge: int(g.cfg.SessionTTL.Seconds()), HttpOnly: true, Secure: g.cfg.PublicScheme == "https", SameSite: http.SameSiteStrictMode})
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(204)
	g.audit(r, "login", "success", "", identity)
}

func (g *Gateway) verify(w http.ResponseWriter, r *http.Request) {
	if c, err := r.Cookie(g.cfg.CookieName); err == nil && g.validSession(c.Value) {
		w.WriteHeader(204)
		return
	}
	key, ok := bearer(r.Header.Values("Authorization"))
	if !ok {
		unauthorized(w)
		return
	}
	identity, err := g.clientIdentity(r)
	if err != nil {
		serviceUnavailable(w)
		g.audit(r, "verify", "unavailable", "client-identity-unavailable", "")
		return
	}
	valid, wait := g.verifyKey(key)
	if wait > 0 {
		rateLimited(w, wait)
		g.audit(r, "verify", "rate-limited", "verifier-capacity", identity)
		return
	}
	if valid {
		g.resetClient(identity)
		w.WriteHeader(204)
		return
	}
	admit, retry, reason := g.chargeFailure(identity)
	if !admit {
		rateLimited(w, retry)
		g.auditRateLimited(r, identity, reason)
		return
	}
	g.audit(r, "verify", "invalid-bearer", "", identity)
	unauthorized(w)
}

func (g *Gateway) logout(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !g.sameOrigin(r) {
		g.audit(r, "logout", "cross-origin", "", "")
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	if c, e := r.Cookie(g.cfg.CookieName); e == nil {
		g.mu.Lock()
		delete(g.sessions, sha256.Sum256([]byte(c.Value)))
		g.mu.Unlock()
	}
	// #nosec G124 -- Secure is deliberately derived from the validated external scheme; HTTP is an explicit private-network mode.
	http.SetCookie(w, &http.Cookie{Name: g.cfg.CookieName, Value: "", Path: "/", MaxAge: -1, HttpOnly: true, Secure: g.cfg.PublicScheme == "https", SameSite: http.SameSiteStrictMode})
	w.WriteHeader(204)
	g.audit(r, "logout", "success", "", "")
}

func (g *Gateway) verifyKey(key string) (bool, time.Duration) {
	if len(key) == 0 || len(key) > 512 {
		return false, 0
	}
	d := sha256.Sum256([]byte(key))
	if g.mode == credentialSHA256 {
		return hmac.Equal(d[:], g.hash), 0
	}
	g.mu.Lock()
	if g.cached {
		ok := hmac.Equal(d[:], g.cachedValid[:])
		g.mu.Unlock()
		return ok, 0
	}
	now := g.now()
	wait := bucketWait(&g.legacyBucket, now, g.cfg.KeyCheckBurst, g.cfg.KeyCheckRefill)
	if wait > 0 {
		g.mu.Unlock()
		return false, wait
	}
	g.legacyBucket.tokens--
	g.mu.Unlock()
	select {
	case g.legacySem <- struct{}{}:
		defer func() { <-g.legacySem }()
	default:
		return false, time.Second
	}
	ok := hmac.Equal(deriveKey([]byte(key), g.salt), g.hash)
	if ok {
		g.mu.Lock()
		g.cachedValid = d
		g.cached = true
		g.mu.Unlock()
	}
	return ok, 0
}

func (g *Gateway) validKey(key string) bool {
	ok, _ := g.verifyKey(key)
	return ok
}

func (g *Gateway) clientIdentity(r *http.Request) (string, error) {
	peer, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		peer = r.RemoteAddr
	}
	p, err := netip.ParseAddr(peer)
	if err != nil {
		return "", err
	}
	trusted := p.Unmap().String() == g.cfg.TrustedProxyIP
	if !trusted {
		return normalizeIdentity(p), nil
	}
	vals := r.Header.Values(g.cfg.ClientIPHeader)
	if len(vals) != 1 || strings.Contains(vals[0], ",") {
		if g.cfg.RequireClientIdentity {
			return "", errors.New("missing client identity")
		}
		return normalizeIdentity(p), nil
	}
	ip, err := netip.ParseAddr(strings.TrimSpace(vals[0]))
	if err != nil {
		return "", err
	}
	return normalizeIdentity(ip), nil
}

func (g *Gateway) clientIP(r *http.Request) string {
	id, _ := g.clientIdentity(r)
	return id
}

func (g *Gateway) blocked(id string) bool {
	g.mu.Lock()
	defer g.mu.Unlock()
	b := g.clients[id]
	return b != nil && bucketWait(b, g.now(), g.cfg.FailureBurst, g.cfg.FailureRefill) > 0
}
func normalizeIdentity(ip netip.Addr) string {
	ip = ip.Unmap()
	if ip.Is4() {
		return ip.String()
	}
	return netip.PrefixFrom(ip, 64).Masked().String()
}

func (g *Gateway) chargeFailure(id string) (bool, time.Duration, string) {
	g.mu.Lock()
	defer g.mu.Unlock()
	now := g.now()
	g.cleanupLocked(now)
	b, reason := g.clientBucketLocked(id, now)
	cw := bucketWait(b, now, g.cfg.FailureBurst, g.cfg.FailureRefill)
	gw := bucketWait(&g.global, now, g.cfg.GlobalBurst, g.cfg.GlobalRefill)
	if cw > 0 || gw > 0 {
		if gw > cw {
			return false, ceilDuration(gw), "global-budget"
		}
		return false, ceilDuration(cw), reason
	}
	b.tokens--
	b.lastSeen = now
	g.global.tokens--
	g.global.lastSeen = now
	return true, 0, ""
}
func (g *Gateway) clientBucketLocked(id string, now time.Time) (*bucket, string) {
	if b := g.clients[id]; b != nil {
		return b, "client-budget"
	}
	if len(g.clients) < g.cfg.StateMaxClients {
		b := &bucket{tokens: float64(g.cfg.FailureBurst), updated: now, lastSeen: now}
		g.clients[id] = b
		return b, "client-budget"
	}
	return &g.overflow, "overflow-budget"
}
func bucketWait(b *bucket, now time.Time, cap int, refill time.Duration) time.Duration {
	if b.updated.IsZero() {
		b.updated = now
		b.tokens = float64(cap)
	}
	if now.After(b.updated) {
		b.tokens = math.Min(float64(cap), b.tokens+float64(now.Sub(b.updated))/float64(refill))
		b.updated = now
	}
	if b.tokens >= 1 {
		return 0
	}
	return time.Duration(math.Ceil((1 - b.tokens) * float64(refill)))
}
func (g *Gateway) resetClient(id string) {
	g.mu.Lock()
	if b := g.clients[id]; b != nil {
		b.tokens = float64(g.cfg.FailureBurst)
		b.updated = g.now()
		b.lastSeen = g.now()
	}
	g.mu.Unlock()
}

func (g *Gateway) validSession(token string) bool {
	if token == "" || len(token) > 512 {
		return false
	}
	k := sha256.Sum256([]byte(token))
	g.mu.Lock()
	defer g.mu.Unlock()
	s, ok := g.sessions[k]
	if !ok {
		return false
	}
	if !g.now().Before(s.expires) {
		delete(g.sessions, k)
		return false
	}
	return true
}
func (g *Gateway) cleanupLoop() {
	t := time.NewTicker(g.cfg.CleanupInterval)
	defer func() { t.Stop(); close(g.done) }()
	for {
		select {
		case now := <-t.C:
			g.mu.Lock()
			g.cleanupLocked(now)
			g.mu.Unlock()
		case <-g.stop:
			return
		}
	}
}
func (g *Gateway) cleanupLocked(now time.Time) {
	for k, s := range g.sessions {
		if !now.Before(s.expires) {
			delete(g.sessions, k)
		}
	}
	for id, b := range g.clients {
		bucketWait(b, now, g.cfg.FailureBurst, g.cfg.FailureRefill)
		if b.tokens >= float64(g.cfg.FailureBurst) && now.Sub(b.lastSeen) >= g.cfg.StateTTL {
			delete(g.clients, id)
		}
	}
}

func (g *Gateway) auditRateLimited(r *http.Request, id, reason string) {
	g.mu.Lock()
	now := g.now()
	b, _ := g.clientBucketLocked(id, now)
	if now.Sub(b.lastAudit) >= time.Minute {
		supp := b.suppressed
		b.suppressed = 0
		b.lastAudit = now
		g.mu.Unlock()
		g.audit(r, "auth", "rate-limited", reason, id, fmt.Sprint(supp))
		return
	}
	b.suppressed++
	g.mu.Unlock()
}
func (g *Gateway) audit(r *http.Request, event, result, reason, client string, extra ...string) {
	if g.cfg.AuditWriter == nil {
		return
	}
	m := map[string]string{"time": g.now().UTC().Format(time.RFC3339), "event": event, "result": result, "method": r.Method}
	if client != "" {
		m["client"] = client
	}
	if reason != "" {
		m["reason"] = reason
	}
	if len(extra) > 0 && extra[0] != "0" {
		m["suppressed"] = extra[0]
	}
	b, _ := json.Marshal(m)
	_, _ = fmt.Fprintln(g.cfg.AuditWriter, string(b))
}

func bearer(v []string) (string, bool) {
	if len(v) != 1 {
		return "", false
	}
	p := strings.Fields(v[0])
	returnValue := len(p) == 2 && strings.EqualFold(p[0], "Bearer") && p[1] != ""
	if !returnValue {
		return "", false
	}
	return p[1], true
}
func randomToken() (string, error) {
	b := make([]byte, 32)
	if _, e := rand.Read(b); e != nil {
		return "", e
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}
func unauthorized(w http.ResponseWriter) {
	w.Header().Set("Cache-Control", "no-store")
	http.Error(w, "unauthorized", http.StatusUnauthorized)
}
func rateLimited(w http.ResponseWriter, d time.Duration) {
	seconds := int(math.Ceil(d.Seconds()))
	if seconds < 1 {
		seconds = 1
	}
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Retry-After", strconv.Itoa(seconds))
	http.Error(w, "too many attempts", http.StatusTooManyRequests)
}
func serviceUnavailable(w http.ResponseWriter) {
	w.Header().Set("Cache-Control", "no-store")
	http.Error(w, "service unavailable", http.StatusServiceUnavailable)
}
func ceilDuration(d time.Duration) time.Duration {
	if d <= 0 {
		return time.Second
	}
	return time.Duration(math.Ceil(d.Seconds())) * time.Second
}
func (g *Gateway) sameOrigin(r *http.Request) bool {
	origins := r.Header.Values("Origin")
	if len(origins) == 0 {
		return true
	}
	if len(origins) != 1 || strings.Contains(origins[0], ",") {
		return false
	}
	o := origins[0]
	u, err := url.Parse(o)
	if err != nil || !strings.EqualFold(u.Scheme, g.cfg.PublicScheme) || u.Host == "" || u.User != nil || u.Path != "" || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" || strings.Contains(o, "#") {
		return false
	}
	originAuthority, ok := canonicalAuthority(g.cfg.PublicScheme, u.Host)
	if !ok {
		return false
	}
	requestAuthority, ok := canonicalAuthority(g.cfg.PublicScheme, r.Host)
	return ok && originAuthority == requestAuthority
}

func canonicalAuthority(scheme, authority string) (string, bool) {
	if scheme != "http" && scheme != "https" || authority == "" || strings.HasSuffix(authority, ":") {
		return "", false
	}
	u, err := url.Parse("//" + authority)
	if err != nil || u.Host == "" || u.User != nil || u.Path != "" || u.RawQuery != "" || u.Fragment != "" {
		return "", false
	}
	host := strings.TrimSuffix(strings.ToLower(u.Hostname()), ".")
	if host == "" {
		return "", false
	}
	if ip := net.ParseIP(host); ip == nil && !validAuthorityHostname(host) {
		return "", false
	}
	port := u.Port()
	defaultPort := "443"
	if scheme == "http" {
		defaultPort = "80"
	}
	if port == "" {
		port = defaultPort
	} else if n, err := strconv.Atoi(port); err != nil || n < 1 || n > 65535 {
		return "", false
	}
	if ip := net.ParseIP(host); ip != nil && strings.Contains(host, ":") {
		host = "[" + host + "]"
	}
	return host + ":" + port, true
}

func expectedAuthority(scheme, host string) string {
	a, _ := canonicalAuthority(scheme, host)
	return a
}

func validAuthorityHostname(host string) bool {
	if len(host) > 253 || strings.HasPrefix(host, ".") || strings.Contains(host, "..") {
		return false
	}
	for _, label := range strings.Split(host, ".") {
		if label == "" || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for _, r := range label {
			if !(r >= 'a' && r <= 'z' || r >= '0' && r <= '9' || r == '-') {
				return false
			}
		}
	}
	return true
}
func decodeLoginKey(r io.Reader) (string, error) {
	d := json.NewDecoder(r)
	t, e := d.Token()
	if e != nil || t != json.Delim('{') {
		return "", errors.New("object required")
	}
	if !d.More() {
		return "", errors.New("key missing")
	}
	n, e := d.Token()
	if e != nil || n != "key" {
		return "", errors.New("only key allowed")
	}
	var k string
	if e = d.Decode(&k); e != nil || k == "" || len(k) > 512 {
		return "", errors.New("invalid key")
	}
	if d.More() {
		return "", errors.New("extra field")
	}
	if t, e = d.Token(); e != nil || t != json.Delim('}') {
		return "", errors.New("invalid object")
	}
	if e = d.Decode(&struct{}{}); e != io.EOF {
		return "", errors.New("trailing json")
	}
	return k, nil
}
func (g *Gateway) securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("Referrer-Policy", "no-referrer")
		next.ServeHTTP(w, r)
	})
}

var _ = context.Canceled

const loginHTML = `<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1,viewport-fit=cover"><meta name="robots" content="noindex,nofollow"><meta name="color-scheme" content="light dark"><meta name="theme-color" content="#fafafa" media="(prefers-color-scheme: light)"><meta name="theme-color" content="#0a0a0a" media="(prefers-color-scheme: dark)"><title>Sign in · DeepSeek Harness</title><style>:root{color-scheme:light dark;--bg:#fafafa;--text:#171717;--muted:#666;--line:rgba(0,0,0,.12);--field:#fff;--button:#171717;--button-text:#fff;--focus:#0072f5;--error:#d93025}@media(prefers-color-scheme:dark){:root{--bg:#0a0a0a;--text:#ededed;--muted:#8f8f8f;--line:rgba(255,255,255,.14);--field:#111;--button:#ededed;--button-text:#171717;--focus:#52a8ff;--error:#ff7b72}}*{box-sizing:border-box}html,body{min-height:100%}body{margin:0;background:var(--bg);color:var(--text);font:15px/1.5 system-ui,-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif;-webkit-font-smoothing:antialiased}.page{min-height:100svh;display:grid;place-items:center;padding:24px 20px}.panel{width:min(100%,360px)}.mark{width:28px;height:28px;margin-bottom:28px}h1{margin:0;font-size:28px;line-height:1.15;letter-spacing:-.9px;font-weight:600}.intro{margin:10px 0 28px;color:var(--muted)}label{display:block;margin-bottom:8px;font-size:13px;font-weight:500}.field-wrap{position:relative}input,button{display:block;width:100%;height:48px;border:0;border-radius:8px;font:inherit;transition:box-shadow .15s,background .15s,opacity .15s}input{padding:0 44px 0 14px;background:var(--field);color:var(--text);box-shadow:0 0 0 1px var(--line);outline:none}input::-ms-reveal,input::-ms-clear{display:none}input:focus-visible{box-shadow:0 0 0 2px var(--focus)}.toggle{position:absolute;right:4px;top:4px;width:40px;height:40px;margin:0;padding:0;background:transparent;color:var(--muted);border:0;border-radius:6px;cursor:pointer;display:grid;place-items:center;-webkit-tap-highlight-color:transparent;user-select:none;transition:color .15s}.toggle:hover{color:var(--text)}.toggle:focus-visible{outline:none;box-shadow:0 0 0 2px var(--focus)}.toggle svg{width:20px;height:20px;pointer-events:none}.toggle .eye-off{display:none}.toggle.active .eye-on{display:none}.toggle.active .eye-off{display:block}button[type="submit"]{margin-top:14px;background:var(--button);color:var(--button-text);font-weight:550;cursor:pointer}button:disabled{opacity:.6;cursor:not-allowed}#msg{min-height:21px;margin:12px 0 0;color:var(--error);font-size:13px}</style></head><body><main class="page"><section class="panel"><svg class="mark" viewBox="0 0 24 24" aria-hidden="true"><path fill="currentColor" d="M12 2 3.3 7v10L12 22l8.7-5V7L12 2Zm0 2.3 6.7 3.8v7.8L12 19.7l-6.7-3.8V8.1L12 4.3Z"/></svg><h1>DeepSeek Harness</h1><p class="intro">Enter your management key to continue.</p><form id="f"><label for="k">Management key</label><div class="field-wrap"><input id="k" type="password" autocomplete="current-password" required autofocus><button type="button" id="t" class="toggle" aria-label="Toggle password visibility" title="Show/Hide"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><g class="eye-on"><path d="M2 12s3-7 10-7 10 7 10 7-3 7-10 7-10-7-10-7Z"/><circle cx="12" cy="12" r="3"/></g><g class="eye-off"><path d="M9.88 9.88a3 3 0 1 0 4.24 4.24"/><path d="M10.73 5.08A10.43 10.43 0 0 1 12 5c7 0 10 7 10 7a13.16 13.16 0 0 1-1.67 2.68"/><path d="M6.61 6.61A13.526 13.526 0 0 0 2 12s3 7 10 7a9.74 9.74 0 0 0 5.39-1.61"/><line x1="2" x2="22" y1="2" y2="22"/></g></svg></button></div><button id="submit" type="submit">Sign in</button></form><p id="msg" role="alert" aria-live="polite"></p></section></main><script>k.oninput=()=>{msg.textContent=''};t.onmousedown=(e)=>e.preventDefault();t.onclick=()=>{let isPwd=k.type==='password';k.type=isPwd?'text':'password';t.classList.toggle('active',isPwd);};f.onsubmit=async(e)=>{e.preventDefault();let keyVal=k.value.trim();if(!keyVal){k.focus();return;}submit.disabled=true;submit.textContent='Signing in…';try{let r=await fetch('/__dsh_auth/session',{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify({key:keyVal})});if(r.ok){let red=new URLSearchParams(location.search).get('redirect')||'/';if(!red.startsWith('/')||red.startsWith('//'))red='/';location.href=red;return;}msg.textContent=r.status===429?'Too many attempts. Try again later.':'Invalid management key.';submit.disabled=false;submit.textContent='Sign in';k.focus();k.select();}catch(err){msg.textContent='Network error. Please check your connection.';submit.disabled=false;submit.textContent='Sign in';k.focus();k.select();}};</script></body></html>`

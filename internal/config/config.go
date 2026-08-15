package config

import (
	"bufio"
	"errors"
	"net"
	"os"
	"strconv"
	"strings"
	"time"
)

type Config struct {
	Listen                string
	KeySalt               string
	KeyHash               string
	SessionTTL            time.Duration
	CookieName            string
	SecureCookie          bool
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
}

const maxDuration = 10 * 365 * 24 * time.Hour

var allowedKeys = map[string]struct{}{
	"LISTEN": {}, "KEY_SALT": {}, "KEY_HASH": {}, "SESSION_TTL": {}, "COOKIE_NAME": {}, "SECURE_COOKIE": {}, "EXPECTED_HOST": {},
	"TRUSTED_PROXY_IP": {}, "CLIENT_IP_HEADER": {}, "REQUIRE_CLIENT_IDENTITY": {}, "AUTH_FAILURE_BURST": {}, "AUTH_FAILURE_REFILL": {},
	"AUTH_GLOBAL_BURST": {}, "AUTH_GLOBAL_REFILL": {}, "AUTH_STATE_TTL": {}, "AUTH_STATE_MAX_CLIENTS": {}, "AUTH_CLEANUP_INTERVAL": {},
	"AUTH_SESSION_MAX": {}, "KEY_CHECK_CONCURRENCY": {}, "KEY_CHECK_BURST": {}, "KEY_CHECK_REFILL": {},
}
var deprecatedKeys = map[string]struct{}{"MAX_FAILURES": {}, "FAILURE_WINDOW": {}, "LOCKOUT": {}}

func Load(path string) (Config, error) {
	info, err := os.Stat(path)
	if err != nil {
		return Config{}, err
	}
	if info.Mode().Perm()&0007 != 0 || info.Mode().Perm()&0030 != 0 {
		return Config{}, errors.New("config permissions must be 0600 or 0640")
	}
	f, err := os.Open(path)
	if err != nil {
		return Config{}, err
	}
	defer f.Close()
	m := map[string]string{}
	s := bufio.NewScanner(f)
	for s.Scan() {
		line := strings.TrimSpace(s.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		k, v, ok := strings.Cut(line, "=")
		if !ok {
			return Config{}, errors.New("invalid config line")
		}
		key := strings.TrimSpace(k)
		if _, old := deprecatedKeys[key]; old {
			return Config{}, errors.New("deprecated config key " + key + ": migrate to AUTH_* token-bucket settings")
		}
		if _, ok := allowedKeys[key]; !ok {
			return Config{}, errors.New("unknown config key: " + key)
		}
		if _, dup := m[key]; dup {
			return Config{}, errors.New("duplicate config key: " + key)
		}
		m[key] = strings.TrimSpace(v)
	}
	if err := s.Err(); err != nil {
		return Config{}, err
	}
	c := Config{Listen: m["LISTEN"], KeySalt: m["KEY_SALT"], KeyHash: m["KEY_HASH"], CookieName: m["COOKIE_NAME"], ExpectedHost: strings.ToLower(m["EXPECTED_HOST"]), TrustedProxyIP: m["TRUSTED_PROXY_IP"], ClientIPHeader: m["CLIENT_IP_HEADER"]}
	if c.Listen == "" {
		c.Listen = "127.0.0.1:18081"
	}
	host, _, err := net.SplitHostPort(c.Listen)
	if err != nil || net.ParseIP(host) == nil || !net.ParseIP(host).IsLoopback() {
		return Config{}, errors.New("LISTEN must be a loopback IP:port")
	}
	if c.KeyHash == "" {
		return Config{}, errors.New("KEY_HASH is required")
	}
	if !strings.HasPrefix(c.KeyHash, "sha256:") && c.KeySalt == "" && !strings.HasPrefix(c.KeyHash, "scrypt:") {
		return Config{}, errors.New("legacy KEY_HASH requires KEY_SALT")
	}
	if !validHostname(c.ExpectedHost) {
		return Config{}, errors.New("EXPECTED_HOST must be a hostname without scheme or path")
	}
	if c.CookieName == "" {
		c.CookieName = "dsh_gateway_session"
	}
	if !validCookieName(c.CookieName) {
		return Config{}, errors.New("invalid COOKIE_NAME")
	}
	if c.TrustedProxyIP == "" {
		c.TrustedProxyIP = "127.0.0.1"
	}
	if ip := net.ParseIP(c.TrustedProxyIP); ip == nil || !ip.IsLoopback() {
		return Config{}, errors.New("TRUSTED_PROXY_IP must be loopback")
	}
	if c.ClientIPHeader == "" {
		c.ClientIPHeader = "X-DSH-Client-IP"
	}
	if !validHeaderName(c.ClientIPHeader) {
		return Config{}, errors.New("invalid CLIENT_IP_HEADER")
	}
	if c.SessionTTL, err = boundedDuration(m["SESSION_TTL"], 12*time.Hour); err != nil {
		return Config{}, fmtErr("SESSION_TTL", err)
	}
	if c.FailureRefill, err = boundedDuration(m["AUTH_FAILURE_REFILL"], 30*time.Second); err != nil {
		return Config{}, fmtErr("AUTH_FAILURE_REFILL", err)
	}
	if c.GlobalRefill, err = boundedDuration(m["AUTH_GLOBAL_REFILL"], 200*time.Millisecond); err != nil {
		return Config{}, fmtErr("AUTH_GLOBAL_REFILL", err)
	}
	if c.StateTTL, err = boundedDuration(m["AUTH_STATE_TTL"], time.Hour); err != nil {
		return Config{}, fmtErr("AUTH_STATE_TTL", err)
	}
	if c.CleanupInterval, err = boundedDuration(m["AUTH_CLEANUP_INTERVAL"], time.Minute); err != nil {
		return Config{}, fmtErr("AUTH_CLEANUP_INTERVAL", err)
	}
	if c.KeyCheckRefill, err = boundedDuration(m["KEY_CHECK_REFILL"], 2*time.Second); err != nil {
		return Config{}, fmtErr("KEY_CHECK_REFILL", err)
	}
	if c.FailureBurst, err = boundedInt(m["AUTH_FAILURE_BURST"], 5); err != nil {
		return Config{}, fmtErr("AUTH_FAILURE_BURST", err)
	}
	if c.GlobalBurst, err = boundedInt(m["AUTH_GLOBAL_BURST"], 100); err != nil {
		return Config{}, fmtErr("AUTH_GLOBAL_BURST", err)
	}
	if c.StateMaxClients, err = boundedInt(m["AUTH_STATE_MAX_CLIENTS"], 10000); err != nil {
		return Config{}, fmtErr("AUTH_STATE_MAX_CLIENTS", err)
	}
	if c.SessionMax, err = boundedInt(m["AUTH_SESSION_MAX"], 10000); err != nil {
		return Config{}, fmtErr("AUTH_SESSION_MAX", err)
	}
	if c.KeyCheckConcurrency, err = boundedInt(m["KEY_CHECK_CONCURRENCY"], 2); err != nil {
		return Config{}, fmtErr("KEY_CHECK_CONCURRENCY", err)
	}
	if c.KeyCheckBurst, err = boundedInt(m["KEY_CHECK_BURST"], 4); err != nil {
		return Config{}, fmtErr("KEY_CHECK_BURST", err)
	}
	if c.SecureCookie, err = parseBool(m["SECURE_COOKIE"], true); err != nil {
		return Config{}, fmtErr("SECURE_COOKIE", err)
	}
	if c.RequireClientIdentity, err = parseBool(m["REQUIRE_CLIENT_IDENTITY"], false); err != nil {
		return Config{}, fmtErr("REQUIRE_CLIENT_IDENTITY", err)
	}
	return c, nil
}
func fmtErr(name string, err error) error { return errors.New(name + ": " + err.Error()) }
func boundedDuration(s string, d time.Duration) (time.Duration, error) {
	if s == "" {
		return d, nil
	}
	v, e := time.ParseDuration(s)
	if e != nil || v <= 0 || v > maxDuration {
		return 0, errors.New("must be positive and at most 10 years")
	}
	return v, nil
}
func boundedInt(s string, d int) (int, error) {
	if s == "" {
		return d, nil
	}
	v, e := strconv.Atoi(s)
	if e != nil || v <= 0 || v > 1_000_000 {
		return 0, errors.New("must be a positive integer at most 1000000")
	}
	return v, nil
}
func parseBool(s string, d bool) (bool, error) {
	if s == "" {
		return d, nil
	}
	return strconv.ParseBool(s)
}
func validHeaderName(s string) bool {
	if s == "" {
		return false
	}
	for _, r := range s {
		if !(r >= 'A' && r <= 'Z' || r >= 'a' && r <= 'z' || r >= '0' && r <= '9' || r == '-') {
			return false
		}
	}
	return true
}
func validCookieName(name string) bool {
	if name == "" {
		return false
	}
	for _, r := range name {
		if r <= 0x20 || r >= 0x7f || strings.ContainsRune("()<>@,;:\\\"/[]?={}", r) {
			return false
		}
	}
	return true
}
func validHostname(host string) bool {
	if host == "" || len(host) > 253 || strings.HasPrefix(host, ".") || strings.HasSuffix(host, ".") || strings.Contains(host, "..") || strings.ContainsAny(host, " /\\:@[]") {
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

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
	Listen         string
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
}

const (
	maxDuration    = 10 * 365 * 24 * time.Hour
	maxMaxFailures = 1_000_000
)

var allowedKeys = map[string]struct{}{
	"LISTEN": {}, "KEY_SALT": {}, "KEY_HASH": {}, "SESSION_TTL": {},
	"COOKIE_NAME": {}, "SECURE_COOKIE": {}, "MAX_FAILURES": {},
	"FAILURE_WINDOW": {}, "LOCKOUT": {}, "TRUSTED_PROXY_IP": {}, "EXPECTED_HOST": {},
}

func Load(path string) (Config, error) {
	info, err := os.Stat(path)
	if err != nil {
		return Config{}, err
	}
	// The service commonly runs as an unprivileged user reading a root-owned,
	// group-readable file. Refuse all permissions for "other" and any write or
	// execute permission for the group; 0600 and 0640 are accepted.
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
		if _, ok := allowedKeys[key]; !ok {
			return Config{}, errors.New("unknown config key: " + key)
		}
		if _, exists := m[key]; exists {
			return Config{}, errors.New("duplicate config key: " + key)
		}
		m[key] = strings.TrimSpace(v)
	}
	if err := s.Err(); err != nil {
		return Config{}, err
	}
	cfg := Config{Listen: m["LISTEN"], KeySalt: m["KEY_SALT"], KeyHash: m["KEY_HASH"], CookieName: m["COOKIE_NAME"], TrustedProxyIP: m["TRUSTED_PROXY_IP"], ExpectedHost: strings.ToLower(m["EXPECTED_HOST"])}
	if cfg.Listen == "" {
		cfg.Listen = "127.0.0.1:18081"
	}
	host, _, err := net.SplitHostPort(cfg.Listen)
	if err != nil || net.ParseIP(host) == nil || !net.ParseIP(host).IsLoopback() {
		return Config{}, errors.New("LISTEN must be a loopback IP:port")
	}
	if cfg.KeySalt == "" || cfg.KeyHash == "" {
		return Config{}, errors.New("KEY_SALT and KEY_HASH are required")
	}
	if !validHostname(cfg.ExpectedHost) {
		return Config{}, errors.New("EXPECTED_HOST must be a hostname without scheme or path")
	}
	if cfg.CookieName == "" {
		cfg.CookieName = "dsh_gateway_session"
	}
	if !validCookieName(cfg.CookieName) {
		return Config{}, errors.New("COOKIE_NAME must be a valid HTTP cookie name")
	}
	cfg.SessionTTL, err = duration(m["SESSION_TTL"], 12*time.Hour)
	if err != nil || cfg.SessionTTL <= 0 || cfg.SessionTTL > maxDuration {
		return Config{}, errors.New("SESSION_TTL must be positive and at most 10 years")
	}
	cfg.FailureWindow, err = duration(m["FAILURE_WINDOW"], 5*time.Minute)
	if err != nil || cfg.FailureWindow <= 0 || cfg.FailureWindow > maxDuration {
		return Config{}, errors.New("FAILURE_WINDOW must be positive and at most 10 years")
	}
	cfg.Lockout, err = duration(m["LOCKOUT"], 15*time.Minute)
	if err != nil || cfg.Lockout <= 0 || cfg.Lockout > maxDuration {
		return Config{}, errors.New("LOCKOUT must be positive and at most 10 years")
	}
	cfg.MaxFailures, err = integer(m["MAX_FAILURES"], 5)
	if err != nil || cfg.MaxFailures > maxMaxFailures {
		return Config{}, errors.New("MAX_FAILURES must be a positive integer at most 1000000")
	}
	cfg.SecureCookie, err = boolean(m["SECURE_COOKIE"], true)
	if err != nil {
		return Config{}, errors.New("SECURE_COOKIE must be true or false")
	}
	if cfg.TrustedProxyIP == "" {
		cfg.TrustedProxyIP = "127.0.0.1"
	}
	if ip := net.ParseIP(cfg.TrustedProxyIP); ip == nil || !ip.IsLoopback() {
		return Config{}, errors.New("TRUSTED_PROXY_IP must be loopback")
	}
	return cfg, nil
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

func duration(s string, d time.Duration) (time.Duration, error) {
	if s == "" {
		return d, nil
	}
	return time.ParseDuration(s)
}

func integer(s string, d int) (int, error) {
	if s == "" {
		return d, nil
	}
	v, err := strconv.Atoi(s)
	if err != nil || v <= 0 {
		return 0, errors.New("invalid positive integer")
	}
	return v, nil
}

func boolean(s string, d bool) (bool, error) {
	if s == "" {
		return d, nil
	}
	return strconv.ParseBool(s)
}
